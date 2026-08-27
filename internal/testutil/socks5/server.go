// Package socks5 — минимальный инструментированный SOCKS5-сервер для тестов.
//
// Зачем он нужен: чтобы ПРОВЕРЯЕМО отличить «трафик пошёл через прокси» от
// «трафик пошёл напрямую». Обычный SOCKS5-сервер этого не даёт — он молча
// работает в обоих случаях, и тест, который просто проверяет доступность
// цели, проходил бы и при полностью сломанной маршрутизации.
//
// Сервер считает соединения и запоминает запрошенные адреса, поэтому в тесте
// можно утверждать: «правило увело example.com напрямую» — и это утверждение
// имеет наблюдаемое подтверждение.
//
// Реализация намеренно минимальна: RFC 1928, только команда CONNECT, плюс
// опциональная аутентификация по имени и паролю (RFC 1929) — она нужна,
// чтобы проверять поведение клиента при неверных учётных данных.
// Это тестовая оснастка, а не продуктовый код.
package socks5

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
)

const (
	version5       = 0x05
	methodNoAuth   = 0x00
	methodUserPass = 0x02
	methodNone     = 0xFF // «подходящего метода нет» — клиент обязан разорвать связь
	authVersion    = 0x01 // версия подпротокола аутентификации, RFC 1929
	authSuccess    = 0x00
	authFailure    = 0x01
	cmdConnect     = 0x01

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	replySuccess     = 0x00
	replyHostUnreach = 0x04
	replyCmdNotSup   = 0x07
)

// Server — тестовый SOCKS5-сервер, ведущий журнал обращений.
type Server struct {
	listener net.Listener

	// Учётные данные. Пустое имя означает «аутентификация не требуется».
	user, pass string

	// pin — отпечаток открытого ключа при запуске с TLS (см. tls.go).
	// Пусто для обычного сервера.
	pin string

	mu       sync.Mutex
	targets  []string
	authFail int

	wg     sync.WaitGroup
	closed chan struct{}
}

// Start поднимает сервер без аутентификации на свободном порту loopback.
func Start() (*Server, error) { return StartOn("127.0.0.1:0") }

// StartWithAuth поднимает сервер, требующий имя и пароль.
// Нужен для проверки поведения клиента при неверных учётных данных.
func StartWithAuth(user, pass string) (*Server, error) {
	s, err := StartOn("127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s.user, s.pass = user, pass
	return s, nil
}

// StartOn поднимает сервер на указанном адресе.
// Порт 0 означает «выбрать свободный».
func StartOn(addr string) (*Server, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("socks5 test server: listen %s: %w", addr, err)
	}
	s := &Server{listener: ln, closed: make(chan struct{})}
	s.wg.Add(1)
	go s.acceptLoop()
	return s, nil
}

// AuthFailures возвращает число отклонённых попыток аутентификации.
func (s *Server) AuthFailures() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.authFail
}

// Addr возвращает адрес, на котором слушает сервер.
func (s *Server) Addr() *net.TCPAddr { return s.listener.Addr().(*net.TCPAddr) }

// Targets возвращает копию списка адресов, которые запрашивались через прокси,
// в порядке поступления.
func (s *Server) Targets() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.targets...)
}

// Count возвращает число обслуженных запросов CONNECT.
func (s *Server) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.targets)
}

// Reset очищает журнал, чтобы один сервер можно было переиспользовать
// между случаями в табличном тесте.
func (s *Server) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.targets = nil
}

// Close останавливает сервер и дожидается завершения обработчиков.
func (s *Server) Close() error {
	select {
	case <-s.closed:
		return nil
	default:
		close(s.closed)
	}
	err := s.listener.Close()
	s.wg.Wait()
	return err
}

func (s *Server) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.closed:
				return // штатное закрытие
			default:
				return // слушатель умер — выходим, тест это заметит
			}
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer conn.Close()
			_ = s.handle(conn)
		}()
	}
}

func (s *Server) handle(conn net.Conn) error {
	if err := s.handshake(conn); err != nil {
		return err
	}

	target, err := readRequest(conn)
	if err != nil {
		return err
	}

	upstream, err := net.Dial("tcp", target)
	if err != nil {
		_ = writeReply(conn, replyHostUnreach)
		return err
	}
	defer upstream.Close()

	// Запрос принят к обслуживанию — фиксируем его в журнале.
	s.mu.Lock()
	s.targets = append(s.targets, target)
	s.mu.Unlock()

	if err := writeReply(conn, replySuccess); err != nil {
		return err
	}

	// Двусторонняя перекачка. Завершение любой стороны прекращает обмен.
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, conn); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, upstream); done <- struct{}{} }()
	<-done
	return nil
}

// handshake — приветствие и, если сервер настроен с учётными данными,
// аутентификация по RFC 1929.
func (s *Server) handshake(conn net.Conn) error {
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		return fmt.Errorf("socks5: чтение приветствия: %w", err)
	}
	if head[0] != version5 {
		return fmt.Errorf("socks5: версия %d не поддерживается", head[0])
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return fmt.Errorf("socks5: чтение методов: %w", err)
	}

	if s.user == "" {
		_, err := conn.Write([]byte{version5, methodNoAuth})
		return err
	}

	if !bytes.Contains(methods, []byte{methodUserPass}) {
		_, _ = conn.Write([]byte{version5, methodNone})
		return fmt.Errorf("socks5: клиент не предложил аутентификацию по паролю")
	}
	if _, err := conn.Write([]byte{version5, methodUserPass}); err != nil {
		return err
	}
	return s.authenticate(conn)
}

// authenticate — подпротокол имя/пароль, RFC 1929.
func (s *Server) authenticate(conn net.Conn) error {
	head := make([]byte, 2) // VER ULEN
	if _, err := io.ReadFull(conn, head); err != nil {
		return fmt.Errorf("socks5: чтение запроса аутентификации: %w", err)
	}
	if head[0] != authVersion {
		return fmt.Errorf("socks5: версия аутентификации %d не поддерживается", head[0])
	}

	user := make([]byte, int(head[1]))
	if _, err := io.ReadFull(conn, user); err != nil {
		return err
	}
	plen := make([]byte, 1)
	if _, err := io.ReadFull(conn, plen); err != nil {
		return err
	}
	pass := make([]byte, int(plen[0]))
	if _, err := io.ReadFull(conn, pass); err != nil {
		return err
	}

	if string(user) != s.user || string(pass) != s.pass {
		s.mu.Lock()
		s.authFail++
		s.mu.Unlock()
		_, _ = conn.Write([]byte{authVersion, authFailure})
		return fmt.Errorf("socks5: неверные учётные данные")
	}

	_, err := conn.Write([]byte{authVersion, authSuccess})
	return err
}

// readRequest разбирает запрос CONNECT и возвращает цель в виде "host:port".
func readRequest(conn net.Conn) (string, error) {
	head := make([]byte, 4) // VER CMD RSV ATYP
	if _, err := io.ReadFull(conn, head); err != nil {
		return "", fmt.Errorf("socks5: чтение запроса: %w", err)
	}
	if head[1] != cmdConnect {
		_ = writeReply(conn, replyCmdNotSup)
		return "", fmt.Errorf("socks5: команда %d не поддерживается", head[1])
	}

	var host string
	switch head[3] {
	case atypIPv4:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", err
		}
		host = net.IP(buf).String()
	case atypIPv6:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", err
		}
		host = net.IP(buf).String()
	case atypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", err
		}
		buf := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", err
		}
		host = string(buf)
	default:
		return "", fmt.Errorf("socks5: тип адреса %d не поддерживается", head[3])
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(portBuf)

	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

func writeReply(conn net.Conn, code byte) error {
	// BND.ADDR и BND.PORT клиентом в режиме CONNECT не используются —
	// отвечаем нулями, как это делает большинство реализаций.
	_, err := conn.Write([]byte{version5, code, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}
