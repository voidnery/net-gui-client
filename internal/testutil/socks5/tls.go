package socks5

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"time"
)

// StartTLS поднимает тестовый SOCKS5-сервер, принимающий соединения по TLS.
//
// Сертификат самоподписанный и создаётся заново при каждом запуске: он живёт
// ровно столько, сколько тест. Класть в репозиторий готовую пару ключей было
// бы хуже во всех отношениях — она протухает, попадает в поиск по утечкам и
// провоцирует использовать её где-то ещё.
//
// Проверять такой сертификат обычным путём нельзя, поэтому клиент в тесте
// работает по отпечатку открытого ключа — см. PublicKeyPin.
func StartTLS() (*Server, error) {
	cert, pin, err := selfSignedCert()
	if err != nil {
		return nil, err
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("socks5 test server: listen: %w", err)
	}

	s := &Server{
		// tls.NewListener сохраняет адрес нижележащего слушателя, поэтому
		// Addr() по-прежнему возвращает *net.TCPAddr.
		listener: tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}}),
		closed:   make(chan struct{}),
		pin:      pin,
	}
	s.wg.Add(1)
	go s.acceptLoop()
	return s, nil
}

// PublicKeyPin возвращает SHA-256 от SubjectPublicKeyInfo сертификата,
// в шестнадцатеричном виде.
//
// ⚠️ Именно от открытого КЛЮЧА, а не от сертификата целиком: ядро (sing-box)
// сверяет CertificatePublicKeySHA256. Отпечаток сертификата — другое число,
// и подстановка одного вместо другого даёт «пин не совпал» без внятного
// объяснения.
//
// Пусто, если сервер поднят без TLS.
func (s *Server) PublicKeyPin() string { return s.pin }

func selfSignedCert() (tls.Certificate, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("socks5 test server: генерация ключа: %w", err)
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "net-gui-client test socks5"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("socks5 test server: создание сертификата: %w", err)
	}

	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("socks5 test server: сериализация открытого ключа: %w", err)
	}
	sum := sha256.Sum256(spki)

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}, hex.EncodeToString(sum[:]), nil
}
