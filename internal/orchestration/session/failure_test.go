package session_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/bbesport/net-gui-client/internal/orchestration/profile"
	"github.com/bbesport/net-gui-client/internal/orchestration/rules"
	"github.com/bbesport/net-gui-client/internal/orchestration/session"
	"github.com/bbesport/net-gui-client/internal/testutil/proxyprobe"
	testsocks "github.com/bbesport/net-gui-client/internal/testutil/socks5"
)

// Негативные сценарии из списка баг-чекинга итерации И-1.
//
// Смысл этих тестов не в том, чтобы «покрыть строки», а в том, чтобы
// зафиксировать НАБЛЮДАЕМОЕ поведение при отказах. Часть выявленного здесь
// поведения неудобна — и именно поэтому важно, чтобы оно было записано
// тестом, а не обнаружено пользователем.

// TestConnectFailsWhenListenPortBusy: порт локального inbound занят.
//
// Ожидание: подключение падает с ошибкой, а сессия остаётся в Idle.
// Худший исход был бы «состояние Connected при неработающем inbound».
func TestConnectFailsWhenListenPortBusy(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("занять порт: %v", err)
	}
	defer busy.Close()
	busyPort := uint16(busy.Addr().(*net.TCPAddr).Port)

	upstream, err := testsocks.Start()
	if err != nil {
		t.Fatalf("запуск тестового SOCKS5: %v", err)
	}
	defer upstream.Close()

	manager := session.NewManager(context.Background())
	defer manager.Close()

	st, err := manager.Connect(context.Background(), session.ConnectOptions{
		Profile:    socksProfile("busy", upstream),
		Policy:     rules.PolicyAllExcept(),
		ListenAddr: netip.MustParseAddr("127.0.0.1"),
		ListenPort: busyPort,
	})
	if err == nil {
		t.Fatal("подключение прошло на занятом порту — ожидалась ошибка")
	}
	if st.State != session.StateIdle {
		t.Errorf("состояние = %s, ожидалось %s", st.State, session.StateIdle)
	}
	if st.Err == "" {
		t.Error("причина отказа не сохранена в статусе — пользователь не узнает, что произошло")
	}
}

// TestConnectSucceedsWhenUpstreamDown фиксирует НЕОЧЕВИДНОЕ поведение.
//
// Если вышестоящий сервер недоступен, подключение всё равно завершается
// успешно: ядро поднимает локальный inbound, а отказ проявляется только при
// первом реальном запросе. Формально это верно — SOCKS5 не устанавливает
// постоянного соединения с сервером, — но пользователю показывается
// «подключено» при полностью нерабочем пути.
//
// ⚠️ Это ровно та ловушка, о которой предупреждает 03-architecture.md §6.1:
// проверка уровня L1 («процесс жив, listener слушает») регулярно врёт.
// Закрывается в И-9 пробой уровня L2 — реальным запросом через аутбаунд.
// До тех пор поведение зафиксировано здесь, чтобы его изменение было
// осознанным, а не случайным.
func TestConnectSucceedsWhenUpstreamDown(t *testing.T) {
	// Занимаем порт и сразу освобождаем: адрес гарантированно свободен,
	// то есть на нём заведомо никто не слушает.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("подобрать порт: %v", err)
	}
	deadPort := uint16(probe.Addr().(*net.TCPAddr).Port)
	probe.Close()

	manager := session.NewManager(context.Background())
	defer manager.Close()

	st, err := manager.Connect(context.Background(), session.ConnectOptions{
		Profile: profile.Profile{
			ID: "dead", Name: "Мёртвый", Kind: profile.KindSOCKS5,
			Server: "127.0.0.1", Port: deadPort,
		},
		Policy: rules.PolicyAllExcept(),
	})
	if err != nil {
		t.Fatalf("подключение: %v", err)
	}
	if st.State != session.StateConnected {
		t.Fatalf("состояние = %s, ожидалось %s", st.State, session.StateConnected)
	}

	// А вот запрос обязан провалиться — путь-то нерабочий.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer target.Close()

	if _, err := proxyprobe.Get(st.Listen, target.URL); err == nil {
		t.Fatal("запрос через мёртвый аутбаунд прошёл — этого быть не может")
	}
}

// TestWrongCredentialsRejected: сервер требует аутентификацию, профиль
// содержит неверные учётные данные.
//
// Ожидание: подключение формально успешно (см. предыдущий тест), но запрос
// не проходит, а сервер фиксирует отклонённую попытку аутентификации.
// Последнее важно: без счётчика на стороне сервера нельзя отличить «неверный
// пароль» от «сервер недоступен», а это разные проблемы для пользователя.
func TestWrongCredentialsRejected(t *testing.T) {
	upstream, err := testsocks.StartWithAuth("правильный", "пароль")
	if err != nil {
		t.Fatalf("запуск тестового SOCKS5: %v", err)
	}
	defer upstream.Close()

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "не должно дойти")
	}))
	defer target.Close()

	manager := session.NewManager(context.Background())
	defer manager.Close()

	p := socksProfile("badcreds", upstream)
	p.Username = "неправильный"
	p.Password = "тоже неправильный"

	st, err := manager.Connect(context.Background(), session.ConnectOptions{
		Profile: p,
		Policy:  rules.PolicyAllExcept(),
	})
	if err != nil {
		t.Fatalf("подключение: %v", err)
	}

	if _, err := proxyprobe.Get(st.Listen, target.URL); err == nil {
		t.Fatal("запрос прошёл с неверными учётными данными")
	}
	if upstream.AuthFailures() == 0 {
		t.Error("сервер не зафиксировал отклонённую аутентификацию — " +
			"значит клиент даже не попытался предъявить учётные данные")
	}
	if upstream.Count() != 0 {
		t.Errorf("обслужено запросов CONNECT = %d, ожидалось 0", upstream.Count())
	}
}

// TestDisconnectTerminatesActiveConnections: отключение при активных
// соединениях.
//
// Ожидание: Disconnect не зависает в ожидании их завершения и обрывает их.
// Зависание здесь было бы худшим исходом: пользователь нажал «отключить»,
// а интерфейс замер — при том что смысл кнопки именно в немедленной
// остановке трафика.
func TestDisconnectTerminatesActiveConnections(t *testing.T) {
	// Цель держит ответ открытым, пока её не отпустят.
	release := make(chan struct{})
	started := make(chan struct{})
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		close(started)
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer target.Close()
	defer close(release)

	upstream, err := testsocks.Start()
	if err != nil {
		t.Fatalf("запуск тестового SOCKS5: %v", err)
	}
	defer upstream.Close()

	manager := session.NewManager(context.Background())
	defer manager.Close()

	st, err := manager.Connect(context.Background(), session.ConnectOptions{
		Profile: socksProfile("active", upstream),
		Policy:  rules.PolicyAllExcept(),
	})
	if err != nil {
		t.Fatalf("подключение: %v", err)
	}

	readErr := make(chan error, 1)
	go func() {
		_, err := proxyprobe.Get(st.Listen, target.URL)
		readErr <- err
	}()

	// Дожидаемся, что соединение реально установлено и висит.
	select {
	case <-started:
	case err := <-readErr:
		t.Fatalf("запрос завершился раньше времени: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("соединение не установилось за отведённое время")
	}

	done := make(chan error, 1)
	go func() {
		_, err := manager.Disconnect()
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("отключение: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Disconnect завис при активном соединении")
	}

	if got := manager.Status().State; got != session.StateIdle {
		t.Errorf("состояние после отключения = %s, ожидалось %s", got, session.StateIdle)
	}

	// Локальный inbound обязан быть закрыт: порт освобождён.
	if conn, err := net.DialTimeout("tcp", st.Listen, 2*time.Second); err == nil {
		conn.Close()
		t.Errorf("локальный inbound %s всё ещё принимает соединения после Disconnect", st.Listen)
	}
}

// TestContradictoryRulesFirstMatchWins: два правила на один и тот же домен
// с противоположными действиями.
//
// Семантика зафиксирована в 03-architecture.md §4.2: выигрывает ПЕРВОЕ
// совпадение. Тест закрепляет это поведение, потому что оно неочевидно и
// пользователь неизбежно создаст такую конфигурацию по ошибке.
func TestContradictoryRulesFirstMatchWins(t *testing.T) {
	const marker = "contradiction"

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, marker)
	}))
	defer target.Close()

	host, _, err := net.SplitHostPort(strings.TrimPrefix(target.URL, "http://"))
	if err != nil {
		t.Fatalf("разбор адреса цели: %v", err)
	}

	upstream, err := testsocks.Start()
	if err != nil {
		t.Fatalf("запуск тестового SOCKS5: %v", err)
	}
	defer upstream.Close()

	manager := session.NewManager(context.Background())
	defer manager.Close()

	// Первое правило говорит «напрямую», второе — «через туннель».
	// Побеждать обязано первое.
	st, err := manager.Connect(context.Background(), session.ConnectOptions{
		Profile: socksProfile("contra", upstream),
		Policy: rules.PolicyAllExcept(
			rules.Rule{Matcher: rules.Matcher{IPCIDR: []string{host + "/32"}}, Action: rules.ActionDirect},
			rules.Rule{Matcher: rules.Matcher{IPCIDR: []string{host + "/32"}}, Action: rules.ActionProxy},
		),
	})
	if err != nil {
		t.Fatalf("подключение: %v", err)
	}

	body, err := proxyprobe.Get(st.Listen, target.URL)
	if err != nil {
		t.Fatalf("запрос: %v", err)
	}
	if body != marker {
		t.Fatalf("тело ответа = %q, ожидалось %q", body, marker)
	}
	if upstream.Count() != 0 {
		t.Errorf("обращений к прокси = %d, ожидалось 0: победило второе правило вместо первого",
			upstream.Count())
	}
}

func socksProfile(id string, s *testsocks.Server) profile.Profile {
	return profile.Profile{
		ID:     id,
		Name:   id,
		Kind:   profile.KindSOCKS5,
		Server: s.Addr().IP.String(),
		Port:   uint16(s.Addr().Port),
	}
}
