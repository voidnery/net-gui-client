package corehost_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"github.com/bbesport/net-gui-client/internal/corehost"
	"github.com/bbesport/net-gui-client/internal/orchestration/profile"
	"github.com/bbesport/net-gui-client/internal/orchestration/rules"
	"github.com/bbesport/net-gui-client/internal/testutil/proxyprobe"
	testsocks "github.com/bbesport/net-gui-client/internal/testutil/socks5"
)

// TestSOCKS5OverTLS — приёмочная проверка типа socks-tls.
//
// Проверяется герметично и целиком:
//
//	HTTP-клиент → наш локальный inbound → аутбаунд socks-tls
//	           → TLS → тестовый SOCKS5-сервер → HTTP-сервер
//
// Как и в TestVerticalSlice, факт прохождения через прокси берётся из журнала
// тестового сервера, а не выводится из доступности цели: тест, проверяющий
// только доступность, проходил бы и при полностью нерабочем аутбаунде.
//
// Сертификат самоподписанный, поэтому проверка идёт по отпечатку открытого
// ключа. Это тот же путь, который предусмотрен для пользователей с
// самоподписанными сертификатами (см. TLSParams.Pin).
func TestSOCKS5OverTLS(t *testing.T) {
	const marker = "socks-tls-ok"

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, marker)
	}))
	defer target.Close()

	upstream, err := testsocks.StartTLS()
	if err != nil {
		t.Fatalf("запуск тестового SOCKS5 поверх TLS: %v", err)
	}
	defer upstream.Close()

	p := profile.Profile{
		ID:     "socks-tls",
		Name:   "SOCKS5 поверх TLS",
		Kind:   profile.KindSOCKS5,
		Server: upstream.Addr().IP.String(),
		Port:   uint16(upstream.Addr().Port),
		TLS: &profile.TLSParams{
			Enabled: true,
			// Самоподписанный сертификат не проходит обычную проверку цепочки,
			// поэтому она отключается, а доверие держится на отпечатке.
			Insecure: true,
			Pin:      upstream.PublicKeyPin(),
		},
	}

	body, requests := runThroughCore(t, p, target.URL, upstream)

	if body != marker {
		t.Fatalf("тело ответа = %q, ожидалось %q", body, marker)
	}
	if requests != 1 {
		t.Errorf("обращений к вышестоящему SOCKS5 = %d, ожидалось 1 (журнал: %v)",
			requests, upstream.Targets())
	}
}

// TestSOCKS5OverTLSRejectsWrongPin доказывает, что пиннинг действительно
// применяется.
//
// Без этой проверки предыдущий тест проходил бы и в случае, когда отпечаток
// вообще не передаётся в ядро: соединение с Insecure=true установилось бы в
// любом случае. Тогда «пиннинг работает» было бы утверждением без основания.
func TestSOCKS5OverTLSRejectsWrongPin(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "не должно дойти")
	}))
	defer target.Close()

	upstream, err := testsocks.StartTLS()
	if err != nil {
		t.Fatalf("запуск тестового SOCKS5 поверх TLS: %v", err)
	}
	defer upstream.Close()

	// Отпечаток правильной длины, но чужой.
	wrongPin := strings.Repeat("ab", 32)
	if wrongPin == upstream.PublicKeyPin() {
		t.Fatal("подобранный отпечаток случайно совпал с настоящим")
	}

	p := profile.Profile{
		ID:     "socks-tls-bad-pin",
		Name:   "SOCKS5 поверх TLS, чужой отпечаток",
		Kind:   profile.KindSOCKS5,
		Server: upstream.Addr().IP.String(),
		Port:   uint16(upstream.Addr().Port),
		TLS: &profile.TLSParams{
			Enabled:  true,
			Insecure: true,
			Pin:      wrongPin,
		},
	}

	listenPort, err := proxyprobe.FreePort()
	if err != nil {
		t.Fatalf("поиск свободного порта: %v", err)
	}

	core, err := corehost.Start(context.Background(), corehost.Config{
		ListenAddr: netip.MustParseAddr("127.0.0.1"),
		ListenPort: listenPort,
		Profile:    p,
		Policy:     rules.PolicyAllExcept(),
		LogLevel:   "error",
	})
	if err != nil {
		t.Fatalf("запуск ядра: %v", err)
	}
	defer core.Close()

	_, err = proxyprobe.Get(net.JoinHostPort("127.0.0.1", strconv.Itoa(int(listenPort))), target.URL)
	if err == nil {
		t.Fatal("запрос прошёл, хотя отпечаток сертификата не совпадает")
	}
}

// TestSOCKS5WithoutTLSStillUsesPlainType: профиль без TLS обязан по-прежнему
// собираться на встроенном типе socks.
//
// Проверка от обратного: если бы buildSOCKS5 переключился на socks-tls
// безусловно, обычный SOCKS перестал бы работать — а это основной протокол
// стенда разработки.
func TestSOCKS5WithoutTLSStillUsesPlainType(t *testing.T) {
	const marker = "plain-socks-ok"

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, marker)
	}))
	defer target.Close()

	upstream, err := testsocks.Start()
	if err != nil {
		t.Fatalf("запуск тестового SOCKS5: %v", err)
	}
	defer upstream.Close()

	p := profile.Profile{
		ID:     "plain-socks",
		Name:   "Обычный SOCKS5",
		Kind:   profile.KindSOCKS5,
		Server: upstream.Addr().IP.String(),
		Port:   uint16(upstream.Addr().Port),
	}

	body, requests := runThroughCore(t, p, target.URL, upstream)

	if body != marker {
		t.Fatalf("тело ответа = %q, ожидалось %q", body, marker)
	}
	if requests != 1 {
		t.Errorf("обращений к вышестоящему SOCKS5 = %d, ожидалось 1 (журнал: %v)",
			requests, upstream.Targets())
	}
}

// runThroughCore поднимает ядро с указанным профилем, делает запрос через
// локальный inbound и возвращает тело ответа вместе с числом обращений к
// вышестоящему прокси.
//
// Счётчик обращений берётся у самого прокси: «трафик пошёл через туннель» —
// это наблюдаемый факт, а не вывод из того, что цель оказалась доступна.
func runThroughCore(t *testing.T, p profile.Profile, targetURL string, upstream *testsocks.Server) (string, int) {
	t.Helper()

	listenPort, err := proxyprobe.FreePort()
	if err != nil {
		t.Fatalf("поиск свободного порта: %v", err)
	}

	core, err := corehost.Start(context.Background(), corehost.Config{
		ListenAddr: netip.MustParseAddr("127.0.0.1"),
		ListenPort: listenPort,
		Profile:    p,
		Policy:     rules.PolicyAllExcept(),
		LogLevel:   "error",
	})
	if err != nil {
		t.Fatalf("запуск ядра: %v", err)
	}
	defer func() {
		if err := core.Close(); err != nil {
			t.Errorf("остановка ядра: %v", err)
		}
	}()

	body, err := proxyprobe.Get(net.JoinHostPort("127.0.0.1", strconv.Itoa(int(listenPort))), targetURL)
	if err != nil {
		t.Fatalf("запрос через локальный inbound: %v", err)
	}
	return body, upstream.Count()
}
