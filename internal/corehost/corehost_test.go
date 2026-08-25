package corehost_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"testing"

	"github.com/bbesport/net-gui-client/internal/corehost"
	"github.com/bbesport/net-gui-client/internal/orchestration/profile"
	"github.com/bbesport/net-gui-client/internal/orchestration/rules"
	"github.com/bbesport/net-gui-client/internal/testutil/proxyprobe"
	testsocks "github.com/bbesport/net-gui-client/internal/testutil/socks5"
)

// TestVerticalSlice — приёмочный тест итерации И-1.
//
// Проверяет сквозную цепочку целиком и герметично, без выхода в интернет:
//
//	HTTP-клиент → наш локальный inbound → маршрутизация по правилам
//	           → [ либо тестовый SOCKS5, либо напрямую ] → HTTP-сервер
//
// Ключевой момент: тестовый SOCKS5-сервер ведёт журнал обращений. Поэтому
// «трафик пошёл через прокси» — это не предположение, а наблюдаемый факт.
// Тест, который просто проверял бы доступность цели, проходил бы и при
// полностью нерабочей маршрутизации.
func TestVerticalSlice(t *testing.T) {
	const marker = "vertical-slice-ok"

	// Целевой HTTP-сервер: то, до чего пытается достучаться пользователь.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, marker)
	}))
	defer target.Close()

	targetHost, targetPortStr, err := net.SplitHostPort(mustURLHost(t, target.URL))
	if err != nil {
		t.Fatalf("разбор адреса цели: %v", err)
	}
	targetPort, _ := strconv.Atoi(targetPortStr)

	// Вышестоящий SOCKS5 — роль «VPN-сервера» в этом тесте.
	upstream, err := testsocks.Start()
	if err != nil {
		t.Fatalf("запуск тестового SOCKS5: %v", err)
	}
	defer upstream.Close()

	proxyProfile := profile.Profile{
		ID:     "test-socks5",
		Name:   "Тестовый SOCKS5",
		Kind:   profile.KindSOCKS5,
		Server: upstream.Addr().IP.String(),
		Port:   uint16(upstream.Addr().Port),
	}

	tests := []struct {
		name         string
		policy       rules.Policy
		wantProxied  bool
		wantRequests int
	}{
		{
			name:         "всё через туннель",
			policy:       rules.PolicyAllExcept(),
			wantProxied:  true,
			wantRequests: 1,
		},
		{
			name:         "только выбранное через туннель, цель не выбрана",
			policy:       rules.PolicyOnlySelected(),
			wantProxied:  false,
			wantRequests: 0,
		},
		{
			name: "только выбранное: цель выбрана по IP",
			policy: rules.PolicyOnlySelected(rules.Rule{
				Matcher: rules.Matcher{IPCIDR: []string{targetHost + "/32"}},
				Action:  rules.ActionProxy,
			}),
			wantProxied:  true,
			wantRequests: 1,
		},
		{
			name: "всё через туннель, кроме цели — исключение по IP",
			policy: rules.PolicyAllExcept(rules.Rule{
				Matcher: rules.Matcher{IPCIDR: []string{targetHost + "/32"}},
				Action:  rules.ActionDirect,
			}),
			wantProxied:  false,
			wantRequests: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			upstream.Reset()

			listenPort, err := proxyprobe.FreePort()
			if err != nil {
				t.Fatalf("поиск свободного порта: %v", err)
			}

			core, err := corehost.Start(context.Background(), corehost.Config{
				ListenAddr: netip.MustParseAddr("127.0.0.1"),
				ListenPort: listenPort,
				Profile:    proxyProfile,
				Policy:     tc.policy,
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

			body, err := proxyprobe.Get(net.JoinHostPort("127.0.0.1", strconv.Itoa(int(listenPort))), target.URL)
			if err != nil {
				t.Fatalf("запрос через локальный inbound: %v", err)
			}
			if body != marker {
				t.Fatalf("тело ответа = %q, ожидалось %q", body, marker)
			}

			got := upstream.Count()
			if got != tc.wantRequests {
				t.Errorf("обращений к вышестоящему SOCKS5 = %d, ожидалось %d (журнал: %v)",
					got, tc.wantRequests, upstream.Targets())
			}

			if tc.wantProxied && got > 0 {
				want := net.JoinHostPort(targetHost, strconv.Itoa(targetPort))
				if upstream.Targets()[0] != want {
					t.Errorf("прокси запросил %q, ожидалось %q", upstream.Targets()[0], want)
				}
			}
		})
	}
}

// TestBuildOptionsRejectsInvalidInput проверяет меру S3 из ADR-006:
// некорректный вход отсекается ДО сборки конфигурации ядра.
func TestBuildOptionsRejectsInvalidInput(t *testing.T) {
	valid := profile.Profile{
		ID: "p", Name: "p", Kind: profile.KindSOCKS5, Server: "127.0.0.1", Port: 1080,
	}

	tests := []struct {
		name string
		cfg  corehost.Config
	}{
		{"пустой профиль", corehost.Config{
			ListenAddr: netip.MustParseAddr("127.0.0.1"), ListenPort: 1,
			Policy: rules.PolicyAllExcept(),
		}},
		{"неизвестный тип профиля", corehost.Config{
			ListenAddr: netip.MustParseAddr("127.0.0.1"), ListenPort: 1,
			Profile: profile.Profile{ID: "x", Name: "x", Kind: "wireguard-9000", Server: "a", Port: 1},
			Policy:  rules.PolicyAllExcept(),
		}},
		{"нулевой порт сервера", corehost.Config{
			ListenAddr: netip.MustParseAddr("127.0.0.1"), ListenPort: 1,
			Profile: profile.Profile{ID: "x", Name: "x", Kind: profile.KindSOCKS5, Server: "a"},
			Policy:  rules.PolicyAllExcept(),
		}},
		{"блокировка как действие по умолчанию", corehost.Config{
			ListenAddr: netip.MustParseAddr("127.0.0.1"), ListenPort: 1,
			Profile: valid,
			Policy:  rules.Policy{Default: rules.ActionBlock},
		}},
		{"правило с пустым матчером", corehost.Config{
			ListenAddr: netip.MustParseAddr("127.0.0.1"), ListenPort: 1,
			Profile: valid,
			Policy:  rules.PolicyAllExcept(rules.Rule{Action: rules.ActionDirect}),
		}},
		{"некорректная подсеть", corehost.Config{
			ListenAddr: netip.MustParseAddr("127.0.0.1"), ListenPort: 1,
			Profile: valid,
			Policy: rules.PolicyAllExcept(rules.Rule{
				Matcher: rules.Matcher{IPCIDR: []string{"не-подсеть"}},
				Action:  rules.ActionDirect,
			}),
		}},
		{"не задан локальный порт", corehost.Config{
			ListenAddr: netip.MustParseAddr("127.0.0.1"),
			Profile:    valid,
			Policy:     rules.PolicyAllExcept(),
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := corehost.BuildOptions(tc.cfg); err == nil {
				t.Fatal("ожидалась ошибка, получено nil — некорректный вход прошёл проверку")
			}
		})
	}
}

// --- вспомогательное ---------------------------------------------------------

func mustURLHost(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("разбор URL %q: %v", raw, err)
	}
	return u.Host
}
