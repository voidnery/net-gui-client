package session_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bbesport/net-gui-client/internal/orchestration/profile"
	"github.com/bbesport/net-gui-client/internal/orchestration/rules"
	"github.com/bbesport/net-gui-client/internal/orchestration/session"
	"github.com/bbesport/net-gui-client/internal/testutil/proxyprobe"
	testsocks "github.com/bbesport/net-gui-client/internal/testutil/socks5"
)

// TestSessionSurvivesConnectContextCancellation — регрессионный тест.
//
// История: в первой реализации Manager.Connect передавал в ядро контекст
// вызова. В службе это контекст gRPC-запроса, который отменяется сразу после
// ответа клиенту. Ядро запускалось, рапортовало «подключено» и молча
// переставало обслуживать соединения: локальный inbound отвечал 502, а в
// журнале ядра появлялось «connection closed: ... context canceled».
//
// Существовавший тест corehost этого не ловил: он вызывал corehost.Start
// с context.Background(), который не отменяется никогда. Ошибка жила именно
// на стыке слоёв, а не внутри любого из них.
//
// Тест воспроизводит ситуацию буквально: контекст, переданный в Connect,
// отменяется сразу после возврата — и трафик обязан продолжать ходить.
func TestSessionSurvivesConnectContextCancellation(t *testing.T) {
	const marker = "session-alive"

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, marker)
	}))
	defer target.Close()

	upstream, err := testsocks.Start()
	if err != nil {
		t.Fatalf("запуск тестового SOCKS5: %v", err)
	}
	defer upstream.Close()

	manager := session.NewManager(context.Background())
	defer manager.Close()

	// Контекст вызова — короткоживущий, как у gRPC-запроса.
	connectCtx, cancelConnect := context.WithCancel(context.Background())

	st, err := manager.Connect(connectCtx, session.ConnectOptions{
		Profile: profile.Profile{
			ID:     "regression",
			Name:   "Регрессия",
			Kind:   profile.KindSOCKS5,
			Server: upstream.Addr().IP.String(),
			Port:   uint16(upstream.Addr().Port),
		},
		Policy: rules.PolicyAllExcept(),
	})
	if err != nil {
		t.Fatalf("подключение: %v", err)
	}
	if st.State != session.StateConnected {
		t.Fatalf("состояние = %s, ожидалось %s", st.State, session.StateConnected)
	}

	// Вот он, ключевой момент: вызов завершён, его контекст мёртв.
	cancelConnect()
	time.Sleep(50 * time.Millisecond) // дать отмене распространиться

	body, err := proxyprobe.Get(st.Listen, target.URL)
	if err != nil {
		t.Fatalf("сессия перестала работать после отмены контекста вызова: %v", err)
	}
	if body != marker {
		t.Fatalf("тело ответа = %q, ожидалось %q", body, marker)
	}
	if upstream.Count() != 1 {
		t.Errorf("обращений к вышестоящему SOCKS5 = %d, ожидалось 1", upstream.Count())
	}
}

// TestDoubleConnectRejected: повторное подключение при активной сессии должно
// быть явной ошибкой, а не молчаливым переподключением — иначе пользователь
// не поймёт, почему у него оборвались все соединения.
func TestDoubleConnectRejected(t *testing.T) {
	upstream, err := testsocks.Start()
	if err != nil {
		t.Fatalf("запуск тестового SOCKS5: %v", err)
	}
	defer upstream.Close()

	manager := session.NewManager(context.Background())
	defer manager.Close()

	opts := session.ConnectOptions{
		Profile: profile.Profile{
			ID: "p", Name: "p", Kind: profile.KindSOCKS5,
			Server: upstream.Addr().IP.String(), Port: uint16(upstream.Addr().Port),
		},
		Policy: rules.PolicyAllExcept(),
	}

	if _, err := manager.Connect(context.Background(), opts); err != nil {
		t.Fatalf("первое подключение: %v", err)
	}
	if _, err := manager.Connect(context.Background(), opts); err == nil {
		t.Fatal("второе подключение прошло без ошибки — сессия молча переподключилась")
	}

	if _, err := manager.Disconnect(); err != nil {
		t.Fatalf("отключение: %v", err)
	}
	// После отключения подключиться снова обязано быть можно.
	if _, err := manager.Connect(context.Background(), opts); err != nil {
		t.Fatalf("повторное подключение после отключения: %v", err)
	}
}

// TestDisconnectIsIdempotent: отключение без активной сессии — не ошибка.
// Команда вызывается в том числе при аварийной уборке, и там она не должна
// добавлять ещё одну ошибку поверх уже случившейся.
func TestDisconnectIsIdempotent(t *testing.T) {
	manager := session.NewManager(context.Background())
	defer manager.Close()

	for i := 0; i < 3; i++ {
		st, err := manager.Disconnect()
		if err != nil {
			t.Fatalf("отключение #%d: %v", i+1, err)
		}
		if st.State != session.StateIdle {
			t.Fatalf("состояние = %s, ожидалось %s", st.State, session.StateIdle)
		}
	}
}

// TestSubscribeReceivesCurrentState: подписчик обязан сразу получить текущее
// состояние, а не ждать следующей смены. Иначе GUI, подключившийся к уже
// работающей службе, показывал бы «отключено» до первого события.
func TestSubscribeReceivesCurrentState(t *testing.T) {
	manager := session.NewManager(context.Background())
	defer manager.Close()

	events, unsubscribe := manager.Subscribe()
	defer unsubscribe()

	select {
	case st := <-events:
		if st.State != session.StateIdle {
			t.Fatalf("первое событие = %s, ожидалось %s", st.State, session.StateIdle)
		}
	case <-time.After(time.Second):
		t.Fatal("подписчик не получил текущее состояние")
	}
}
