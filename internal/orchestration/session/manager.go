// Package session — управление активным подключением.
//
// Это слой оркестрации: он платформонезависим и не содержит ни одного вызова
// Windows API. Инвариант из 03-architecture.md §3.1 — цена входа в Linux и
// macOS. Всё платформозависимое живёт в internal/platform.
//
// В И-1 автомат состояний упрощён до Idle/Connecting/Connected. Состояния
// Degraded, Failing и Failed добавляются в И-9 и И-10 вместе с подсистемой
// проб и цепочкой резервирования.
package session

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/bbesport/net-gui-client/internal/corehost"
	"github.com/bbesport/net-gui-client/internal/orchestration/profile"
	"github.com/bbesport/net-gui-client/internal/orchestration/rules"
)

// State — фаза сессии.
type State string

const (
	StateIdle       State = "idle"
	StateConnecting State = "connecting"
	StateConnected  State = "connected"
)

// Status — наблюдаемое состояние сессии.
type Status struct {
	State     State
	ProfileID string
	Listen    string
	Policy    rules.Policy
	Err       string
}

// Manager владеет активной сессией. Единственный на процесс.
type Manager struct {
	// baseCtx — контекст ЖИЗНИ СЛУЖБЫ, а не отдельного запроса.
	//
	// ⚠️ Именно здесь легко ошибиться, и я ошибся при первой реализации.
	// Ядро живёт дольше вызова, который его запустил. Если передать в него
	// контекст RPC-запроса, ядро умрёт в момент, когда gRPC ответит клиенту:
	// запустится, отрапортует «подключено» — и молча перестанет обслуживать
	// соединения. Симптом — 502 от локального inbound и запись в журнале
	// ядра «connection closed: ... context canceled».
	//
	// Правило: контекст запроса управляет ТОЛЬКО длительностью запроса.
	// Всё, что переживает запрос, получает контекст своего владельца.
	baseCtx context.Context

	mu     sync.Mutex
	core   *corehost.Core
	status Status

	subs   map[int]chan Status
	nextID int
}

// NewManager создаёт менеджер в состоянии Idle.
//
// base — контекст жизни службы. Его отмена означает завершение работы, а не
// отмену отдельной операции.
func NewManager(base context.Context) *Manager {
	if base == nil {
		base = context.Background()
	}
	return &Manager{
		baseCtx: base,
		status:  Status{State: StateIdle},
		subs:    make(map[int]chan Status),
	}
}

// Status возвращает текущее состояние.
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status
}

// Subscribe возвращает канал событий и функцию отписки.
//
// Канал буферизован: медленный подписчик не должен блокировать смену
// состояния сессии. При переполнении буфера событие для этого подписчика
// отбрасывается — состояние всё равно можно получить через Status().
func (m *Manager) Subscribe() (<-chan Status, func()) {
	m.mu.Lock()
	defer m.mu.Unlock()

	id := m.nextID
	m.nextID++
	ch := make(chan Status, 16)
	m.subs[id] = ch

	// Сразу отдаём текущее состояние: подписчик не должен ждать следующей
	// смены, чтобы узнать, что происходит сейчас.
	ch <- m.status

	return ch, func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		if c, ok := m.subs[id]; ok {
			delete(m.subs, id)
			close(c)
		}
	}
}

// setStatus обновляет состояние и рассылает его подписчикам.
// Вызывается с уже захваченным m.mu.
func (m *Manager) setStatus(s Status) {
	m.status = s
	for _, ch := range m.subs {
		select {
		case ch <- s:
		default: // подписчик не успевает — пропускаем, не блокируя всех
		}
	}
}

// ConnectOptions — параметры подключения.
type ConnectOptions struct {
	Profile    profile.Profile
	Policy     rules.Policy
	ListenAddr netip.Addr
	// ListenPort. Ноль — выбрать свободный порт автоматически.
	ListenPort uint16
}

// Connect поднимает сессию. Повторный вызов при активной сессии — ошибка:
// неявное переподключение скрыло бы от пользователя разрыв соединений.
//
// Параметр ctx намеренно НЕ используется для запуска ядра — только для
// возможной отмены самой операции подключения. Ядро получает baseCtx,
// потому что переживает вызов. См. комментарий к полю Manager.baseCtx.
func (m *Manager) Connect(ctx context.Context, opts ConnectOptions) (Status, error) {
	_ = ctx // отмена операции подключения появится вместе с FSM в И-10

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.core != nil {
		return m.status, fmt.Errorf("session: уже подключено (профиль %q); сначала отключитесь",
			m.status.ProfileID)
	}

	listenAddr := opts.ListenAddr
	if !listenAddr.IsValid() {
		listenAddr = netip.MustParseAddr("127.0.0.1")
	}
	port := opts.ListenPort
	if port == 0 {
		p, err := freePort(listenAddr)
		if err != nil {
			return m.status, fmt.Errorf("session: подбор свободного порта: %w", err)
		}
		port = p
	}

	listen := net.JoinHostPort(listenAddr.String(), fmt.Sprint(port))
	m.setStatus(Status{
		State:     StateConnecting,
		ProfileID: opts.Profile.ID,
		Listen:    listen,
		Policy:    opts.Policy,
	})

	core, err := corehost.Start(m.baseCtx, corehost.Config{
		ListenAddr: listenAddr,
		ListenPort: port,
		Profile:    opts.Profile,
		Policy:     opts.Policy,
	})
	if err != nil {
		m.setStatus(Status{State: StateIdle, Err: err.Error()})
		return m.status, err
	}

	m.core = core
	m.setStatus(Status{
		State:     StateConnected,
		ProfileID: opts.Profile.ID,
		Listen:    listen,
		Policy:    opts.Policy,
	})
	return m.status, nil
}

// Disconnect останавливает сессию. Отключение при отсутствии сессии — не ошибка:
// команда идемпотентна, потому что вызывается в том числе при аварийной уборке.
func (m *Manager) Disconnect() (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.core == nil {
		m.setStatus(Status{State: StateIdle})
		return m.status, nil
	}

	err := m.core.Close()
	m.core = nil

	st := Status{State: StateIdle}
	if err != nil {
		st.Err = err.Error()
	}
	m.setStatus(st)
	return m.status, err
}

// Close останавливает сессию и закрывает всех подписчиков.
func (m *Manager) Close() error {
	_, err := m.Disconnect()

	m.mu.Lock()
	defer m.mu.Unlock()
	for id, ch := range m.subs {
		delete(m.subs, id)
		close(ch)
	}
	return err
}

func freePort(addr netip.Addr) (uint16, error) {
	ln, err := net.Listen("tcp", net.JoinHostPort(addr.String(), "0"))
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return uint16(ln.Addr().(*net.TCPAddr).Port), nil
}
