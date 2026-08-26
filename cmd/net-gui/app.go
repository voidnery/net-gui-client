//go:build windows

package main

import (
	"context"
	"sync"
	"time"

	"github.com/bbesport/net-gui-client/internal/client"
	pb "github.com/bbesport/net-gui-client/proto/netgui/v1"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// События, отправляемые во фронтенд.
const (
	eventStatus  = "session:status" // смена состояния сессии
	eventService = "service:link"   // связь со службой появилась или пропала
	eventProblem = "app:problem"    // проблема, которую нужно показать пользователю
)

// app — прослойка между интерфейсом и службой.
//
// Ни одного решения здесь не принимается: методы транслируют вызовы в
// контракт gRPC и обратно. Бизнес-логика живёт в службе (принцип P1).
type app struct {
	version string

	ctx context.Context // контекст Wails, доступен после onStartup

	mu     sync.Mutex
	cli    *client.Client
	linked bool // есть ли связь со службой прямо сейчас
	tr     *tray

	// names — кэш «идентификатор профиля → отображаемое имя».
	// Служба возвращает в статусе только идентификатор: имя нужно человеку,
	// а не протоколу, и разрешать его — забота представления.
	names map[string]string

	stop context.CancelFunc
	done chan struct{}
}

// setTray связывает приложение с меню в области уведомлений.
func (a *app) setTray(t *tray) {
	a.mu.Lock()
	a.tr = t
	a.mu.Unlock()
}

// ShowWindow разворачивает окно. Вызывается из трея и из фронтенда.
func (a *app) ShowWindow() {
	if !ensure(a.ctx) {
		return
	}
	runtime.WindowShow(a.ctx)
	runtime.WindowUnminimise(a.ctx)
}

func newApp(version string) *app {
	return &app{version: version, done: make(chan struct{}), names: map[string]string{}}
}

func (a *app) onStartup(ctx context.Context) {
	a.ctx = ctx

	supervisorCtx, cancel := context.WithCancel(context.Background())
	a.stop = cancel

	go a.supervise(supervisorCtx)
	a.startTray()
}

func (a *app) onShutdown(_ context.Context) {
	if a.stop != nil {
		a.stop()
	}
	select {
	case <-a.done:
	case <-time.After(2 * time.Second):
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cli != nil {
		_ = a.cli.Close()
		a.cli = nil
	}
}

// --- надзор за связью со службой ---------------------------------------------

// supervise поддерживает связь со службой и поток событий.
//
// Интерфейс — долгоживущий процесс в трее, а служба может быть не запущена,
// перезапущена или обновлена под ним. Разовое подключение при старте
// означало бы, что после любого перезапуска службы окно показывает
// устаревшее состояние и не оживает до перезапуска самого интерфейса.
func (a *app) supervise(ctx context.Context) {
	defer close(a.done)

	const (
		retryMin = 1 * time.Second
		retryMax = 15 * time.Second
	)
	retry := retryMin

	for {
		if err := a.pump(ctx); err != nil && ctx.Err() == nil {
			a.setLinked(false, client.Explain(err))
			select {
			case <-ctx.Done():
				return
			case <-time.After(retry):
			}
			// Нарастающая пауза: служба может быть остановлена надолго,
			// и опрашивать её каждую секунду бессмысленно.
			retry *= 2
			if retry > retryMax {
				retry = retryMax
			}
			continue
		}
		if ctx.Err() != nil {
			return
		}
		retry = retryMin
	}
}

// pump устанавливает связь и качает поток событий до разрыва.
func (a *app) pump(ctx context.Context) error {
	cli, err := client.Dial()
	if err != nil {
		return err
	}
	defer cli.Close()

	if _, err := cli.Hello(ctx, "net-gui", a.version); err != nil {
		return err
	}

	a.mu.Lock()
	a.cli = cli
	a.mu.Unlock()

	a.setLinked(true, "")

	// Кэш имён наполняется ДО подписки на события: первое же событие
	// статуса придёт с идентификатором профиля, и без имён трей показал бы
	// «home» вместо «Домашний SOCKS5» до первого обращения к списку.
	a.ListProfiles()

	stream, err := cli.Subscribe(ctx)
	if err != nil {
		return err
	}

	for {
		ev, err := stream.Recv()
		if err != nil {
			a.mu.Lock()
			a.cli = nil
			a.mu.Unlock()
			return err
		}
		if s := ev.GetStatusChanged(); s != nil {
			view := a.statusView(s)
			a.emit(eventStatus, view)
			a.refreshTray(view)
		}
	}
}

func (a *app) setLinked(linked bool, problem string) {
	a.mu.Lock()
	changed := a.linked != linked
	a.linked = linked
	a.mu.Unlock()

	if !changed {
		return
	}
	a.emit(eventService, map[string]any{"linked": linked})
	if !linked && problem != "" {
		a.emit(eventProblem, map[string]any{"text": problem})
	}
}

func (a *app) emit(name string, data any) {
	if !ensure(a.ctx) {
		return
	}
	runtime.EventsEmit(a.ctx, name, data)
}

// refreshTray обновляет меню в области уведомлений.
//
// Трей обязан отражать то же состояние, что и окно: пользователь чаще
// смотрит на значок, чем открывает интерфейс, и расхождение между ними
// нарушило бы принцип U2 («никаких молчаливых состояний»).
func (a *app) refreshTray(st StatusView) {
	a.mu.Lock()
	t := a.tr
	a.mu.Unlock()
	if t != nil {
		t.refresh(st)
	}
}

// client возвращает активное соединение или nil.
func (a *app) client() *client.Client {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cli
}

// rememberNames обновляет кэш имён профилей.
func (a *app) rememberNames(items []ProfileView) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, p := range items {
		a.names[p.ID] = p.Name
	}
}

// profileName возвращает отображаемое имя профиля.
//
// Если имя ещё не известно (например, статус пришёл раньше, чем список
// профилей), возвращается идентификатор. Показать идентификатор хуже, чем
// имя, но лучше, чем пустое место.
func (a *app) profileName(id string) string {
	if id == "" {
		return ""
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if name, ok := a.names[id]; ok && name != "" {
		return name
	}
	return id
}

// --- методы, вызываемые из интерфейса ----------------------------------------
//
// Все они возвращают структуры, а не protobuf-типы: Wails сериализует их в
// JSON, а сгенерированные protobuf-типы дают неудобные для фронтенда имена
// полей и лишние служебные поля.

// AppInfo — сведения о приложении и связи со службой.
type AppInfo struct {
	Version       string `json:"version"`
	Linked        bool   `json:"linked"`
	ServerVersion string `json:"serverVersion"`
	APIVersion    uint32 `json:"apiVersion"`
	Compatible    bool   `json:"compatible"`
	Problem       string `json:"problem"`
}

// GetAppInfo возвращает состояние связи со службой.
func (a *app) GetAppInfo() AppInfo {
	info := AppInfo{Version: a.version}

	cli := a.client()
	if cli == nil {
		info.Problem = "нет связи со службой"
		return info
	}

	srv, err := cli.Hello(context.Background(), "net-gui", a.version)
	if err != nil {
		info.Problem = client.Explain(err)
		return info
	}
	info.Linked = true
	info.ServerVersion = srv.Version
	info.APIVersion = srv.APIVersion
	info.Compatible = srv.Compatible
	return info
}

// StatusView — состояние сессии в виде, удобном для интерфейса.
type StatusView struct {
	State     string `json:"state"`
	ProfileID string `json:"profileId"`
	// ProfileName — отображаемое имя профиля.
	//
	// Служба хранит и возвращает только идентификатор: имя нужно человеку,
	// а не протоколу. Разрешение имени — забота представления. Без этого
	// поля трей показывал бы «home», а окно — «Домашний SOCKS5», то есть
	// одну сущность под двумя названиями (нарушение принципа U2).
	ProfileName string `json:"profileName"`
	Listen      string `json:"listen"`
	Policy      string `json:"policy"`
	RuleCount   int    `json:"ruleCount"`
	Error       string `json:"error"`
}

// GetStatus возвращает текущее состояние сессии.
func (a *app) GetStatus() StatusView {
	cli := a.client()
	if cli == nil {
		return StatusView{State: "unlinked"}
	}
	st, err := cli.Status(context.Background())
	if err != nil {
		return StatusView{State: "unlinked", Error: client.Explain(err)}
	}
	return a.statusView(st)
}

// ProfileView — профиль в виде, удобном для интерфейса.
type ProfileView struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Server string `json:"server"`
	Port   uint32 `json:"port"`
}

// ListProfiles возвращает сохранённые профили.
func (a *app) ListProfiles() []ProfileView {
	cli := a.client()
	if cli == nil {
		return nil
	}
	items, err := cli.ListProfiles(context.Background())
	if err != nil {
		return nil
	}

	out := make([]ProfileView, 0, len(items))
	for _, p := range items {
		out = append(out, ProfileView{
			ID: p.GetId(), Name: p.GetName(), Kind: kindName(p.GetKind()),
			Server: p.GetServer(), Port: p.GetPort(),
		})
	}
	a.rememberNames(out)
	return out
}

// Connect подключается по профилю.
//
// policy: "all-except" — всё через туннель, кроме исключений;
// "only-selected" — только выбранное через туннель.
func (a *app) Connect(profileID, policy string) StatusView {
	cli := a.client()
	if cli == nil {
		return StatusView{State: "unlinked", Error: "нет связи со службой"}
	}

	action := pb.Action_ACTION_PROXY
	if policy == "only-selected" {
		action = pb.Action_ACTION_DIRECT
	}

	st, err := cli.Connect(context.Background(), profileID,
		&pb.Policy{DefaultAction: action}, 0)
	if err != nil {
		return StatusView{State: "idle", Error: errText(err)}
	}
	return a.statusView(st)
}

// Disconnect отключает сессию.
func (a *app) Disconnect() StatusView {
	cli := a.client()
	if cli == nil {
		return StatusView{State: "unlinked", Error: "нет связи со службой"}
	}
	st, err := cli.Disconnect(context.Background())
	if err != nil {
		return StatusView{State: "idle", Error: errText(err)}
	}
	return a.statusView(st)
}

// --- преобразования ----------------------------------------------------------

// statusView переводит состояние из контракта в вид для интерфейса.
//
// Метод на app, а не свободная функция: для подстановки имени профиля нужен
// кэш имён. Подставлять имя в каждом потребителе отдельно нельзя — окно и
// трей неизбежно разойдутся в том, что показывают.
func (a *app) statusView(s *pb.Status) StatusView {
	v := StatusView{
		State:     stateName(s.GetState()),
		ProfileID: s.GetProfileId(),
		Listen:    s.GetListenAddress(),
		Error:     s.GetError(),
	}
	v.ProfileName = a.profileName(v.ProfileID)
	if p := s.GetPolicy(); p != nil {
		v.RuleCount = len(p.GetRules())
		switch p.GetDefaultAction() {
		case pb.Action_ACTION_PROXY:
			v.Policy = "all-except"
		case pb.Action_ACTION_DIRECT:
			v.Policy = "only-selected"
		}
	}
	return v
}

// stateName переводит состояние в стабильный идентификатор.
//
// Именно идентификатор, а не текст: перевод на язык пользователя —
// забота фронтенда, где живёт словарь локализации. Возвращать отсюда
// готовые русские строки означало бы прибить язык к серверной части.
func stateName(s pb.SessionState) string {
	switch s {
	case pb.SessionState_SESSION_STATE_CONNECTING:
		return "connecting"
	case pb.SessionState_SESSION_STATE_CONNECTED:
		return "connected"
	case pb.SessionState_SESSION_STATE_IDLE:
		return "idle"
	default:
		return "unknown"
	}
}

func kindName(k pb.Kind) string {
	if k == pb.Kind_KIND_SOCKS5 {
		return "socks5"
	}
	return "unknown"
}

func errText(err error) string {
	if hint := client.Explain(err); hint != "" {
		return hint
	}
	return err.Error()
}
