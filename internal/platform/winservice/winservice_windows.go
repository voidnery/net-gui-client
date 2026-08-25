//go:build windows

// Package winservice — регистрация и управление службой Windows.
//
// Вынесен из cmd/net-svc, потому что теми же операциями пользуется
// инсталлятор. Дублировать логику регистрации службы нельзя: расхождение
// между «как ставит инсталлятор» и «как ставит сама программа» приведёт к
// службе с неожиданными параметрами запуска.
package winservice

import (
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	// Name — имя службы в диспетчере служб Windows.
	Name = "NetGuiClientService"

	// DisplayName — отображаемое имя в списке служб.
	DisplayName = "net-gui-client"

	// Description — описание, видимое в оснастке «Службы».
	Description = "Управление VPN- и прокси-подключениями для net-gui-client."

	// StartArg — аргумент, с которым диспетчер запускает исполняемый файл.
	StartArg = "run"
)

// ErrNotInstalled сообщает, что службы нет в системе.
var ErrNotInstalled = errors.New("winservice: служба не установлена")

// ErrAlreadyInstalled сообщает, что служба уже зарегистрирована.
var ErrAlreadyInstalled = errors.New("winservice: служба уже установлена")

// Install регистрирует службу и настраивает автозапуск.
// Требует прав администратора.
func Install(exePath string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("winservice: подключение к диспетчеру служб (нужны права администратора): %w", err)
	}
	defer m.Disconnect()

	if s, err := m.OpenService(Name); err == nil {
		s.Close()
		return ErrAlreadyInstalled
	}

	s, err := m.CreateService(Name, exePath, mgr.Config{
		DisplayName: DisplayName,
		Description: Description,
		StartType:   mgr.StartAutomatic,
		// LocalSystem указана явно, чтобы намерение было видно в коде:
		// службе нужны права на создание TUN-адаптера, изменение маршрутов
		// и установку фильтров WFP.
		ServiceStartName: "LocalSystem",
	}, StartArg)
	if err != nil {
		return fmt.Errorf("winservice: создание службы: %w", err)
	}
	defer s.Close()

	// Автоматический перезапуск после сбоя. Служба, управляющая сетевым
	// состоянием, не должна оставаться лежать после единичной ошибки —
	// иначе пользователь остаётся без интернета до ручного вмешательства.
	err = s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 15 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
	}, 86400)
	if err != nil {
		return fmt.Errorf("winservice: настройка перезапуска после сбоя: %w", err)
	}

	if err := eventlog.InstallAsEventCreate(Name,
		eventlog.Error|eventlog.Warning|eventlog.Info); err != nil {
		// Отсутствие источника в журнале событий не мешает работе,
		// но лишает диагностики — сообщаем вызывающему, пусть решает сам.
		return fmt.Errorf("winservice: регистрация источника журнала событий: %w", err)
	}
	return nil
}

// Uninstall останавливает и удаляет службу.
func Uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("winservice: подключение к диспетчеру служб (нужны права администратора): %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(Name)
	if err != nil {
		return ErrNotInstalled
	}
	defer s.Close()

	// Останавливаем до удаления: удаление работающей службы оставляет её
	// помеченной к удалению до перезагрузки, и повторная установка
	// становится невозможной — классическая ловушка при обновлении.
	if err := stopAndWait(s, 30*time.Second); err != nil {
		return fmt.Errorf("winservice: остановка перед удалением: %w", err)
	}

	if err := s.Delete(); err != nil {
		return fmt.Errorf("winservice: удаление службы: %w", err)
	}
	_ = eventlog.Remove(Name) // источника может и не быть — не ошибка
	return nil
}

// Start запускает установленную службу.
func Start() error {
	m, s, err := open(windows.SERVICE_START | windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return err
	}
	defer m.Disconnect()
	defer s.Close()

	if err := s.Start(StartArg); err != nil {
		return fmt.Errorf("winservice: запуск службы: %w", err)
	}
	return nil
}

// Stop останавливает службу и дожидается фактической остановки.
func Stop() error {
	m, s, err := open(windows.SERVICE_STOP | windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return err
	}
	defer m.Disconnect()
	defer s.Close()

	return stopAndWait(s, 30*time.Second)
}

// Info — сведения о зарегистрированной службе.
type Info struct {
	State       svc.State
	StartType   uint32
	Account     string
	BinaryPath  string
	Installed   bool
	Description string
}

// Query возвращает состояние службы.
//
// Открывает её с правами ТОЛЬКО НА ЧТЕНИЕ: узнать, работает ли служба,
// должен уметь любой пользователь. mgr.Connect запрашивает
// SC_MANAGER_ALL_ACCESS и потому требует администратора — для запроса
// состояния это избыточно и мешает диагностике.
func Query() (Info, error) {
	m, s, err := open(windows.SERVICE_QUERY_STATUS | windows.SERVICE_QUERY_CONFIG)
	if err != nil {
		if errors.Is(err, ErrNotInstalled) {
			return Info{Installed: false}, nil
		}
		return Info{}, err
	}
	defer m.Disconnect()
	defer s.Close()

	st, err := s.Query()
	if err != nil {
		return Info{}, fmt.Errorf("winservice: запрос состояния: %w", err)
	}
	cfg, err := s.Config()
	if err != nil {
		return Info{}, fmt.Errorf("winservice: запрос конфигурации: %w", err)
	}

	return Info{
		Installed:   true,
		State:       st.State,
		StartType:   cfg.StartType,
		Account:     cfg.ServiceStartName,
		BinaryPath:  cfg.BinaryPathName,
		Description: cfg.Description,
	}, nil
}

// IsInstalled сообщает, зарегистрирована ли служба.
func IsInstalled() bool {
	info, err := Query()
	return err == nil && info.Installed
}

// open открывает диспетчер и службу с минимально необходимыми правами.
func open(access uint32) (*mgr.Mgr, *mgr.Service, error) {
	// SC_MANAGER_CONNECT — минимум для доступа к конкретной службе.
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return nil, nil, fmt.Errorf("winservice: подключение к диспетчеру служб: %w", err)
	}
	m := &mgr.Mgr{Handle: scm}

	h, err := windows.OpenService(scm, windows.StringToUTF16Ptr(Name), access)
	if err != nil {
		m.Disconnect()
		return nil, nil, ErrNotInstalled
	}
	return m, &mgr.Service{Name: Name, Handle: h}, nil
}

func stopAndWait(s *mgr.Service, timeout time.Duration) error {
	st, err := s.Control(svc.Stop)
	if err != nil {
		// Служба уже остановлена — это не ошибка.
		return nil
	}

	deadline := time.Now().Add(timeout)
	for st.State != svc.Stopped {
		if time.Now().After(deadline) {
			return fmt.Errorf("служба не остановилась за %s", timeout)
		}
		time.Sleep(300 * time.Millisecond)
		st, err = s.Query()
		if err != nil {
			return fmt.Errorf("запрос состояния при остановке: %w", err)
		}
	}
	return nil
}

// StateName возвращает человекочитаемое имя состояния.
func StateName(s svc.State) string {
	switch s {
	case svc.Stopped:
		return "остановлена"
	case svc.StartPending:
		return "запускается"
	case svc.StopPending:
		return "останавливается"
	case svc.Running:
		return "работает"
	case svc.ContinuePending:
		return "возобновляется"
	case svc.PausePending:
		return "приостанавливается"
	case svc.Paused:
		return "приостановлена"
	default:
		return "неизвестно"
	}
}

// StartTypeName возвращает человекочитаемый тип запуска.
func StartTypeName(t uint32) string {
	switch t {
	case mgr.StartAutomatic:
		return "автоматически"
	case mgr.StartManual:
		return "вручную"
	case mgr.StartDisabled:
		return "отключена"
	default:
		return "неизвестно"
	}
}
