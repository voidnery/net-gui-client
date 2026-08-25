//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/bbesport/net-gui-client/internal/platform/winservice"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
)

// runService запускает приложение под управлением диспетчера служб.
func runService() error {
	// Журнал событий Windows — единственный способ сообщить о проблеме,
	// когда службу запускает система: консоли у неё нет.
	elog, err := eventlog.Open(winservice.Name)
	if err != nil {
		// Отсутствие источника в журнале не должно мешать работе.
		return svc.Run(winservice.Name, &serviceHandler{log: discardLogger{}})
	}
	defer elog.Close()

	return svc.Run(winservice.Name, &serviceHandler{log: &eventLogger{elog: elog}})
}

// serviceHandler реализует контракт диспетчера служб Windows.
type serviceHandler struct {
	log logger
}

// Execute вызывается диспетчером служб. Возврат из него означает остановку.
func (h *serviceHandler) Execute(
	_ []string,
	requests <-chan svc.ChangeRequest,
	status chan<- svc.Status,
) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown

	status <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	application, err := newApp(ctx, h.log)
	if err != nil {
		h.log.Error("не удалось запустить службу: %v", err)
		// Ненулевой код выхода виден в диспетчере служб и в журнале событий.
		return false, 1
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- application.serve() }()

	status <- svc.Status{State: svc.Running, Accepts: accepted}

	for {
		select {
		case err := <-serveErr:
			status <- svc.Status{State: svc.StopPending}
			application.stop()
			if err != nil {
				h.log.Error("канал управления остановлен с ошибкой: %v", err)
				return false, 2
			}
			return false, 0

		case req := <-requests:
			switch req.Cmd {
			case svc.Interrogate:
				status <- req.CurrentStatus

			case svc.Stop, svc.Shutdown:
				// Shutdown приходит при выключении системы и имеет жёсткий
				// лимит времени. Сессия гасится в обоих случаях одинаково:
				// оставить поднятый туннель при выключении означает
				// испорченное сетевое состояние при следующем старте.
				status <- svc.Status{State: svc.StopPending}
				application.stop()
				return false, 0

			default:
				h.log.Warn("получена неизвестная команда управления: %v", req.Cmd)
			}
		}
	}
}

// eventLogger направляет журнал службы в журнал событий Windows.
//
// Уровни здесь не косметика: отклонённое подключение (мера S2) — событие
// безопасности, и администратор должен уметь отфильтровать его по типу
// «Предупреждение». Пока всё писалось уровнем Information, попытка обхода
// защиты терялась среди строк «служба запущена».
//
// Идентификаторы событий разведены по уровням, чтобы по ним можно было
// строить фильтры и оповещения.
type eventLogger struct {
	elog *eventlog.Log
}

const (
	eventIDInfo  = 1
	eventIDWarn  = 2
	eventIDError = 3
)

func (l *eventLogger) Info(format string, args ...any) {
	_ = l.elog.Info(eventIDInfo, fmt.Sprintf(format, args...))
}

func (l *eventLogger) Warn(format string, args ...any) {
	_ = l.elog.Warning(eventIDWarn, fmt.Sprintf(format, args...))
}

func (l *eventLogger) Error(format string, args ...any) {
	_ = l.elog.Error(eventIDError, fmt.Sprintf(format, args...))
}

// --- команды управления службой ----------------------------------------------
//
// Тонкие обёртки над internal/platform/winservice. Логика регистрации живёт
// там, потому что теми же операциями пользуется инсталлятор: расхождение
// между «как ставит инсталлятор» и «как ставит сама программа» дало бы
// службу с неожиданными параметрами запуска.

func installService() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("определение пути исполняемого файла: %w", err)
	}
	exe, err = filepath.Abs(exe)
	if err != nil {
		return fmt.Errorf("нормализация пути: %w", err)
	}

	if err := winservice.Install(exe); err != nil {
		return err
	}
	fmt.Printf("служба %s установлена (%s)\n", winservice.Name, exe)
	return nil
}

func uninstallService() error {
	if err := winservice.Uninstall(); err != nil {
		if errors.Is(err, winservice.ErrNotInstalled) {
			fmt.Printf("служба %s не установлена\n", winservice.Name)
			return nil
		}
		return err
	}
	fmt.Printf("служба %s удалена\n", winservice.Name)
	return nil
}

func startService() error {
	if err := winservice.Start(); err != nil {
		return err
	}
	fmt.Printf("служба %s запущена\n", winservice.Name)
	return nil
}

func stopService() error {
	if err := winservice.Stop(); err != nil {
		return err
	}
	fmt.Printf("служба %s остановлена\n", winservice.Name)
	return nil
}

func statusService() error {
	info, err := winservice.Query()
	if err != nil {
		return err
	}
	if !info.Installed {
		fmt.Printf("служба %s не установлена\n", winservice.Name)
		return nil
	}

	fmt.Printf("служба:           %s\n", winservice.Name)
	fmt.Printf("состояние:        %s\n", winservice.StateName(info.State))
	fmt.Printf("запуск:           %s\n", winservice.StartTypeName(info.StartType))
	fmt.Printf("учётная запись:   %s\n", info.Account)
	fmt.Printf("исполняемый файл: %s\n", info.BinaryPath)
	return nil
}
