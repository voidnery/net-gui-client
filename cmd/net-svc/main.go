// Command net-svc — привилегированная служба управления подключением.
//
// Работает в двух режимах:
//   - под диспетчером служб Windows (обычная эксплуатация, LocalSystem);
//   - как консольное приложение (`net-svc run`) — для отладки.
//
// Режим определяется автоматически: svc.IsWindowsService() сообщает, кто нас
// запустил. Разделение нужно, чтобы отлаживать логику, не переустанавливая
// службу на каждый прогон.
//
// Принцип P1 (ADR-004): вся функциональность доступна через контракт gRPC.
// Графический интерфейс — лишь один из клиентов.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sys/windows/svc"
)

// Version подставляется линкером при релизной сборке.
var Version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	// Когда службу запускает диспетчер, аргументов может не быть вовсе.
	// Проверка «кто нас запустил» обязана идти первой.
	isService, err := svc.IsWindowsService()
	if err != nil {
		return fmt.Errorf("определение режима запуска: %w", err)
	}
	if isService {
		return runService()
	}

	command := "run"
	if len(args) > 0 {
		command = args[0]
	}

	switch command {
	case "run":
		return runConsole()
	case "install":
		return installService()
	case "uninstall":
		return uninstallService()
	case "start":
		return startService()
	case "stop":
		return stopService()
	case "status":
		return statusService()
	case "version":
		fmt.Printf("net-svc %s\n", Version)
		return nil
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		return fmt.Errorf("неизвестная команда %q (попробуйте 'net-svc help')", command)
	}
}

func usage() {
	fmt.Println(`net-svc — служба управления подключением

Использование:
  net-svc <команда>

Команды:
  run          запустить в консоли (режим отладки; по умолчанию)
  install      установить службу Windows и включить автозапуск
  uninstall    остановить и удалить службу
  start        запустить установленную службу
  stop         остановить службу
  status       показать состояние службы
  version      версия
  help         эта справка

Команды install, uninstall, start и stop требуют прав администратора.

Обычному пользователю запускать net-svc вручную не нужно: службу
устанавливает инсталлятор, а управление идёт через net-cli или графический
интерфейс по каналу управления.`)
}

// runConsole запускает службу как обычное приложение — для отладки.
func runConsole() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	application, err := newApp(ctx, newConsoleLogger(os.Stdout))
	if err != nil {
		return err
	}
	defer application.stop()

	serveErr := make(chan error, 1)
	go func() { serveErr <- application.serve() }()

	fmt.Println("готов. Ctrl+C для остановки.")

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
		fmt.Println("\nостановка...")
		application.stop()
		return nil
	}
}
