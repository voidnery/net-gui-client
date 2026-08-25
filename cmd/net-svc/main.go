// Command net-svc — служба управления подключением.
//
// На итерации И-1 это консольное приложение, а не служба Windows. Разделение
// намеренное: «заставить трафик пойти» и «сделать привилегированную службу
// безопасной» — две разные задачи, и смешивать их в одной итерации значит
// отлаживать обе сразу. Служба под LocalSystem появляется в И-2 вместе с
// мерами S1, S2, S5 из ADR-006.
//
// Принцип P1 (ADR-004): вся функциональность доступна через контракт gRPC.
// Графический интерфейс — лишь один из клиентов, и он появится в И-3.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/bbesport/net-gui-client/internal/ipc"
	"github.com/bbesport/net-gui-client/internal/orchestration/session"
	"github.com/bbesport/net-gui-client/internal/store"

	"google.golang.org/grpc"
)

// Version подставляется линкером при релизной сборке.
var Version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	dir, err := dataDir()
	if err != nil {
		return err
	}

	profiles, err := store.OpenProfiles(filepath.Join(dir, "profiles.json"))
	if err != nil {
		return err
	}

	// Ctrl+C и завершение от системы приводят к корректной остановке,
	// а не к обрыву. Это часть принципа P-G: изменения обратимы.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Менеджер получает контекст ЖИЗНИ ПРОЦЕССА. Ядро живёт дольше любого
	// отдельного вызова gRPC, поэтому контекст запроса ему не годится.
	manager := session.NewManager(ctx)
	// Уборка при любом выходе: сессия не должна пережить процесс.
	defer func() {
		if err := manager.Close(); err != nil {
			fmt.Fprintln(os.Stderr, "warn: остановка сессии:", err)
		}
	}()

	listener, err := ipc.Listen()
	if err != nil {
		return err
	}

	grpcServer := grpc.NewServer()
	ipc.NewServer(Version, profiles, manager).Register(grpcServer)

	serveErr := make(chan error, 1)
	go func() { serveErr <- grpcServer.Serve(listener) }()

	fmt.Printf("net-svc %s\n", Version)
	fmt.Printf("канал управления: %s\n", ipc.PipeName)
	fmt.Printf("хранилище профилей: %s\n", dir)
	fmt.Println("готов. Ctrl+C для остановки.")

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
		fmt.Println("\nостановка...")
		grpcServer.GracefulStop()
		return nil
	}
}

// dataDir возвращает каталог данных службы.
//
// ⚠️ В И-1 это каталог текущего пользователя, потому что net-svc пока не
// служба. В И-2 каталог переезжает в %ProgramData% с ограничением прав на
// запись (мера S5 из ADR-006). Прецедент, ради которого это важно, —
// CVE-2025-8069: AWS Client VPN грузил конфигурацию из пути, доступного на
// запись непривилегированному пользователю, что давало выполнение кода.
func dataDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("net-svc: определение каталога данных: %w", err)
	}
	dir := filepath.Join(base, "net-gui-client")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("net-svc: создание каталога %s: %w", dir, err)
	}
	return dir, nil
}
