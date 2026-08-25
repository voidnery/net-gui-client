//go:build windows

// Package ipc — транспорт канала управления между клиентами и службой.
//
// На Windows это именованный канал (named pipe), на Linux и macOS будет
// unix domain socket. Контракт gRPC (ADR-004) от транспорта не зависит —
// меняется только диалер и слушатель.
//
// ⚠️ Это самая уязвимая поверхность продукта. Локальное повышение привилегий
// через канал управления привилегированной службы находили в OpenVPN
// (CVE-2024-4877 — перехват именованного канала), в Cato Client
// (CVE-2024-6975), в IXON VPN. Меры S1 и S2 из ADR-006 адресуют именно это.
package ipc

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/Microsoft/go-winio"
)

// PipeName — путь именованного канала.
const PipeName = `\\.\pipe\net-gui-client`

// pipeSDDL — дескриптор безопасности канала (мера S1).
//
//	D:P            — DACL, защищённый: наследование запрещено
//	(A;;GA;;;SY)   — полный доступ для LocalSystem (сама служба)
//	(A;;GA;;;BA)   — полный доступ для локальных администраторов
//	(A;;GRGW;;;IU) — чтение и запись для интерактивных пользователей
//
// Ключевое: «интерактивные пользователи» (IU) — это те, кто вошёл в систему
// локально. Сетевые входы под эту группу не подпадают, поэтому канал
// недоступен удалённо. Именно этого не хватало в CVE-2024-24974.
//
// Явно НЕ указано: Everyone, Anonymous, Network. Отсутствие записи в DACL
// означает запрет — но защищённый флаг P нужен, чтобы наследование не
// добавило разрешений сверху.
const pipeSDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)"

// Listen создаёт именованный канал и возвращает слушатель.
//
// Флаг первого экземпляра канала задаётся библиотекой: winio.ListenPipe
// возвращает ошибку, если канал с таким именем уже существует. Это защита от
// сценария «атакующий занял канал раньше службы» — того самого, что лежит в
// основе CVE-2024-4877.
func Listen() (net.Listener, error) {
	ln, err := winio.ListenPipe(PipeName, &winio.PipeConfig{
		SecurityDescriptor: pipeSDDL,
		MessageMode:        false,
		InputBufferSize:    64 * 1024,
		OutputBufferSize:   64 * 1024,
	})
	if err != nil {
		return nil, fmt.Errorf("ipc: создание канала %s: %w", PipeName, err)
	}
	return ln, nil
}

// Dial подключается к каналу службы.
func Dial(ctx context.Context) (net.Conn, error) {
	deadline := 5 * time.Second
	if dl, ok := ctx.Deadline(); ok {
		deadline = time.Until(dl)
	}
	conn, err := winio.DialPipe(PipeName, &deadline)
	if err != nil {
		return nil, fmt.Errorf("ipc: подключение к %s: %w", PipeName, err)
	}
	return conn, nil
}

// DialContext — диалер в форме, которую ожидает grpc.NewClient.
// Адрес игнорируется: канал определяется константой PipeName.
func DialContext(ctx context.Context, _ string) (net.Conn, error) {
	return Dial(ctx)
}
