//go:build windows

// Command net-gui — графический интерфейс и агент в области уведомлений.
//
// Процесс живёт в сессии пользователя БЕЗ прав администратора и общается со
// службой по каналу управления (ADR-004). Бизнес-логики здесь нет: интерфейс
// только отображает состояние и отправляет команды. Это прямое следствие
// принципа P1 — служба полностью функциональна без графического интерфейса.
//
// ⚠️ Визуальное оформление в этой итерации намеренно НЕ прорабатывается.
// И-3 даёт функциональный каркас: навигацию, живой поток событий, трей.
// Дизайн — отдельная итерация по указанию заказчика.
//
// Почему процесс должен работать постоянно. Служба живёт в сеансе 0 и не
// может показать окно пользователю. Требование T7 («всплывающее окно при
// отказе всех узлов») выполнимо только если в пользовательском сеансе есть
// живой процесс. Поэтому net-gui стартует вместе с сеансом и живёт в трее
// со скрытым окном; окно — лишь одно из представлений.
package main

import (
	"context"
	"embed"
	"fmt"
	"os"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
)

//go:embed all:frontend/dist
var assets embed.FS

// Version подставляется линкером при релизной сборке.
var Version = "dev"

func main() {
	app := newApp(Version)

	err := wails.Run(&options.App{
		Title:  "net-gui-client",
		Width:  1000,
		Height: 700,

		MinWidth:  760,
		MinHeight: 520,

		AssetServer: &assetserver.Options{Assets: assets},

		// Закрытие окна не завершает процесс: приложение уходит в трей.
		// Без этого пользователь, нажавший крестик, терял бы и уведомления
		// о падении соединения, и активную сессию из виду.
		HideWindowOnClose: true,

		OnStartup:  app.onStartup,
		OnShutdown: app.onShutdown,

		Bind: []any{app},

		Windows: &windows.Options{
			// Тема окна следует системной. Собственная тема появится
			// вместе с визуальным оформлением.
			Theme: windows.SystemDefault,
		},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "не удалось запустить интерфейс:", err)
		os.Exit(1)
	}
}

// ensure — вспомогательная проверка, что контекст Wails получен.
// Вызов методов рантайма до OnStartup приводит к панике.
func ensure(ctx context.Context) bool { return ctx != nil }
