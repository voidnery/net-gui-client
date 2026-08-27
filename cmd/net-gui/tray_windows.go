//go:build windows

package main

import (
	_ "embed"
	"fmt"

	"fyne.io/systray"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// Значок в области уведомлений. Тот же файл, что и значок приложения.
//
//go:embed build/windows/icon.ico
var trayIcon []byte

// Трей — обязательная часть, а не украшение.
//
// Служба живёт в сеансе 0 и не может показать пользователю ни окна, ни
// уведомления. Требование T7 («всплывающее окно при отказе всех узлов»)
// выполнимо только через процесс в пользовательском сеансе. Значок в трее —
// это признак того, что такой процесс жив, и точка входа к нему после
// закрытия окна.
//
// Wails v2 собственной поддержки трея не имеет (появилась только в v3),
// поэтому используется отдельная библиотека. Её цикл сообщений живёт в
// своей горутине и с циклом Wails не конфликтует.

type tray struct {
	app *app

	miStatus     *systray.MenuItem
	miConnect    *systray.MenuItem
	miDisconnect *systray.MenuItem
	miShow       *systray.MenuItem
	miQuit       *systray.MenuItem
}

func (a *app) startTray() {
	t := &tray{app: a}
	go systray.Run(t.onReady, func() {})
}

func (t *tray) onReady() {
	systray.SetIcon(trayIcon)
	systray.SetTitle("net-gui-client")
	systray.SetTooltip("net-gui-client")

	// Первый пункт — состояние. Он неактивен и служит подписью:
	// пользователь должен видеть, подключён ли он, не открывая окна.
	t.miStatus = systray.AddMenuItem("—", "")
	t.miStatus.Disable()

	systray.AddSeparator()
	t.miConnect = systray.AddMenuItem("Подключить", "")
	t.miDisconnect = systray.AddMenuItem("Отключить", "")

	systray.AddSeparator()
	t.miShow = systray.AddMenuItem("Открыть окно", "")
	t.miQuit = systray.AddMenuItem("Выход", "")

	t.app.setTray(t)
	t.refresh(t.app.GetStatus())

	for {
		select {
		case <-t.miConnect.ClickedCh:
			t.quickConnect()
		case <-t.miDisconnect.ClickedCh:
			t.refresh(t.app.Disconnect())
		case <-t.miShow.ClickedCh:
			t.app.ShowWindow()
		case <-t.miQuit.ClickedCh:
			// Явный выход из трея — единственный способ завершить процесс:
			// закрытие окна лишь прячет его (HideWindowOnClose).
			systray.Quit()
			if ensure(t.app.ctx) {
				runtime.Quit(t.app.ctx)
			}
			return
		}
	}
}

// quickConnect подключается по первому доступному профилю.
//
// Полноценное подменю «последние профили» появится вместе с экраном
// Профили (И-4): сейчас профили заводятся только через net-cli, и список
// в трее был бы почти всегда пуст.
func (t *tray) quickConnect() {
	profiles := t.app.ListProfiles()
	if len(profiles) == 0 {
		// Молча ничего не делать нельзя — пользователь решит, что сломалось.
		t.app.ShowWindow()
		return
	}
	// Быстрое подключение из трея использует режим прокси.
	//
	// Режим туннеля меняет маршрутизацию всей системы, и включать его одним
	// нажатием в трее, без явного выбора, — это ровно тот случай, когда
	// пользователь получает не то, о чём просил. Выбор режима остаётся на
	// экране подключения.
	t.refresh(t.app.Connect(profiles[0].ID, "all-except", "proxy"))
}

// refresh приводит меню в соответствие состоянию сессии.
func (t *tray) refresh(st StatusView) {
	if t.miStatus == nil {
		return
	}

	var label string
	switch st.State {
	case "connected":
		label = "Подключено"
		// Имя, а не идентификатор: в окне показано то же самое, и одна
		// сущность не должна называться в двух местах по-разному.
		if st.ProfileName != "" {
			label += ": " + st.ProfileName
		}
	case "connecting":
		label = "Подключение..."
	case "unlinked":
		label = "Нет связи со службой"
	default:
		label = "Отключено"
	}

	t.miStatus.SetTitle(label)
	systray.SetTooltip(fmt.Sprintf("net-gui-client — %s", label))

	connected := st.State == "connected"
	linked := st.State != "unlinked"

	if connected || !linked {
		t.miConnect.Disable()
	} else {
		t.miConnect.Enable()
	}
	if connected {
		t.miDisconnect.Enable()
	} else {
		t.miDisconnect.Disable()
	}
}
