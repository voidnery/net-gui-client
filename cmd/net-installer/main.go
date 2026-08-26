//go:build windows

// Command net-installer — установка, обновление и удаление net-gui-client.
//
// Почему собственный инсталлятор, а не MSI или NSIS. Главное требование —
// точный контроль над списками доступа: мера S4 из ADR-006 требует, чтобы
// каталог установки был недоступен на запись обычным пользователям, иначе
// подмена исполняемого файла службы даёт выполнение кода с правами SYSTEM.
// Инструменты упаковки выражают такие требования косвенно и неудобно, а
// здесь это несколько строк, покрытых теми же тестами, что и остальной код.
//
// Упаковка в MSI для корпоративного развёртывания — отдельная задача этапа
// выпуска; она обернёт этот же исполняемый файл.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/bbesport/net-gui-client/internal/platform/secdir"
	"github.com/bbesport/net-gui-client/internal/platform/winservice"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Version подставляется линкером при релизной сборке.
var Version = "dev"

const (
	productName = "net-gui-client"
	publisher   = "net-gui-client authors"

	// registryKey — запись в «Программы и компоненты».
	registryKey = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\net-gui-client`
)

// payload — файлы, входящие в поставку.
//
// Порядок значим: net-svc.exe идёт первым, потому что именно его регистрирует
// диспетчер служб.
var payload = []string{
	"net-svc.exe",
	"net-cli.exe",
	"net-gui.exe",
	// И-5: wintun.dll (официальный подписанный, см. NOTICE)
}

// autostartKey — ключ автозапуска графического интерфейса.
//
// HKLM, а не HKCU: продукт устанавливается на машину, и агент в области
// уведомлений должен подниматься у любого вошедшего пользователя. Иначе
// уведомление об отказе всех узлов (требование T7) не дойдёт до того, кто
// не запускал интерфейс вручную.
const autostartKey = `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`

const autostartValue = "net-gui-client"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "\nОШИБКА:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	command := "install"
	if len(args) > 0 {
		command = args[0]
	}

	switch command {
	case "install":
		return install(args[1:])
	case "uninstall":
		return uninstall(args[1:])
	case "status":
		return status()
	case "version":
		fmt.Printf("net-installer %s\n", Version)
		return nil
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		return fmt.Errorf("неизвестная команда %q (попробуйте 'net-installer help')", command)
	}
}

func usage() {
	fmt.Println(`net-installer — установка net-gui-client

Использование:
  net-installer <команда> [флаги]

Команды:
  install      установить или обновить (по умолчанию)
  uninstall    удалить
  status       показать состояние установки
  version      версия
  help         эта справка

Флаги uninstall:
  -keep-data   сохранить профили и настройки

Установка и удаление требуют прав администратора.`)
}

// --- установка ---------------------------------------------------------------

func install(args []string) error {
	if err := requireAdmin(); err != nil {
		return err
	}

	source, err := sourceDir()
	if err != nil {
		return err
	}
	if err := checkPayload(source); err != nil {
		return err
	}

	target, err := targetDir()
	if err != nil {
		return err
	}

	upgrading := winservice.IsInstalled()
	if upgrading {
		fmt.Println("Обнаружена установленная версия — выполняется обновление.")
	}

	fmt.Printf("Установка %s %s\n", productName, Version)
	fmt.Printf("  откуда: %s\n", source)
	fmt.Printf("  куда:   %s\n\n", target)

	// 1. Служба останавливается и снимается с регистрации ДО замены файлов.
	//
	// Заменить исполняемый файл работающей службы Windows не даст: он открыт
	// на выполнение. Именно на этом ломается обновление у многих продуктов —
	// файлы копируются частично, и остаётся нерабочая установка.
	if upgrading {
		fmt.Println("[1/5] остановка и снятие регистрации предыдущей версии...")
		if err := winservice.Uninstall(); err != nil && !errors.Is(err, winservice.ErrNotInstalled) {
			return fmt.Errorf("не удалось снять предыдущую версию: %w", err)
		}
	} else {
		fmt.Println("[1/5] предыдущая установка не обнаружена")
	}

	// 2. Каталог и права. Права выставляются ДО копирования файлов:
	// иначе между копированием и ужесточением прав остаётся окно, в котором
	// файлы уже на месте, а защиты ещё нет.
	fmt.Println("[2/5] подготовка каталога и прав доступа...")
	if err := os.MkdirAll(target, 0o755); err != nil {
		return fmt.Errorf("создание каталога %s: %w", target, err)
	}
	if err := secdir.HardenProgramDir(target); err != nil {
		return fmt.Errorf("установка прав на каталог: %w", err)
	}
	if err := secdir.Verify(target); err != nil {
		// Проверяем то, что сами же установили. Если здесь что-то не так,
		// служба всё равно откажется запускаться — лучше узнать сейчас.
		return fmt.Errorf("проверка прав после установки: %w", err)
	}

	// 3. Файлы.
	fmt.Println("[3/5] копирование файлов...")
	for _, name := range payload {
		if err := copyFile(filepath.Join(source, name), filepath.Join(target, name)); err != nil {
			return err
		}
		fmt.Printf("      %s\n", name)
	}

	// Инсталлятор копирует и сам себя: на него ссылается UninstallString в
	// «Программах и компонентах». Без этого кнопка «Удалить» вела бы в
	// никуда, как только пользователь удалит дистрибутив из загрузок.
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("определение пути инсталлятора: %w", err)
	}
	if err := copyFile(self, filepath.Join(target, "net-installer.exe")); err != nil {
		return fmt.Errorf("копирование инсталлятора: %w", err)
	}
	fmt.Println("      net-installer.exe")

	// 4. Регистрация службы.
	fmt.Println("[4/5] регистрация службы...")
	if err := winservice.Install(filepath.Join(target, "net-svc.exe")); err != nil {
		return fmt.Errorf("регистрация службы: %w", err)
	}

	// 5. Записи в реестре: список программ и автозапуск интерфейса.
	fmt.Println("[5/5] регистрация в реестре...")
	if err := writeUninstallEntry(target); err != nil {
		return fmt.Errorf("запись в список программ: %w", err)
	}
	if err := writeAutostart(target); err != nil {
		return fmt.Errorf("настройка автозапуска интерфейса: %w", err)
	}

	// Запуск службы. Оставлять её остановленной — значит требовать от
	// пользователя ещё одного действия после «установка завершена», причём
	// действия, требующего прав администратора. Ошибка запуска не отменяет
	// установку: файлы на месте, служба зарегистрирована, автозапуск
	// сработает при следующей загрузке.
	fmt.Println("\nЗапуск службы...")
	if err := winservice.Start(); err != nil {
		fmt.Printf("  не удалось запустить: %v\n", err)
		fmt.Println("  Служба зарегистрирована и стартует автоматически при следующей загрузке.")
	} else {
		fmt.Println("  служба запущена")
	}

	cli := filepath.Join(target, "net-cli.exe")
	fmt.Println("\nГотово.")
	fmt.Println("\n  Проверить связь со службой:")
	fmt.Printf("    cmd:        \"%s\" hello\n", cli)
	fmt.Printf("    PowerShell: & \"%s\" hello\n", cli)
	return nil
}

// --- удаление ----------------------------------------------------------------

func uninstall(args []string) error {
	if err := requireAdmin(); err != nil {
		return err
	}

	keepData := false
	for _, a := range args {
		if a == "-keep-data" || a == "--keep-data" {
			keepData = true
		}
	}

	target, err := targetDir()
	if err != nil {
		return err
	}

	fmt.Printf("Удаление %s\n\n", productName)

	fmt.Println("[1/4] остановка и снятие регистрации службы...")
	if err := winservice.Uninstall(); err != nil && !errors.Is(err, winservice.ErrNotInstalled) {
		fmt.Printf("      предупреждение: %v\n", err)
	}

	fmt.Println("[2/4] удаление файлов...")
	deferred := removeTree(target)

	fmt.Println("[3/4] удаление записей из реестра...")
	if err := registry.DeleteKey(registry.LOCAL_MACHINE, registryKey); err != nil {
		fmt.Printf("      предупреждение: список программ: %v\n", err)
	}
	if err := removeAutostart(); err != nil {
		fmt.Printf("      предупреждение: автозапуск: %v\n", err)
	}

	dataDir := filepath.Join(os.Getenv("ProgramData"), productName)
	if keepData {
		fmt.Printf("[4/4] данные сохранены: %s\n", dataDir)
	} else {
		fmt.Println("[4/4] удаление профилей и настроек...")
		if err := os.RemoveAll(dataDir); err != nil {
			fmt.Printf("      предупреждение: не удалось удалить %s: %v\n", dataDir, err)
		}
	}

	fmt.Println("\nГотово.")
	if deferred > 0 {
		fmt.Printf("\n  %d объект(ов) заняты другими процессами и будут удалены\n", deferred)
		fmt.Println("  при следующей перезагрузке. Это нормально и не требует действий.")
		fmt.Println("\n  Обычная причина — открытая консоль, у которой каталог установки")
		fmt.Println("  является текущим, либо сам инсталлятор, запущенный из этого каталога.")
	}
	return nil
}

// removeTree удаляет каталог со всем содержимым.
//
// Возвращает число объектов, которые удалить не удалось и которые
// запланированы к удалению при следующей перезагрузке.
//
// Почему не os.RemoveAll. В Windows файл нельзя удалить, пока он открыт, а
// каталог — пока он является текущим для какого-либо процесса. При удалении
// это встречается постоянно в двух случаях:
//
//   - инсталлятор запущен из каталога установки — именно туда указывает
//     UninstallString в «Программах и компонентах», и удалить сам себя
//     работающий процесс не может;
//   - у пользователя открыта консоль с этим каталогом в качестве текущего.
//
// os.RemoveAll в обоих случаях останавливается и оставляет установку
// наполовину удалённой. Штатное решение Windows — запланировать удаление на
// перезагрузку через MoveFileEx.
func removeTree(root string) int {
	if _, err := os.Stat(root); os.IsNotExist(err) {
		return 0
	}

	deferred := 0

	// Сначала файлы, потом сам каталог: непустой каталог не удалится.
	entries, err := os.ReadDir(root)
	if err != nil {
		fmt.Printf("      предупреждение: чтение %s: %v\n", root, err)
	}
	for _, e := range entries {
		path := filepath.Join(root, e.Name())
		if err := os.RemoveAll(path); err != nil {
			if scheduleDeleteOnReboot(path) {
				fmt.Printf("      %s — занят, удаление отложено до перезагрузки\n", e.Name())
				deferred++
			} else {
				fmt.Printf("      предупреждение: не удалось удалить %s: %v\n", e.Name(), err)
			}
			continue
		}
		fmt.Printf("      %s\n", e.Name())
	}

	if err := os.Remove(root); err != nil {
		if scheduleDeleteOnReboot(root) {
			fmt.Printf("      каталог занят, удаление отложено до перезагрузки\n")
			deferred++
		} else {
			fmt.Printf("      предупреждение: не удалось удалить каталог: %v\n", err)
		}
	}
	return deferred
}

// scheduleDeleteOnReboot помечает объект к удалению при следующей загрузке.
//
// MoveFileEx с пустым адресатом и флагом MOVEFILE_DELAY_UNTIL_REBOOT —
// документированный способ удалить то, что занято прямо сейчас. Запись
// попадает в реестр (PendingFileRenameOperations), и удаление выполняет
// диспетчер сеансов до запуска пользовательских процессов.
//
// Требует прав администратора, которые у нас уже есть.
func scheduleDeleteOnReboot(path string) bool {
	from, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	// Пустой адресат означает «удалить».
	err = windows.MoveFileEx(from, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)
	return err == nil
}

// --- состояние ---------------------------------------------------------------

func status() error {
	target, err := targetDir()
	if err != nil {
		return err
	}

	fmt.Printf("каталог установки: %s\n", target)
	if _, err := os.Stat(target); os.IsNotExist(err) {
		fmt.Println("  не установлено")
	} else {
		if err := secdir.Verify(target); err != nil {
			fmt.Printf("  ⚠ права доступа: %v\n", err)
		} else {
			fmt.Println("  права доступа: в порядке")
		}
	}

	info, err := winservice.Query()
	if err != nil {
		return err
	}
	if !info.Installed {
		fmt.Println("служба:            не зарегистрирована")
		return nil
	}
	fmt.Printf("служба:            %s (%s)\n", winservice.StateName(info.State), info.Account)
	fmt.Printf("исполняемый файл:  %s\n", info.BinaryPath)
	return nil
}

// --- вспомогательное ---------------------------------------------------------

func requireAdmin() error {
	if isElevated() {
		return nil
	}
	return errors.New(`нужны права администратора.

  Запустите командную строку или PowerShell от имени администратора
  и повторите команду.`)
}

func isElevated() bool {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY, 2,
		windows.SECURITY_BUILTIN_DOMAIN_RID, windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0, &sid,
	)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)

	member, err := windows.Token(0).IsMember(sid)
	return err == nil && member
}

// sourceDir — каталог, где лежит сам инсталлятор и файлы поставки.
func sourceDir() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("определение пути инсталлятора: %w", err)
	}
	return filepath.Dir(exe), nil
}

func targetDir() (string, error) {
	base := os.Getenv("ProgramFiles")
	if base == "" {
		return "", errors.New("переменная окружения ProgramFiles не задана")
	}
	return filepath.Join(base, productName), nil
}

// checkPayload убеждается, что все файлы поставки на месте, ДО того как
// что-либо будет изменено в системе.
func checkPayload(source string) error {
	var missing []string
	for _, name := range payload {
		if _, err := os.Stat(filepath.Join(source, name)); err != nil {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("рядом с инсталлятором нет файлов поставки: %s\n  ожидались в %s",
			strings.Join(missing, ", "), source)
	}
	return nil
}

// copyFile копирует файл целиком, заменяя существующий.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("чтение %s: %w", src, err)
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return fmt.Errorf("запись %s: %w", dst, err)
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return fmt.Errorf("копирование %s: %w", filepath.Base(src), err)
	}
	// Sync до закрытия: без него данные могут остаться в кэше ОС,
	// и внезапное отключение питания оставит обрезанный исполняемый файл.
	return out.Sync()
}

// writeAutostart включает автозапуск графического интерфейса при входе
// пользователя в систему.
//
// Зачем это обязательно, а не «удобная опция»: служба работает в сеансе 0 и
// не может показать окно. Уведомление об отказе всех узлов (требование T7)
// доходит до пользователя только через процесс в его сеансе. Без автозапуска
// оно не дошло бы до того, кто не открывал интерфейс вручную.
func writeAutostart(target string) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, autostartKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()

	exe := filepath.Join(target, "net-gui.exe")
	return k.SetStringValue(autostartValue, fmt.Sprintf(`"%s"`, exe))
}

// removeAutostart убирает запись автозапуска.
func removeAutostart() error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, autostartKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()

	err = k.DeleteValue(autostartValue)
	if errors.Is(err, registry.ErrNotExist) {
		return nil // записи не было — не ошибка
	}
	return err
}

// writeUninstallEntry регистрирует продукт в «Программах и компонентах».
func writeUninstallEntry(target string) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, registryKey, registry.WRITE)
	if err != nil {
		return err
	}
	defer k.Close()

	installer := filepath.Join(target, "net-installer.exe")

	values := []struct {
		name  string
		value string
	}{
		{"DisplayName", productName},
		{"DisplayVersion", Version},
		{"Publisher", publisher},
		{"InstallLocation", target},
		{"UninstallString", fmt.Sprintf(`"%s" uninstall`, installer)},
		{"QuietUninstallString", fmt.Sprintf(`"%s" uninstall`, installer)},
	}
	for _, v := range values {
		if err := k.SetStringValue(v.name, v.value); err != nil {
			return err
		}
	}

	// Продукт не поддерживает выборочное изменение и восстановление —
	// сообщаем это системе, чтобы соответствующие кнопки не показывались.
	for _, name := range []string{"NoModify", "NoRepair"} {
		if err := k.SetDWordValue(name, 1); err != nil {
			return err
		}
	}
	return nil
}
