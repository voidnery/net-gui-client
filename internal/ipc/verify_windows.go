//go:build windows

package ipc

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Мера S2 из ADR-006 — верификация процесса, подключившегося к каналу.
//
// Зачем это нужно. ACL канала (мера S1) отвечает на вопрос «кому можно
// подключаться», но не на вопрос «что именно подключилось». Любая программа,
// запущенная тем же пользователем, проходит проверку ACL — включая вредоносную.
// А по ту сторону канала находится служба с правами LocalSystem.
//
// Прецедент: CVE-2024-4877 в OpenVPN для Windows. Локальный атакующий с
// минимальными правами перехватывал именованный канал GUI и получал полный
// доступ SYSTEM.
//
// Что проверяется здесь: исполняемый файл подключившегося процесса обязан
// лежать в защищённом каталоге установки. Записать туда файл без прав
// администратора невозможно, поэтому проверка отсекает произвольную программу
// пользователя.
//
// Чего здесь НЕТ и почему. Проверки подписи Authenticode пока нет: продукт
// ещё не подписывается, подпись появится через SignPath Foundation после
// появления инсталлятора (см. docs/experiments/E0-signing-and-av-baseline.md).
// Место для неё подготовлено — см. verifySignature.

var (
	modkernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procGetNamedPipeClientProcessID = modkernel32.NewProc("GetNamedPipeClientProcessId")
)

// ErrUntrustedClient возвращается, когда подключившийся процесс не прошёл проверку.
var ErrUntrustedClient = errors.New("ipc: клиент не прошёл проверку доверия")

// fdConn — интерфейс для получения дескриптора ОС из соединения.
//
// go-winio не экспортирует свой тип соединения, но метод Fd продвигается из
// встроенного неэкспортируемого win32File, поэтому доступен через
// приведение к интерфейсу.
type fdConn interface {
	Fd() uintptr
}

// ClientInfo — сведения о процессе на другом конце канала.
type ClientInfo struct {
	PID       uint32
	ImagePath string
}

// clientOf определяет процесс, подключившийся к каналу.
func clientOf(conn net.Conn) (ClientInfo, error) {
	fc, ok := conn.(fdConn)
	if !ok {
		return ClientInfo{}, fmt.Errorf("ipc: соединение %T не даёт дескриптор ОС", conn)
	}

	var pid uint32
	// uintptr(unsafe.Pointer(...)) записан прямо в выражении вызова —
	// иначе сборщик мусора перестанет видеть pid как живой объект.
	// См. docs/gui_client_study.md §6.3.
	rc, _, err := procGetNamedPipeClientProcessID.Call(
		fc.Fd(),
		uintptr(unsafe.Pointer(&pid)),
	)
	if rc == 0 {
		return ClientInfo{}, fmt.Errorf("ipc: GetNamedPipeClientProcessId: %w", err)
	}

	// PROCESS_QUERY_LIMITED_INFORMATION — минимально необходимое право.
	// Открываем дескриптор сразу: он удерживает объект процесса и не даёт
	// переиспользовать идентификатор под другой процесс между проверками.
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ClientInfo{}, fmt.Errorf("ipc: OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(h)

	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return ClientInfo{}, fmt.Errorf("ipc: QueryFullProcessImageName(%d): %w", pid, err)
	}

	return ClientInfo{PID: pid, ImagePath: windows.UTF16ToString(buf[:size])}, nil
}

// VerifyClient проверяет, что подключившийся процесс запущен из доверенного
// каталога. Пустой trustedDir отключает проверку — это допустимо только в
// режиме разработчика, см. cmd/net-svc.
func VerifyClient(conn net.Conn, trustedDir string) (ClientInfo, error) {
	info, err := clientOf(conn)
	if err != nil {
		return info, err
	}
	if trustedDir == "" {
		return info, nil
	}

	if err := verifyPath(info.ImagePath, trustedDir); err != nil {
		return info, err
	}
	return info, verifySignature(info.ImagePath)
}

// verifyPath проверяет, что исполняемый файл лежит внутри доверенного каталога.
//
// Сравнение делается по очищенным абсолютным путям, без учёта регистра —
// файловая система Windows регистронезависима, и `filepath.Clean` сам по себе
// этого не учитывает. Проверка на разделитель в конце обязательна: иначе
// каталог `C:\Program Files\net-gui-client-evil` прошёл бы как вложенный в
// `C:\Program Files\net-gui-client`.
func verifyPath(imagePath, trustedDir string) error {
	image, err := filepath.Abs(imagePath)
	if err != nil {
		return fmt.Errorf("%w: не удалось нормализовать путь %s: %v", ErrUntrustedClient, imagePath, err)
	}
	trusted, err := filepath.Abs(trustedDir)
	if err != nil {
		return fmt.Errorf("%w: не удалось нормализовать каталог %s: %v", ErrUntrustedClient, trustedDir, err)
	}

	prefix := strings.ToLower(filepath.Clean(trusted))
	if !strings.HasSuffix(prefix, string(filepath.Separator)) {
		prefix += string(filepath.Separator)
	}
	if !strings.HasPrefix(strings.ToLower(filepath.Clean(image)), prefix) {
		return fmt.Errorf("%w: %s находится вне доверенного каталога %s",
			ErrUntrustedClient, image, trusted)
	}
	return nil
}

// verifySignature — место для проверки подписи Authenticode.
//
// Пока не реализовано: продукт не подписывается. Подпись появится бесплатно
// через SignPath Foundation после того, как будет готов инсталлятор
// (docs/experiments/E0-signing-and-av-baseline.md). До тех пор защиту
// обеспечивают ACL канала (S1) и проверка каталога (verifyPath).
//
// Когда подпись появится — здесь будет WinVerifyTrust плюс сверка издателя.
// Отдельная функция существует именно для того, чтобы это изменение
// затронуло одно место, а не расползлось по коду.
func verifySignature(imagePath string) error {
	_ = imagePath
	return nil
}
