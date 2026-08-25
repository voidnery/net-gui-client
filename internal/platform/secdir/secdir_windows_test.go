//go:build windows

package secdir

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// TestVerifyRejectsWorldWritable: каталог, доступный на запись всем, должен
// быть отвергнут.
//
// Это буквально сценарий CVE-2025-8069: программа с повышенными привилегиями
// читала конфигурацию из каталога, куда мог писать обычный пользователь.
func TestVerifyRejectsWorldWritable(t *testing.T) {
	dir := t.TempDir()

	// Даём группе «Everyone» полный доступ — то состояние, которое
	// проверка обязана поймать.
	setDirSDDL(t, dir, "D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)(A;OICI;GA;;;WD)")

	err := Verify(dir)
	if err == nil {
		t.Fatal("каталог с полным доступом для Everyone принят — мера S5 не работает")
	}
	if !errors.Is(err, ErrWritableByUsers) {
		t.Fatalf("ошибка не обёрнута вокруг ErrWritableByUsers: %v", err)
	}
	if !strings.Contains(err.Error(), "Everyone") {
		t.Errorf("в сообщении не названа виновная группа: %v", err)
	}
}

// TestVerifyRejectsUsersGroup: право записи для встроенной группы «Users» —
// ровно то, что каталог наследует от %ProgramData% по умолчанию.
//
// Именно поэтому служба обязана права УСТАНАВЛИВАТЬ, а не только проверять.
func TestVerifyRejectsUsersGroup(t *testing.T) {
	dir := t.TempDir()
	setDirSDDL(t, dir, "D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)(A;OICI;0x100116;;;BU)")

	err := Verify(dir)
	if err == nil {
		t.Fatal("каталог с правом записи для Users принят — мера S5 не работает")
	}
	if !strings.Contains(err.Error(), "Users") {
		t.Errorf("в сообщении не названа группа Users: %v", err)
	}
}

// TestHardenThenVerify: после Harden проверка обязана проходить.
//
// Пара «установить, затем проверить» — это и есть рабочий сценарий службы
// при старте. Тест закрепляет, что две функции согласованы между собой:
// Harden не должен оставлять состояние, которое Verify забракует.
func TestHardenThenVerify(t *testing.T) {
	dir := t.TempDir()

	// Сначала намеренно делаем каталог небезопасным.
	setDirSDDL(t, dir, "D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)(A;OICI;GA;;;WD)")
	if err := Verify(dir); err == nil {
		t.Fatal("подготовка теста не удалась: каталог должен был быть небезопасным")
	}

	if err := Harden(dir); err != nil {
		t.Fatalf("Harden: %v", err)
	}
	if err := Verify(dir); err != nil {
		t.Fatalf("после Harden проверка не прошла — функции рассогласованы: %v", err)
	}
}

// TestHardenRemovesInheritance: Harden обязан отключать наследование.
//
// Без флага PROTECTED_DACL_SECURITY_INFORMATION унаследованные от родителя
// разрешения добавились бы к нашим, и ограничение стало бы бессмысленным.
func TestHardenRemovesInheritance(t *testing.T) {
	parent := t.TempDir()
	setDirSDDL(t, parent, "D:(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)(A;OICI;GA;;;WD)")

	child := filepath.Join(parent, "data")
	if err := os.MkdirAll(child, 0o700); err != nil {
		t.Fatalf("создание подкаталога: %v", err)
	}

	// Подкаталог унаследовал полный доступ для Everyone.
	if err := Verify(child); err == nil {
		t.Fatal("подготовка теста не удалась: подкаталог должен был унаследовать права")
	}

	if err := Harden(child); err != nil {
		t.Fatalf("Harden: %v", err)
	}
	if err := Verify(child); err != nil {
		t.Fatalf("наследование не отключено: %v", err)
	}
}

// TestVerifyOnMissingDirectory: несуществующий каталог — ошибка чтения прав,
// а не молчаливое «всё в порядке».
func TestVerifyOnMissingDirectory(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "нет-такого")
	if err := Verify(missing); err == nil {
		t.Fatal("проверка несуществующего каталога прошла успешно")
	}
}

// setDirSDDL выставляет каталогу список доступа, заданный строкой SDDL.
func setDirSDDL(t *testing.T, path, sddl string) {
	t.Helper()

	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatalf("разбор SDDL %q: %v", sddl, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatalf("извлечение DACL: %v", err)
	}

	info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION)
	if strings.HasPrefix(sddl, "D:P") {
		info |= windows.PROTECTED_DACL_SECURITY_INFORMATION
	} else {
		info |= windows.UNPROTECTED_DACL_SECURITY_INFORMATION
	}

	if err := windows.SetNamedSecurityInfo(
		path, windows.SE_FILE_OBJECT, info, nil, nil, dacl, nil,
	); err != nil {
		t.Fatalf("установка прав на %s: %v", path, err)
	}
}
