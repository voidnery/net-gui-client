//go:build windows

// Package secdir — проверка прав доступа к каталогу данных службы.
//
// Мера S5 из ADR-006. Прецедент, ради которого она существует, —
// CVE-2025-8069 в AWS Client VPN: программа загружала конфигурацию из пути
// `C:\usr\local\...`, доступного на запись непривилегированному пользователю.
// Атакующий подкладывал туда свой файл и получал выполнение кода с
// повышенными привилегиями.
//
// Отсюда правило: служба под LocalSystem не читает и не исполняет ничего из
// каталогов, куда обычный пользователь может писать. Проверка выполняется
// при старте, и её провал — отказ запуска, а не предупреждение.
package secdir

import (
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ErrWritableByUsers сообщает, что каталог доступен на запись слишком широкому
// кругу учётных записей.
var ErrWritableByUsers = errors.New("secdir: каталог доступен на запись непривилегированным пользователям")

// hardenedSDDL — список доступа, устанавливаемый на каталог данных службы.
//
//	D:P        — DACL, защищённый: наследование от родителя ОТКЛЮЧЕНО.
//	             Это ключевая часть: без флага P каталог, созданный внутри
//	             %ProgramData%, унаследует право записи для группы «Users».
//	OICI       — права наследуются создаваемыми файлами и подкаталогами.
//	GA;;;SY    — полный доступ для LocalSystem (под ней работает служба).
//	GA;;;BA    — полный доступ для локальных администраторов.
//
// Группы «Users», «Authenticated Users» и «Everyone» не упомянуты вовсе:
// в списке доступа отсутствие записи означает отсутствие прав.
const hardenedSDDL = "D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)"

// programDirSDDL — список доступа для каталога установки программы.
//
// Отличие от hardenedSDDL: группе «Users» даётся чтение и запуск
// (GXGR), но НЕ запись. Без права запуска обычный пользователь не смог бы
// запустить net-cli и графический интерфейс; с правом записи вся мера S4
// потеряла бы смысл.
//
//	GXGR;;;BU — GENERIC_EXECUTE | GENERIC_READ для встроенной группы Users
const programDirSDDL = "D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)(A;OICI;GXGR;;;BU)"

// HardenProgramDir устанавливает права на каталог установки программы:
// полный доступ администраторам и системе, чтение и запуск — пользователям.
//
// Требует прав администратора: каталог создаётся в %ProgramFiles%.
func HardenProgramDir(path string) error {
	return applySDDL(path, programDirSDDL)
}

// Harden устанавливает на каталог ограниченный список доступа.
//
// Проверять права мало — их надо задавать. Каталог, созданный внутри
// %ProgramData% обычным вызовом MkdirAll, наследует от родителя право записи
// для группы «Users», и проверка Verify его закономерно отвергнет. Поэтому
// служба сначала устанавливает нужный список доступа, и только потом
// проверяет результат.
//
// Права на изменение списка доступа есть у владельца каталога, поэтому
// операция работает и без прав администратора — если каталог создали мы.
func Harden(path string) error {
	return applySDDL(path, hardenedSDDL)
}

// applySDDL применяет к объекту файловой системы список доступа из строки SDDL.
func applySDDL(path, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("secdir: разбор SDDL: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("secdir: извлечение DACL из SDDL: %w", err)
	}

	err = windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		// PROTECTED_DACL_SECURITY_INFORMATION отключает наследование от
		// родительского каталога. Без него унаследованные разрешения
		// добавятся к нашим, и ограничение окажется бессмысленным.
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	)
	if err != nil {
		return fmt.Errorf("secdir: установка прав доступа на %s: %w", path, err)
	}
	return nil
}

// dangerousRights — права, позволяющие подменить содержимое каталога.
//
// Список намеренно широкий. Права на изменение самого списка доступа
// (WRITE_DAC) и владельца (WRITE_OWNER) включены: обладая ими, атакующий
// выдаст себе всё остальное сам.
const dangerousRights = windows.FILE_WRITE_DATA |
	windows.FILE_APPEND_DATA |
	windows.FILE_WRITE_EA |
	windows.FILE_WRITE_ATTRIBUTES |
	windows.DELETE |
	windows.WRITE_DAC |
	windows.WRITE_OWNER |
	windows.GENERIC_WRITE |
	windows.GENERIC_ALL

// untrustedSIDs — учётные записи, которым запись в каталог службы недопустима.
//
// Здесь перечислены группы, членство в которых не требует привилегий:
// получить их может любой вошедший в систему пользователь, а значит и любая
// запущенная им программа.
var untrustedSIDs = []struct {
	sid  windows.WELL_KNOWN_SID_TYPE
	name string
}{
	{windows.WinWorldSid, "Everyone"},
	{windows.WinAuthenticatedUserSid, "Authenticated Users"},
	{windows.WinBuiltinUsersSid, "Users"},
	{windows.WinInteractiveSid, "Interactive"},
	{windows.WinAnonymousSid, "Anonymous"},
}

// Verify проверяет, что каталог недоступен на запись непривилегированным
// учётным записям.
//
// Возвращает ошибку, обёрнутую вокруг ErrWritableByUsers, если находит
// разрешающую запись для одной из недоверенных групп.
func Verify(path string) error {
	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("secdir: чтение прав доступа %s: %w", path, err)
	}

	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("secdir: получение DACL для %s: %w", path, err)
	}
	if dacl == nil {
		// NULL DACL означает «доступ разрешён всем». Это худший из возможных
		// вариантов, и он встречается чаще, чем хотелось бы: так выглядит
		// «мы забыли выставить права».
		return fmt.Errorf("%w: %s имеет NULL DACL — доступ открыт всем", ErrWritableByUsers, path)
	}

	untrusted, err := resolveUntrustedSIDs()
	if err != nil {
		return err
	}

	// Множество, а не список: у одной группы бывает несколько записей ACL
	// (например, действующая и наследуемая), и без дедупликации сообщение
	// выглядит как «право есть у Authenticated Users, Authenticated Users».
	seen := make(map[string]bool)
	var problems []string

	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return fmt.Errorf("secdir: чтение записи ACL #%d: %w", i, err)
		}
		// Интересуют только разрешающие записи: запрещающие лишь сужают доступ.
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		if uint32(ace.Mask)&dangerousRights == 0 {
			continue
		}

		aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		for _, u := range untrusted {
			if aceSID.Equals(u.sid) && !seen[u.name] {
				seen[u.name] = true
				problems = append(problems, u.name)
			}
		}
	}

	if len(problems) > 0 {
		return fmt.Errorf("%w: %s — право на запись есть у %s",
			ErrWritableByUsers, path, strings.Join(problems, ", "))
	}
	return nil
}

type resolvedSID struct {
	sid  *windows.SID
	name string
}

func resolveUntrustedSIDs() ([]resolvedSID, error) {
	out := make([]resolvedSID, 0, len(untrustedSIDs))
	for _, u := range untrustedSIDs {
		sid, err := windows.CreateWellKnownSid(u.sid)
		if err != nil {
			return nil, fmt.Errorf("secdir: построение SID %s: %w", u.name, err)
		}
		out = append(out, resolvedSID{sid: sid, name: u.name})
	}
	return out, nil
}
