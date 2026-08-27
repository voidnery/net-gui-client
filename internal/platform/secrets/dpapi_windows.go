//go:build windows

package secrets

import (
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modcrypt32  = windows.NewLazySystemDLL("crypt32.dll")
	modkernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procCryptProtectData   = modcrypt32.NewProc("CryptProtectData")
	procCryptUnprotectData = modcrypt32.NewProc("CryptUnprotectData")
	procLocalFree          = modkernel32.NewProc("LocalFree")
)

const (
	// cryptProtectUIForbidden запрещает показ диалогов. Служба работает без
	// рабочего стола: диалог там не появится, а вызов просто зависнет.
	cryptProtectUIForbidden = 0x1

	// cryptProtectLocalMachine — ключ машины, а не пользователя.
	//
	// Обязателен: служба работает от LocalSystem, а профили создаёт
	// пользователь через графический интерфейс. Шифрование ключом пользователя
	// сделало бы данные нечитаемыми для той самой службы, которой они нужны.
	cryptProtectLocalMachine = 0x4
)

// dataBlob — DATA_BLOB из wincrypt.h.
//
//	typedef struct _CRYPTOAPI_BLOB {
//	    DWORD cbData;
//	    BYTE  *pbData;
//	} DATA_BLOB;
//
// Раскладка обязана совпадать побайтово. На 64-разрядной платформе Go сам
// вставит четыре байта выравнивания перед указателем — ровно как компилятор C.
type dataBlob struct {
	cbData uint32
	pbData *byte
}

func newBlob(b []byte) dataBlob {
	if len(b) == 0 {
		return dataBlob{}
	}
	return dataBlob{cbData: uint32(len(b)), pbData: &b[0]}
}

// bytes копирует содержимое блоба в память Go.
//
// Именно копирует: исходный буфер выделен LocalAlloc внутри Windows и должен
// быть освобождён через LocalFree. Возвращать срез поверх чужой памяти
// означало бы отдать наружу указатель, который вот-вот станет недействительным.
func (b *dataBlob) bytes() []byte {
	if b.pbData == nil || b.cbData == 0 {
		return nil
	}
	out := make([]byte, b.cbData)
	copy(out, unsafe.Slice(b.pbData, b.cbData))
	return out
}

func (b *dataBlob) free() {
	if b.pbData == nil {
		return
	}
	_, _, _ = procLocalFree.Call(uintptr(unsafe.Pointer(b.pbData)))
	b.pbData = nil
}

// Protect шифрует данные ключом машины.
func Protect(plain []byte) ([]byte, error) {
	if len(plain) == 0 {
		return nil, nil
	}
	return crypt(procCryptProtectData, "CryptProtectData", plain)
}

// Unprotect расшифровывает данные, зашифрованные Protect на этой же машине.
func Unprotect(blob []byte) ([]byte, error) {
	if len(blob) == 0 {
		return nil, nil
	}
	return crypt(procCryptUnprotectData, "CryptUnprotectData", blob)
}

// crypt — общее тело для обеих операций: сигнатуры CryptProtectData и
// CryptUnprotectData совпадают, различается только направление.
func crypt(proc *windows.LazyProc, name string, in []byte) ([]byte, error) {
	inBlob := newBlob(in)
	entropyBlob := newBlob(appEntropy)
	var outBlob dataBlob

	// ⚠️ unsafe.Pointer превращается в uintptr ПРЯМО в списке аргументов.
	// Промежуточная переменная типа uintptr не считается ссылкой: сборщик
	// мусора вправе переместить или освободить объект между присваиванием и
	// вызовом. Подробности — docs/gui_client_study.md, раздел 6.3.
	r, _, callErr := proc.Call(
		uintptr(unsafe.Pointer(&inBlob)),
		0, // szDataDescr — описание, нам не нужно
		uintptr(unsafe.Pointer(&entropyBlob)),
		0, // pvReserved
		0, // pPromptStruct
		cryptProtectUIForbidden|cryptProtectLocalMachine,
		uintptr(unsafe.Pointer(&outBlob)),
	)

	// Буферы обязаны дожить до конца вызова: блобы ссылаются на них, а через
	// uintptr сборщик мусора этих ссылок не видит.
	runtime.KeepAlive(in)
	runtime.KeepAlive(appEntropy)

	if r == 0 {
		return nil, fmt.Errorf("secrets: %s: %w", name, callErr)
	}
	defer outBlob.free()

	return outBlob.bytes(), nil
}
