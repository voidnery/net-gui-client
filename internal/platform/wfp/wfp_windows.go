//go:build windows

// Package wfp — работа с Windows Filtering Platform из пользовательского режима.
//
// Ключевой факт, установленный исследованием (RQ4) и подтверждаемый экспериментом E4:
// фильтры с действием permit/block ставятся через user-mode API fwpuclnt.dll
// и НЕ требуют драйвера режима ядра. Драйвер нужен только для действия callout,
// то есть для перенаправления соединений — а от него проект отказался (ADR-007).
//
// Отсюда без драйвера решаются: kill-switch, политика IPv6, блокировка стороннего
// DoH, блокировка QUIC и защита окна переключения при failover.
package wfp

import (
	"fmt"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ---------------------------------------------------------------------------
// Константы Windows Filtering Platform
// ---------------------------------------------------------------------------

const (
	// Динамическая сессия: все фильтры, добавленные в её рамках, автоматически
	// удаляются при закрытии дескриптора движка или при завершении процесса.
	// Это ключевая гарантия обратимости (принцип P-G): аварийное завершение
	// службы не оставляет систему с висящими правилами блокировки.
	fwpmSessionFlagDynamic = 0x00000001

	rpcCAuthnWinNT = 10
	rpcCAuthnDefault = 0xFFFFFFFF

	// Действия фильтра. Флаг terminating означает, что решение окончательное
	// и дальнейшие фильтры на этом слое не опрашиваются.
	fwpActionFlagTerminating = 0x00001000
	fwpActionBlock           = 0x00000001 | fwpActionFlagTerminating
	fwpActionPermit          = 0x00000002 | fwpActionFlagTerminating

	// Типы значений FWP_VALUE0 / FWP_CONDITION_VALUE0 — перечисление FWP_DATA_TYPE.
	//
	// ⚠️ Значения обязаны точно соответствовать порядку в enum из fwptypes.h.
	// Ошибка здесь не даёт ошибки компиляции: WFP просто интерпретирует поле
	// union по другому варианту. Так, FWP_UINT64 хранит в union УКАЗАТЕЛЬ
	// (UINT64* uint64), а FWP_UINT32 — значение по месту. Перепутать их
	// означает заставить ядро разыменовать наше число как адрес.
	//
	//	FWP_EMPTY             = 0
	//	FWP_UINT8             = 1
	//	FWP_UINT16            = 2
	//	FWP_UINT32            = 3
	//	FWP_UINT64            = 4   // union хранит указатель!
	//	FWP_INT8              = 5
	//	...
	//	FWP_BYTE_ARRAY16_TYPE = 11
	fwpUint8       = 1
	fwpUint16      = 2
	fwpUint32      = 3
	fwpUint64      = 4
	fwpByteArray16 = 11

	fwpMatchEqual = 0
)

// Слои и условия WFP. GUID взяты из fwpmu.h Windows SDK.
var (
	// ALE_AUTH_CONNECT_V4/V6 — слой авторизации исходящего соединения.
	// Именно здесь решается, разрешить ли процессу установить соединение.
	layerALEAuthConnectV4 = windows.GUID{
		Data1: 0xc38d57d1, Data2: 0x05a7, Data3: 0x4c33,
		Data4: [8]byte{0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82},
	}
	layerALEAuthConnectV6 = windows.GUID{
		Data1: 0x4a72393b, Data2: 0x319f, Data3: 0x44bc,
		Data4: [8]byte{0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4},
	}

	// Универсальный подслой — используется, когда собственный подслой не нужен.
	sublayerUniversal = windows.GUID{
		Data1: 0xeebecc03, Data2: 0xced4, Data3: 0x4380,
		Data4: [8]byte{0x81, 0x9a, 0x27, 0x34, 0x39, 0x7b, 0x2b, 0x74},
	}

	// Условие: удалённый IP-адрес.
	conditionIPRemoteAddress = windows.GUID{
		Data1: 0xb235ae9a, Data2: 0x1d64, Data3: 0x49b8,
		Data4: [8]byte{0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45},
	}
)

// ---------------------------------------------------------------------------
// Структуры Windows API
//
// Раскладка полей обязана побайтово совпадать с C-структурами из fwpmtypes.h.
// Поля `_` — явное выравнивание. Go расставил бы его и сам, но здесь оно
// выписано намеренно: молчаливое расхождение раскладки даёт не ошибку
// компиляции, а повреждение памяти в чужом процессе.
// ---------------------------------------------------------------------------

type displayData0 struct {
	name        *uint16
	description *uint16
}

type session0 struct {
	sessionKey           windows.GUID
	displayData          displayData0
	flags                uint32
	txnWaitTimeoutInMSec uint32
	processID            uint32
	_                    uint32
	sid                  *windows.SID
	username             *uint16
	kernelMode           int32
	_                    uint32
}

type byteBlob struct {
	size uint32
	_    uint32
	data *byte
}

// value0 — FWP_VALUE0. Union приведён к uintptr: наибольший член союза
// на x64 занимает 8 байт (указатель или UINT64).
type value0 struct {
	typ   uint32
	_     uint32
	value uintptr
}

type conditionValue0 struct {
	typ   uint32
	_     uint32
	value uintptr
}

type action0 struct {
	typ        uint32
	filterType windows.GUID
}

type filterCondition0 struct {
	fieldKey       windows.GUID
	matchType      uint32
	_              uint32
	conditionValue conditionValue0
}

type filter0 struct {
	filterKey           windows.GUID
	displayData         displayData0
	flags               uint32
	_                   uint32
	providerKey         *windows.GUID
	providerData        byteBlob
	layerKey            windows.GUID
	subLayerKey         windows.GUID
	weight              value0
	numFilterConditions uint32
	_                   uint32
	filterCondition     *filterCondition0
	action              action0
	_                   uint32 // выравнивание перед union rawContext/providerContextKey
	rawContext          uint64
	_                   [8]byte // остаток union (GUID шире, чем UINT64)
	reserved            *windows.GUID
	filterID            uint64
	effectiveWeight     value0
}

// ---------------------------------------------------------------------------
// Привязка к fwpuclnt.dll
// ---------------------------------------------------------------------------

var (
	modFwpuclnt = windows.NewLazySystemDLL("fwpuclnt.dll")

	procFwpmEngineOpen0  = modFwpuclnt.NewProc("FwpmEngineOpen0")
	procFwpmEngineClose0 = modFwpuclnt.NewProc("FwpmEngineClose0")
	procFwpmFilterAdd0   = modFwpuclnt.NewProc("FwpmFilterAdd0")
	procFwpmFilterDelete0 = modFwpuclnt.NewProc("FwpmFilterDeleteById0")
)

// ---------------------------------------------------------------------------
// Публичный API
// ---------------------------------------------------------------------------

// Engine — открытая сессия WFP. Все установленные через неё фильтры
// живут ровно столько, сколько живёт Engine.
type Engine struct {
	handle windows.Handle
	name   string
}

// Open открывает динамическую сессию WFP.
//
// Требует прав администратора. Возвращаемый Engine обязан быть закрыт;
// но даже если процесс аварийно завершится, фильтры будут сняты системой —
// в этом смысл динамической сессии.
func Open(name string) (*Engine, error) {
	displayName, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, fmt.Errorf("wfp: encode session name: %w", err)
	}

	sess := session0{
		displayData: displayData0{name: displayName},
		flags:       fwpmSessionFlagDynamic,
	}

	var handle windows.Handle
	rc, _, _ := procFwpmEngineOpen0.Call(
		0,                              // serverName: NULL — локальная машина
		uintptr(rpcCAuthnWinNT),        // authnService
		0,                              // authIdentity: NULL — текущий пользователь
		uintptr(unsafe.Pointer(&sess)), // session
		uintptr(unsafe.Pointer(&handle)),
	)
	if rc != 0 {
		return nil, fmt.Errorf("wfp: FwpmEngineOpen0: %w", windows.Errno(rc))
	}

	return &Engine{handle: handle, name: name}, nil
}

// Close закрывает сессию. Все её фильтры снимаются системой автоматически.
func (e *Engine) Close() error {
	if e == nil || e.handle == 0 {
		return nil
	}
	rc, _, _ := procFwpmEngineClose0.Call(uintptr(e.handle))
	e.handle = 0
	if rc != 0 {
		return fmt.Errorf("wfp: FwpmEngineClose0: %w", windows.Errno(rc))
	}
	return nil
}

// FilterID — идентификатор установленного фильтра, присвоенный системой.
type FilterID uint64

// BlockOutboundToIP запрещает исходящие соединения к указанному адресу.
//
// Строительный блок для kill-switch и для блокировки стороннего DoH
// по списку известных резолверов.
func (e *Engine) BlockOutboundToIP(addr netip.Addr, description string) (FilterID, error) {
	if !addr.Is4() {
		// IPv6 требует условия типа FWP_BYTE_ARRAY16 вместо FWP_UINT32.
		// Будет добавлено в И-8 вместе с политикой IPv6.
		return 0, fmt.Errorf("wfp: IPv6 not implemented in E4 prototype")
	}

	name, err := windows.UTF16PtrFromString("net-gui-client: " + description)
	if err != nil {
		return 0, fmt.Errorf("wfp: encode filter name: %w", err)
	}

	// WFP ожидает адрес IPv4 как UINT32 в host byte order.
	b := addr.As4()
	hostOrder := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])

	cond := filterCondition0{
		fieldKey:  conditionIPRemoteAddress,
		matchType: fwpMatchEqual,
		conditionValue: conditionValue0{
			typ:   fwpUint32,
			value: uintptr(hostOrder),
		},
	}

	f := filter0{
		displayData:         displayData0{name: name},
		layerKey:            layerALEAuthConnectV4,
		subLayerKey:         sublayerUniversal,
		weight:              value0{typ: fwpUint8, value: 15}, // максимальный вес в диапазоне UINT8
		numFilterConditions: 1,
		filterCondition:     &cond,
		action:              action0{typ: fwpActionBlock},
	}

	var id uint64
	rc, _, _ := procFwpmFilterAdd0.Call(
		uintptr(e.handle),
		uintptr(unsafe.Pointer(&f)),
		0, // securityDescriptor: NULL
		uintptr(unsafe.Pointer(&id)),
	)
	if rc != 0 {
		return 0, fmt.Errorf("wfp: FwpmFilterAdd0: %w", windows.Errno(rc))
	}

	return FilterID(id), nil
}

// DeleteFilter снимает ранее установленный фильтр досрочно.
func (e *Engine) DeleteFilter(id FilterID) error {
	rc, _, _ := procFwpmFilterDelete0.Call(uintptr(e.handle), uintptr(id))
	if rc != 0 {
		return fmt.Errorf("wfp: FwpmFilterDeleteById0(%d): %w", id, windows.Errno(rc))
	}
	return nil
}
