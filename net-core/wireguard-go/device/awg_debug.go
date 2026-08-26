package device

import (
	"encoding/binary"
	"fmt"
	"os"
	"sync/atomic"
)

// Диагностика обфускации AmneziaWG.
//
// Включается переменной окружения NETGUI_AWG_DEBUG=1 и пишет в stderr; в
// выключенном состоянии стоит один вызов atomic-свободной проверки булевой
// переменной, так что на горячем пути она бесплатна.
//
// Оставлена постоянно, а не удалена после отладки, и вот почему. Без неё
// «рукопожатие не прошло» невозможно отличить от «ответ пришёл, но был
// отброшен классификацией» — это два совершенно разных дефекта с одинаковым
// внешним проявлением. Пока диагностики не было, отладка шла перебором
// гипотез; первое же измерение входящих датаграмм до классификации показало,
// что сервер отвечает, и сузило поиск до приёмного пути (эксперимент E3).
//
// Секретов не печатает: только размеры пакетов и значения заголовков.
// Ключи, адреса и содержимое пакетов сюда не попадают.
var awgDebug = os.Getenv("NETGUI_AWG_DEBUG") == "1"

var awgRecvSeq atomic.Uint64

func awgLogf(format string, args ...any) {
	if !awgDebug {
		return
	}
	fmt.Fprintf(os.Stderr, "[awg-fork] "+format+"\n", args...)
}

// awgLogRecv печатает каждую входящую датаграмму до классификации.
func awgLogRecv(packet []byte, msgType uint32, pad int, ok bool) {
	if !awgDebug {
		return
	}
	var head uint32
	if len(packet) >= 4 {
		head = binary.LittleEndian.Uint32(packet[:4])
	}
	n := awgRecvSeq.Add(1)
	if ok {
		awgLogf("recv #%d: %d байт, заголовок=%d → тип=%d, дополнение=%d", n, len(packet), head, msgType, pad)
		return
	}
	dump := packet
	if len(dump) > 20 {
		dump = dump[:20]
	}
	awgLogf("recv #%d: %d байт, заголовок=%d → НЕ ОПОЗНАН, первые байты=%x", n, len(packet), head, dump)
}

// logSetup сообщает, дошли ли параметры обфускации до устройства.
//
// Различить «обфускация не настроена» и «настроена, но не доехала до Device»
// иначе невозможно: оба случая выглядят как обычный WireGuard, но первый —
// это норма, а второй — дефект связывания.
func (c *AWGConfig) logSetup() {
	if !awgDebug {
		return
	}
	if c == nil {
		awgLogf("конфигурация обфускации НЕ получена из контекста — обычный WireGuard")
		return
	}
	awgLogf("обфускация активна: Jc=%d Jmin=%d Jmax=%d S1=%d S2=%d H1=%d H2=%d H3=%d H4=%d",
		c.Jc, c.Jmin, c.Jmax, c.S1, c.S2, c.H1, c.H2, c.H3, c.H4)
}
