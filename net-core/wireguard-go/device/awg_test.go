package device

import (
	"encoding/binary"
	"testing"
)

// Синтетические параметры обфускации.
//
// Значения выдуманы, а не взяты из конфигураций заказчика. Причина не в
// удобстве: H1..H4 не являются ключами, но однозначно опознают трафик к
// конкретному серверу, а репозиторий публичный. Боевые конфигурации
// проверяются отдельным тестом, читающим testdata/live — каталог закрыт
// .gitignore (см. internal/orchestration/profile/parse_wg_test.go).
//
// Форма подобрана так, чтобы размеры пакетов не совпадали между собой:
// init = 31+148 = 179, response = 97+92 = 189, cookie = 64. Совпадение
// размеров сделало бы тест бессмысленным — классификация опирается именно
// на них.
var testAWG = &AWGConfig{
	Jc: 4, Jmin: 40, Jmax: 200,
	S1: 31, S2: 97,
	H1: 0x1A2B3C4D, H2: 0x5E6F7081, H3: 0x92A3B4C5, H4: 0xD6E7F80B,
}

// packetOf собирает пакет заданного размера с заданным значением в поле типа
// по смещению pad.
func packetOf(size, pad int, header uint32) []byte {
	p := make([]byte, size)
	binary.LittleEndian.PutUint32(p[pad:pad+4], header)
	return p
}

func TestClassifyHandshake(t *testing.T) {
	tests := []struct {
		name    string
		packet  []byte
		msgType uint32
		padding int
	}{
		{
			name:    "инициация",
			packet:  packetOf(testAWG.S1+MessageInitiationSize, testAWG.S1, testAWG.H1),
			msgType: MessageInitiationType,
			padding: testAWG.S1,
		},
		{
			name:    "ответ",
			packet:  packetOf(testAWG.S2+MessageResponseSize, testAWG.S2, testAWG.H2),
			msgType: MessageResponseType,
			padding: testAWG.S2,
		},
		{
			name:    "ответ-cookie",
			packet:  packetOf(MessageCookieReplySize, 0, testAWG.H3),
			msgType: MessageCookieReplyType,
			padding: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msgType, padding, ok := testAWG.classify(tc.packet)
			if !ok {
				t.Fatal("пакет рукопожатия не опознан")
			}
			if msgType != tc.msgType {
				t.Errorf("тип = %d, ожидался %d", msgType, tc.msgType)
			}
			if padding != tc.padding {
				t.Errorf("дополнение = %d, ожидалось %d", padding, tc.padding)
			}
		})
	}
}

// TestClassifyTransportWithForeignHeader закрывает дефект, найденный в E3.
//
// Значения H1..H4 в AmneziaWG задают ДИАПАЗОН, а не константу: отправитель
// берёт из него произвольное значение. Живые серверы ams1 и fin1 ставили в
// пакетах данных младший байт H4 (0x3E и 0x93), а не H4 целиком. Точное
// сравнение отбрасывало эти пакеты, и отказ выглядел как «перестали слышать
// ответ через 15 секунд» — при полностью установленной сессии.
//
// Поэтому пакет данных обязан опознаваться по остатку, при любом значении
// в поле типа.
func TestClassifyTransportWithForeignHeader(t *testing.T) {
	headers := []uint32{
		testAWG.H4,           // значение целиком
		testAWG.H4 & 0xFF,    // младший байт — так поступают живые серверы
		MessageTransportType, // стандартный тип
		0xDEADBEEF,           // произвольное значение из диапазона
	}

	for _, h := range headers {
		packet := packetOf(96, 0, h)
		msgType, padding, ok := testAWG.classify(packet)
		if !ok {
			t.Errorf("заголовок %#x: пакет данных не опознан", h)
			continue
		}
		if msgType != MessageTransportType {
			t.Errorf("заголовок %#x: тип = %d, ожидался %d", h, msgType, MessageTransportType)
		}
		if padding != 0 {
			t.Errorf("заголовок %#x: дополнение = %d, ожидалось 0", h, padding)
		}
	}
}

// TestClassifyRejectsTooShort: пакет меньше транспортного заголовка не может
// быть ничем осмысленным и обязан отсеиваться до разбора.
func TestClassifyRejectsTooShort(t *testing.T) {
	if _, _, ok := testAWG.classify(make([]byte, MessageTransportSize-1)); ok {
		t.Error("слишком короткий пакет опознан")
	}
}

// TestClassifyNilConfigIsPlainWireGuard: без обфускации тип читается как есть
// и дополнение не отрезается.
func TestClassifyNilConfigIsPlainWireGuard(t *testing.T) {
	var cfg *AWGConfig
	packet := packetOf(MessageInitiationSize, 0, MessageInitiationType)

	msgType, padding, ok := cfg.classify(packet)
	if !ok || msgType != MessageInitiationType || padding != 0 {
		t.Errorf("classify = (%d, %d, %t), ожидалось (%d, 0, true)",
			msgType, padding, ok, MessageInitiationType)
	}
}

// TestSetHeaderNilConfigWritesStandardType: setHeader пишет поле типа и при
// выключенной обфускации.
//
// Проверка не формальная: setHeader вызывается на общем пути сборки
// транспортного заголовка, где поле заполняется с нуля. Если бы она молча
// ничего не делала при nil, обычный WireGuard отправлял бы пакеты с типом 0.
func TestSetHeaderNilConfigWritesStandardType(t *testing.T) {
	var cfg *AWGConfig
	buf := make([]byte, 4)

	cfg.setHeader(buf, MessageTransportType)

	if got := binary.LittleEndian.Uint32(buf); got != MessageTransportType {
		t.Errorf("записан тип %d, ожидался %d", got, MessageTransportType)
	}
}

// TestSetHeaderSubstitutes: при включённой обфускации пишется подменённое
// значение.
func TestSetHeaderSubstitutes(t *testing.T) {
	buf := make([]byte, 4)
	testAWG.setHeader(buf, MessageTransportType)

	if got := binary.LittleEndian.Uint32(buf); got != testAWG.H4 {
		t.Errorf("записан тип %#x, ожидался %#x", got, testAWG.H4)
	}
}

// TestJunkPacketsShape: мусор обязан укладываться в заданные границы размера
// и не совпадать по форме ни с одним пакетом рукопожатия.
func TestJunkPacketsShape(t *testing.T) {
	junks := testAWG.junkPackets()
	if len(junks) != testAWG.Jc {
		t.Fatalf("мусорных пакетов %d, ожидалось %d", len(junks), testAWG.Jc)
	}

	for i, j := range junks {
		if len(j) < testAWG.Jmin || len(j) > testAWG.Jmax {
			t.Errorf("пакет %d: размер %d вне границ %d..%d",
				i, len(j), testAWG.Jmin, testAWG.Jmax)
		}
		if testAWG.looksLikeHandshake(j) {
			t.Errorf("пакет %d: совпал по форме с пакетом рукопожатия", i)
		}
	}
}

// TestJunkBuffersReserveEncapsulatingPrefix: буферы уходят в SendBuffers,
// который отрезает служебный префикс по постоянному смещению. Без запаса
// первые байты мусора уехали бы за границу пакета.
func TestJunkBuffersReserveEncapsulatingPrefix(t *testing.T) {
	for i, buf := range testAWG.junkBuffers() {
		payload := len(buf) - MessageEncapsulatingTransportSize
		if payload < testAWG.Jmin || payload > testAWG.Jmax {
			t.Errorf("буфер %d: полезная часть %d вне границ %d..%d",
				i, payload, testAWG.Jmin, testAWG.Jmax)
		}
	}
}

// TestNilConfigJunkIsAbsent: без обфускации мусор не отправляется.
func TestNilConfigJunkIsAbsent(t *testing.T) {
	var cfg *AWGConfig
	if got := cfg.junkBuffers(); got != nil {
		t.Errorf("без обфускации получено %d мусорных пакетов", len(got))
	}
}
