package device

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	mrand "math/rand"
)

// Обфускация AmneziaWG 2.0.
//
// # Почему это здесь, а не снаружи
//
// Первая попытка реализовать обфускацию как преобразование UDP-датаграмм
// снаружи библиотеки провалилась, и провал был поучительным. Подмена типа
// сообщения ломает MAC1:
//
//	mac1 = MAC(HASH(LABEL_MAC1 || Spub_responder), msg[0 : offset_of_mac1])
//
// Область покрытия MAC1 включает поле типа. Если менять тип после того, как
// MAC уже вычислен, принимающая сторона посчитает MAC по изменённым байтам
// и получит расхождение — пакет отбрасывается молча, без диагностики.
//
// Поэтому подмена типа обязана происходить ДО вычисления MAC, то есть внутри
// сборки сообщения. Дополнение S1/S2 и мусорные пакеты, напротив, MAC'ом не
// покрываются и могли бы остаться снаружи — но живут здесь же, чтобы вся
// логика обфускации была в одном месте и сверялась с эталоном целиком.
//
// Соответствует amnezia-vpn/amneziawg-go, файлы device/send.go и
// device/receive.go.

// AWGConfig — параметры обфускации AmneziaWG 2.0.
type AWGConfig struct {
	// Jc — число мусорных пакетов перед первым рукопожатием.
	Jc int
	// Jmin, Jmax — границы случайного размера мусорного пакета.
	Jmin int
	Jmax int
	// S1, S2 — размер случайного дополнения перед пакетами init и response.
	S1 int
	S2 int
	// H1..H4 — значения, заменяющие стандартные типы сообщений 1..4.
	H1 uint32
	H2 uint32
	H3 uint32
	H4 uint32
}

type awgConfigKey struct{}

// ContextWithAWGConfig помещает параметры обфускации в контекст.
//
// Передача через контекст выбрана потому, что sing-box не даёт другого пути:
// его WireGuard-endpoint не имеет поля для наших параметров. При этом
// NewDevice уже принимает контекст и читает из него зависимости —
// см. service.FromContext[pause.Manager] в device.go, — так что приём не
// вводит нового способа связывания, а следует существующему.
func ContextWithAWGConfig(ctx context.Context, cfg *AWGConfig) context.Context {
	return context.WithValue(ctx, awgConfigKey{}, cfg)
}

// AWGConfigFromContext достаёт параметры обфускации. nil означает обычный
// WireGuard без обфускации.
func AWGConfigFromContext(ctx context.Context) *AWGConfig {
	cfg, _ := ctx.Value(awgConfigKey{}).(*AWGConfig)
	return cfg
}

// headerFor возвращает подменённое значение типа сообщения.
//
// Безопасна для нулевого получателя: без обфускации тип остаётся стандартным.
// Это позволяет вызывать её на общем пути сборки пакетов, не разветвляя код на
// «с обфускацией» и «без неё».
func (c *AWGConfig) headerFor(msgType uint32) uint32 {
	if c == nil {
		return msgType
	}
	switch msgType {
	case MessageInitiationType:
		return c.H1
	case MessageResponseType:
		return c.H2
	case MessageCookieReplyType:
		return c.H3
	case MessageTransportType:
		return c.H4
	default:
		return msgType
	}
}

// standardFor выполняет обратное преобразование: из подменённого значения
// в стандартный тип. Возвращает false, если значение не опознано.
func (c *AWGConfig) standardFor(header uint32) (uint32, bool) {
	switch header {
	case c.H1:
		return MessageInitiationType, true
	case c.H2:
		return MessageResponseType, true
	case c.H3:
		return MessageCookieReplyType, true
	case c.H4:
		return MessageTransportType, true
	default:
		return 0, false
	}
}

// paddingFor возвращает размер дополнения для типа сообщения.
// В версии 2.0 дополняются только init и response.
func (c *AWGConfig) paddingFor(msgType uint32) int {
	if c == nil {
		return 0
	}
	switch msgType {
	case MessageInitiationType:
		return c.S1
	case MessageResponseType:
		return c.S2
	default:
		return 0
	}
}

// setHeader записывает в буфер тип сообщения — подменённый, если обфускация
// включена, и стандартный, если нет. Пишет всегда, поэтому пригодна и там, где
// поле типа заполняется с нуля (транспортный заголовок).
//
// ⚠️ Для рукопожатия вызывается СТРОГО до AddMacs: MAC1 покрывает поле типа,
// и подмена после вычисления MAC даёт расхождение на стороне сервера.
func (c *AWGConfig) setHeader(packet []byte, msgType uint32) {
	if len(packet) < 4 {
		return
	}
	binary.LittleEndian.PutUint32(packet[:4], c.headerFor(msgType))
}

// fillPadding заполняет область дополнения случайными байтами.
//
// Вызывается ПОСЛЕ AddMacs: дополнение не входит в область покрытия MAC.
//
// Дополнение размещается ВНУТРИ буфера, а не приклеивается снаружи:
// Bind.Send вызывается с постоянным смещением MessageEncapsulatingTransportSize,
// и менять раскладку буфера нельзя — иначе первые байты пакета уедут.
func (c *AWGConfig) fillPadding(area []byte) {
	if len(area) == 0 {
		return
	}
	if _, err := rand.Read(area); err != nil {
		// Источник случайности недоступен. Предсказуемое дополнение само
		// станет сигнатурой, поэтому заполняем хотя бы изменяющимся
		// значением, а не оставляем нули.
		for i := range area {
			area[i] = byte(mrand.Intn(256))
		}
	}
}

// classify определяет тип входящего пакета и размер его дополнения.
//
// # Почему пакеты рукопожатия и данных опознаются по-разному
//
// Значения H1..H4 в AmneziaWG — не константы, а ДИАПАЗОНЫ: отправитель берёт
// из диапазона произвольное значение (PickOne), приёмник проверяет попадание
// в диапазон (Contains). Проверять точное равенство нельзя.
//
// Для рукопожатия это не мешает: размер пакета фиксирован, и пара
// «размер + заголовок» опознаёт тип надёжно даже при точном сравнении.
// А вот пакет данных длины не имеет, и опознавать его по заголовку не на что
// опереться — что и вскрылось в E3: сервер присылал данные с типом 62 при
// H4 = 0x369E513E, и точное сравнение их отбрасывало. Сессия при этом была
// установлена, поэтому отказ выглядел как «перестали слышать ответ».
//
// Поэтому пакет данных опознаётся ПО ОСТАТКУ: всё, что не подошло ни под один
// пакет рукопожатия и достаточно велико, считается данными. Ошибка такого
// решения безопасна — дальше идёт поиск индекса получателя, и чужой пакет
// отсеется там же, где его отсеивает обычный WireGuard.
func (c *AWGConfig) classify(packet []byte) (msgType uint32, padding int, ok bool) {
	if c == nil {
		if len(packet) < 4 {
			return 0, 0, false
		}
		return binary.LittleEndian.Uint32(packet[:4]), 0, true
	}

	for _, t := range []uint32{
		MessageInitiationType, MessageResponseType, MessageCookieReplyType,
	} {
		pad := c.paddingFor(t)
		if len(packet) != pad+messageSizeFor(t) {
			continue
		}
		if binary.LittleEndian.Uint32(packet[pad:pad+4]) == c.headerFor(t) {
			return t, pad, true
		}
	}

	if len(packet) >= MessageTransportSize {
		return MessageTransportType, 0, true
	}
	return 0, 0, false
}

// restoreHeader возвращает стандартный тип сообщения в буфер.
//
// ⚠️ Вызывается СТРОГО после проверки MAC1: отправитель вычислял MAC по
// версии с подменённым типом, и проверка обязана идти по тем же байтам.
func (c *AWGConfig) restoreHeader(packet []byte, msgType uint32) {
	if c == nil || len(packet) < 4 {
		return
	}
	binary.LittleEndian.PutUint32(packet[:4], msgType)
}

// junkPackets возвращает мусорные пакеты, отправляемые перед первым
// рукопожатием.
func (c *AWGConfig) junkPackets() [][]byte {
	if c == nil || c.Jc <= 0 {
		return nil
	}

	out := make([][]byte, 0, c.Jc)
	for i := 0; i < c.Jc; i++ {
		size := c.Jmin
		if c.Jmax > c.Jmin {
			// Стойкость здесь не нужна: это шум, а не секрет.
			// Важна лишь непредсказуемость размера для наблюдателя.
			size += mrand.Intn(c.Jmax - c.Jmin + 1)
		}
		if size <= 0 {
			continue
		}

		pkt := make([]byte, size)
		if _, err := rand.Read(pkt); err != nil {
			continue
		}

		// Мусорный пакет не должен совпасть с пакетом рукопожатия: иначе
		// принимающая сторона примет его за настоящий, а настоящий отбросит
		// как повтор — отказ, который невозможно диагностировать.
		//
		// С пакетом данных совпадения не проверяем: он опознаётся по остатку,
		// и мусор неизбежно попадёт под это описание. Отсеется он у получателя
		// на поиске индекса — там же, где обычный WireGuard отсеивает шум.
		if c.looksLikeHandshake(pkt) {
			i--
			continue
		}
		out = append(out, pkt)
	}
	return out
}

// messageSizeFor возвращает размер сообщения указанного типа.
// Для пакетов данных — минимальный размер заголовка.
func messageSizeFor(msgType uint32) int {
	switch msgType {
	case MessageInitiationType:
		return MessageInitiationSize
	case MessageResponseType:
		return MessageResponseSize
	case MessageCookieReplyType:
		return MessageCookieReplySize
	case MessageTransportType:
		return MessageTransportSize
	default:
		return 0
	}
}

// junkBuffers возвращает мусорные пакеты, готовые к передаче в SendBuffers:
// каждый уже содержит служебный префикс MessageEncapsulatingTransportSize,
// который Bind.Send отрезает по смещению.
func (c *AWGConfig) junkBuffers() [][]byte {
	junks := c.junkPackets()
	if len(junks) == 0 {
		return nil
	}
	out := make([][]byte, 0, len(junks))
	for _, junk := range junks {
		buf := make([]byte, MessageEncapsulatingTransportSize+len(junk))
		copy(buf[MessageEncapsulatingTransportSize:], junk)
		out = append(out, buf)
	}
	return out
}

// looksLikeHandshake сообщает, что пакет совпал бы с одним из пакетов
// рукопожатия по паре «размер + заголовок».
func (c *AWGConfig) looksLikeHandshake(packet []byte) bool {
	for _, t := range []uint32{
		MessageInitiationType, MessageResponseType, MessageCookieReplyType,
	} {
		pad := c.paddingFor(t)
		if len(packet) != pad+messageSizeFor(t) {
			continue
		}
		if binary.LittleEndian.Uint32(packet[pad:pad+4]) == c.headerFor(t) {
			return true
		}
	}
	return false
}
