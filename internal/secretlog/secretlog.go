// Package secretlog — маскирование секретов при записи в журнал (мера S7).
//
// # Почему маскирование именно при записи
//
// ADR-006 требует: «Логи не содержат секретов. Маскирование при записи, а не
// при экспорте». Разница принципиальная. Если маскировать при экспорте, секрет
// уже лежит на диске в открытом виде: его прочтёт любой, у кого есть доступ к
// файлу, его заберёт резервная копия, он останется после сбоя экспорта.
// Фильтр на выходе защищает только тот путь, о котором мы вспомнили.
//
// # Почему реестр, а не разбор строк
//
// Опознавать секреты по виду («это похоже на приватный ключ») — гадание:
// формат ключа Hysteria2 не отличается от обычного пароля, а пароль вообще
// может быть любым. Поэтому реестр знает КОНКРЕТНЫЕ значения: они приходят
// из загруженных профилей и вычёркиваются при удалении профиля.
//
// Следствие, которое стоит держать в голове: секрет, не попавший в реестр,
// не будет замаскирован. Поэтому регистрация выполняется в хранилище
// профилей — единственном месте, через которое секреты попадают в процесс,
// см. internal/store.
package secretlog

import (
	"bytes"
	"io"
	"sort"
	"strings"
	"sync"
)

// MinSecretLen — минимальная длина значения, которое имеет смысл маскировать.
//
// Порог нужен из-за побочных замен: секрет «12» встретился бы в номерах
// портов, адресах и временных метках, превратив журнал в кашу. Четыре символа
// — компромисс, и он смещён в сторону маскирования намеренно.
//
// Асимметрия ущерба здесь полная. Лишняя замена портит одну строку журнала и
// исправляется чтением соседних. Пропущенный секрет утекает навсегда: журналы
// пересылают в поддержку, кладут в резервные копии и прикладывают к
// обращениям.
const MinSecretLen = 4

// maxBuffered — предел незавершённой строки в маскирующем writer'е.
//
// Защита от неограниченного роста буфера, если в поток попадёт содержимое без
// переводов строки. Величина заведомо больше любой реальной строки журнала.
const maxBuffered = 64 << 10

// Registry — набор известных секретов.
//
// Значения хранятся в порядке убывания длины. Это не оптимизация, а
// требование корректности: если один секрет является частью другого,
// замена короткого первым оставила бы от длинного хвост.
type Registry struct {
	mu      sync.RWMutex
	secrets []string
}

// New создаёт независимый реестр. Нужен прежде всего тестам: они не должны
// влиять друг на друга через общее состояние.
func New() *Registry { return &Registry{} }

var defaultRegistry = New()

// Default возвращает реестр процесса.
//
// Глобальное состояние выбрано сознательно. Маскирование обязано работать
// независимо от того, вспомнил ли о нём автор конкретного вызова: именно
// «забыли подключить фильтр» и есть тот способ утечки, который мера S7
// закрывает. Общий реестр делает гарантию свойством процесса, а не
// дисциплины вызывающего кода.
func Default() *Registry { return defaultRegistry }

// Add вносит значения в реестр. Пустые и слишком короткие игнорируются,
// повторные не дублируются.
func (r *Registry) Add(values ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, v := range values {
		if len(v) < MinSecretLen {
			continue
		}
		if r.indexOf(v) >= 0 {
			continue
		}
		r.secrets = append(r.secrets, v)
	}
	r.sortLocked()
}

// Forget убирает значения из реестра — например, когда профиль удалён.
//
// Забывать нужно: реестр просматривается на каждой строке журнала, и
// бесконечно растущий список секретов от давно удалённых профилей стоил бы
// времени на каждой записи.
func (r *Registry) Forget(values ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, v := range values {
		if i := r.indexOf(v); i >= 0 {
			r.secrets = append(r.secrets[:i], r.secrets[i+1:]...)
		}
	}
}

// Len сообщает число известных секретов.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.secrets)
}

// Mask заменяет все известные секреты на «***».
func (r *Registry) Mask(s string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if len(r.secrets) == 0 {
		return s
	}
	for _, secret := range r.secrets {
		s = strings.ReplaceAll(s, secret, "***")
	}
	return s
}

// longestLocked возвращает длину самого длинного секрета.
// Вызывается при захваченной блокировке.
func (r *Registry) longestLocked() int {
	if len(r.secrets) == 0 {
		return 0
	}
	return len(r.secrets[0]) // отсортированы по убыванию длины
}

func (r *Registry) indexOf(v string) int {
	for i, s := range r.secrets {
		if s == v {
			return i
		}
	}
	return -1
}

func (r *Registry) sortLocked() {
	sort.SliceStable(r.secrets, func(i, j int) bool {
		return len(r.secrets[i]) > len(r.secrets[j])
	})
}

// Writer оборачивает поток вывода маскирующим слоем.
//
// Обёртка построчная, и это существенно: запись в журнал не обязана
// приходить одним вызовом Write. Секрет, разорванный между двумя вызовами,
// не был бы найден поиском подстроки — и утёк бы именно потому, что
// маскирование «работает».
func (r *Registry) Writer(dst io.Writer) *MaskingWriter {
	return &MaskingWriter{registry: r, dst: dst}
}

// MaskingWriter — поток вывода с маскированием секретов.
type MaskingWriter struct {
	registry *Registry
	dst      io.Writer

	mu  sync.Mutex
	buf []byte
}

func (w *MaskingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.buf = append(w.buf, p...)

	// Отдаём наружу только завершённые строки: только для них известно, что
	// секрет не продолжится в следующем вызове Write.
	for {
		i := bytes.IndexByte(w.buf, '\n')
		if i < 0 {
			break
		}
		line := string(w.buf[:i+1])
		w.buf = w.buf[i+1:]

		if _, err := io.WriteString(w.dst, w.registry.Mask(line)); err != nil {
			return len(p), err
		}
	}

	// Предохранитель от неограниченного роста. Хвост длиной с самый длинный
	// секрет оставляем в буфере: иначе принудительный сброс мог бы разрезать
	// секрет ровно по границе и выпустить обе половины наружу.
	if len(w.buf) > maxBuffered {
		w.registry.mu.RLock()
		keep := w.registry.longestLocked()
		w.registry.mu.RUnlock()

		if keep > len(w.buf) {
			keep = len(w.buf)
		}
		cut := len(w.buf) - keep
		if cut > 0 {
			head := string(w.buf[:cut])
			w.buf = w.buf[cut:]
			if _, err := io.WriteString(w.dst, w.registry.Mask(head)); err != nil {
				return len(p), err
			}
		}
	}

	// Возвращаем len(p), а не число переданных дальше байтов: для io.Writer
	// это означает «принято полностью», что и произошло — часть данных лежит
	// в буфере до конца строки. Иначе вызывающий счёл бы запись неполной.
	return len(p), nil
}

// Flush выталкивает незавершённую строку. Вызывается при завершении работы:
// последняя запись в журнал может не оканчиваться переводом строки.
func (w *MaskingWriter) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if len(w.buf) == 0 {
		return nil
	}
	rest := string(w.buf)
	w.buf = nil

	_, err := io.WriteString(w.dst, w.registry.Mask(rest))
	return err
}
