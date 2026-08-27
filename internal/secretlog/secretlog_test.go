package secretlog

import (
	"bytes"
	"strings"
	"sync"
	"testing"
)

func TestMask(t *testing.T) {
	r := New()
	r.Add("s3cret-password", "wg-private-key-value")

	got := r.Mask("подключение: пароль=s3cret-password ключ=wg-private-key-value порт=1080")

	if strings.Contains(got, "s3cret-password") || strings.Contains(got, "wg-private-key-value") {
		t.Fatalf("секрет остался в строке: %q", got)
	}
	if !strings.Contains(got, "порт=1080") {
		t.Errorf("несекретная часть повреждена: %q", got)
	}
}

// TestMaskOverlappingSecrets проверяет порядок замены.
//
// Если один секрет является частью другого, замена короткого первым оставила
// бы от длинного хвост — и в журнал попал бы фрагмент ключа. Поэтому реестр
// хранит значения по убыванию длины.
func TestMaskOverlappingSecrets(t *testing.T) {
	r := New()
	// Короткий добавлен первым намеренно: порядок добавления не должен влиять.
	r.Add("password", "password-with-suffix")

	got := r.Mask("значение=password-with-suffix")

	if strings.Contains(got, "with-suffix") {
		t.Errorf("от длинного секрета остался хвост: %q", got)
	}
	if got != "значение=***" {
		t.Errorf("получено %q, ожидалось %q", got, "значение=***")
	}
}

func TestShortValuesIgnored(t *testing.T) {
	r := New()
	r.Add("", "ab", strings.Repeat("x", MinSecretLen-1))

	if r.Len() != 0 {
		t.Errorf("в реестре %d значений, ожидалось 0", r.Len())
	}
}

func TestAddIsIdempotent(t *testing.T) {
	r := New()
	r.Add("secret-value")
	r.Add("secret-value")

	if r.Len() != 1 {
		t.Errorf("в реестре %d значений, ожидалось 1", r.Len())
	}
}

func TestForget(t *testing.T) {
	r := New()
	r.Add("secret-value")
	r.Forget("secret-value")

	if r.Len() != 0 {
		t.Fatalf("в реестре %d значений, ожидалось 0", r.Len())
	}
	if got := r.Mask("x=secret-value"); got != "x=secret-value" {
		t.Errorf("забытое значение всё ещё маскируется: %q", got)
	}
}

// TestWriterMasksAcrossWrites — главный случай, ради которого writer
// построчный.
//
// Запись в журнал не обязана приходить одним вызовом Write. Секрет,
// разорванный между двумя вызовами, не нашёлся бы поиском подстроки: каждая
// половина по отдельности секретом не является. Утечка выглядела бы как
// исправно работающее маскирование.
func TestWriterMasksAcrossWrites(t *testing.T) {
	var out bytes.Buffer
	r := New()
	r.Add("super-secret-token")

	w := r.Writer(&out)
	mustWrite(t, w, "токен=super-")
	mustWrite(t, w, "secret-token конец\n")

	if strings.Contains(out.String(), "super-secret-token") {
		t.Fatalf("секрет утёк при разрыве между вызовами Write: %q", out.String())
	}
	if want := "токен=*** конец\n"; out.String() != want {
		t.Errorf("получено %q, ожидалось %q", out.String(), want)
	}
}

// TestWriterHoldsIncompleteLine: незавершённая строка не выдаётся наружу,
// иначе следующий вызов Write мог бы дописать вторую половину секрета.
func TestWriterHoldsIncompleteLine(t *testing.T) {
	var out bytes.Buffer
	r := New()

	w := r.Writer(&out)
	mustWrite(t, w, "строка без перевода")

	if out.Len() != 0 {
		t.Errorf("незавершённая строка выдана наружу: %q", out.String())
	}

	if err := w.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if out.String() != "строка без перевода" {
		t.Errorf("после Flush получено %q", out.String())
	}
}

// TestWriterReportsFullWrite: Write обязан сообщать о полном приёме данных.
//
// Часть байтов остаётся в буфере до конца строки. Если вернуть число
// переданных дальше байтов, вызывающий сочтёт запись неполной и по контракту
// io.Writer будет вправе считать это ошибкой.
func TestWriterReportsFullWrite(t *testing.T) {
	r := New()
	w := r.Writer(&bytes.Buffer{})

	data := []byte("без перевода строки")
	n, err := w.Write(data)

	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(data) {
		t.Errorf("Write вернул %d, ожидалось %d", n, len(data))
	}
}

// TestWriterFlushesMultipleLines: несколько строк в одном вызове Write
// обрабатываются все, а не только первая.
func TestWriterFlushesMultipleLines(t *testing.T) {
	var out bytes.Buffer
	r := New()
	r.Add("hidden-value")

	w := r.Writer(&out)
	mustWrite(t, w, "a=hidden-value\nb=hidden-value\nc=1\n")

	if strings.Contains(out.String(), "hidden-value") {
		t.Fatalf("секрет остался: %q", out.String())
	}
	if want := "a=***\nb=***\nc=1\n"; out.String() != want {
		t.Errorf("получено %q, ожидалось %q", out.String(), want)
	}
}

// TestConcurrentUse: реестр и writer используются из разных горутин —
// журнал пишут все подсистемы сразу. Проверяется под -race.
func TestConcurrentUse(t *testing.T) {
	r := New()
	w := r.Writer(&bytes.Buffer{})

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r.Add(strings.Repeat("s", 8+i))
			_, _ = w.Write([]byte("строка журнала\n"))
			_ = r.Mask("что-нибудь")
			r.Forget(strings.Repeat("s", 8+i))
		}(i)
	}
	wg.Wait()
}

func mustWrite(t *testing.T, w *MaskingWriter, s string) {
	t.Helper()
	if _, err := w.Write([]byte(s)); err != nil {
		t.Fatalf("Write(%q): %v", s, err)
	}
}
