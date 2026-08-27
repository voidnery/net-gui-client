//go:build windows

package secrets

import (
	"bytes"
	"testing"
)

func TestProtectUnprotectRoundTrip(t *testing.T) {
	plain := []byte("приватный ключ, которого не должно быть на диске открытым")

	blob, err := Protect(plain)
	if err != nil {
		t.Fatalf("Protect: %v", err)
	}
	if bytes.Contains(blob, plain) {
		t.Fatal("шифротекст содержит исходные данные — шифрования не произошло")
	}

	got, err := Unprotect(blob)
	if err != nil {
		t.Fatalf("Unprotect: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("расшифровано %q, ожидалось %q", got, plain)
	}
}

func TestEmptyInput(t *testing.T) {
	blob, err := Protect(nil)
	if err != nil || blob != nil {
		t.Errorf("Protect(nil) = (%v, %v), ожидалось (nil, nil)", blob, err)
	}
	plain, err := Unprotect(nil)
	if err != nil || plain != nil {
		t.Errorf("Unprotect(nil) = (%v, %v), ожидалось (nil, nil)", plain, err)
	}
}

// TestUnprotectRejectsGarbage: повреждённый или подменённый блоб обязан
// давать ошибку, а не мусор. Файл профилей могут испортить — расшифровка
// «чего получилось» подсунула бы ядру мусорный ключ.
func TestUnprotectRejectsGarbage(t *testing.T) {
	if _, err := Unprotect([]byte("это не шифротекст DPAPI")); err == nil {
		t.Error("повреждённый блоб принят без ошибки")
	}
}

// TestEntropyIsApplied доказывает, что дополнительная энтропия действительно
// участвует в шифровании.
//
// Без этой проверки appEntropy могла бы не передаваться в вызов, и никто бы
// не заметил: шифрование и расшифровка продолжали бы работать, просто блоб
// стал бы расшифровываться любой программой на машине.
func TestEntropyIsApplied(t *testing.T) {
	plain := []byte("значение для проверки энтропии")

	blob, err := Protect(plain)
	if err != nil {
		t.Fatalf("Protect: %v", err)
	}

	original := appEntropy
	t.Cleanup(func() { appEntropy = original })
	appEntropy = []byte("другая энтропия")

	if _, err := Unprotect(blob); err == nil {
		t.Error("блоб расшифрован с ДРУГОЙ энтропией — значит энтропия не применяется")
	}
}

// TestProtectIsNotDeterministic: два шифрования одного значения дают разные
// блобы. Иначе по совпадению шифротекстов можно было бы узнать, что два
// профиля используют один и тот же пароль, не расшифровывая ни одного.
func TestProtectIsNotDeterministic(t *testing.T) {
	plain := []byte("одно и то же значение")

	first, err := Protect(plain)
	if err != nil {
		t.Fatalf("Protect: %v", err)
	}
	second, err := Protect(plain)
	if err != nil {
		t.Fatalf("Protect: %v", err)
	}

	if bytes.Equal(first, second) {
		t.Error("шифрование детерминировано: одинаковые секреты дают одинаковый шифротекст")
	}
}
