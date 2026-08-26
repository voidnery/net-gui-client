package profile

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLiveConfigsParseAndValidate прогоняет разбор на реальных файлах заказчика.
//
// Файлы лежат в testdata/live, закрытом .gitignore, и в репозиторий не
// попадают: они содержат приватные ключи. Если каталог пуст — тест
// пропускается, чтобы сборка на чужой машине и в CI не падала из-за
// отсутствия чужих секретов.
//
// Ценность теста в том, что проверка, отвергающая рабочую конфигурацию, хуже
// отсутствия проверки: она делает продукт неработоспособным там, где он
// работал бы. Синтетические примеры такого не ловят — они написаны под уже
// известные представления о формате.
func TestLiveConfigsParseAndValidate(t *testing.T) {
	matches, err := filepath.Glob(filepath.Join("..", "..", "..", "testdata", "live", "*.conf"))
	if err != nil {
		t.Fatalf("поиск конфигураций: %v", err)
	}
	if len(matches) == 0 {
		t.Skip("testdata/live пуст: боевые конфигурации недоступны")
	}

	for _, path := range matches {
		name := filepath.Base(path)
		t.Run(name, func(t *testing.T) {
			content, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("чтение: %v", err)
			}

			p, err := ParseWireGuardConf("test", name, string(content))
			if err != nil {
				t.Fatalf("разбор рабочей конфигурации отвергнут: %v", err)
			}
			if err := p.Validate(); err != nil {
				t.Fatalf("рабочая конфигурация не прошла проверку: %v", err)
			}

			// Диагностика без секретов: тип и параметры обфускации, но не ключи.
			t.Logf("тип %s, обфускация настроена: %t", p.Kind, p.WireGuard != nil && p.WireGuard.Obfuscation != nil)
		})
	}
}
