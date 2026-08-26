package awg

import "testing"

// Значения здесь синтетические, а не взятые из конфигураций заказчика.
//
// Причина не в удобстве: параметры H1..H4 не являются ключами, но однозначно
// опознают трафик к конкретному серверу. Репозиторий публичный, поэтому
// боевые значения проверяются отдельным тестом, который читает файлы из
// testdata/live — каталога, закрытого .gitignore (см. profile/parse_wg_test.go).
func TestValidate(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		ok   bool
	}{
		{"пустая — обычный WireGuard", Config{}, true},
		{
			name: "типичный набор параметров",
			cfg: Config{Jc: 5, Jmin: 43, Jmax: 233, S1: 20, S2: 91,
				H1: 1000001, H2: 1000002, H3: 1000003, H4: 1000004},
			ok: true,
		},
		{
			name: "S1 и S2 дают одинаковый размер пакета",
			// 92+148 == 148+92: init и response станут неразличимы.
			cfg: Config{S1: MessageResponseSize, S2: MessageInitiationSize,
				H1: 1, H2: 2, H3: 3, H4: 4},
			ok: false,
		},
		{
			name: "совпадающие заголовки",
			cfg:  Config{S1: 20, S2: 91, H1: 100, H2: 100, H3: 3, H4: 4},
			ok:   false,
		},
		{
			name: "Jmax меньше Jmin",
			cfg:  Config{Jc: 3, Jmin: 200, Jmax: 100, S1: 20, S2: 91, H1: 1, H2: 2, H3: 3, H4: 4},
			ok:   false,
		},
		{
			name: "отрицательное дополнение",
			cfg:  Config{S1: -1, S2: 91, H1: 1, H2: 2, H3: 3, H4: 4},
			ok:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.ok && err != nil {
				t.Errorf("конфигурация отвергнута: %v", err)
			}
			if !tc.ok && err == nil {
				t.Error("некорректная конфигурация принята")
			}
		})
	}
}
