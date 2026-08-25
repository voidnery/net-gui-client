//go:build windows

package ipc

import (
	"errors"
	"strings"
	"testing"
)

// TestVerifyPath — проверка меры S2 на уровне логики сравнения путей.
//
// Функция маленькая, но ошибка в ней означает обход защиты, ради которой она
// написана. Особое внимание — случаю «каталог-сосед с общим префиксом»:
// наивная проверка через strings.HasPrefix без разделителя пропустила бы
// `C:\Program Files\net-gui-client-evil` как вложенный в
// `C:\Program Files\net-gui-client`.
func TestVerifyPath(t *testing.T) {
	const trusted = `C:\Program Files\net-gui-client`

	tests := []struct {
		name  string
		image string
		want  bool // true — путь должен быть принят
	}{
		{
			name:  "файл прямо в доверенном каталоге",
			image: `C:\Program Files\net-gui-client\net-cli.exe`,
			want:  true,
		},
		{
			name:  "файл во вложенном каталоге",
			image: `C:\Program Files\net-gui-client\bin\net-gui.exe`,
			want:  true,
		},
		{
			name:  "другой регистр — Windows регистронезависима",
			image: `C:\PROGRAM FILES\NET-GUI-CLIENT\net-cli.exe`,
			want:  true,
		},
		{
			name:  "путь с лишними разделителями нормализуется",
			image: `C:\Program Files\net-gui-client\.\net-cli.exe`,
			want:  true,
		},
		{
			name:  "каталог-сосед с общим префиксом ОТКЛОНЯЕТСЯ",
			image: `C:\Program Files\net-gui-client-evil\net-cli.exe`,
			want:  false,
		},
		{
			name:  "выход вверх через .. ОТКЛОНЯЕТСЯ",
			image: `C:\Program Files\net-gui-client\..\evil\net-cli.exe`,
			want:  false,
		},
		{
			name:  "посторонний каталог",
			image: `C:\Users\someone\AppData\Local\Temp\net-cli.exe`,
			want:  false,
		},
		{
			name:  "сам доверенный каталог без имени файла",
			image: `C:\Program Files\net-gui-client`,
			want:  false, // это каталог, а не исполняемый файл в нём
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyPath(tc.image, trusted)
			switch {
			case tc.want && err != nil:
				t.Errorf("путь отклонён, хотя должен быть принят: %v", err)
			case !tc.want && err == nil:
				t.Error("путь принят, хотя должен быть отклонён — это обход меры S2")
			case !tc.want && !errors.Is(err, ErrUntrustedClient):
				t.Errorf("ошибка не обёрнута вокруг ErrUntrustedClient: %v", err)
			}
		})
	}
}

// TestVerifyPathErrorMentionsBothPaths: сообщение об отказе обязано называть и
// отвергнутый путь, и ожидаемый каталог.
//
// Без этого разбор инцидента превращается в угадывание: администратор видит
// «клиент отклонён» и не знает ни кто именно, ни откуда его ждали.
func TestVerifyPathErrorMentionsBothPaths(t *testing.T) {
	const trusted = `C:\Program Files\net-gui-client`
	const image = `C:\Temp\evil\net-cli.exe`

	err := verifyPath(image, trusted)
	if err == nil {
		t.Fatal("ожидался отказ")
	}
	msg := err.Error()
	if !strings.Contains(msg, `C:\Temp\evil\net-cli.exe`) {
		t.Errorf("в сообщении нет отвергнутого пути: %s", msg)
	}
	if !strings.Contains(msg, trusted) {
		t.Errorf("в сообщении нет доверенного каталога: %s", msg)
	}
	// Обратные слэши не должны быть удвоены: сообщение читают глазами.
	if strings.Contains(msg, `\\`) {
		t.Errorf("путь выведен через %%q и стал нечитаемым: %s", msg)
	}
}

// TestVerifyClientWithEmptyTrustedDirSkipsCheck фиксирует поведение режима
// разработчика: пустой каталог отключает проверку.
//
// Тест существует, чтобы это поведение нельзя было изменить незаметно:
// пустая строка не должна однажды начать означать «отклонять всё» или,
// наоборот, «принимать всё» в релизной сборке.
func TestVerifyPathEmptyTrustedDirIsCallerResponsibility(t *testing.T) {
	// verifyPath сам по себе пустой каталог не обрабатывает — решение
	// принимает VerifyClient. Здесь закрепляем, что verifyPath на пустом
	// каталоге отвергает всё, то есть безопасен по умолчанию.
	if err := verifyPath(`C:\anything\net-cli.exe`, ""); err == nil {
		t.Error("verifyPath с пустым доверенным каталогом принял путь — " +
			"поведение по умолчанию должно быть отказом")
	}
}
