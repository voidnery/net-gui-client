//go:build windows

// Package wintun_test проверяет подлинность драйвера Wintun, вкомпилированного
// в наш двоичный файл (мера S4).
//
// # Почему проверка здесь, а не во время работы
//
// План И-5 требует «загрузки официального wintun.dll с проверкой подписи».
// Действительность оказалась иной: sing-tun не грузит файл с диска. Драйвер
// вкомпилирован директивой //go:embed и загружается самописным загрузчиком PE
// прямо из памяти (memmod.LoadLibrary).
//
// Проверять подпись в момент такой загрузки нечего и негде: Windows не
// участвует в ней и ничего не подписывает. Поэтому осмысленная гарантия
// сдвигается на этап сборки: убедиться, что вкомпилированы именно официальные
// байты, подписанные WireGuard LLC.
//
// Что это ловит: подмену в кэше модулей, вредоносное обновление зависимости,
// подмену в цепочке поставки. Иначе говоря — ровно то, ради чего мера S4 и
// существует.
//
// Чего это НЕ ловит: подмену уже собранного двоичного файла. От неё защищает
// подпись самого приложения (E0), а не эта проверка.
package wintun_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// singTunPath — путь к вкомпилированному wintun.dll в кэше модулей.
//
// Каталог модуля спрашивается у самого go, а не собирается из версии вручную.
// Первая версия этого теста брала версию из debug.ReadBuildInfo — и всегда
// пропускалась: sing-tun не входит в зависимости ЭТОГО тестового двоичного
// файла, потому что пакет его не импортирует. Вечно пропускаемый тест хуже
// отсутствующего: он создаёт видимость проверки.
func singTunPath(t *testing.T) string {
	t.Helper()

	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}",
		"github.com/sagernet/sing-tun").Output()
	if err != nil {
		t.Fatalf("не удалось найти модуль sing-tun: %v", err)
	}

	dir := strings.TrimSpace(string(out))
	if dir == "" {
		t.Fatal("go list вернул пустой путь к модулю sing-tun")
	}
	return filepath.Join(dir, "internal", "wintun", "amd64", "wintun.dll")
}

type signature struct {
	Status  int    `json:"Status"`
	Subject string `json:"Subject"`
	Issuer  string `json:"Issuer"`
}

// TestEmbeddedWintunIsOfficiallySigned — мера S4.
//
// Драйвер, работающий в ядре системы, обязан быть подлинным. Подпись WireGuard
// LLC — единственное доказательство этого, которое можно проверить, не
// доверяя тому, кто положил файл в кэш модулей.
func TestEmbeddedWintunIsOfficiallySigned(t *testing.T) {
	path := singTunPath(t)
	if _, err := os.Stat(path); err != nil {
		t.Skipf("вкомпилированный wintun.dll не найден: %v", err)
	}

	script := `$s = Get-AuthenticodeSignature -LiteralPath '` + path + `'; ` +
		`ConvertTo-Json -InputObject ([pscustomobject]@{` +
		`Status = [int]$s.Status; ` +
		`Subject = [string]$s.SignerCertificate.Subject; ` +
		`Issuer = [string]$s.SignerCertificate.Issuer}) -Depth 3`

	raw, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).Output()
	if err != nil {
		t.Fatalf("проверка подписи: %v", err)
	}

	var sig signature
	if err := json.Unmarshal(raw, &sig); err != nil {
		t.Fatalf("разбор результата проверки: %v (вывод: %s)", err, raw)
	}

	// SignatureStatus.Valid == 0. Остальные значения — от NotSigned до
	// HashMismatch, и все означают, что доверять файлу нельзя.
	if sig.Status != 0 {
		t.Fatalf("подпись недействительна: статус %d, подписант %q", sig.Status, sig.Subject)
	}

	if !strings.Contains(sig.Subject, "WireGuard LLC") {
		t.Errorf("драйвер подписан не WireGuard LLC, а %q", sig.Subject)
	}

	// Диагностика без секретов: по ней видно, чем именно подписан файл,
	// если проверка вдруг начнёт падать после обновления зависимости.
	t.Logf("подписант: %s", sig.Subject)
	t.Logf("издатель:  %s", sig.Issuer)
}

// TestEmbeddedWintunSignatureSurvivesCertificateExpiry поясняет неочевидное.
//
// Сертификат WireGuard LLC истёк 14.12.2021, и это НЕ делает подпись
// недействительной: она содержит метку времени от независимого центра. Метка
// доказывает, что подписание произошло, пока сертификат был действителен.
//
// Тест существует, чтобы будущий читатель, увидев дату истечения, не решил,
// что проверка сломана и её надо ослабить.
func TestEmbeddedWintunSignatureSurvivesCertificateExpiry(t *testing.T) {
	path := singTunPath(t)
	if _, err := os.Stat(path); err != nil {
		t.Skipf("вкомпилированный wintun.dll не найден: %v", err)
	}

	script := `$s = Get-AuthenticodeSignature -LiteralPath '` + path + `'; ` +
		`ConvertTo-Json -InputObject ([pscustomobject]@{` +
		`Status = [int]$s.Status; ` +
		`Subject = [string]$s.TimeStamperCertificate.Subject; ` +
		`Issuer = ''}) -Depth 3`

	raw, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).Output()
	if err != nil {
		t.Fatalf("проверка метки времени: %v", err)
	}

	var sig signature
	if err := json.Unmarshal(raw, &sig); err != nil {
		t.Fatalf("разбор результата: %v", err)
	}

	if sig.Subject == "" {
		t.Fatal("подпись без метки времени: после истечения сертификата она станет недействительной")
	}
	t.Logf("метка времени: %s", sig.Subject)
}
