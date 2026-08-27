package profile

import (
	"strings"
	"testing"
)

// Значения выдуманы: UUID и пароли ниже не принадлежат ни одному серверу.
const (
	testUUID = "3f1a2b4c-5d6e-4f70-8192-a3b4c5d6e7f8"
	testPBK  = "xR9v2Qm8Lp0KdWt4Zc1Nb7Hs3Ye6Uj5Ao2Ig4Fk1Dl0"
)

func TestImportVLESSReality(t *testing.T) {
	link := "vless://" + testUUID + "@vpn.example.org:443" +
		"?security=reality&pbk=" + testPBK + "&sid=a1b2c3d4&sni=www.microsoft.com" +
		"&fp=chrome&flow=xtls-rprx-vision&type=tcp#Мой%20сервер"

	p, err := Import("v1", "", link)
	if err != nil {
		t.Fatalf("разбор ссылки: %v", err)
	}

	if p.Kind != KindVLESS {
		t.Errorf("тип %q, ожидался %q", p.Kind, KindVLESS)
	}
	if p.Name != "Мой сервер" {
		t.Errorf("имя %q — фрагмент ссылки не использован", p.Name)
	}
	if p.Server != "vpn.example.org" || p.Port != 443 {
		t.Errorf("адрес %s:%d", p.Server, p.Port)
	}
	if p.VLESS == nil || p.VLESS.UUID != testUUID {
		t.Fatalf("UUID разобран неверно: %+v", p.VLESS)
	}
	if p.VLESS.Flow != "xtls-rprx-vision" {
		t.Errorf("flow = %q", p.VLESS.Flow)
	}
	if p.VLESS.Reality == nil || p.VLESS.Reality.PublicKey != testPBK {
		t.Fatalf("параметры reality разобраны неверно: %+v", p.VLESS.Reality)
	}
	if p.VLESS.Reality.ShortID != "a1b2c3d4" {
		t.Errorf("sid = %q", p.VLESS.Reality.ShortID)
	}
	if p.TLS == nil || !p.TLS.Enabled {
		t.Fatal("TLS не включён, хотя security=reality")
	}
	if p.TLS.SNI != "www.microsoft.com" {
		t.Errorf("sni = %q", p.TLS.SNI)
	}
	// Отпечаток обязателен для REALITY: маскировка строится на том, что
	// рукопожатие неотличимо от браузерного.
	if p.TLS.Fingerprint != "chrome" {
		t.Errorf("fp = %q", p.TLS.Fingerprint)
	}
}

// TestImportVLESSRealityWithoutKey: reality без публичного ключа — это
// заведомо неработающий профиль, и лучше сказать об этом при импорте.
func TestImportVLESSRealityWithoutKey(t *testing.T) {
	link := "vless://" + testUUID + "@vpn.example.org:443?security=reality&sni=a.example"

	if _, err := Import("v1", "", link); err == nil {
		t.Fatal("ссылка reality без pbk принята")
	}
}

// TestImportVLESSUnsupportedTransport закрывает случай, который иначе
// проявился бы только у пользователя.
//
// Ядро собрано без транспортов ws/grpc. Принять такую ссылку значило бы
// сохранить профиль, который никогда не подключится, — и человек искал бы
// причину в сервере.
func TestImportVLESSUnsupportedTransport(t *testing.T) {
	link := "vless://" + testUUID + "@vpn.example.org:443?type=ws&security=tls"

	_, err := Import("v1", "", link)
	if err == nil {
		t.Fatal("ссылка с транспортом ws принята")
	}
	if !strings.Contains(err.Error(), "ws") {
		t.Errorf("ошибка не называет транспорт: %v", err)
	}
}

func TestImportHysteria2(t *testing.T) {
	link := "hysteria2://p%40ssw0rd-secret@vpn.example.org:8443" +
		"?sni=example.org&obfs=salamander&obfs-password=obfs-secret-value" +
		"&up=100%20mbps&down=200&insecure=1#Финляндия"

	p, err := Import("h1", "", link)
	if err != nil {
		t.Fatalf("разбор ссылки: %v", err)
	}

	if p.Kind != KindHysteria2 {
		t.Errorf("тип %q", p.Kind)
	}
	if p.Name != "Финляндия" {
		t.Errorf("имя %q", p.Name)
	}
	// Пароль приходит в процентном кодировании: @ внутри пароля обязан
	// восстановиться, иначе аутентификация не пройдёт.
	if p.Password != "p@ssw0rd-secret" {
		t.Errorf("пароль %q — процентное кодирование не раскрыто", p.Password)
	}
	if p.Hysteria2 == nil || p.Hysteria2.ObfsType != "salamander" {
		t.Fatalf("обфускация разобрана неверно: %+v", p.Hysteria2)
	}
	if p.Hysteria2.ObfsPassword != "obfs-secret-value" {
		t.Errorf("пароль обфускации %q", p.Hysteria2.ObfsPassword)
	}
	if p.Hysteria2.UpMbps != 100 || p.Hysteria2.DownMbps != 200 {
		t.Errorf("скорости up=%d down=%d — «100 mbps» не разобрано",
			p.Hysteria2.UpMbps, p.Hysteria2.DownMbps)
	}
	if p.TLS == nil || !p.TLS.Enabled {
		t.Error("TLS не включён, хотя Hysteria2 работает поверх QUIC")
	}
	if !p.TLS.Insecure {
		t.Error("insecure=1 не учтён")
	}
}

// TestImportHysteria2ShortScheme: сокращение hy2:// встречается не реже
// полного имени.
func TestImportHysteria2ShortScheme(t *testing.T) {
	p, err := Import("h1", "", "hy2://secret-auth-string@vpn.example.org:8443")
	if err != nil {
		t.Fatalf("разбор hy2://: %v", err)
	}
	if p.Kind != KindHysteria2 {
		t.Errorf("тип %q", p.Kind)
	}
}

// TestImportHysteria2AuthWithColon: строка аутентификации Hysteria2 может
// содержать двоеточие. url.Parse разделит её на «пользователя» и «пароль» —
// собирать обратно обязательно, иначе половина пароля потеряется.
func TestImportHysteria2AuthWithColon(t *testing.T) {
	p, err := Import("h1", "", "hysteria2://user:pass@vpn.example.org:8443")
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if p.Password != "user:pass" {
		t.Errorf("строка аутентификации %q, ожидалась %q", p.Password, "user:pass")
	}
}

func TestImportSOCKS5(t *testing.T) {
	p, err := Import("s1", "", "socks5://tester:pwd-value-here@127.0.0.1:1080#Локальный")
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if p.Kind != KindSOCKS5 {
		t.Errorf("тип %q", p.Kind)
	}
	if p.Username != "tester" || p.Password != "pwd-value-here" {
		t.Errorf("учётные данные: %q / %q", p.Username, p.Password)
	}
	if p.Name != "Локальный" {
		t.Errorf("имя %q", p.Name)
	}
}

// TestImportDetectsWireGuardByContent: тип определяется по содержимому.
//
// Имя файла ненадёжно — пользователь волен переименовать что угодно.
func TestImportDetectsWireGuardByContent(t *testing.T) {
	conf := `[Interface]
PrivateKey = aGVsbG8td29ybGQtZmFrZS1rZXktdmFsdWUtMDAwMDA=
Address = 10.0.0.2/32

[Peer]
PublicKey = cGVlci1mYWtlLXB1YmxpYy1rZXktdmFsdWUtMDAwMDA=
Endpoint = vpn.example.org:51820
AllowedIPs = 0.0.0.0/0
`

	p, err := Import("w1", "Тест", conf)
	if err != nil {
		t.Fatalf("разбор wg-quick: %v", err)
	}
	if p.Kind != KindWireGuard {
		t.Errorf("тип %q, ожидался %q", p.Kind, KindWireGuard)
	}
	if p.Name != "Тест" {
		t.Errorf("явно заданное имя проигнорировано: %q", p.Name)
	}
}

func TestImportRejectsUnknown(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{"пусто", "   "},
		{"неизвестная схема", "ss://something@host:1080"},
		{"просто текст", "какой-то текст"},
		{"нет порта", "socks5://host"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Import("x", "", tc.content); err == nil {
				t.Error("содержимое принято, хотя не должно было")
			}
		})
	}
}

// TestImportExplicitNameWins: имя, заданное пользователем, важнее фрагмента
// ссылки — иначе переименование в интерфейсе откатывалось бы при импорте.
func TestImportExplicitNameWins(t *testing.T) {
	p, err := Import("s1", "Своё имя", "socks5://127.0.0.1:1080#Из%20ссылки")
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if p.Name != "Своё имя" {
		t.Errorf("имя %q", p.Name)
	}
}

// TestInsecureDefaultsToFalse: флаг, ослабляющий проверку сертификата,
// обязан по умолчанию быть выключен при любом непонятном значении.
func TestInsecureDefaultsToFalse(t *testing.T) {
	for _, v := range []string{"", "0", "false", "no", "мусор"} {
		if isTruthy(v) {
			t.Errorf("значение %q истолковано как включение", v)
		}
	}
	for _, v := range []string{"1", "true", "TRUE", "yes"} {
		if !isTruthy(v) {
			t.Errorf("значение %q не истолковано как включение", v)
		}
	}
}

// TestImportWireGuardWithoutName закрывает дефект, найденный сквозной
// проверкой: файл wg-quick своего имени не несёт, и без запасного варианта
// импорт отвергался проверкой профиля как «пустое имя».
//
// Модульные тесты его не поймали, потому что все передавали имя явно.
func TestImportWireGuardWithoutName(t *testing.T) {
	conf := `[Interface]
PrivateKey = aGVsbG8td29ybGQtZmFrZS1rZXktdmFsdWUtMDAwMDA=
Address = 10.0.0.2/32

[Peer]
PublicKey = cGVlci1mYWtlLXB1YmxpYy1rZXktdmFsdWUtMDAwMDA=
Endpoint = vpn.example.org:51820
AllowedIPs = 0.0.0.0/0
`

	p, err := Import("wg-id", "", conf)
	if err != nil {
		t.Fatalf("импорт без имени отвергнут: %v", err)
	}
	if p.Name != "wg-id" {
		t.Errorf("имя %q, ожидался идентификатор", p.Name)
	}
}

// TestImportSOCKS5OverTLS: SOCKS5 передаёт пароль открытым текстом, поэтому
// возможность завернуть его в TLS выражена и в ссылке.
func TestImportSOCKS5OverTLS(t *testing.T) {
	link := "socks5://tester:pwd-value-here@vpn.example.org:1080" +
		"?security=tls&sni=vpn.example.org&insecure=1" +
		"&pinSHA256=" + strings.Repeat("ab", 32) + "#Через%20TLS"

	p, err := Import("s1", "", link)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if p.TLS == nil || !p.TLS.Enabled {
		t.Fatal("TLS не включён")
	}
	if p.TLS.SNI != "vpn.example.org" {
		t.Errorf("sni = %q", p.TLS.SNI)
	}
	if !p.TLS.Insecure {
		t.Error("insecure=1 не учтён")
	}
	if p.TLS.Pin != strings.Repeat("ab", 32) {
		t.Errorf("отпечаток = %q", p.TLS.Pin)
	}
}

// TestImportSOCKS5UnknownSecurity: непонятное значение security — это не
// повод молча собрать профиль без TLS. Пользователь считал бы соединение
// защищённым.
func TestImportSOCKS5UnknownSecurity(t *testing.T) {
	if _, err := Import("s1", "", "socks5://127.0.0.1:1080?security=reality"); err == nil {
		t.Fatal("неизвестное значение security принято")
	}
}
