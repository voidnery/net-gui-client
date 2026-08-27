package profile

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// Import разбирает содержимое, которое пользователь принёс из внешнего
// источника: ссылку-подписку или файл конфигурации.
//
// Тип определяется по СОДЕРЖИМОМУ, а не по имени файла или выбору в
// интерфейсе. Имя файла — это то, что пользователь мог переименовать, а
// выпадающий список «укажите тип» перекладывает на человека работу, которую
// программа делает надёжнее: набор форматов различим однозначно.
//
// Пустое имя означает «взять из содержимого»: в ссылках имя лежит во
// фрагменте после решётки, и обычно это именно то, как пользователь называет
// сервер у себя.
func Import(id, name, content string) (Profile, error) {
	trimmed := strings.TrimSpace(content)
	if trimmed == "" {
		return Profile{}, fmt.Errorf("profile: пустое содержимое")
	}

	switch {
	case hasScheme(trimmed, "vless"):
		return parseVLESSLink(id, name, trimmed)
	case hasScheme(trimmed, "hysteria2"), hasScheme(trimmed, "hy2"):
		return parseHysteria2Link(id, name, trimmed)
	case hasScheme(trimmed, "socks5"), hasScheme(trimmed, "socks"):
		return parseSOCKS5Link(id, name, trimmed)
	case strings.Contains(trimmed, "[Interface]"):
		// Имя выбирается тем же правилом, что и для ссылок. Формат wg-quick
		// своего имени не несёт, поэтому запасной вариант здесь один — ID.
		// Без этого импорт файла без явного имени отвергался проверкой
		// профиля: «пустое имя».
		return ParseWireGuardConf(id, pickName(name, "", id), content)
	default:
		return Profile{}, fmt.Errorf(
			"profile: формат не распознан; поддерживаются ссылки vless://, hysteria2://, socks5:// и файлы wg-quick")
	}
}

func hasScheme(s, scheme string) bool {
	return strings.HasPrefix(strings.ToLower(s), scheme+"://")
}

// parseVLESSLink разбирает ссылку вида
//
//	vless://<uuid>@<host>:<port>?security=reality&pbk=...&sni=...#<имя>
func parseVLESSLink(id, name, link string) (Profile, error) {
	u, err := url.Parse(link)
	if err != nil {
		return Profile{}, fmt.Errorf("profile: разбор ссылки vless: %w", err)
	}

	host, port, err := hostPort(u)
	if err != nil {
		return Profile{}, err
	}

	uuid := u.User.Username()
	if uuid == "" {
		return Profile{}, fmt.Errorf("profile: в ссылке vless нет UUID")
	}

	q := u.Query()

	// Транспорт. Ядро собирается только для голого TCP, поэтому ws, grpc и
	// прочие обязаны отвергаться явно. Молчаливое игнорирование дало бы
	// профиль, который сохраняется без ошибок и не подключается никогда.
	if t := q.Get("type"); t != "" && t != "tcp" {
		return Profile{}, fmt.Errorf("profile: транспорт %q для vless пока не поддерживается (только tcp)", t)
	}

	p := Profile{
		ID:     id,
		Name:   pickName(name, u.Fragment, id),
		Kind:   KindVLESS,
		Server: host,
		Port:   port,
		VLESS:  &VLESSParams{UUID: uuid, Flow: q.Get("flow")},
	}

	security := strings.ToLower(q.Get("security"))
	switch security {
	case "", "none":
		// Без TLS. Допустимо, хотя и редко встречается.

	case "tls", "xtls", "reality":
		p.TLS = &TLSParams{
			Enabled:     true,
			SNI:         firstNonEmpty(q.Get("sni"), q.Get("peer"), q.Get("host")),
			Fingerprint: q.Get("fp"),
			Insecure:    isTruthy(firstNonEmpty(q.Get("allowInsecure"), q.Get("insecure"))),
			Pin:         q.Get("pinSHA256"),
		}
		if alpn := q.Get("alpn"); alpn != "" {
			p.TLS.ALPN = splitList(alpn)
		}

		if security == "reality" {
			pbk := q.Get("pbk")
			if pbk == "" {
				return Profile{}, fmt.Errorf("profile: security=reality, но не задан публичный ключ (pbk)")
			}
			p.VLESS.Reality = &RealityParams{PublicKey: pbk, ShortID: q.Get("sid")}
		}

	default:
		return Profile{}, fmt.Errorf("profile: неизвестное значение security=%q в ссылке vless", security)
	}

	return p, p.Validate()
}

// parseHysteria2Link разбирает ссылку вида
//
//	hysteria2://<пароль>@<host>:<port>?sni=...&obfs=salamander#<имя>
//
// Принимается и сокращение hy2://.
func parseHysteria2Link(id, name, link string) (Profile, error) {
	u, err := url.Parse(link)
	if err != nil {
		return Profile{}, fmt.Errorf("profile: разбор ссылки hysteria2: %w", err)
	}

	host, port, err := hostPort(u)
	if err != nil {
		return Profile{}, err
	}

	// Аутентификация Hysteria2 — одна строка, которая вполне может содержать
	// двоеточие. url.Parse разделит её на «пользователя» и «пароль», поэтому
	// собираем обратно.
	auth := u.User.Username()
	if pass, ok := u.User.Password(); ok {
		auth = auth + ":" + pass
	}
	if auth == "" {
		return Profile{}, fmt.Errorf("profile: в ссылке hysteria2 нет пароля")
	}

	q := u.Query()

	p := Profile{
		ID:       id,
		Name:     pickName(name, u.Fragment, id),
		Kind:     KindHysteria2,
		Server:   host,
		Port:     port,
		Password: auth,
		// Hysteria2 работает поверх QUIC, то есть TLS есть всегда.
		TLS: &TLSParams{
			Enabled:  true,
			SNI:      firstNonEmpty(q.Get("sni"), q.Get("peer")),
			Insecure: isTruthy(firstNonEmpty(q.Get("insecure"), q.Get("allowInsecure"))),
			Pin:      q.Get("pinSHA256"),
		},
	}
	if alpn := q.Get("alpn"); alpn != "" {
		p.TLS.ALPN = splitList(alpn)
	}

	obfs := strings.ToLower(q.Get("obfs"))
	if obfs != "" || q.Get("obfs-password") != "" {
		p.Hysteria2 = &Hysteria2Params{
			ObfsType:     obfs,
			ObfsPassword: firstNonEmpty(q.Get("obfs-password"), q.Get("obfsPassword")),
		}
	}

	// Пропускная способность записывается по-разному: «100», «100 mbps»,
	// «100mbps». Берём ведущее число, остальное отбрасываем.
	if up := parseLeadingInt(q.Get("up")); up > 0 {
		p.ensureHysteria2().UpMbps = up
	}
	if down := parseLeadingInt(q.Get("down")); down > 0 {
		p.ensureHysteria2().DownMbps = down
	}

	return p, p.Validate()
}

// parseSOCKS5Link разбирает ссылку вида
//
//	socks5://<user>:<pass>@<host>:<port>?security=tls&sni=...&pinSHA256=...#<имя>
//
// Параметры TLS — наше расширение: общепринятой ссылки для SOCKS5 поверх TLS
// не существует. Имена параметров взяты те же, что в ссылках vless и
// hysteria2, чтобы не заводить третье написание одного и того же.
//
// Смысл в самом наличии такой возможности: SOCKS5 передаёт пароль открытым
// текстом, и обёртка в TLS для него не излишество.
func parseSOCKS5Link(id, name, link string) (Profile, error) {
	u, err := url.Parse(link)
	if err != nil {
		return Profile{}, fmt.Errorf("profile: разбор ссылки socks5: %w", err)
	}

	host, port, err := hostPort(u)
	if err != nil {
		return Profile{}, err
	}

	p := Profile{
		ID:     id,
		Name:   pickName(name, u.Fragment, id),
		Kind:   KindSOCKS5,
		Server: host,
		Port:   port,
	}
	if u.User != nil {
		p.Username = u.User.Username()
		if pass, ok := u.User.Password(); ok {
			p.Password = pass
		}
	}

	q := u.Query()
	switch security := strings.ToLower(q.Get("security")); security {
	case "", "none":
		// Обычный SOCKS5 без TLS.

	case "tls":
		p.TLS = &TLSParams{
			Enabled:     true,
			SNI:         firstNonEmpty(q.Get("sni"), q.Get("peer")),
			Fingerprint: q.Get("fp"),
			Insecure:    isTruthy(firstNonEmpty(q.Get("allowInsecure"), q.Get("insecure"))),
			Pin:         q.Get("pinSHA256"),
		}
		if alpn := q.Get("alpn"); alpn != "" {
			p.TLS.ALPN = splitList(alpn)
		}

	default:
		return Profile{}, fmt.Errorf("profile: неизвестное значение security=%q в ссылке socks5", security)
	}

	return p, p.Validate()
}

func (p *Profile) ensureHysteria2() *Hysteria2Params {
	if p.Hysteria2 == nil {
		p.Hysteria2 = &Hysteria2Params{}
	}
	return p.Hysteria2
}

func hostPort(u *url.URL) (string, uint16, error) {
	host := u.Hostname()
	if host == "" {
		return "", 0, fmt.Errorf("profile: в ссылке не задан адрес сервера")
	}

	raw := u.Port()
	if raw == "" {
		return "", 0, fmt.Errorf("profile: в ссылке не задан порт")
	}
	port, err := strconv.ParseUint(raw, 10, 16)
	if err != nil {
		return "", 0, fmt.Errorf("profile: некорректный порт %q", raw)
	}
	if port == 0 {
		return "", 0, fmt.Errorf("profile: порт не может быть нулевым")
	}
	return host, uint16(port), nil
}

// pickName выбирает имя профиля: явно заданное, затем из ссылки, затем ID.
func pickName(explicit, fromLink, id string) string {
	if s := strings.TrimSpace(explicit); s != "" {
		return s
	}
	if s := strings.TrimSpace(fromLink); s != "" {
		return s
	}
	return id
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// isTruthy трактует значения флагов в ссылках.
//
// Единого соглашения нет: встречаются 1, true и yes. Всё остальное, включая
// пустоту, считается отрицанием — для флага, ослабляющего проверку
// сертификата, умолчание обязано быть безопасным.
func isTruthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes":
		return true
	default:
		return false
	}
}

func splitList(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// parseLeadingInt берёт число из начала строки: «100 mbps» → 100.
func parseLeadingInt(s string) int {
	s = strings.TrimSpace(s)
	end := 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0
	}
	n, err := strconv.Atoi(s[:end])
	if err != nil {
		return 0
	}
	return n
}
