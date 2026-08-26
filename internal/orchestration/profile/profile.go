// Package profile — декларативная модель подключения.
//
// Это НАША модель, а не конфигурация ядра. Разделение принципиально и
// продиктовано мерой S3 из ADR-006: служба не принимает от клиента сырой
// конфиг ядра, только декларативное описание, из которого конфиг собирается
// внутри службы. Прецедент, ради которого это сделано, — CVE-2024-6975.
//
// Побочная выгода: модель переживает смену версии ядра и не тянет его
// внутреннюю терминологию в интерфейс пользователя.
package profile

import (
	"fmt"
	"net/netip"
	"strings"
)

// Kind — тип транспорта наружу.
type Kind string

const (
	KindSOCKS5    Kind = "socks5"
	KindHysteria2 Kind = "hysteria2"
	KindWireGuard Kind = "wireguard"
	KindAmneziaWG Kind = "amneziawg"
	KindVLESS     Kind = "vless"
)

// Profile — описание одного пути наружу.
//
// Общие поля вынесены наверх, протокольные — в отдельные структуры.
// Плоская структура со всеми полями сразу превратилась бы в свалку, где
// половина полей не имеет смысла для конкретного типа, и проверить её
// было бы нечем.
type Profile struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind Kind   `json:"kind"`

	Server string `json:"server"`
	Port   uint16 `json:"port"`

	// Username и Password используются протоколами с парольной
	// аутентификацией: SOCKS5 и Hysteria2 (там пароль в поле Password).
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`

	TLS       *TLSParams       `json:"tls,omitempty"`
	Hysteria2 *Hysteria2Params `json:"hysteria2,omitempty"`
	WireGuard *WireGuardParams `json:"wireguard,omitempty"`
	VLESS     *VLESSParams     `json:"vless,omitempty"`
}

// TLSParams — параметры TLS для протоколов, которые его используют.
type TLSParams struct {
	Enabled bool     `json:"enabled"`
	SNI     string   `json:"sni,omitempty"`
	ALPN    []string `json:"alpn,omitempty"`

	// Insecure отключает проверку сертификата сервера.
	//
	// ⚠️ Это снижение защиты: соединение становится уязвимым к подмене
	// сертификата. Допустимо только для серверов с самоподписанным
	// сертификатом, и интерфейс обязан предупреждать об этом явно.
	// Предпочтительный путь — Pin с отпечатком сертификата.
	Insecure bool `json:"insecure,omitempty"`

	// Pin — SHA-256 отпечаток сертификата в шестнадцатеричном виде.
	// Заданный отпечаток проверяется даже при Insecure.
	Pin string `json:"pin,omitempty"`
}

// Hysteria2Params — параметры Hysteria2.
type Hysteria2Params struct {
	// ObfsType — тип обфускации. Поддерживается "salamander" или пусто.
	ObfsType     string `json:"obfsType,omitempty"`
	ObfsPassword string `json:"obfsPassword,omitempty"`

	UpMbps   int `json:"upMbps,omitempty"`
	DownMbps int `json:"downMbps,omitempty"`
}

// WireGuardParams — параметры WireGuard и AmneziaWG.
//
// AmneziaWG отличается только набором параметров обфускации: сам протокол
// тот же. Поэтому структура общая, а различие выражено полем Kind профиля.
type WireGuardParams struct {
	PrivateKey string         `json:"privateKey"`
	Address    []netip.Prefix `json:"address"`
	MTU        uint32         `json:"mtu,omitempty"`
	DNS        []string       `json:"dns,omitempty"`

	PeerPublicKey string         `json:"peerPublicKey"`
	PresharedKey  string         `json:"presharedKey,omitempty"`
	AllowedIPs    []netip.Prefix `json:"allowedIPs"`
	Keepalive     uint16         `json:"keepalive,omitempty"`

	// Obfuscation — параметры AmneziaWG. Пусто означает обычный WireGuard.
	Obfuscation *AmneziaParams `json:"obfuscation,omitempty"`
}

// AmneziaParams — параметры обфускации AmneziaWG 2.0.
//
// Имена совпадают с ключами файлов .conf, чтобы разбор конфигурации читался
// однозначно и сверялся с исходным файлом глазами.
type AmneziaParams struct {
	Jc   int    `json:"jc"`
	Jmin int    `json:"jmin"`
	Jmax int    `json:"jmax"`
	S1   int    `json:"s1"`
	S2   int    `json:"s2"`
	H1   uint32 `json:"h1"`
	H2   uint32 `json:"h2"`
	H3   uint32 `json:"h3"`
	H4   uint32 `json:"h4"`
}

// VLESSParams — параметры VLESS.
//
// ⚠️ Реализовано по спецификации, но НЕ проверено против живого сервера:
// у заказчика на момент И-4 не было доступного сервера с VLESS+Reality.
// До проверки утверждать работоспособность нельзя — только собираемость.
type VLESSParams struct {
	UUID string `json:"uuid"`
	// Flow — управление потоком, например "xtls-rprx-vision".
	Flow string `json:"flow,omitempty"`
	// Reality — параметры маскировки под настоящий TLS-сайт.
	Reality *RealityParams `json:"reality,omitempty"`
}

// RealityParams — параметры REALITY.
type RealityParams struct {
	PublicKey string `json:"publicKey"`
	ShortID   string `json:"shortId,omitempty"`
}

// Validate проверяет профиль перед тем, как из него будет собран конфиг ядра.
//
// Проверка обязательна и выполняется на стороне службы: это часть меры S3.
// Всё, что приходит извне, считается недоверенным, включая ввод собственного
// графического интерфейса.
func (p Profile) Validate() error {
	if strings.TrimSpace(p.ID) == "" {
		return fmt.Errorf("profile: пустой идентификатор")
	}
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("profile %q: пустое имя", p.ID)
	}
	if strings.TrimSpace(p.Server) == "" {
		return fmt.Errorf("profile %q: не задан адрес сервера", p.ID)
	}
	if _, err := netip.ParseAddr(p.Server); err != nil && !isPlausibleHost(p.Server) {
		return fmt.Errorf("profile %q: некорректный адрес сервера %q", p.ID, p.Server)
	}
	if p.Port == 0 {
		return fmt.Errorf("profile %q: не задан порт", p.ID)
	}

	switch p.Kind {
	case KindSOCKS5:
		return nil

	case KindHysteria2:
		if p.Password == "" {
			return fmt.Errorf("profile %q: Hysteria2 требует пароль", p.ID)
		}
		if h := p.Hysteria2; h != nil && h.ObfsType != "" && h.ObfsType != "salamander" {
			return fmt.Errorf("profile %q: неподдерживаемый тип обфускации %q", p.ID, h.ObfsType)
		}
		return nil

	case KindWireGuard, KindAmneziaWG:
		return p.validateWireGuard()

	case KindVLESS:
		if p.VLESS == nil || p.VLESS.UUID == "" {
			return fmt.Errorf("profile %q: VLESS требует UUID", p.ID)
		}
		return nil

	default:
		return fmt.Errorf("profile %q: неподдерживаемый тип %q", p.ID, p.Kind)
	}
}

func (p Profile) validateWireGuard() error {
	w := p.WireGuard
	if w == nil {
		return fmt.Errorf("profile %q: не заданы параметры WireGuard", p.ID)
	}
	if w.PrivateKey == "" {
		return fmt.Errorf("profile %q: не задан приватный ключ", p.ID)
	}
	if w.PeerPublicKey == "" {
		return fmt.Errorf("profile %q: не задан публичный ключ узла", p.ID)
	}
	if len(w.Address) == 0 {
		return fmt.Errorf("profile %q: не задан адрес интерфейса", p.ID)
	}
	if len(w.AllowedIPs) == 0 {
		return fmt.Errorf("profile %q: не задан список разрешённых подсетей", p.ID)
	}

	hasObfs := w.Obfuscation != nil
	if p.Kind == KindAmneziaWG && !hasObfs {
		return fmt.Errorf("profile %q: тип amneziawg без параметров обфускации — "+
			"используйте тип wireguard", p.ID)
	}
	if p.Kind == KindWireGuard && hasObfs {
		return fmt.Errorf("profile %q: тип wireguard с параметрами обфускации — "+
			"используйте тип amneziawg", p.ID)
	}
	return nil
}

// HasSecrets сообщает, содержит ли профиль значения, которые нельзя
// показывать и записывать в журнал (мера S7).
func (p Profile) HasSecrets() bool {
	if p.Password != "" {
		return true
	}
	if p.WireGuard != nil && (p.WireGuard.PrivateKey != "" || p.WireGuard.PresharedKey != "") {
		return true
	}
	if p.Hysteria2 != nil && p.Hysteria2.ObfsPassword != "" {
		return true
	}
	if p.VLESS != nil && p.VLESS.UUID != "" {
		return true
	}
	return false
}

// Redacted возвращает копию профиля с вырезанными секретами.
//
// Мера S7 из ADR-006: журналы не должны содержать секретов. Маскирование
// делается ПРИ ЗАПИСИ, а не при экспорте — иначе секрет уже лежит на диске,
// и любой сбой экспорта оставляет его доступным.
func (p Profile) Redacted() Profile {
	const mask = "***"

	out := p
	if out.Password != "" {
		out.Password = mask
	}
	if out.WireGuard != nil {
		w := *out.WireGuard
		if w.PrivateKey != "" {
			w.PrivateKey = mask
		}
		if w.PresharedKey != "" {
			w.PresharedKey = mask
		}
		out.WireGuard = &w
	}
	if out.Hysteria2 != nil {
		h := *out.Hysteria2
		if h.ObfsPassword != "" {
			h.ObfsPassword = mask
		}
		out.Hysteria2 = &h
	}
	if out.VLESS != nil {
		v := *out.VLESS
		if v.UUID != "" {
			v.UUID = mask
		}
		out.VLESS = &v
	}
	return out
}

func isPlausibleHost(s string) bool {
	if len(s) > 253 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}
