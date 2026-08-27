package corehost

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"

	"github.com/bbesport/net-gui-client/internal/corehost/sockstls"
	"github.com/bbesport/net-gui-client/internal/orchestration/profile"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

// buildResult — результат трансляции профиля.
//
// Аутбаунды и endpoint'ы разделены, потому что sing-box относит WireGuard к
// endpoint'ам, а не к аутбаундам: у него есть собственный сетевой интерфейс
// и адрес, чего у обычного аутбаунда нет.
type buildResult struct {
	Outbounds []option.Outbound
	Endpoints []option.Endpoint
	// ProxyTag — тег, на который ссылаются правила маршрутизации.
	ProxyTag string
}

// buildProxy транслирует профиль в записи конфигурации ядра.
func buildProxy(p profile.Profile) (buildResult, error) {
	switch p.Kind {
	case profile.KindSOCKS5:
		return buildSOCKS5(p)
	case profile.KindHysteria2:
		return buildHysteria2(p)
	case profile.KindWireGuard, profile.KindAmneziaWG:
		return buildWireGuard(p)
	case profile.KindVLESS:
		return buildVLESS(p)
	default:
		// Validate() уже отсёк такие случаи; ветка оставлена, чтобы
		// добавление типа в profile.Kind без правки транслятора приводило
		// к явной ошибке, а не к молчаливому пропуску.
		return buildResult{}, fmt.Errorf("corehost: транслятор не знает тип %q", p.Kind)
	}
}

func buildSOCKS5(p profile.Profile) (buildResult, error) {
	base := option.SOCKSOutboundOptions{
		ServerOptions: option.ServerOptions{Server: p.Server, ServerPort: p.Port},
		Version:       "5",
		Username:      p.Username,
		Password:      p.Password,
	}

	// SOCKS5 передаёт пароль открытым текстом, поэтому обёртка в TLS — не
	// излишество. У встроенного в ядро типа socks секции TLS нет, и при
	// включённом TLS используется наш тип socks-tls.
	if p.TLS != nil && p.TLS.Enabled {
		return buildResult{
			ProxyTag: tagProxy,
			Outbounds: []option.Outbound{{
				Type: sockstls.Type,
				Tag:  tagProxy,
				Options: &sockstls.Options{
					SOCKSOutboundOptions: base,
					OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
						TLS: buildTLS(p, true),
					},
				},
			}},
		}, nil
	}

	return buildResult{
		ProxyTag: tagProxy,
		Outbounds: []option.Outbound{{
			Type:    "socks",
			Tag:     tagProxy,
			Options: &base,
		}},
	}, nil
}

func buildHysteria2(p profile.Profile) (buildResult, error) {
	opts := &option.Hysteria2OutboundOptions{
		ServerOptions: option.ServerOptions{Server: p.Server, ServerPort: p.Port},
		Password:      p.Password,
	}

	if h := p.Hysteria2; h != nil {
		if h.ObfsType != "" {
			opts.Obfs = &option.Hysteria2Obfs{
				Type:     h.ObfsType,
				Password: h.ObfsPassword,
			}
		}
		opts.UpMbps = h.UpMbps
		opts.DownMbps = h.DownMbps
	}

	// Hysteria2 работает поверх QUIC, то есть TLS обязателен всегда.
	opts.OutboundTLSOptionsContainer = option.OutboundTLSOptionsContainer{
		TLS: buildTLS(p, true),
	}

	return buildResult{
		ProxyTag:  tagProxy,
		Outbounds: []option.Outbound{{Type: "hysteria2", Tag: tagProxy, Options: opts}},
	}, nil
}

// buildWireGuard транслирует WireGuard и AmneziaWG.
//
// Различие между ними — только в наличии обфускации, а она задаётся не
// здесь: параметры уходят в ядро через контекст, см. corehost.Start.
func buildWireGuard(p profile.Profile) (buildResult, error) {
	w := p.WireGuard

	peer := option.WireGuardPeer{
		Address:                     p.Server,
		Port:                        p.Port,
		PublicKey:                   w.PeerPublicKey,
		PreSharedKey:                w.PresharedKey,
		AllowedIPs:                  badoption.Listable[netip.Prefix](w.AllowedIPs),
		PersistentKeepaliveInterval: w.Keepalive,
	}

	endpointOpts := &option.WireGuardEndpointOptions{
		Address:    badoption.Listable[netip.Prefix](w.Address),
		PrivateKey: w.PrivateKey,
		MTU:        w.MTU,
		Peers:      []option.WireGuardPeer{peer},
	}

	// Параметры обфускации сюда НЕ попадают: они передаются в ядро через
	// контекст, потому что подмена типов сообщений выполняется внутри
	// форка wireguard-go — до вычисления MAC. См. corehost.Start и
	// ADR-001, дополнение от 2026-08-26.
	res := buildResult{ProxyTag: tagProxy}

	res.Endpoints = append(res.Endpoints, option.Endpoint{
		Type:    "wireguard",
		Tag:     tagProxy,
		Options: endpointOpts,
	})
	return res, nil
}

// buildVLESS транслирует VLESS.
//
// ⚠️ НЕ ПРОВЕРЕНО против живого сервера: на момент реализации у заказчика
// не было доступного сервера с VLESS+Reality. Код собирается и соответствует
// спецификации, но утверждать работоспособность нельзя.
func buildVLESS(p profile.Profile) (buildResult, error) {
	v := p.VLESS

	opts := &option.VLESSOutboundOptions{
		ServerOptions: option.ServerOptions{Server: p.Server, ServerPort: p.Port},
		UUID:          v.UUID,
		Flow:          v.Flow,
	}

	tls := buildTLS(p, p.TLS != nil && p.TLS.Enabled)
	if v.Reality != nil && tls != nil {
		tls.Reality = &option.OutboundRealityOptions{
			Enabled:   true,
			PublicKey: v.Reality.PublicKey,
			ShortID:   v.Reality.ShortID,
		}
	}
	opts.OutboundTLSOptionsContainer = option.OutboundTLSOptionsContainer{TLS: tls}

	return buildResult{
		ProxyTag:  tagProxy,
		Outbounds: []option.Outbound{{Type: "vless", Tag: tagProxy, Options: opts}},
	}, nil
}

// buildTLS собирает параметры TLS.
//
// force означает, что протокол требует TLS всегда (например, Hysteria2
// поверх QUIC) — тогда секция создаётся даже без явных настроек.
func buildTLS(p profile.Profile, force bool) *option.OutboundTLSOptions {
	t := p.TLS
	if t == nil && !force {
		return nil
	}
	if t == nil {
		return &option.OutboundTLSOptions{Enabled: true}
	}

	out := &option.OutboundTLSOptions{
		Enabled:    t.Enabled || force,
		ServerName: t.SNI,
		Insecure:   t.Insecure,
		ALPN:       badoption.Listable[string](t.ALPN),
	}
	if t.Fingerprint != "" {
		out.UTLS = &option.OutboundUTLSOptions{Enabled: true, Fingerprint: t.Fingerprint}
	}
	if t.Pin != "" {
		// Пиннинг отпечатка строже, чем проверка цепочки: он привязывает
		// соединение к конкретному сертификату. Работает и при Insecure,
		// что позволяет безопасно использовать самоподписанные сертификаты.
		//
		// Ядро ожидает отпечаток байтами, а пользователь задаёт его строкой
		// в шестнадцатеричном виде — с двоеточиями или без, как показывают
		// openssl и браузеры. Некорректный отпечаток отсекается на этапе
		// проверки профиля, здесь он уже разобран.
		if pin, err := decodePin(t.Pin); err == nil {
			out.CertificatePublicKeySHA256 = badoption.Listable[[]byte]{pin}
		}
	}
	return out
}

// decodePin разбирает отпечаток сертификата.
//
// Принимаются оба общепринятых начертания: сплошная строка и группы по два
// знака через двоеточие. Отвергать второе означало бы заставлять
// пользователя вручную править то, что он скопировал из вывода openssl.
func decodePin(s string) ([]byte, error) {
	cleaned := strings.NewReplacer(":", "", " ", "", "-", "").Replace(s)
	raw, err := hex.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("corehost: отпечаток сертификата не является шестнадцатеричным: %w", err)
	}
	if len(raw) != sha256.Size {
		return nil, fmt.Errorf("corehost: отпечаток длиной %d байт, ожидалось %d (SHA-256)",
			len(raw), sha256.Size)
	}
	return raw, nil
}
