// Package corehost — управление жизненным циклом ядра протоколов.
//
// Ядро (форк sing-box, ADR-001) линкуется как Go-пакет, а не запускается
// отдельным процессом. Это то, ради чего выбиралась лицензия GPL-3.0:
// прямой доступ к маршрутизатору, списку соединений и метрикам без
// межпроцессной сериализации.
//
// ⚠️ Мера S3 из ADR-006: конфигурация ядра собирается ЗДЕСЬ, из проверенной
// декларативной модели. Ни один внешний вызывающий не может передать сюда
// готовый конфиг — такой возможности просто нет в API пакета.
package corehost

import (
	"context"
	"fmt"
	"net/netip"
	"os"

	"github.com/bbesport/net-gui-client/internal/orchestration/profile"
	"github.com/bbesport/net-gui-client/internal/orchestration/rules"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

// Теги аутбаундов внутри конфигурации ядра. Наружу не выставляются —
// это деталь трансляции, а не часть пользовательской модели.
const (
	tagProxy  = "proxy"
	tagDirect = "direct"
	tagIn     = "in"
	tagDNS    = "dns-local"
)

// Config — вход для сборки конфигурации ядра.
type Config struct {
	// ListenAddr и ListenPort — локальный inbound, куда пользователь
	// направляет приложения в режиме «Прокси».
	ListenAddr netip.Addr
	ListenPort uint16

	Profile profile.Profile
	Policy  rules.Policy

	// LogLevel: trace | debug | info | warn | error. Пусто — warn.
	LogLevel string
}

// BuildOptions транслирует нашу декларативную модель в конфигурацию ядра.
//
// Функция экспортирована намеренно: она чистая, детерминированная и
// тестируется без запуска ядра. На ней же будет построен тестер правил (И-7).
func BuildOptions(cfg Config) (option.Options, error) {
	if err := cfg.Profile.Validate(); err != nil {
		return option.Options{}, err
	}
	if err := cfg.Policy.Validate(); err != nil {
		return option.Options{}, err
	}
	if !cfg.ListenAddr.IsValid() {
		return option.Options{}, fmt.Errorf("corehost: не задан адрес локального inbound")
	}
	if cfg.ListenPort == 0 {
		return option.Options{}, fmt.Errorf("corehost: не задан порт локального inbound")
	}

	logLevel := cfg.LogLevel
	if logLevel == "" {
		// Переменная окружения — диагностическая лазейка для разработки и
		// для разбора обращений в поддержку: поднять подробность логов ядра,
		// не пересобирая приложение. Значения: trace | debug | info | warn | error.
		logLevel = os.Getenv("NETGUI_CORE_LOG")
	}
	if logLevel == "" {
		logLevel = "warn"
	}

	outbound, err := buildOutbound(cfg.Profile)
	if err != nil {
		return option.Options{}, err
	}

	listen := badoption.Addr(cfg.ListenAddr)

	return option.Options{
		Log: &option.LogOptions{
			Level:     logLevel,
			Timestamp: true,
		},
		// ⚠️ Без секции DNS соединения по доменному имени не устанавливаются
		// вовсе: начиная с sing-box 1.12 резолвер должен быть задан явно,
		// иначе маршрутизатор не знает, чем разрешать имена, и возвращает
		// ошибку ещё до попытки соединения. Симптом — 502 от локального
		// inbound при полностью исправном аутбаунде.
		//
		// Здесь используется системный резолвер. Это временное решение
		// итерации И-1: полноценная подсистема DNS с fake-IP, режимом
		// sniffing и защитой от утечек — итерация И-6 (ADR-005).
		DNS: &option.DNSOptions{
			RawDNSOptions: option.RawDNSOptions{
				Servers: []option.DNSServerOptions{{
					Type:    "local",
					Tag:     tagDNS,
					Options: &option.LocalDNSServerOptions{},
				}},
				Final: tagDNS,
			},
		},
		Inbounds: []option.Inbound{{
			// mixed — HTTP CONNECT и SOCKS5 на одном порту.
			Type: "mixed",
			Tag:  tagIn,
			Options: &option.HTTPMixedInboundOptions{
				ListenOptions: option.ListenOptions{
					Listen:     &listen,
					ListenPort: cfg.ListenPort,
				},
				// Системный прокси НЕ прописывается: в И-1 реализован
				// только режим «Прокси». Системный прокси — И-11.
				SetSystemProxy: false,
			},
		}},
		Outbounds: []option.Outbound{
			outbound,
			{Type: "direct", Tag: tagDirect, Options: &option.DirectOutboundOptions{}},
		},
		Route: buildRoute(cfg.Policy),
	}, nil
}

func buildOutbound(p profile.Profile) (option.Outbound, error) {
	switch p.Kind {
	case profile.KindSOCKS5:
		return option.Outbound{
			Type: "socks",
			Tag:  tagProxy,
			Options: &option.SOCKSOutboundOptions{
				ServerOptions: option.ServerOptions{
					Server:     p.Server,
					ServerPort: p.Port,
				},
				Version:  "5",
				Username: p.Username,
				Password: p.Password,
			},
		}, nil
	default:
		// Validate() уже отсёк такие случаи; ветка оставлена, чтобы
		// добавление типа в profile.Kind без правки транслятора
		// приводило к явной ошибке, а не к молчаливому пропуску.
		return option.Outbound{}, fmt.Errorf("corehost: транслятор не знает тип %q", p.Kind)
	}
}

func buildRoute(p rules.Policy) *option.RouteOptions {
	route := &option.RouteOptions{
		Final: outboundTag(p.Default),
		Rules: make([]option.Rule, 0, len(p.Rules)),
		// Резолвер по умолчанию для аутбаундов, которым нужно разрешить имя.
		//
		// Проверено на живом прогоне: проксируемые домены НЕ разрешаются
		// локально — в SOCKS5 уходит само имя, и резолв происходит на стороне
		// сервера. В журнале тестового прокси видно «CONNECT
		// www.msftconnecttest.com:80», а не IP-адрес. Резолвер задействуется
		// для прямых соединений и для правил, которым нужен адрес.
		//
		// Полноценная подсистема DNS — fake-IP, режим sniffing, тест утечек,
		// политика стороннего DoH — итерация И-6 (ADR-005).
		DefaultDomainResolver: &option.DomainResolveOptions{Server: tagDNS},
	}
	for _, r := range p.Rules {
		route.Rules = append(route.Rules, option.Rule{
			Type: "default",
			DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{
					Domain:       badoption.Listable[string](r.Domain),
					DomainSuffix: badoption.Listable[string](r.DomainSuffix),
					IPCIDR:       badoption.Listable[string](r.IPCIDR),
				},
				RuleAction: ruleAction(r.Action),
			},
		})
	}
	return route
}

func ruleAction(a rules.Action) option.RuleAction {
	if a == rules.ActionBlock {
		return option.RuleAction{Action: "reject"}
	}
	return option.RuleAction{
		Action:       "route",
		RouteOptions: option.RouteActionOptions{Outbound: outboundTag(a)},
	}
}

func outboundTag(a rules.Action) string {
	if a == rules.ActionDirect {
		return tagDirect
	}
	return tagProxy
}

// Core — запущенный экземпляр ядра.
type Core struct {
	box *box.Box
}

// Start собирает конфигурацию и запускает ядро.
//
// Возвращённый Core обязан быть закрыт вызовом Close.
func Start(ctx context.Context, cfg Config) (*Core, error) {
	opts, err := BuildOptions(cfg)
	if err != nil {
		return nil, err
	}

	// include.Context регистрирует реализации протоколов в контексте.
	// Без этого ядро не знает ни одного типа inbound или outbound:
	// sing-box использует контекст Go как контейнер внедрения зависимостей,
	// а не глобальные синглтоны.
	ctx = include.Context(ctx)

	b, err := box.New(box.Options{Options: opts, Context: ctx})
	if err != nil {
		return nil, fmt.Errorf("corehost: сборка ядра: %w", err)
	}
	if err := b.Start(); err != nil {
		_ = b.Close()
		return nil, fmt.Errorf("corehost: запуск ядра: %w", err)
	}
	return &Core{box: b}, nil
}

// Close останавливает ядро и освобождает ресурсы.
func (c *Core) Close() error {
	if c == nil || c.box == nil {
		return nil
	}
	err := c.box.Close()
	c.box = nil
	if err != nil {
		return fmt.Errorf("corehost: остановка ядра: %w", err)
	}
	return nil
}
