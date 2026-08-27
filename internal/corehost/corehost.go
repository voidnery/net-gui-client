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
	"strings"

	"github.com/bbesport/net-gui-client/internal/corehost/sockstls"
	"github.com/bbesport/net-gui-client/internal/orchestration/profile"
	"github.com/bbesport/net-gui-client/internal/orchestration/rules"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	wgdevice "github.com/sagernet/wireguard-go/device"
)

// Теги аутбаундов внутри конфигурации ядра. Наружу не выставляются —
// это деталь трансляции, а не часть пользовательской модели.
const (
	tagProxy  = "proxy"
	tagDirect = "direct"
	tagIn     = "in"
	tagTun    = "tun"
	tagDNS    = "dns-local"

	// tagDNSRemote — резолвер, доступный ЧЕРЕЗ туннель.
	tagDNSRemote = "dns-remote"
)

// defaultTunnelDNS — резолвер на случай, когда профиль своего не задаёт.
//
// Выбор чужого резолвера за пользователя — решение политики, и оно здесь
// временное: полноценная подсистема DNS с fake-IP и защитой от утечек — это
// итерация И-6 (ADR-005). Пока важно другое: в режиме туннеля системный
// резолвер использовать НЕЛЬЗЯ, и что-то указать необходимо.
const defaultTunnelDNS = "1.1.1.1"

// Параметры сетевого адаптера в режиме туннеля.
const (
	// tunInterfaceName — имя адаптера.
	//
	// Постоянное, а не случайное: после аварийного завершения адаптер нужно
	// найти и убрать, а искать его по имени надёжнее, чем по эвристике
	// «что-то похожее на наше».
	tunInterfaceName = "netgui"

	// tunAddress4 и tunAddress6 — адреса самого адаптера.
	//
	// Диапазоны выбраны из тех, что не встречаются в домашних и офисных
	// сетях: 172.19.0.0/30 лежит внутри частного блока 172.16/12, но узкая
	// маска делает совпадение маловероятным. Совпадение означало бы, что
	// туннель перехватывает адрес, принадлежащий локальной сети.
	tunAddress4 = "172.19.0.1/30"
	tunAddress6 = "fdfe:dcba:9876::1/126"

	// tunMTU по умолчанию.
	//
	// 1500 — размер кадра Ethernet. Для профилей WireGuard берётся MTU из
	// самого профиля: он уже учитывает накладные расходы туннеля, и брать
	// больше означало бы фрагментацию на каждом пакете.
	tunMTU = 1500
)

// Mode — режим работы соединения.
//
// Из трёх режимов, заявленных в задании, здесь два. Системный прокси — это
// не отдельный способ передачи трафика, а лишь настройка Windows поверх
// режима «прокси», и он появится в И-11.
type Mode string

const (
	// ModeProxy — локальный прокси. Приложения направляются на него вручную.
	ModeProxy Mode = "proxy"

	// ModeTunnel — сетевой адаптер TUN: весь трафик системы идёт через
	// туннель без настройки отдельных приложений.
	//
	// ⚠️ Требует прав администратора: создание адаптера и правка таблицы
	// маршрутизации непривилегированному процессу недоступны.
	ModeTunnel Mode = "tunnel"
)

// Config — вход для сборки конфигурации ядра.
type Config struct {
	// ListenAddr и ListenPort — локальный inbound, куда пользователь
	// направляет приложения в режиме «Прокси».
	ListenAddr netip.Addr
	ListenPort uint16

	Profile profile.Profile
	Policy  rules.Policy

	// Mode — режим работы. Пусто означает ModeProxy: так поведение остаётся
	// прежним для всего кода, написанного до появления туннеля.
	Mode Mode

	// LogLevel: trace | debug | info | warn | error. Пусто — warn.
	LogLevel string
}

// mode возвращает режим с учётом значения по умолчанию.
func (c Config) mode() Mode {
	if c.Mode == "" {
		return ModeProxy
	}
	return c.Mode
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
	switch cfg.mode() {
	case ModeProxy, ModeTunnel:
	default:
		return option.Options{}, fmt.Errorf("corehost: неизвестный режим %q", cfg.Mode)
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

	proxy, err := buildProxy(cfg.Profile)
	if err != nil {
		return option.Options{}, err
	}

	listen := badoption.Addr(cfg.ListenAddr)

	return option.Options{
		Log: &option.LogOptions{
			Level:     logLevel,
			Timestamp: true,
		},
		DNS:      buildDNS(cfg),
		Inbounds: buildInbounds(cfg, listen),
		Outbounds: append(proxy.Outbounds,
			option.Outbound{Type: "direct", Tag: tagDirect, Options: &option.DirectOutboundOptions{}},
		),
		Endpoints: proxy.Endpoints,
		Route:     buildRoute(cfg.Policy, cfg.mode()),
	}, nil
}

// buildDNS собирает секцию разрешения имён.
//
// ⚠️ Без этой секции соединения по доменному имени не устанавливаются вовсе:
// начиная с sing-box 1.12 резолвер должен быть задан явно, иначе
// маршрутизатор не знает, чем разрешать имена, и возвращает ошибку ещё до
// попытки соединения. Симптом — 502 от локального inbound при полностью
// исправном аутбаунде.
//
// # Почему в режиме туннеля нельзя системный резолвер
//
// В режиме прокси системный резолвер работает и проверен с И-1. В режиме
// туннеля он даёт замкнутую петлю: sing-tun перехватывает запросы DNS и
// направляет их в ядро, ядро спрашивает систему, запрос системы снова
// попадает в туннель. Ответом становится мусор.
//
// Найдено экспериментом E6: имя ifconfig.me разрешилось в 127.206.0.124 —
// адрес из петлевого диапазона, — и соединение, разумеется, не установилось.
// Машина при этом выглядела «подключённой».
//
// Поэтому в режиме туннеля заводится ВТОРОЙ резолвер, доступный через сам
// туннель, и именно он отвечает на запросы пользователя.
func buildDNS(cfg Config) *option.DNSOptions {
	local := option.DNSServerOptions{
		Type:    "local",
		Tag:     tagDNS,
		Options: &option.LocalDNSServerOptions{},
	}

	if cfg.mode() != ModeTunnel {
		return &option.DNSOptions{
			RawDNSOptions: option.RawDNSOptions{
				Servers: []option.DNSServerOptions{local},
				Final:   tagDNS,
			},
		}
	}

	remote := option.DNSServerOptions{
		Type: "udp",
		Tag:  tagDNSRemote,
		Options: &option.RemoteDNSServerOptions{
			DNSServerAddressOptions: option.DNSServerAddressOptions{
				Server: tunnelDNSFor(cfg.Profile),
			},
			// Detour отправляет сам запрос DNS через туннель. Без него
			// запрос ушёл бы мимо — и это была бы утечка: наблюдатель на
			// стороне провайдера видел бы, какие имена запрашиваются.
			RawLocalDNSServerOptions: option.RawLocalDNSServerOptions{
				DialerOptions: option.DialerOptions{Detour: tagProxy},
			},
		},
	}

	return &option.DNSOptions{
		RawDNSOptions: option.RawDNSOptions{
			// Системный резолвер остаётся, но НЕ как основной: он нужен,
			// чтобы разрешить адрес самого VPN-сервера, если тот задан
			// именем. Разрешать его через туннель невозможно — туннеля
			// ещё нет.
			Servers: []option.DNSServerOptions{local, remote},
			Final:   tagDNSRemote,
		},
	}
}

// tunnelDNSFor выбирает резолвер для режима туннеля.
//
// Предпочтение — резолверу из профиля: провайдер VPN задаёт его не случайно,
// а потому что тот доступен изнутри туннеля и не отдаёт наружу историю
// запросов.
func tunnelDNSFor(p profile.Profile) string {
	if w := p.WireGuard; w != nil {
		for _, s := range w.DNS {
			if s = strings.TrimSpace(s); s != "" {
				return s
			}
		}
	}
	return defaultTunnelDNS
}

// buildInbounds собирает входящие точки.
//
// Локальный прокси создаётся ВСЕГДА, в том числе в режиме туннеля. Стоит он
// один порт на loopback, а даёт две вещи: возможность направить в туннель
// отдельное приложение, не трогая систему, и точку для диагностики, когда
// нужно сравнить «через туннель» и «мимо».
func buildInbounds(cfg Config, listen badoption.Addr) []option.Inbound {
	inbounds := []option.Inbound{{
		// mixed — HTTP CONNECT и SOCKS5 на одном порту.
		Type: "mixed",
		Tag:  tagIn,
		Options: &option.HTTPMixedInboundOptions{
			ListenOptions: option.ListenOptions{
				Listen:     &listen,
				ListenPort: cfg.ListenPort,
			},
			// Системный прокси НЕ прописывается: это отдельный режим,
			// он появится в И-11.
			SetSystemProxy: false,
		},
	}}

	if cfg.mode() != ModeTunnel {
		return inbounds
	}

	return append(inbounds, option.Inbound{
		Type:    tagTun,
		Tag:     tagTun,
		Options: buildTun(cfg),
	})
}

// buildTun собирает параметры сетевого адаптера.
func buildTun(cfg Config) *option.TunInboundOptions {
	return &option.TunInboundOptions{
		InterfaceName: tunInterfaceName,
		MTU:           tunMTUFor(cfg.Profile),
		Address:       tunAddresses(cfg.Profile),

		// AutoRoute поднимает маршруты 0.0.0.0/1 + 128.0.0.0/1 и ::/1 +
		// 8000::/1. Половинки вместо 0.0.0.0/0 берутся не из суеверия: они
		// перекрывают маршрут по умолчанию, не удаляя его, поэтому
		// восстановление сводится к их снятию.
		AutoRoute: true,

		// ⚠️ StrictRoute намеренно ВЫКЛЮЧЕН на этой итерации.
		//
		// Он добавляет правила брандмауэра, отсекающие трафик мимо туннеля,
		// то есть решает задачу защиты от утечек — это итерация И-8. Здесь же
		// проверяется другое: что систему удаётся вернуть в исходное
		// состояние. Каждое дополнительное изменение в системе — это то, что
		// придётся откатывать, и включать его до того, как откат доказан,
		// значит усложнять себе проверку.
		StrictRoute: false,

		// gvisor — сетевой стек в пространстве пользователя.
		//
		// Выбран вместо system по причине этой же итерации: он не трогает
		// стек Windows и потому оставляет после себя меньше следов. Цена —
		// пропускная способность; измерение и возможная смена на system —
		// вопрос итерации со статистикой.
		Stack: "gvisor",
	}
}

// tunAddresses выбирает адреса адаптера — и тем самым решает, какие семейства
// адресов туннель ПЕРЕХВАТЫВАЕТ.
//
// Маршруты в sing-tun выводятся из списка адресов: без адреса IPv6 маршруты
// IPv6 не создаются вовсе (BuildAutoRouteRanges, проверка len(Inet6Address)).
//
// # Почему это важнее, чем кажется
//
// Первая версия выдавала адрес IPv6 безусловно. На профиле AmneziaWG, у
// которого есть только 10.9.0.15/32, это привело к тому, что система
// направила весь трафик IPv6 в туннель, а туннель нести его не может.
// Результат — сотни отказов «missing IPv6 local address» и машина БЕЗ
// интернета при поднятом туннеле. Найдено экспериментом E6.
//
// Правило простое: перехватывать только то, что умеем донести. Чёрная дыра
// хуже отсутствия перехвата — она ломает связь, причём молча.
//
// ⚠️ Следствие, которое надо знать: для профилей без IPv6 трафик IPv6 идёт
// МИМО туннеля, то есть утекает напрямую. Это осознанная граница И-5:
// закрытие утечек — итерация И-8, и закрывать их надо явной блокировкой, а
// не случайной чёрной дырой.
func tunAddresses(p profile.Profile) badoption.Listable[netip.Prefix] {
	out := badoption.Listable[netip.Prefix]{netip.MustParsePrefix(tunAddress4)}
	if profileCarriesIPv6(p) {
		out = append(out, netip.MustParsePrefix(tunAddress6))
	}
	return out
}

// profileCarriesIPv6 сообщает, способен ли профиль передавать IPv6.
//
// Для WireGuard ответ точен: он записан в самой конфигурации — туннелю выдан
// адрес IPv6 или не выдан.
//
// Для протоколов-прокси (SOCKS5, Hysteria2, VLESS) ответ неизвестен в
// принципе: способность нести IPv6 зависит от сервера, а не от профиля.
// Выбран осторожный ответ «нет». Ошибиться в эту сторону означает утечку
// IPv6 мимо туннеля; ошибиться в другую — оставить пользователя без связи.
// Второе хуже и, в отличие от первого, не имеет обходного пути.
func profileCarriesIPv6(p profile.Profile) bool {
	w := p.WireGuard
	if w == nil {
		return false
	}
	for _, a := range w.Address {
		if a.Addr().Is6() && !a.Addr().Is4In6() {
			return true
		}
	}
	return false
}

// tunMTUFor выбирает MTU адаптера.
//
// Для WireGuard берётся MTU профиля: он уже уменьшен на накладные расходы
// туннеля. Адаптер с большим MTU, чем у туннеля, приводит к фрагментации
// каждого крупного пакета — соединение работает, но заметно медленнее, и
// причину такого замедления найти тяжело.
func tunMTUFor(p profile.Profile) uint32 {
	if w := p.WireGuard; w != nil && w.MTU > 0 {
		return w.MTU
	}
	return tunMTU
}

func buildRoute(p rules.Policy, mode Mode) *option.RouteOptions {
	route := &option.RouteOptions{
		Final: outboundTag(p.Default),
		Rules: make([]option.Rule, 0, len(p.Rules)),

		// ⚠️ Обязательно в режиме туннеля.
		//
		// Соединение с VPN-сервером обязано идти МИМО туннеля. Без явного
		// определения исходящего интерфейса пакеты к серверу попадают в
		// маршрут по умолчанию — то есть в тот самый туннель, который они
		// должны поднять. Получается петля, и туннель не поднимается вовсе.
		//
		// В режиме прокси включать не требуется, и поведение, проверенное на
		// живых прогонах, не меняется.
		AutoDetectInterface: mode == ModeTunnel,
		// Резолвер по умолчанию для аутбаундов, которым нужно разрешить имя.
		//
		// ВСЕГДА системный, в том числе в режиме туннеля: здесь разрешается
		// адрес самого VPN-сервера, а через ещё не поднятый туннель это
		// невозможно.
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
	// В режиме туннеля первыми идут два служебных правила. Они не относятся
	// к политике пользователя и потому стоят ДО его правил.
	if mode == ModeTunnel {
		route.Rules = append(route.Rules, tunnelServiceRules()...)
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

// tunnelServiceRules возвращает правила, без которых режим туннеля не
// работает.
//
// # Почему без них разрешение имён молчит
//
// sing-tun прописывает адаптеру резолвер — адрес самого туннеля плюс один
// (у нас 172.19.0.2). Это фиктивный адрес: никакого сервера DNS там нет.
// Расчёт на то, что запросы к нему будут ПЕРЕХВАЧЕНЫ и отданы подсистеме
// разрешения имён самого ядра.
//
// Перехват включается отдельным правилом маршрутизации. Без него пакеты к
// 172.19.0.2 просто уходят в никуда, и системный резолвер ждёт ответа до
// истечения времени ожидания.
//
// Найдено экспериментом E6: туннель передавал данные (проверка через
// локальный прокси ядра выходила на адрес сервера), а системный путь
// сообщал «lookup ifconfig.me: i/o timeout». Разделение двух путей измерения
// и указало на разрешение имён, а не на туннель.
func tunnelServiceRules() []option.Rule {
	return []option.Rule{
		{
			// Определение протокола по содержимому. Без него правило ниже
			// не с чем сопоставлять: «протокол dns» — это результат разбора
			// пакета, а не номер порта.
			Type: "default",
			DefaultOptions: option.DefaultRule{
				RuleAction: option.RuleAction{Action: "sniff"},
			},
		},
		{
			// Перехват: запросы DNS уходят в подсистему разрешения имён
			// ядра, а не в сеть.
			Type: "default",
			DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{
					Protocol: badoption.Listable[string]{"dns"},
				},
				RuleAction: option.RuleAction{Action: "hijack-dns"},
			},
		},
	}
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

	// Реестры протоколов кладутся в контекст: sing-box использует контекст
	// Go как контейнер внедрения зависимостей, а не глобальные синглтоны.
	// Именно поэтому в один процесс можно поместить несколько независимых
	// экземпляров ядра.
	//
	// Параметры обфускации AmneziaWG передаются ядру через контекст.
	//
	// Способ выбран не от хорошей жизни: WireGuard-endpoint в sing-box не
	// имеет поля для наших параметров, а подмена типов сообщений обязана
	// происходить внутри сборки пакета — до вычисления MAC. Форк
	// wireguard-go читает их из контекста тем же приёмом, каким сам
	// wireguard-go читает оттуда остальные зависимости.
	if w := cfg.Profile.WireGuard; w != nil && w.Obfuscation != nil {
		o := w.Obfuscation
		ctx = wgdevice.ContextWithAWGConfig(ctx, &wgdevice.AWGConfig{
			Jc: o.Jc, Jmin: o.Jmin, Jmax: o.Jmax,
			S1: o.S1, S2: o.S2,
			H1: o.H1, H2: o.H2, H3: o.H3, H4: o.H4,
		})
	}

	// SOCKS5 поверх TLS — наш собственный тип аутбаунда: у встроенного SOCKS
	// секции TLS нет. Регистрируется в реестре ДО сборки ядра, иначе ядро о
	// нём не узнает. Подробности — internal/corehost/sockstls.
	outbounds := include.OutboundRegistry()
	sockstls.RegisterOutbound(outbounds)

	ctx = box.Context(ctx,
		include.InboundRegistry(),
		outbounds,
		include.EndpointRegistry(),
		include.DNSTransportRegistry(),
		include.ServiceRegistry(),
	)

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
