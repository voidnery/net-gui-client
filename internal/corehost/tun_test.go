package corehost_test

import (
	"net/netip"
	"testing"

	"github.com/bbesport/net-gui-client/internal/corehost"
	"github.com/bbesport/net-gui-client/internal/orchestration/profile"
	"github.com/bbesport/net-gui-client/internal/orchestration/rules"

	"github.com/sagernet/sing-box/option"
)

func tunTestConfig(mode corehost.Mode) corehost.Config {
	return corehost.Config{
		ListenAddr: netip.MustParseAddr("127.0.0.1"),
		ListenPort: 1080,
		Mode:       mode,
		Policy:     rules.PolicyAllExcept(),
		Profile: profile.Profile{
			ID: "t", Name: "t", Kind: profile.KindSOCKS5,
			Server: "example.org", Port: 1080,
		},
	}
}

// findInbound возвращает входящую точку по тегу.
func findInbound(opts option.Options, tag string) (option.Inbound, bool) {
	for _, in := range opts.Inbounds {
		if in.Tag == tag {
			return in, true
		}
	}
	return option.Inbound{}, false
}

// TestProxyModeHasNoTun: режим по умолчанию не создаёт сетевой адаптер.
//
// Проверка не формальная: создание адаптера требует прав администратора и
// меняет таблицу маршрутизации. Появление его там, где пользователь просил
// обычный прокси, — это изменение системы, о котором он не просил.
func TestProxyModeHasNoTun(t *testing.T) {
	opts, err := corehost.BuildOptions(tunTestConfig(corehost.ModeProxy))
	if err != nil {
		t.Fatalf("сборка конфигурации: %v", err)
	}
	if _, ok := findInbound(opts, "tun"); ok {
		t.Error("в режиме прокси создан сетевой адаптер")
	}
	if opts.Route.AutoDetectInterface {
		t.Error("в режиме прокси включено определение исходящего интерфейса")
	}
}

// TestDefaultModeIsProxy: пустой режим означает прокси.
//
// Весь код, написанный до появления туннеля, оставляет поле пустым. Если бы
// умолчанием стал туннель, обновление молча начало бы менять маршрутизацию
// на машинах пользователей.
func TestDefaultModeIsProxy(t *testing.T) {
	cfg := tunTestConfig(corehost.ModeProxy)
	cfg.Mode = ""

	opts, err := corehost.BuildOptions(cfg)
	if err != nil {
		t.Fatalf("сборка конфигурации: %v", err)
	}
	if _, ok := findInbound(opts, "tun"); ok {
		t.Error("пустой режим создал сетевой адаптер")
	}
}

// TestTunnelModeBuildsAdapter проверяет параметры адаптера.
func TestTunnelModeBuildsAdapter(t *testing.T) {
	opts, err := corehost.BuildOptions(tunTestConfig(corehost.ModeTunnel))
	if err != nil {
		t.Fatalf("сборка конфигурации: %v", err)
	}

	in, ok := findInbound(opts, "tun")
	if !ok {
		t.Fatal("в режиме туннеля адаптер не создан")
	}
	tun, ok := in.Options.(*option.TunInboundOptions)
	if !ok {
		t.Fatalf("параметры адаптера имеют тип %T", in.Options)
	}

	if tun.InterfaceName == "" {
		t.Error("имя адаптера пустое: после аварийного завершения его не найти")
	}
	if !tun.AutoRoute {
		t.Error("маршруты не поднимаются — трафик мимо туннеля")
	}
	if tun.StrictRoute {
		t.Error("StrictRoute включён: защита от утечек — итерация И-8, здесь она усложняет откат")
	}
	// Профиль SOCKS5 не сообщает о способности нести IPv6, поэтому адрес
	// только один — см. TestTunnelDoesNotCaptureIPv6WithoutSupport.
	if len(tun.Address) != 1 {
		t.Errorf("адресов у адаптера %d, ожидался 1 (только IPv4)", len(tun.Address))
	}

	// Локальный прокси обязан остаться: через него сравнивают «через туннель»
	// и «мимо» при разборе неисправностей.
	if _, ok := findInbound(opts, "in"); !ok {
		t.Error("в режиме туннеля пропал локальный прокси")
	}
}

// TestTunnelModeDetectsOutboundInterface закрывает условие, без которого
// туннель не поднимается вовсе.
//
// Соединение с VPN-сервером обязано идти мимо туннеля. Без определения
// исходящего интерфейса пакеты к серверу попадают в маршрут по умолчанию —
// то есть в тот самый туннель, который они должны поднять.
func TestTunnelModeDetectsOutboundInterface(t *testing.T) {
	opts, err := corehost.BuildOptions(tunTestConfig(corehost.ModeTunnel))
	if err != nil {
		t.Fatalf("сборка конфигурации: %v", err)
	}
	if !opts.Route.AutoDetectInterface {
		t.Fatal("определение исходящего интерфейса выключено — получится петля маршрутизации")
	}
}

// TestTunnelMTUFollowsProfile: MTU адаптера не должен превышать MTU туннеля,
// иначе каждый крупный пакет фрагментируется.
func TestTunnelMTUFollowsProfile(t *testing.T) {
	cfg := tunTestConfig(corehost.ModeTunnel)
	cfg.Profile = profile.Profile{
		ID: "wg", Name: "wg", Kind: profile.KindWireGuard,
		Server: "example.org", Port: 51820,
		WireGuard: &profile.WireGuardParams{
			PrivateKey:    "aGVsbG8td29ybGQtZmFrZS1rZXktdmFsdWUtMDAwMDA=",
			PeerPublicKey: "cGVlci1mYWtlLXB1YmxpYy1rZXktdmFsdWUtMDAwMDA=",
			Address:       []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")},
			AllowedIPs:    []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
			MTU:           1420,
		},
	}

	opts, err := corehost.BuildOptions(cfg)
	if err != nil {
		t.Fatalf("сборка конфигурации: %v", err)
	}
	in, _ := findInbound(opts, "tun")
	tun := in.Options.(*option.TunInboundOptions)

	if tun.MTU != 1420 {
		t.Errorf("MTU адаптера %d, ожидалось 1420 (как у профиля)", tun.MTU)
	}
}

// TestUnknownModeRejected: опечатка в режиме обязана давать отказ, а не
// молчаливый переход к прокси.
func TestUnknownModeRejected(t *testing.T) {
	if _, err := corehost.BuildOptions(tunTestConfig("туннель")); err == nil {
		t.Fatal("неизвестный режим принят")
	}
}

// wgProfile собирает профиль WireGuard с заданными адресами туннеля.
func wgProfile(addresses ...string) profile.Profile {
	prefixes := make([]netip.Prefix, 0, len(addresses))
	for _, a := range addresses {
		prefixes = append(prefixes, netip.MustParsePrefix(a))
	}
	return profile.Profile{
		ID: "wg", Name: "wg", Kind: profile.KindWireGuard,
		Server: "example.org", Port: 51820,
		WireGuard: &profile.WireGuardParams{
			PrivateKey:    "aGVsbG8td29ybGQtZmFrZS1rZXktdmFsdWUtMDAwMDA=",
			PeerPublicKey: "cGVlci1mYWtlLXB1YmxpYy1rZXktdmFsdWUtMDAwMDA=",
			Address:       prefixes,
			AllowedIPs:    []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		},
	}
}

func tunOptions(t *testing.T, cfg corehost.Config) *option.TunInboundOptions {
	t.Helper()

	opts, err := corehost.BuildOptions(cfg)
	if err != nil {
		t.Fatalf("сборка конфигурации: %v", err)
	}
	in, ok := findInbound(opts, "tun")
	if !ok {
		t.Fatal("адаптер не создан")
	}
	return in.Options.(*option.TunInboundOptions)
}

// TestTunnelDoesNotCaptureIPv6WithoutSupport закрывает дефект, найденный
// экспериментом E6.
//
// Адрес IPv6 выдавался адаптеру безусловно. На профиле, у которого IPv6 нет,
// система направляла весь трафик IPv6 в туннель — и он проваливался в чёрную
// дыру. Машина оставалась БЕЗ интернета при поднятом туннеле, а журнал
// заполнялся отказами «missing IPv6 local address».
//
// Маршруты выводятся из списка адресов, поэтому отсутствие адреса IPv6 и есть
// отказ от его перехвата.
func TestTunnelDoesNotCaptureIPv6WithoutSupport(t *testing.T) {
	cfg := tunTestConfig(corehost.ModeTunnel)
	cfg.Profile = wgProfile("10.9.0.15/32")

	tun := tunOptions(t, cfg)

	for _, a := range tun.Address {
		if a.Addr().Is6() && !a.Addr().Is4In6() {
			t.Fatalf("адаптеру выдан адрес IPv6 %s, хотя профиль его не несёт", a)
		}
	}
	if len(tun.Address) == 0 {
		t.Fatal("адаптеру не выдано ни одного адреса")
	}
}

// TestTunnelCapturesIPv6WhenProfileHasIt: если профиль умеет IPv6, туннель
// обязан его перехватывать — иначе трафик пойдёт мимо, то есть утечёт.
func TestTunnelCapturesIPv6WhenProfileHasIt(t *testing.T) {
	cfg := tunTestConfig(corehost.ModeTunnel)
	cfg.Profile = wgProfile("10.9.0.15/32", "fd00:1234::2/128")

	tun := tunOptions(t, cfg)

	var has4, has6 bool
	for _, a := range tun.Address {
		if a.Addr().Is4() {
			has4 = true
		}
		if a.Addr().Is6() && !a.Addr().Is4In6() {
			has6 = true
		}
	}
	if !has4 {
		t.Error("нет адреса IPv4")
	}
	if !has6 {
		t.Error("профиль несёт IPv6, но адаптер его не перехватывает — трафик утечёт мимо туннеля")
	}
}

// --- разрешение имён ---------------------------------------------------------

func dnsOf(t *testing.T, cfg corehost.Config) *option.DNSOptions {
	t.Helper()

	opts, err := corehost.BuildOptions(cfg)
	if err != nil {
		t.Fatalf("сборка конфигурации: %v", err)
	}
	if opts.DNS == nil {
		t.Fatal("секция DNS отсутствует: соединения по имени не установятся вовсе")
	}
	return opts.DNS
}

// TestProxyModeKeepsSystemResolver защищает поведение, проверенное с И-1.
//
// В режиме прокси системный резолвер работает и подтверждён живыми прогонами.
// Менять его заодно с исправлением туннеля значило бы чинить то, что не
// сломано.
func TestProxyModeKeepsSystemResolver(t *testing.T) {
	dns := dnsOf(t, tunTestConfig(corehost.ModeProxy))

	if len(dns.Servers) != 1 {
		t.Fatalf("резолверов %d, ожидался 1", len(dns.Servers))
	}
	if dns.Servers[0].Type != "local" {
		t.Errorf("тип резолвера %q, ожидался local", dns.Servers[0].Type)
	}
	if dns.Final != "dns-local" {
		t.Errorf("основной резолвер %q, ожидался dns-local", dns.Final)
	}
}

// TestTunnelModeResolvesThroughTunnel закрывает дефект, найденный E6.
//
// Системный резолвер в режиме туннеля даёт замкнутую петлю: sing-tun
// перехватывает запросы DNS и направляет их в ядро, ядро спрашивает систему,
// запрос системы снова попадает в туннель. В эксперименте имя ifconfig.me
// разрешилось в 127.206.0.124 — адрес из петлевого диапазона.
func TestTunnelModeResolvesThroughTunnel(t *testing.T) {
	cfg := tunTestConfig(corehost.ModeTunnel)
	cfg.Profile = wgProfile("10.9.0.15/32")
	cfg.Profile.WireGuard.DNS = []string{"1.1.1.1", "1.0.0.1"}

	dns := dnsOf(t, cfg)

	if dns.Final == "dns-local" {
		t.Fatal("основным остался системный резолвер — получится петля разрешения имён")
	}

	var remote *option.DNSServerOptions
	for i := range dns.Servers {
		if dns.Servers[i].Tag == dns.Final {
			remote = &dns.Servers[i]
		}
	}
	if remote == nil {
		t.Fatalf("основной резолвер %q не описан среди серверов", dns.Final)
	}
	if remote.Type != "udp" {
		t.Errorf("тип основного резолвера %q, ожидался udp", remote.Type)
	}

	opts, ok := remote.Options.(*option.RemoteDNSServerOptions)
	if !ok {
		t.Fatalf("параметры резолвера имеют тип %T", remote.Options)
	}
	if opts.Server != "1.1.1.1" {
		t.Errorf("адрес резолвера %q, ожидался заданный в профиле", opts.Server)
	}
	// Без detour запрос ушёл бы мимо туннеля — а это утечка: наблюдатель
	// видел бы, какие имена запрашиваются.
	if opts.Detour != "proxy" {
		t.Errorf("запросы DNS идут мимо туннеля (detour = %q)", opts.Detour)
	}
}

// TestTunnelModeFallsBackToDefaultResolver: профиль без своего DNS всё равно
// обязан получить рабочее разрешение имён.
func TestTunnelModeFallsBackToDefaultResolver(t *testing.T) {
	cfg := tunTestConfig(corehost.ModeTunnel) // профиль SOCKS5, DNS не задан

	dns := dnsOf(t, cfg)

	for i := range dns.Servers {
		if dns.Servers[i].Tag != dns.Final {
			continue
		}
		opts := dns.Servers[i].Options.(*option.RemoteDNSServerOptions)
		if opts.Server == "" {
			t.Fatal("резолвер не задан: имена разрешаться не будут")
		}
		return
	}
	t.Fatalf("основной резолвер %q не описан среди серверов", dns.Final)
}

// TestSystemResolverStaysForServerAddress: системный резолвер обязан остаться
// доступным в режиме туннеля.
//
// Через него разрешается адрес самого VPN-сервера, если тот задан именем.
// Разрешать его через туннель невозможно — туннеля ещё нет.
func TestSystemResolverStaysForServerAddress(t *testing.T) {
	cfg := tunTestConfig(corehost.ModeTunnel)
	cfg.Profile = wgProfile("10.9.0.15/32")

	opts, err := corehost.BuildOptions(cfg)
	if err != nil {
		t.Fatalf("сборка конфигурации: %v", err)
	}

	var hasLocal bool
	for _, s := range opts.DNS.Servers {
		if s.Type == "local" {
			hasLocal = true
		}
	}
	if !hasLocal {
		t.Error("системный резолвер убран: адрес сервера, заданный именем, разрешить будет нечем")
	}

	if r := opts.Route.DefaultDomainResolver; r == nil || r.Server != "dns-local" {
		t.Error("аутбаунды разрешают имена не системным резолвером — адрес сервера не разрешится")
	}
}

// TestTunnelHijacksDNS закрывает дефект, найденный E6.
//
// sing-tun прописывает адаптеру фиктивный резолвер — адрес туннеля плюс один.
// Никакого сервера там нет: расчёт на перехват запросов ядром. Перехват
// включается правилом маршрутизации, и без него пакеты уходят в никуда, а
// системный резолвер ждёт до истечения времени ожидания.
//
// В эксперименте это выглядело так: туннель передавал данные (замер через
// локальный прокси ядра выходил на адрес сервера), а системный путь сообщал
// «lookup ifconfig.me: i/o timeout».
func TestTunnelHijacksDNS(t *testing.T) {
	opts, err := corehost.BuildOptions(tunTestConfig(corehost.ModeTunnel))
	if err != nil {
		t.Fatalf("сборка конфигурации: %v", err)
	}

	var sniff, hijack bool
	for _, r := range opts.Route.Rules {
		switch r.DefaultOptions.RuleAction.Action {
		case "sniff":
			sniff = true
		case "hijack-dns":
			hijack = true
			// Перехват обязан быть после определения протокола: «протокол
			// dns» — это результат разбора пакета, а не номер порта.
			if !sniff {
				t.Error("перехват DNS стоит раньше определения протокола — сопоставлять будет нечего")
			}
		}
	}

	if !sniff {
		t.Error("нет правила определения протокола")
	}
	if !hijack {
		t.Fatal("нет правила перехвата DNS — системный резолвер будет ждать ответа от несуществующего сервера")
	}
}

// TestProxyModeHasNoServiceRules: в режиме прокси перехват не нужен и не
// должен появляться.
//
// Там системный резолвер работает напрямую и проверен живыми прогонами с И-1.
// Перехват сломал бы то, что работает.
func TestProxyModeHasNoServiceRules(t *testing.T) {
	opts, err := corehost.BuildOptions(tunTestConfig(corehost.ModeProxy))
	if err != nil {
		t.Fatalf("сборка конфигурации: %v", err)
	}

	for _, r := range opts.Route.Rules {
		switch a := r.DefaultOptions.RuleAction.Action; a {
		case "sniff", "hijack-dns":
			t.Errorf("в режиме прокси появилось служебное правило %q", a)
		}
	}
}

// TestUserRulesComeAfterServiceRules: правила пользователя не должны
// перехватывать запросы DNS раньше служебных.
//
// Иначе правило «всё через туннель» поймает запрос DNS первым, и перехват не
// сработает — то есть дефект вернётся, но уже только при непустой политике.
func TestUserRulesComeAfterServiceRules(t *testing.T) {
	cfg := tunTestConfig(corehost.ModeTunnel)
	cfg.Policy = rules.PolicyOnlySelected(rules.Rule{
		Matcher: rules.Matcher{Domain: []string{"example.org"}},
		Action:  rules.ActionProxy,
	})

	opts, err := corehost.BuildOptions(cfg)
	if err != nil {
		t.Fatalf("сборка конфигурации: %v", err)
	}
	if len(opts.Route.Rules) < 3 {
		t.Fatalf("правил %d, ожидались два служебных и одно пользовательское", len(opts.Route.Rules))
	}

	if got := opts.Route.Rules[0].DefaultOptions.RuleAction.Action; got != "sniff" {
		t.Errorf("первое правило %q, ожидалось sniff", got)
	}
	if got := opts.Route.Rules[1].DefaultOptions.RuleAction.Action; got != "hijack-dns" {
		t.Errorf("второе правило %q, ожидалось hijack-dns", got)
	}
}
