// Command e6-tun-probe — эксперимент E6: что остаётся в системе после
// аварийного завершения с поднятым туннелем.
//
// # Зачем
//
// Итерация И-5 отвечает на один вопрос: умеем ли мы безопасно поднять туннель
// и гарантированно вернуть систему в исходное состояние. Ключевой сценарий
// приёмки — убийство службы через диспетчер задач НЕ оставляет машину без
// интернета.
//
// Писать механику восстановления до того, как измерено, что именно требует
// восстановления, — значит угадывать. Эта проба измеряет.
//
// # Почему состояние снимается через PowerShell
//
// Точный способ — IP Helper API (GetIpForwardTable2). Он требует ручного
// описания раскладки MIB_IPFORWARD_ROW2: около сотни байт из вложенных
// объединений SOCKADDR_INET. Ошибка в раскладке даёт не отказ, а обращение по
// неверному адресу — этот проект уже получал такой отказ на константе WFP
// (см. docs/gui_client_study.md, раздел 6.7).
//
// Для ДИАГНОСТИЧЕСКОГО средства цена ошибки не оправдана: Get-NetRoute и
// Get-NetAdapter возвращают то же самое, а разбор JSON проверяем глазами.
// Если по итогам эксперимента окажется, что производственному коду нужен
// разбор таблицы маршрутов, он будет написан через IP Helper — но уже зная,
// что именно из неё нужно.
//
// ⚠️ Не входит в поставку продукта.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/bbesport/net-gui-client/internal/corehost"
	"github.com/bbesport/net-gui-client/internal/orchestration/profile"
	"github.com/bbesport/net-gui-client/internal/orchestration/rules"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "ОТКАЗ:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return errors.New("не задана команда")
	}

	switch args[0] {
	case "snapshot":
		return cmdSnapshot(args[1:])
	case "compare":
		return cmdCompare(args[1:])
	case "up":
		return cmdUp(args[1:], false)
	case "crash":
		return cmdUp(args[1:], true)
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("неизвестная команда %q", args[0])
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `E6 — что остаётся в системе после падения с поднятым туннелем

  e6-tun-probe snapshot -out before.json
        Снять состояние сети в файл.

  e6-tun-probe up -conf <профиль> [-hold 20s]
        Поднять туннель, подержать, ШТАТНО опустить. Снимки до и после
        сравниваются автоматически.

  e6-tun-probe crash -conf <профиль> [-hold 10s]
        Поднять туннель и АВАРИЙНО завершиться, не закрывая ядро.
        Снимок «до» пишется в файл, указанный через -out.

  e6-tun-probe compare -before before.json
        Сравнить текущее состояние с сохранённым снимком.

⚠️ Требуются права администратора: создание сетевого адаптера и правка
   таблицы маршрутизации непривилегированному процессу недоступны.
`)
}

// --- состояние сети -----------------------------------------------------------

// Snapshot — состояние сети в момент снятия.
type Snapshot struct {
	TakenAt  time.Time `json:"takenAt"`
	Adapters []Adapter `json:"adapters"`
	Routes   []Route   `json:"routes"`

	// Internet — удалось ли достучаться наружу в момент снятия.
	// Главный показатель: остальное — подробности, объясняющие почему.
	Internet bool   `json:"internet"`
	ExitIP   string `json:"exitIp,omitempty"`

	// Reason — на каком шаге всё сломалось, если интернета нет.
	//
	// Различать «имя не разрешается» и «соединение не устанавливается»
	// обязательно: это разные неисправности с разными причинами, а голое
	// «интернета нет» одинаково выглядит в обоих случаях и не даёт зацепки.
	Reason string `json:"reason,omitempty"`
}

// Adapter — сетевой адаптер.
type Adapter struct {
	Name   string `json:"name"`
	Index  int    `json:"index"`
	Status string `json:"status"`
	MTU    int    `json:"mtu"`
}

// Route — маршрут.
type Route struct {
	Destination string `json:"destination"`
	NextHop     string `json:"nextHop"`
	Index       int    `json:"index"`
	Metric      int    `json:"metric"`
}

func (r Route) key() string {
	return fmt.Sprintf("%s → %s (интерфейс %d, метрика %d)",
		r.Destination, r.NextHop, r.Index, r.Metric)
}

func takeSnapshot() (Snapshot, error) {
	s := Snapshot{TakenAt: time.Now()}

	adapters, err := readAdapters()
	if err != nil {
		return Snapshot{}, err
	}
	s.Adapters = adapters

	routes, err := readRoutes()
	if err != nil {
		return Snapshot{}, err
	}
	s.Routes = routes

	s.ExitIP, s.Internet, s.Reason = probeInternet()
	return s, nil
}

// psJSON выполняет команду PowerShell и разбирает её вывод как JSON.
//
// Две тонкости, каждая из которых уже приводила к отказу.
//
// -Depth 3: без явной глубины ConvertTo-Json сворачивает вложенные объекты в
// строку «System.Object[]».
//
// Передача через -InputObject, а не по конвейеру: для единственного элемента
// конвейер выдаёт объект, а не массив из одного объекта, и разбор ломается
// ровно на пограничном случае. Ключ -AsArray, который решает это в PowerShell
// 7, в Windows PowerShell 5.1 отсутствует — а 5.1 и стоит в системе.
func psJSON(script string, out any) error {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	raw, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(ee.Stderr) > 0 {
			return fmt.Errorf("powershell: %s", strings.TrimSpace(string(ee.Stderr)))
		}
		return fmt.Errorf("powershell: %w", err)
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil // пустой результат — не ошибка
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("разбор вывода powershell: %w", err)
	}
	return nil
}

func readAdapters() ([]Adapter, error) {
	var rows []struct {
		Name   string `json:"Name"`
		Index  int    `json:"ifIndex"`
		Status string `json:"Status"`
		MTU    int    `json:"MtuSize"`
	}
	err := psJSON(
		`$i = @(Get-NetAdapter | Select-Object Name,ifIndex,Status,MtuSize); `+
			`ConvertTo-Json -InputObject $i -Depth 3`,
		&rows)
	if err != nil {
		return nil, err
	}

	out := make([]Adapter, 0, len(rows))
	for _, r := range rows {
		out = append(out, Adapter{Name: r.Name, Index: r.Index, Status: r.Status, MTU: r.MTU})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	return out, nil
}

func readRoutes() ([]Route, error) {
	var rows []struct {
		Destination string `json:"DestinationPrefix"`
		NextHop     string `json:"NextHop"`
		Index       int    `json:"ifIndex"`
		Metric      int    `json:"RouteMetric"`
	}
	err := psJSON(
		`$i = @(Get-NetRoute | Select-Object DestinationPrefix,NextHop,ifIndex,RouteMetric); `+
			`ConvertTo-Json -InputObject $i -Depth 3`,
		&rows)
	if err != nil {
		return nil, err
	}

	out := make([]Route, 0, len(rows))
	for _, r := range rows {
		out = append(out, Route{
			Destination: r.Destination, NextHop: r.NextHop,
			Index: r.Index, Metric: r.Metric,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key() < out[j].key() })
	return out, nil
}

// probeInternet проверяет связь с внешним миром В ОБХОД прокси.
//
// Переменные окружения HTTP_PROXY игнорируются намеренно: на машине
// разработки вполне может стоять посторонний прокси, и тогда проба измеряла
// бы его доступность, а не работоспособность сети.
//
// Проверка идёт по шагам, и это главное в ней. Первый прогон E6 сообщил
// «интернета нет» — и этого оказалось недостаточно, чтобы понять, сломано
// разрешение имён или передача пакетов. Теперь ответ содержит шаг, на котором
// всё остановилось.
//
// Разрешение имени запрашивается ТОЛЬКО для IPv4 (ip4): проба измеряет
// работоспособность туннеля, а не готовность сети к IPv6. Запрос AAAA в сети
// без IPv6 добавляет секунды ожидания и шум, не относящийся к делу.
func probeInternet() (exitIP string, ok bool, reason string) {
	const host = "ifconfig.me"

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil {
		return "", false, fmt.Sprintf("имя %s не разрешается (DNS): %v", host, err)
	}
	if len(addrs) == 0 {
		return "", false, fmt.Sprintf("имя %s не разрешается: пустой ответ", host)
	}

	if note := suspiciousAddress(addrs[0]); note != "" {
		return "", false, fmt.Sprintf("имя %s разрешилось в %s — %s", host, addrs[0], note)
	}

	target := net.JoinHostPort(addrs[0].String(), "80")
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", target)
	if err != nil {
		return "", false, fmt.Sprintf("имя разрешилось в %s, но соединение не устанавливается: %v",
			addrs[0], err)
	}
	_ = conn.Close()

	client := &http.Client{
		Timeout:   8 * time.Second,
		Transport: &http.Transport{Proxy: nil},
	}
	resp, err := client.Get("http://" + host + "/ip")
	if err != nil {
		return "", false, fmt.Sprintf("соединение есть, но ответа HTTP нет: %v", err)
	}
	defer resp.Body.Close()

	buf := make([]byte, 64)
	n, _ := resp.Body.Read(buf)
	return strings.TrimSpace(string(buf[:n])), true, ""
}

// probeViaProxy проверяет связь ЧЕРЕЗ локальный прокси ядра.
//
// Второй, независимый замер. Он отличается от прямого ровно двумя вещами:
// имя разрешает само ядро (а не система), и маршрут выбирает тоже ядро (а не
// таблица маршрутизации Windows).
//
// Смысл в различении. Если через прокси связь есть, а напрямую нет — туннель
// исправен, сломан системный путь: перехват DNS, порядок маршрутов, чужой
// клиент. Если нет в обоих — не работает сам туннель. Без этого различения
// «интернета нет» одинаково выглядит в двух совершенно разных случаях, и
// первый прогон E6 именно на этом и застрял.
func probeViaProxy(port uint16) (exitIP string, ok bool, reason string) {
	proxyURL, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	if err != nil {
		return "", false, err.Error()
	}

	client := &http.Client{
		Timeout:   12 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}

	// Имя передаётся прокси НЕразрешённым: разрешать его должно ядро.
	resp, err := client.Get("http://ifconfig.me/ip")
	if err != nil {
		return "", false, err.Error()
	}
	defer resp.Body.Close()

	buf := make([]byte, 64)
	n, _ := resp.Body.Read(buf)
	return strings.TrimSpace(string(buf[:n])), true, ""
}

// --- сравнение ----------------------------------------------------------------

func compare(before, after Snapshot) {
	fmt.Println()
	fmt.Println("=== СРАВНЕНИЕ СОСТОЯНИЙ ===")
	fmt.Printf("до:    %s\n", before.TakenAt.Format("15:04:05"))
	fmt.Printf("после: %s\n", after.TakenAt.Format("15:04:05"))
	fmt.Println()

	// Главное — интернет. Всё остальное объясняет, почему он есть или нет.
	fmt.Printf("интернет до:    %s\n", yesNo(before.Internet, before.ExitIP))
	if before.Reason != "" {
		fmt.Printf("                причина: %s\n", before.Reason)
	}
	fmt.Printf("интернет после: %s\n", yesNo(after.Internet, after.ExitIP))
	if after.Reason != "" {
		fmt.Printf("                причина: %s\n", after.Reason)
	}
	fmt.Println()

	reportAdapters(before, after)
	reportRoutes(before, after)

	fmt.Println()
	switch {
	case !after.Internet && before.Internet:
		fmt.Println("❌ ОТРИЦАТЕЛЬНЫЙ: интернет был и пропал. Система НЕ восстановлена.")
	case len(diffAdapters(before, after)) > 0 || len(diffRoutes(before, after)) > 0:
		fmt.Println("⚠️  ЧАСТИЧНЫЙ: интернет работает, но в системе остались следы (см. выше).")
	default:
		fmt.Println("✅ ПОЛОЖИТЕЛЬНЫЙ: состояние сети совпадает с исходным.")
	}
}

func yesNo(ok bool, ip string) string {
	if ok {
		return "есть (" + ip + ")"
	}
	return "НЕТ"
}

func diffAdapters(before, after Snapshot) []Adapter {
	known := make(map[string]bool, len(before.Adapters))
	for _, a := range before.Adapters {
		known[a.Name] = true
	}
	var extra []Adapter
	for _, a := range after.Adapters {
		if !known[a.Name] {
			extra = append(extra, a)
		}
	}
	return extra
}

func diffRoutes(before, after Snapshot) []Route {
	known := make(map[string]bool, len(before.Routes))
	for _, r := range before.Routes {
		known[r.key()] = true
	}
	var extra []Route
	for _, r := range after.Routes {
		if !known[r.key()] {
			extra = append(extra, r)
		}
	}
	return extra
}

func reportAdapters(before, after Snapshot) {
	extra := diffAdapters(before, after)
	missing := diffAdapters(after, before)

	fmt.Printf("адаптеров: было %d, стало %d\n", len(before.Adapters), len(after.Adapters))
	for _, a := range extra {
		fmt.Printf("  + ЛИШНИЙ: %s (интерфейс %d, %s, MTU %d)\n", a.Name, a.Index, a.Status, a.MTU)
	}
	for _, a := range missing {
		fmt.Printf("  − ПРОПАЛ:  %s (интерфейс %d)\n", a.Name, a.Index)
	}
}

func reportRoutes(before, after Snapshot) {
	extra := diffRoutes(before, after)
	missing := diffRoutes(after, before)

	fmt.Printf("маршрутов: было %d, стало %d\n", len(before.Routes), len(after.Routes))
	for _, r := range extra {
		fmt.Printf("  + ЛИШНИЙ: %s\n", r.key())
	}
	for _, r := range missing {
		fmt.Printf("  − ПРОПАЛ:  %s\n", r.key())
	}
}

// --- команды ------------------------------------------------------------------

func cmdSnapshot(args []string) error {
	fs := flag.NewFlagSet("snapshot", flag.ContinueOnError)
	out := fs.String("out", "", "файл для записи снимка")
	if err := fs.Parse(args); err != nil {
		return err
	}

	s, err := takeSnapshot()
	if err != nil {
		return err
	}
	fmt.Printf("адаптеров: %d, маршрутов: %d, интернет: %s\n",
		len(s.Adapters), len(s.Routes), yesNo(s.Internet, s.ExitIP))
	if s.Reason != "" {
		fmt.Printf("причина: %s\n", s.Reason)
	}

	if *out == "" {
		return nil
	}
	return writeSnapshot(*out, s)
}

func cmdCompare(args []string) error {
	fs := flag.NewFlagSet("compare", flag.ContinueOnError)
	before := fs.String("before", "", "файл со снимком «до»")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *before == "" {
		return errors.New("нужен -before")
	}

	prev, err := readSnapshot(*before)
	if err != nil {
		return err
	}
	now, err := takeSnapshot()
	if err != nil {
		return err
	}
	compare(prev, now)
	return nil
}

func cmdUp(args []string, crash bool) error {
	fs := flag.NewFlagSet("up", flag.ContinueOnError)
	conf := fs.String("conf", "", "файл профиля")
	out := fs.String("out", "e6-before.json", "файл для снимка «до»")
	hold := fs.Duration("hold", 20*time.Second, "сколько держать туннель")
	// Режим переключается ради проверки самой пробы: двойной замер можно
	// прогнать в режиме прокси, где права администратора не нужны. Для
	// эксперимента используется значение по умолчанию.
	mode := fs.String("mode", string(corehost.ModeTunnel), "режим: tunnel | proxy")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *conf == "" {
		return errors.New("нужен -conf")
	}

	p, err := loadProfile(*conf)
	if err != nil {
		return err
	}

	fmt.Println("[1] Снимок состояния ДО ...")
	before, err := takeSnapshot()
	if err != nil {
		return err
	}
	fmt.Printf("    адаптеров %d, маршрутов %d, интернет %s\n",
		len(before.Adapters), len(before.Routes), yesNo(before.Internet, before.ExitIP))

	if err := writeSnapshot(*out, before); err != nil {
		return err
	}
	fmt.Printf("    снимок сохранён: %s\n", *out)

	port, err := freePort()
	if err != nil {
		return err
	}

	fmt.Printf("[2] Поднимаю ядро в режиме %s ...\n", *mode)
	core, err := corehost.Start(context.Background(), corehost.Config{
		ListenAddr: netip.MustParseAddr("127.0.0.1"),
		ListenPort: port,
		Mode:       corehost.Mode(*mode),
		Profile:    p,
		Policy:     rules.PolicyAllExcept(),
		LogLevel:   logLevel(),
	})
	if err != nil {
		return fmt.Errorf("запуск ядра: %w", err)
	}

	fmt.Printf("[3] Туннель поднят, держу %s ...\n", *hold)
	time.Sleep(*hold)

	during, err := takeSnapshot()
	if err != nil {
		_ = core.Close()
		return err
	}
	fmt.Printf("    во время работы: адаптеров %d, маршрутов %d\n",
		len(during.Adapters), len(during.Routes))
	fmt.Printf("    [а] напрямую (системный путь):    %s\n",
		yesNo(during.Internet, during.ExitIP))
	if during.Reason != "" {
		fmt.Printf("        причина: %s\n", during.Reason)
	}

	proxyIP, proxyOK, proxyReason := probeViaProxy(port)
	fmt.Printf("    [б] через локальный прокси ядра: %s\n", yesNo(proxyOK, proxyIP))
	if proxyReason != "" {
		fmt.Printf("        причина: %s\n", proxyReason)
	}

	fmt.Println()
	switch {
	case proxyOK && !during.Internet:
		fmt.Println("    ⇒ ТУННЕЛЬ ИСПРАВЕН. Сломан системный путь: перехват DNS,")
		fmt.Println("      порядок маршрутов или посторонний сетевой клиент.")
	case proxyOK && during.Internet:
		fmt.Println("    ⇒ Оба пути работают.")
	case !proxyOK && !during.Internet:
		fmt.Println("    ⇒ НЕ РАБОТАЕТ САМ ТУННЕЛЬ: связи нет ни одним путём.")
	default:
		fmt.Println("    ⇒ Напрямую работает, через прокси — нет. Неисправность в ядре.")
	}
	fmt.Println()
	for _, a := range diffAdapters(before, during) {
		fmt.Printf("    + появился адаптер %s (интерфейс %d)\n", a.Name, a.Index)
	}
	fmt.Printf("    + появилось маршрутов: %d\n", len(diffRoutes(before, during)))

	if crash {
		fmt.Println()
		fmt.Println("[4] АВАРИЙНОЕ ЗАВЕРШЕНИЕ: ядро не закрывается.")
		fmt.Println("    Это имитация убийства службы через диспетчер задач.")
		fmt.Println()
		fmt.Printf("    Дальше выполните:  e6-tun-probe compare -before %s\n", *out)
		os.Stdout.Sync()

		// os.Exit не выполняет отложенные вызовы и не даёт ядру закрыться —
		// ровно то, что происходит при TerminateProcess.
		os.Exit(3)
	}

	fmt.Println("[4] Штатное закрытие ядра ...")
	if err := core.Close(); err != nil {
		return fmt.Errorf("остановка ядра: %w", err)
	}

	// Снятие адаптера и маршрутов не мгновенно: драйвер убирает их
	// асинхронно. Пауза не «на всякий случай», а потому что без неё проба
	// измеряла бы промежуточное состояние.
	time.Sleep(3 * time.Second)

	after, err := takeSnapshot()
	if err != nil {
		return err
	}
	compare(before, after)
	return nil
}

// --- вспомогательное ----------------------------------------------------------

func loadProfile(path string) (profile.Profile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return profile.Profile{}, fmt.Errorf("чтение %s: %w", path, err)
	}
	p, err := profile.Import("e6", "", string(raw))
	if err != nil {
		return profile.Profile{}, err
	}
	fmt.Printf("профиль: %s, сервер %s:%d\n", p.Kind, p.Server, p.Port)
	return p, nil
}

func writeSnapshot(path string, s Snapshot) error {
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o600)
}

func readSnapshot(path string) (Snapshot, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Snapshot{}, fmt.Errorf("чтение %s: %w", path, err)
	}
	var s Snapshot
	if err := json.Unmarshal(raw, &s); err != nil {
		return Snapshot{}, fmt.Errorf("разбор %s: %w", path, err)
	}
	return s, nil
}

func freePort() (uint16, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return uint16(ln.Addr().(*net.TCPAddr).Port), nil
}

func logLevel() string {
	if v := os.Getenv("NETGUI_CORE_LOG"); v != "" {
		return v
	}
	return "warn"
}

// suspiciousAddress распознаёт адреса, которые не могут быть настоящим
// адресом узла в интернете.
//
// Появился по итогам E6. Проба сообщала «соединение не устанавливается» для
// адреса 127.206.0.124 — и это уводило в сторону: искали неисправность в
// туннеле, тогда как имя вообще не разрешалось по-настоящему. Подставные
// адреса раздают инструменты, перехватывающие разрешение имён: Proxifier
// отдаёт приложению адрес из петлевого диапазона, клиенты на базе sing-box —
// из 198.18.0.0/15 (режим fake-IP).
//
// Отличить это от собственной неисправности важно: причина находится вне
// нашего кода, и чинить у себя нечего.
func suspiciousAddress(a netip.Addr) string {
	switch {
	case a.IsLoopback():
		return "это петлевой адрес. Так поступают инструменты, перехватывающие " +
			"разрешение имён (например Proxifier). Остановите их и повторите"
	case fakeIPRange.Contains(a):
		return "это адрес из диапазона fake-IP (198.18.0.0/15). Его раздают " +
			"клиенты на базе sing-box. Остановите их и повторите"
	case a.IsUnspecified():
		return "это неопределённый адрес: разрешение имён не работает"
	default:
		return ""
	}
}

// fakeIPRange — диапазон, применяемый в режиме fake-IP.
var fakeIPRange = netip.MustParsePrefix("198.18.0.0/15")
