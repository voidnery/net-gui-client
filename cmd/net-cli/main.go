// Command net-cli — клиент управления службой net-svc.
//
// Принцип P1 (ADR-004): CLI покрывает 100% функций графического интерфейса и
// является эталонным потребителем контракта. Он же — инструмент
// интеграционного тестирования и основа будущей Linux server edition.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/bbesport/net-gui-client/internal/client"
	"github.com/bbesport/net-gui-client/internal/ipc"
	pb "github.com/bbesport/net-gui-client/proto/netgui/v1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Version подставляется линкером при релизной сборке.
var Version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		if hint := explain(err); hint != "" {
			fmt.Fprintln(os.Stderr, "\n"+hint)
		}
		os.Exit(1)
	}
}

// explain переводит технические ошибки транспорта в понятную подсказку.
//
// Без этого пользователь, чей запрос отклонила проверка доверия (мера S2),
// видит только «error reading server preface: EOF» — сообщение, по которому
// невозможно догадаться ни о причине, ни о том, что делать дальше.
func explain(err error) string {
	msg := err.Error()

	switch {
	case strings.Contains(msg, "The system cannot find the file specified"),
		strings.Contains(msg, "cannot find the file"):
		return "Похоже, служба net-svc не запущена.\n" +
			"  Проверьте состояние:   net-svc status\n" +
			"  Запустите:             net-svc start   (нужны права администратора)"

	case strings.Contains(msg, "server preface"),
		strings.Contains(msg, "connection reset"):
		return "Служба разорвала соединение сразу после подключения.\n" +
			"  Наиболее вероятная причина — проверка доверия к клиенту (мера S2):\n" +
			"  net-cli должен запускаться из того же каталога, что и net-svc.\n" +
			"  Точная причина записана в журнал службы."

	case strings.Contains(msg, "Access is denied"),
		strings.Contains(msg, "Отказано в доступе"):
		return "Нет прав на подключение к каналу управления.\n" +
			"  Канал доступен только интерактивным пользователям этого компьютера."
	}
	return ""
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return nil
	}

	switch args[0] {
	case "version":
		fmt.Printf("net-cli %s\n", Version)
		return nil
	case "help", "-h", "--help":
		usage()
		return nil
	case "hello":
		return withClient(cmdHello)
	case "status":
		return withClient(cmdStatus)
	case "watch":
		return withClient(cmdWatch)
	case "connect":
		return withClient(func(ctx context.Context, c *conn) error { return cmdConnect(ctx, c, args[1:]) })
	case "disconnect":
		return withClient(cmdDisconnect)
	case "profile":
		return withClient(func(ctx context.Context, c *conn) error { return cmdProfile(ctx, c, args[1:]) })
	default:
		return fmt.Errorf("неизвестная команда %q (попробуйте 'net-cli help')", args[0])
	}
}

func usage() {
	fmt.Println(`net-cli — управление службой net-svc

Использование:
  net-cli <команда> [аргументы]

Команды:
  hello                     проверить связь со службой и совместимость версий
  status                    показать состояние сессии
  watch                     следить за событиями (Ctrl+C для выхода)
  connect <id> [флаги]      подключиться по профилю
  disconnect                отключиться
  profile list              список профилей
  profile add [флаги]       добавить или заменить профиль
  profile rm <id>           удалить профиль
  version                   версия клиента
  help                      эта справка

Флаги connect:
  -policy all-except|only-selected   политика маршрутизации (по умолчанию all-except)
  -direct <список>                   домены/подсети, идущие напрямую
  -proxy  <список>                   домены/подсети, идущие через туннель
  -port   <порт>                     порт локального inbound (0 — автоматически)

Флаги profile add:
  -id, -name, -server, -port, -user, -pass

Примеры:
  net-cli profile add -id home -name "Домашний" -server 10.0.0.1 -port 1080
  net-cli connect home -policy only-selected -proxy example.com,10.20.0.0/16
  net-cli connect home -policy all-except -direct bank.ru`)
}

// --- соединение --------------------------------------------------------------

type conn struct {
	control  pb.ControlServiceClient
	profiles pb.ProfileServiceClient
	sessions pb.SessionServiceClient
	events   pb.EventServiceClient
}

func withClient(fn func(context.Context, *conn) error) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Транспорт — именованный канал, поэтому адрес фиктивный: настоящий
	// путь зашит в диалере. insecure.NewCredentials здесь корректно:
	// шифровать локальный канал незачем, защита обеспечивается его ACL
	// (мера S1, см. internal/ipc).
	cc, err := grpc.NewClient("passthrough:///net-svc",
		grpc.WithContextDialer(ipc.DialContext),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return fmt.Errorf("подключение к службе: %w", err)
	}
	defer cc.Close()

	return fn(ctx, &conn{
		control:  pb.NewControlServiceClient(cc),
		profiles: pb.NewProfileServiceClient(cc),
		sessions: pb.NewSessionServiceClient(cc),
		events:   pb.NewEventServiceClient(cc),
	})
}

// --- команды -----------------------------------------------------------------

func cmdHello(ctx context.Context, c *conn) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	resp, err := c.control.Hello(ctx, &pb.HelloRequest{
		ClientName: "net-cli", ClientVersion: Version,
	})
	if err != nil {
		return fmt.Errorf("служба не отвечает: %w", err)
	}

	fmt.Printf("служба:        %s\n", resp.GetServerVersion())
	fmt.Printf("версия API:    %d\n", resp.GetApiVersion())
	if resp.GetApiVersion() != ipc.APIVersion {
		fmt.Printf("⚠️  клиент собран под версию API %d — обновите ту сторону, что старее\n",
			ipc.APIVersion)
	}
	return nil
}

func cmdStatus(ctx context.Context, c *conn) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	st, err := c.sessions.GetStatus(ctx, &pb.GetStatusRequest{})
	if err != nil {
		return err
	}
	printStatus(st)
	return nil
}

func cmdWatch(ctx context.Context, c *conn) error {
	stream, err := c.events.Subscribe(ctx, &pb.SubscribeRequest{})
	if err != nil {
		return err
	}
	fmt.Println("слежу за событиями, Ctrl+C для выхода")
	for {
		ev, err := stream.Recv()
		if err != nil {
			return err
		}
		if s := ev.GetStatusChanged(); s != nil {
			fmt.Printf("[%s] состояние: %s\n",
				time.Unix(0, ev.GetUnixNano()).Format("15:04:05"), stateName(s.GetState()))
		}
	}
}

func cmdConnect(ctx context.Context, c *conn, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("не указан идентификатор профиля")
	}
	id := args[0]

	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	policyName := fs.String("policy", "all-except", "all-except | only-selected")
	directList := fs.String("direct", "", "домены и подсети, идущие напрямую")
	proxyList := fs.String("proxy", "", "домены и подсети, идущие через туннель")
	port := fs.Uint("port", 0, "порт локального inbound")
	modeName := fs.String("mode", "proxy", "proxy | tunnel")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	policy, err := buildPolicy(*policyName, *directList, *proxyList)
	if err != nil {
		return err
	}

	mode, err := parseMode(*modeName)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	st, err := c.sessions.Connect(ctx, &pb.ConnectRequest{
		ProfileId: id, Policy: policy, ListenPort: uint32(*port), Mode: mode,
	})
	if err != nil {
		return err
	}
	printStatus(st)

	if st.GetState() != pb.SessionState_SESSION_STATE_CONNECTED {
		return nil
	}
	if st.GetMode() == pb.Mode_MODE_TUNNEL {
		// В режиме туннеля направлять приложения никуда не нужно: трафик
		// системы уже идёт через туннель. Прежняя подсказка в этом режиме
		// вводила бы в заблуждение.
		fmt.Printf("\nВесь трафик системы идёт через туннель.\n")
		return nil
	}
	fmt.Printf("\nНаправьте приложения на HTTP или SOCKS5 прокси %s\n", st.GetListenAddress())
	return nil
}

func cmdDisconnect(ctx context.Context, c *conn) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	st, err := c.sessions.Disconnect(ctx, &pb.DisconnectRequest{})
	if err != nil {
		return err
	}
	printStatus(st)
	return nil
}

func cmdProfile(ctx context.Context, c *conn, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("нужна подкоманда: list | add | import | rm")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	switch args[0] {
	case "list":
		resp, err := c.profiles.List(ctx, &pb.ListProfilesRequest{})
		if err != nil {
			return err
		}
		if len(resp.GetProfiles()) == 0 {
			fmt.Println("профилей нет")
			return nil
		}
		fmt.Printf("%-16s %-24s %-10s %-24s %s\n", "ID", "ИМЯ", "ТИП", "АДРЕС", "СЕКРЕТ")
		for _, p := range resp.GetProfiles() {
			// Служба не возвращает секретов (мера S6), поэтому показываем
			// только факт их наличия.
			secret := "—"
			if p.GetHasSecrets() {
				secret = "задан"
			}
			addr := fmt.Sprintf("%s:%d", p.GetServer(), p.GetPort())
			fmt.Printf("%-16s %-24s %-10s %-24s %s\n",
				p.GetId(), p.GetName(), kindName(p.GetKind()), addr, secret)
		}
		return nil

	case "import":
		fs := flag.NewFlagSet("profile import", flag.ContinueOnError)
		id := fs.String("id", "", "идентификатор")
		name := fs.String("name", "", "отображаемое имя (пусто — взять из ссылки)")
		file := fs.String("file", "", "файл конфигурации")
		link := fs.String("link", "", "ссылка vless:// | hysteria2:// | socks5://")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *id == "" {
			return fmt.Errorf("нужен -id")
		}
		if (*file == "") == (*link == "") {
			return fmt.Errorf("укажите ровно одно: -file или -link")
		}

		content := *link
		if *file != "" {
			raw, err := os.ReadFile(*file)
			if err != nil {
				return fmt.Errorf("чтение %s: %w", *file, err)
			}
			content = string(raw)
		}

		// Содержимое уходит в службу неразобранным: разбор — недоверенный
		// ввод, и по принципу P1 он выполняется на стороне службы.
		resp, err := c.profiles.Import(ctx, &pb.ImportProfileRequest{
			Id: *id, Name: *name, Content: content,
		})
		if err != nil {
			return err
		}
		p := resp.GetProfile()
		fmt.Printf("импортирован профиль %q: %s, %s:%d\n",
			p.GetId(), kindName(p.GetKind()), p.GetServer(), p.GetPort())
		return nil

	case "add":
		fs := flag.NewFlagSet("profile add", flag.ContinueOnError)
		id := fs.String("id", "", "идентификатор")
		name := fs.String("name", "", "отображаемое имя")
		server := fs.String("server", "", "адрес сервера")
		port := fs.Uint("port", 0, "порт сервера")
		user := fs.String("user", "", "имя пользователя")
		pass := fs.String("pass", "", "пароль")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *name == "" {
			*name = *id
		}
		resp, err := c.profiles.Put(ctx, &pb.PutProfileRequest{Profile: &pb.Profile{
			Id: *id, Name: *name, Kind: pb.Kind_KIND_SOCKS5,
			Server: *server, Port: uint32(*port), Username: *user, Password: *pass,
		}})
		if err != nil {
			return err
		}
		fmt.Printf("сохранён профиль %q\n", resp.GetProfile().GetId())
		return nil

	case "rm":
		if len(args) < 2 {
			return fmt.Errorf("не указан идентификатор профиля")
		}
		if _, err := c.profiles.Remove(ctx, &pb.RemoveProfileRequest{Id: args[1]}); err != nil {
			return err
		}
		fmt.Printf("удалён профиль %q\n", args[1])
		return nil

	default:
		return fmt.Errorf("неизвестная подкоманда %q", args[0])
	}
}

// --- вспомогательное ---------------------------------------------------------

// buildPolicy собирает политику из флагов командной строки.
//
// Списки разбираются одинаково: элемент, похожий на подсеть (содержит "/"),
// попадает в ip_cidr, остальное — в domain_suffix. Суффикс, а не точное
// совпадение: пользователь, написавший "example.com", почти наверняка имеет
// в виду и поддомены.
func buildPolicy(name, directList, proxyList string) (*pb.Policy, error) {
	var def pb.Action
	switch name {
	case "all-except":
		def = pb.Action_ACTION_PROXY
	case "only-selected":
		def = pb.Action_ACTION_DIRECT
	default:
		return nil, fmt.Errorf("неизвестная политика %q (all-except | only-selected)", name)
	}

	policy := &pb.Policy{DefaultAction: def}
	if r := parseList(proxyList, pb.Action_ACTION_PROXY); r != nil {
		policy.Rules = append(policy.Rules, r)
	}
	if r := parseList(directList, pb.Action_ACTION_DIRECT); r != nil {
		policy.Rules = append(policy.Rules, r)
	}
	return policy, nil
}

func parseList(list string, action pb.Action) *pb.Rule {
	m := &pb.Matcher{}
	for _, item := range strings.Split(list, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if strings.Contains(item, "/") {
			m.IpCidr = append(m.IpCidr, item)
		} else {
			m.DomainSuffix = append(m.DomainSuffix, item)
		}
	}
	if len(m.IpCidr) == 0 && len(m.DomainSuffix) == 0 {
		return nil
	}
	return &pb.Rule{Matcher: m, Action: action}
}

func printStatus(st *pb.Status) {
	fmt.Printf("состояние:  %s\n", stateName(st.GetState()))
	if st.GetProfileId() != "" {
		fmt.Printf("профиль:    %s\n", st.GetProfileId())
	}
	if st.GetListenAddress() != "" {
		fmt.Printf("слушает:    %s\n", st.GetListenAddress())
	}
	// Режим показывается всегда, когда сессия есть: «подключено» означает
	// разное в режиме прокси и в режиме туннеля.
	if st.GetState() != pb.SessionState_SESSION_STATE_IDLE {
		fmt.Printf("режим:      %s\n", modeName(st.GetMode()))
	}
	if p := st.GetPolicy(); p != nil && p.GetDefaultAction() != pb.Action_ACTION_UNSPECIFIED {
		fmt.Printf("политика:   по умолчанию %s, правил %d\n",
			actionName(p.GetDefaultAction()), len(p.GetRules()))
	}
	if st.GetError() != "" {
		fmt.Printf("ошибка:     %s\n", st.GetError())
	}
}

func stateName(s pb.SessionState) string {
	switch s {
	case pb.SessionState_SESSION_STATE_CONNECTING:
		return "подключение"
	case pb.SessionState_SESSION_STATE_CONNECTED:
		return "подключено"
	case pb.SessionState_SESSION_STATE_IDLE:
		return "отключено"
	default:
		return "неизвестно"
	}
}

func actionName(a pb.Action) string {
	switch a {
	case pb.Action_ACTION_PROXY:
		return "через туннель"
	case pb.Action_ACTION_DIRECT:
		return "напрямую"
	case pb.Action_ACTION_BLOCK:
		return "блокировать"
	default:
		return "не задано"
	}
}

// kindName — тонкая обёртка над общим отображением.
//
// Своей таблицы здесь нет намеренно: три копии одного соответствия уже
// разошлись однажды, см. client.KindName.
func kindName(k pb.Kind) string { return client.KindName(k) }

// parseMode разбирает режим из командной строки.
//
// Опечатка обязана давать отказ, а не молчаливый переход к прокси: разница
// между режимами — это разница между «через туннель идёт выбранное
// приложение» и «через туннель идёт всё».
func parseMode(s string) (pb.Mode, error) {
	switch s {
	case "", "proxy":
		return pb.Mode_MODE_PROXY, nil
	case "tunnel":
		return pb.Mode_MODE_TUNNEL, nil
	default:
		return pb.Mode_MODE_UNSPECIFIED, fmt.Errorf("неизвестный режим %q: proxy | tunnel", s)
	}
}

// modeName — подпись режима для человека.
func modeName(m pb.Mode) string {
	switch m {
	case pb.Mode_MODE_TUNNEL:
		return "туннель (весь трафик системы)"
	case pb.Mode_MODE_PROXY:
		return "прокси (только направленные приложения)"
	default:
		return "?"
	}
}
