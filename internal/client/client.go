// Package client — клиент канала управления службой.
//
// Общий для net-cli и net-gui. Вынесен в отдельный пакет по тому же
// соображению, что и winservice: два клиента, написанных независимо,
// неизбежно разойдутся в трактовке контракта, и расхождение проявится
// как «в CLI работает, а в интерфейсе нет».
//
// Принцип P1 (ADR-004): графический интерфейс не имеет привилегированного
// доступа к службе. Он такой же потребитель контракта, как CLI.
package client

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bbesport/net-gui-client/internal/ipc"
	pb "github.com/bbesport/net-gui-client/proto/netgui/v1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Client — подключение к службе.
type Client struct {
	conn     *grpc.ClientConn
	control  pb.ControlServiceClient
	profiles pb.ProfileServiceClient
	sessions pb.SessionServiceClient
	events   pb.EventServiceClient
}

// Dial открывает соединение с каналом управления.
//
// Соединение ленивое: gRPC не подключается, пока не сделан первый вызов.
// Поэтому Dial сам по себе не сообщает, запущена ли служба — для этого
// служит Hello.
func Dial() (*Client, error) {
	// Адрес фиктивный: реальный путь именованного канала зашит в диалере.
	// insecure.NewCredentials корректно для локального канала — шифровать
	// нечего, защиту обеспечивают ACL канала (мера S1) и проверка клиента
	// (мера S2), см. internal/ipc.
	conn, err := grpc.NewClient("passthrough:///net-svc",
		grpc.WithContextDialer(ipc.DialContext),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("client: подключение к службе: %w", err)
	}

	return &Client{
		conn:     conn,
		control:  pb.NewControlServiceClient(conn),
		profiles: pb.NewProfileServiceClient(conn),
		sessions: pb.NewSessionServiceClient(conn),
		events:   pb.NewEventServiceClient(conn),
	}, nil
}

// Close закрывает соединение.
func (c *Client) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

// --- ControlService ----------------------------------------------------------

// ServerInfo — сведения о службе, полученные при рукопожатии.
type ServerInfo struct {
	Version    string
	APIVersion uint32
	// Compatible сообщает, совпадает ли версия контракта.
	Compatible bool
}

// Hello проверяет связь со службой и совместимость версий контракта.
func (c *Client) Hello(ctx context.Context, clientName, clientVersion string) (ServerInfo, error) {
	ctx, cancel := withTimeout(ctx, 5*time.Second)
	defer cancel()

	resp, err := c.control.Hello(ctx, &pb.HelloRequest{
		ClientName: clientName, ClientVersion: clientVersion,
	})
	if err != nil {
		return ServerInfo{}, err
	}
	return ServerInfo{
		Version:    resp.GetServerVersion(),
		APIVersion: resp.GetApiVersion(),
		Compatible: resp.GetApiVersion() == ipc.APIVersion,
	}, nil
}

// --- ProfileService ----------------------------------------------------------

// ListProfiles возвращает сохранённые профили.
func (c *Client) ListProfiles(ctx context.Context) ([]*pb.Profile, error) {
	ctx, cancel := withTimeout(ctx, 10*time.Second)
	defer cancel()

	resp, err := c.profiles.List(ctx, &pb.ListProfilesRequest{})
	if err != nil {
		return nil, err
	}
	return resp.GetProfiles(), nil
}

// PutProfile создаёт или заменяет профиль.
func (c *Client) PutProfile(ctx context.Context, p *pb.Profile) (*pb.Profile, error) {
	ctx, cancel := withTimeout(ctx, 10*time.Second)
	defer cancel()

	resp, err := c.profiles.Put(ctx, &pb.PutProfileRequest{Profile: p})
	if err != nil {
		return nil, err
	}
	return resp.GetProfile(), nil
}

// RemoveProfile удаляет профиль.
func (c *Client) RemoveProfile(ctx context.Context, id string) error {
	ctx, cancel := withTimeout(ctx, 10*time.Second)
	defer cancel()

	_, err := c.profiles.Remove(ctx, &pb.RemoveProfileRequest{Id: id})
	return err
}

// --- SessionService ----------------------------------------------------------

// Connect поднимает сессию по указанному профилю.
func (c *Client) Connect(ctx context.Context, profileID string, policy *pb.Policy, listenPort uint32) (*pb.Status, error) {
	ctx, cancel := withTimeout(ctx, 30*time.Second)
	defer cancel()

	return c.sessions.Connect(ctx, &pb.ConnectRequest{
		ProfileId: profileID, Policy: policy, ListenPort: listenPort,
	})
}

// Disconnect останавливает сессию.
func (c *Client) Disconnect(ctx context.Context) (*pb.Status, error) {
	ctx, cancel := withTimeout(ctx, 15*time.Second)
	defer cancel()

	return c.sessions.Disconnect(ctx, &pb.DisconnectRequest{})
}

// Status возвращает текущее состояние сессии.
func (c *Client) Status(ctx context.Context) (*pb.Status, error) {
	ctx, cancel := withTimeout(ctx, 5*time.Second)
	defer cancel()

	return c.sessions.GetStatus(ctx, &pb.GetStatusRequest{})
}

// --- EventService ------------------------------------------------------------

// Subscribe открывает поток событий службы.
//
// Контекст управляет временем жизни потока: отмена завершает подписку.
// Таймаут здесь НЕ ставится намеренно — поток долгоживущий по замыслу.
func (c *Client) Subscribe(ctx context.Context) (pb.EventService_SubscribeClient, error) {
	return c.events.Subscribe(ctx, &pb.SubscribeRequest{})
}

// --- диагностика -------------------------------------------------------------

// ErrKind — категория отказа связи со службой.
type ErrKind int

const (
	// ErrKindUnknown — причина не распознана.
	ErrKindUnknown ErrKind = iota
	// ErrKindServiceDown — служба не запущена.
	ErrKindServiceDown
	// ErrKindRejected — служба разорвала соединение, вероятно проверкой доверия.
	ErrKindRejected
	// ErrKindAccessDenied — нет прав на подключение к каналу.
	ErrKindAccessDenied
)

// Classify определяет категорию ошибки связи.
//
// Транспортные ошибки gRPC нечитаемы для человека: «error reading server
// preface: EOF» ничего не говорит ни пользователю, ни поддержке. Разбор
// вынесен сюда, чтобы и CLI, и графический интерфейс объясняли одно и то же
// одинаково.
func Classify(err error) ErrKind {
	if err == nil {
		return ErrKindUnknown
	}
	msg := err.Error()

	switch {
	case strings.Contains(msg, "cannot find the file"),
		strings.Contains(msg, "Не удается найти указанный файл"):
		return ErrKindServiceDown

	case strings.Contains(msg, "server preface"),
		strings.Contains(msg, "connection reset"):
		return ErrKindRejected

	case strings.Contains(msg, "Access is denied"),
		strings.Contains(msg, "Отказано в доступе"):
		return ErrKindAccessDenied
	}
	return ErrKindUnknown
}

// Explain возвращает подсказку для пользователя или пустую строку.
func Explain(err error) string {
	switch Classify(err) {
	case ErrKindServiceDown:
		return "Служба net-svc не запущена.\n" +
			"  Проверьте состояние:   net-svc status\n" +
			"  Запустите:             net-svc start   (нужны права администратора)"

	case ErrKindRejected:
		return "Служба разорвала соединение сразу после подключения.\n" +
			"  Наиболее вероятная причина — проверка доверия к клиенту (мера S2):\n" +
			"  клиент должен запускаться из того же каталога, что и net-svc.\n" +
			"  Точная причина записана в журнал событий Windows."

	case ErrKindAccessDenied:
		return "Нет прав на подключение к каналу управления.\n" +
			"  Канал доступен только интерактивным пользователям этого компьютера."
	}
	return ""
}

// ErrServiceUnavailable — обобщённая ошибка недоступности службы.
var ErrServiceUnavailable = errors.New("служба недоступна")

func withTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		// Вызывающий уже задал предельный срок — не сокращаем его.
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, d)
}
