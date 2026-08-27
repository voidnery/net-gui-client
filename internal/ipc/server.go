// Package ipc, серверная часть: реализация сервисов контракта netgui.v1.
package ipc

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/bbesport/net-gui-client/internal/corehost"
	"github.com/bbesport/net-gui-client/internal/orchestration/profile"
	"github.com/bbesport/net-gui-client/internal/orchestration/rules"
	"github.com/bbesport/net-gui-client/internal/orchestration/session"
	"github.com/bbesport/net-gui-client/internal/store"
	pb "github.com/bbesport/net-gui-client/proto/netgui/v1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// APIVersion — версия контракта управления. Увеличивается при несовместимых
// изменениях; клиент сверяет её при рукопожатии (ADR-004).
const APIVersion = 1

// Server реализует все сервисы контракта поверх менеджера сессии и хранилища.
type Server struct {
	pb.UnimplementedControlServiceServer
	pb.UnimplementedProfileServiceServer
	pb.UnimplementedSessionServiceServer
	pb.UnimplementedEventServiceServer

	version  string
	profiles *store.Profiles
	sessions *session.Manager
}

// NewServer собирает реализацию сервисов.
func NewServer(version string, profiles *store.Profiles, sessions *session.Manager) *Server {
	return &Server{version: version, profiles: profiles, sessions: sessions}
}

// Register регистрирует все сервисы в gRPC-сервере.
func (s *Server) Register(g *grpc.Server) {
	pb.RegisterControlServiceServer(g, s)
	pb.RegisterProfileServiceServer(g, s)
	pb.RegisterSessionServiceServer(g, s)
	pb.RegisterEventServiceServer(g, s)
}

// --- ControlService ----------------------------------------------------------

func (s *Server) Hello(_ context.Context, _ *pb.HelloRequest) (*pb.HelloResponse, error) {
	return &pb.HelloResponse{ServerVersion: s.version, ApiVersion: APIVersion}, nil
}

// --- ProfileService ----------------------------------------------------------

func (s *Server) List(_ context.Context, _ *pb.ListProfilesRequest) (*pb.ListProfilesResponse, error) {
	items := s.profiles.List()
	out := make([]*pb.Profile, 0, len(items))
	for _, p := range items {
		out = append(out, profileToPB(p))
	}
	return &pb.ListProfilesResponse{Profiles: out}, nil
}

func (s *Server) Put(_ context.Context, req *pb.PutProfileRequest) (*pb.PutProfileResponse, error) {
	incoming, err := profileFromPB(req.GetProfile())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	if existing, ok := s.profiles.Get(incoming.ID); ok {
		incoming, err = mergeProfile(existing, incoming)
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
	}

	if err := incoming.Validate(); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := s.profiles.Put(incoming); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return &pb.PutProfileResponse{Profile: profileToPB(incoming)}, nil
}

// mergeProfile накладывает пришедшие от клиента поля на сохранённый профиль.
//
// Нужно потому, что контракт передаёт лишь часть полей профиля: имя, адрес,
// порт, имя пользователя и пароль. Ключи WireGuard, параметры обфускации,
// настройки TLS в нём не выражены — они попадают в хранилище только через
// импорт. Прямая замена сохранённого профиля пришедшим стёрла бы всё это при
// обычном переименовании.
//
// Пустой пароль означает «оставить прежний»: клиент не получает секретов в
// ответах и потому не может прислать обратно то, чего не видел.
func mergeProfile(existing, incoming profile.Profile) (profile.Profile, error) {
	if incoming.Kind != existing.Kind {
		// Смена протокола меняет и набор обязательных параметров, которых в
		// контракте нет. Такой профиль следует создавать импортом заново,
		// а не превращать один в другой.
		return profile.Profile{}, fmt.Errorf(
			"профиль %q уже существует с типом %q: смена типа на %q не поддерживается",
			existing.ID, existing.Kind, incoming.Kind)
	}

	out := existing
	out.Name = incoming.Name
	out.Server = incoming.Server
	out.Port = incoming.Port
	out.Username = incoming.Username

	if incoming.Password != "" {
		out.Password = incoming.Password
	}
	return out, nil
}

// Import создаёт профиль из ссылки или файла конфигурации.
//
// Пустой идентификатор допустим: служба выдаёт его сама. Придумывать
// идентификаторы на стороне клиента нельзя — только служба знает, какие уже
// заняты, и только она может обеспечить неповторяемость.
func (s *Server) Import(_ context.Context, req *pb.ImportProfileRequest) (*pb.ImportProfileResponse, error) {
	id := req.GetId()
	if id == "" {
		// Разбираем с временным идентификатором: настоящий выводится из имени,
		// а имя становится известно только после разбора.
		draft, err := profile.Import(draftID, req.GetName(), req.GetContent())
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		id = s.freeID(draft)
	}

	p, err := profile.Import(id, req.GetName(), req.GetContent())
	if err != nil {
		// Текст ошибки разбора уходит клиенту: он объясняет, что именно не так
		// со ссылкой. Секретов в нём нет — разбор сообщает о структуре, а не
		// о значениях.
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := s.profiles.Put(p); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return &pb.ImportProfileResponse{Profile: profileToPB(p)}, nil
}

// draftID — временный идентификатор для предварительного разбора.
//
// Значение подобрано так, чтобы его нельзя было спутать с настоящим именем
// профиля: если оно всё же окажется именем, значит своего имени у содержимого
// не было.
const draftID = "draft-import"

// freeID подбирает свободный идентификатор для профиля.
//
// Основа — имя профиля, приведённое к латинице и дефисам: идентификатор
// виден пользователю в net-cli, и «ams1» удобнее, чем случайный набор знаков.
// Если от имени ничего не осталось — например, оно целиком кириллическое, —
// основой становится тип профиля.
func (s *Server) freeID(p profile.Profile) string {
	var base string

	// Имя, совпавшее с временным идентификатором, означает, что своего имени у
	// содержимого нет: разбор подставил вместо него то, что мы сами и передали.
	// Так происходит с файлами wg-quick — формат имени не несёт. Без этой
	// проверки идентификатор получался буквально «draft-import».
	if p.Name != draftID {
		base = slug(p.Name)
	}
	if base == "" {
		base = string(p.Kind)
	}

	if _, taken := s.profiles.Get(base); !taken {
		return base
	}
	// Повтор — обычное дело: два профиля одного провайдера легко называются
	// одинаково. Нумеруем, а не отказываем.
	for n := 2; ; n++ {
		candidate := base + "-" + strconv.Itoa(n)
		if _, taken := s.profiles.Get(candidate); !taken {
			return candidate
		}
	}
}

// slug оставляет от строки только латинские буквы, цифры и дефисы.
//
// Транслитерация намеренно НЕ делается. Она требует выбора схемы (их
// несколько, и они дают разные результаты), а выигрыш сомнителен:
// «домашний-сервер» в качестве идентификатора читается не лучше, чем
// «amneziawg-2», зато порождает вопрос, почему «й» превратилось именно в это.
func slug(s string) string {
	var b strings.Builder
	lastDash := true // не начинать с дефиса

	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		case r == '-' || r == '_' || r == ' ' || r == '.':
			if !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

func (s *Server) Remove(_ context.Context, req *pb.RemoveProfileRequest) (*pb.RemoveProfileResponse, error) {
	if err := s.profiles.Remove(req.GetId()); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &pb.RemoveProfileResponse{}, nil
}

// --- SessionService ----------------------------------------------------------

func (s *Server) Connect(ctx context.Context, req *pb.ConnectRequest) (*pb.Status, error) {
	p, ok := s.profiles.Get(req.GetProfileId())
	if !ok {
		return nil, status.Errorf(codes.NotFound, "профиль %q не найден", req.GetProfileId())
	}

	policy, err := policyFromPB(req.GetPolicy())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	port, err := portFromPB(req.GetListenPort())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	mode, err := modeFromPB(req.GetMode())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	st, err := s.sessions.Connect(ctx, session.ConnectOptions{
		Profile:    p,
		Policy:     policy,
		ListenAddr: netip.MustParseAddr("127.0.0.1"),
		ListenPort: port,
		Mode:       mode,
	})
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	return statusToPB(st), nil
}

func (s *Server) Disconnect(_ context.Context, _ *pb.DisconnectRequest) (*pb.Status, error) {
	st, err := s.sessions.Disconnect()
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return statusToPB(st), nil
}

func (s *Server) GetStatus(_ context.Context, _ *pb.GetStatusRequest) (*pb.Status, error) {
	return statusToPB(s.sessions.Status()), nil
}

// --- EventService ------------------------------------------------------------

func (s *Server) Subscribe(_ *pb.SubscribeRequest, stream grpc.ServerStreamingServer[pb.Event]) error {
	events, unsubscribe := s.sessions.Subscribe()
	defer unsubscribe()

	for {
		select {
		case <-stream.Context().Done():
			return nil // клиент отключился — штатное завершение
		case st, ok := <-events:
			if !ok {
				return nil // служба останавливается
			}
			err := stream.Send(&pb.Event{
				UnixNano: timestamppb.Now().AsTime().UnixNano(),
				Payload:  &pb.Event_StatusChanged{StatusChanged: statusToPB(st)},
			})
			if err != nil {
				return err
			}
		}
	}
}

// --- преобразования между контрактом и доменной моделью ----------------------
//
// Слой преобразования существует намеренно: доменная модель не должна знать
// о protobuf, а контракт не должен диктовать внутренние типы. Заодно здесь
// проходит валидация всего, что пришло извне, — часть меры S3.

// profileToPB собирает профиль для отправки клиенту.
//
// ⚠️ Поле Password намеренно НЕ заполняется: секреты не покидают службу
// (мера S6). Клиенту сообщается лишь факт наличия секрета — этого достаточно,
// чтобы показать «пароль задан», и недостаточно, чтобы его узнать.
//
// Раньше пароль уходил клиенту в каждом ответе List. Канал защищён списком
// доступа и проверкой клиента (мера S2), поэтому утечкой это не было, но
// секрет копировался в чужой процесс без всякой надобности.
func profileToPB(p profile.Profile) *pb.Profile {
	return &pb.Profile{
		Id:         p.ID,
		Name:       p.Name,
		Kind:       kindToPB(p.Kind),
		Server:     p.Server,
		Port:       uint32(p.Port),
		Username:   p.Username,
		HasSecrets: p.HasSecrets(),
	}
}

func profileFromPB(p *pb.Profile) (profile.Profile, error) {
	if p == nil {
		return profile.Profile{}, fmt.Errorf("профиль не задан")
	}
	kind, err := kindFromPB(p.GetKind())
	if err != nil {
		return profile.Profile{}, err
	}
	port, err := portFromPB(p.GetPort())
	if err != nil {
		return profile.Profile{}, err
	}
	out := profile.Profile{
		ID:       p.GetId(),
		Name:     p.GetName(),
		Kind:     kind,
		Server:   p.GetServer(),
		Port:     port,
		Username: p.GetUsername(),
		Password: p.GetPassword(),
	}
	// Проверка здесь НЕ выполняется: пришедшее может быть неполным — например,
	// переименование профиля AmneziaWG не несёт ни ключей, ни параметров
	// обфускации, потому что контракт их не передаёт. Полнота достигается
	// слиянием с сохранённым профилем, и проверяется уже результат.
	return out, nil
}

// portFromPB сужает uint32 из контракта до uint16.
//
// protobuf не имеет 16-битного целого, поэтому порт приходит как uint32.
// Без явной проверки значение 65536 молча превратилось бы в 0 при
// преобразовании — классический источник трудноуловимых ошибок.
func portFromPB(v uint32) (uint16, error) {
	if v > 65535 {
		return 0, fmt.Errorf("порт %d вне допустимого диапазона", v)
	}
	return uint16(v), nil
}

// kindTable — единственное соответствие между внутренним типом профиля и
// значением контракта.
//
// Одна таблица вместо двух switch: расхождение между прямым и обратным
// преобразованием иначе обнаруживается не при сборке, а при попытке
// подключиться профилем, который «не того типа».
var kindTable = []struct {
	internal profile.Kind
	wire     pb.Kind
}{
	{profile.KindSOCKS5, pb.Kind_KIND_SOCKS5},
	{profile.KindHysteria2, pb.Kind_KIND_HYSTERIA2},
	{profile.KindWireGuard, pb.Kind_KIND_WIREGUARD},
	{profile.KindAmneziaWG, pb.Kind_KIND_AMNEZIAWG},
	{profile.KindVLESS, pb.Kind_KIND_VLESS},
}

func kindToPB(k profile.Kind) pb.Kind {
	for _, e := range kindTable {
		if e.internal == k {
			return e.wire
		}
	}
	return pb.Kind_KIND_UNSPECIFIED
}

func kindFromPB(k pb.Kind) (profile.Kind, error) {
	for _, e := range kindTable {
		if e.wire == k {
			return e.internal, nil
		}
	}
	return "", fmt.Errorf("неподдерживаемый тип профиля %s", k)
}

// modeTable — единственное соответствие между режимом ядра и значением
// контракта. Одна таблица вместо двух switch, по той же причине, что и
// kindTable: расхождение прямого и обратного преобразования иначе
// обнаруживается не при сборке, а при работе не в том режиме.
var modeTable = []struct {
	internal corehost.Mode
	wire     pb.Mode
}{
	{corehost.ModeProxy, pb.Mode_MODE_PROXY},
	{corehost.ModeTunnel, pb.Mode_MODE_TUNNEL},
}

func modeToPB(m corehost.Mode) pb.Mode {
	for _, e := range modeTable {
		if e.internal == m {
			return e.wire
		}
	}
	return pb.Mode_MODE_PROXY
}

// modeFromPB переводит режим из контракта.
//
// MODE_UNSPECIFIED означает режим прокси, а не ошибку: клиент, собранный до
// появления режимов, поля не заполняет, и его поведение обязано остаться
// прежним.
func modeFromPB(m pb.Mode) (corehost.Mode, error) {
	if m == pb.Mode_MODE_UNSPECIFIED {
		return corehost.ModeProxy, nil
	}
	for _, e := range modeTable {
		if e.wire == m {
			return e.internal, nil
		}
	}
	return "", fmt.Errorf("неподдерживаемый режим %s", m)
}

func actionToPB(a rules.Action) pb.Action {
	switch a {
	case rules.ActionProxy:
		return pb.Action_ACTION_PROXY
	case rules.ActionDirect:
		return pb.Action_ACTION_DIRECT
	case rules.ActionBlock:
		return pb.Action_ACTION_BLOCK
	default:
		return pb.Action_ACTION_UNSPECIFIED
	}
}

func actionFromPB(a pb.Action) (rules.Action, error) {
	switch a {
	case pb.Action_ACTION_PROXY:
		return rules.ActionProxy, nil
	case pb.Action_ACTION_DIRECT:
		return rules.ActionDirect, nil
	case pb.Action_ACTION_BLOCK:
		return rules.ActionBlock, nil
	default:
		return "", fmt.Errorf("действие не задано")
	}
}

func policyToPB(p rules.Policy) *pb.Policy {
	out := &pb.Policy{
		DefaultAction: actionToPB(p.Default),
		Rules:         make([]*pb.Rule, 0, len(p.Rules)),
	}
	for _, r := range p.Rules {
		out.Rules = append(out.Rules, &pb.Rule{
			Matcher: &pb.Matcher{
				Domain:       r.Domain,
				DomainSuffix: r.DomainSuffix,
				IpCidr:       r.IPCIDR,
			},
			Action: actionToPB(r.Action),
		})
	}
	return out
}

func policyFromPB(p *pb.Policy) (rules.Policy, error) {
	if p == nil {
		return rules.Policy{}, fmt.Errorf("политика не задана")
	}
	def, err := actionFromPB(p.GetDefaultAction())
	if err != nil {
		return rules.Policy{}, fmt.Errorf("действие по умолчанию: %w", err)
	}

	out := rules.Policy{Default: def, Rules: make([]rules.Rule, 0, len(p.GetRules()))}
	for i, r := range p.GetRules() {
		act, err := actionFromPB(r.GetAction())
		if err != nil {
			return rules.Policy{}, fmt.Errorf("правило #%d: %w", i+1, err)
		}
		out.Rules = append(out.Rules, rules.Rule{
			Matcher: rules.Matcher{
				Domain:       r.GetMatcher().GetDomain(),
				DomainSuffix: r.GetMatcher().GetDomainSuffix(),
				IPCIDR:       r.GetMatcher().GetIpCidr(),
			},
			Action: act,
		})
	}
	return out, out.Validate()
}

func statusToPB(s session.Status) *pb.Status {
	var state pb.SessionState
	switch s.State {
	case session.StateConnecting:
		state = pb.SessionState_SESSION_STATE_CONNECTING
	case session.StateConnected:
		state = pb.SessionState_SESSION_STATE_CONNECTED
	default:
		state = pb.SessionState_SESSION_STATE_IDLE
	}
	return &pb.Status{
		State:         state,
		ProfileId:     s.ProfileID,
		ListenAddress: s.Listen,
		Policy:        policyToPB(s.Policy),
		Error:         s.Err,
		Mode:          modeToPB(s.Mode),
	}
}
