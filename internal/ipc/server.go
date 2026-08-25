// Package ipc, серверная часть: реализация сервисов контракта netgui.v1.
package ipc

import (
	"context"
	"fmt"
	"net/netip"

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
	p, err := profileFromPB(req.GetProfile())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := s.profiles.Put(p); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return &pb.PutProfileResponse{Profile: profileToPB(p)}, nil
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

	st, err := s.sessions.Connect(ctx, session.ConnectOptions{
		Profile:    p,
		Policy:     policy,
		ListenAddr: netip.MustParseAddr("127.0.0.1"),
		ListenPort: port,
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

func profileToPB(p profile.Profile) *pb.Profile {
	return &pb.Profile{
		Id:       p.ID,
		Name:     p.Name,
		Kind:     kindToPB(p.Kind),
		Server:   p.Server,
		Port:     uint32(p.Port),
		Username: p.Username,
		Password: p.Password,
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
	return out, out.Validate()
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

func kindToPB(k profile.Kind) pb.Kind {
	if k == profile.KindSOCKS5 {
		return pb.Kind_KIND_SOCKS5
	}
	return pb.Kind_KIND_UNSPECIFIED
}

func kindFromPB(k pb.Kind) (profile.Kind, error) {
	if k == pb.Kind_KIND_SOCKS5 {
		return profile.KindSOCKS5, nil
	}
	return "", fmt.Errorf("неподдерживаемый тип профиля %s", k)
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
	}
}
