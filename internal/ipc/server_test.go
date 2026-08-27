package ipc

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bbesport/net-gui-client/internal/corehost"
	"github.com/bbesport/net-gui-client/internal/orchestration/session"
	"github.com/bbesport/net-gui-client/internal/store"
	pb "github.com/bbesport/net-gui-client/proto/netgui/v1"
)

const testPassword = "pwd-ipc-9c41e7b0"

func newTestServer(t *testing.T) *Server {
	t.Helper()

	profiles, err := store.OpenProfiles(filepath.Join(t.TempDir(), "profiles.json"))
	if err != nil {
		t.Fatalf("хранилище профилей: %v", err)
	}
	return NewServer("test", profiles, session.NewManager(context.Background()))
}

func putSOCKS5(t *testing.T, s *Server, id, password string) *pb.Profile {
	t.Helper()

	resp, err := s.Put(context.Background(), &pb.PutProfileRequest{Profile: &pb.Profile{
		Id: id, Name: "профиль " + id, Kind: pb.Kind_KIND_SOCKS5,
		Server: "example.org", Port: 1080, Username: "user", Password: password,
	}})
	if err != nil {
		t.Fatalf("Put %s: %v", id, err)
	}
	return resp.GetProfile()
}

// TestResponsesCarryNoSecrets — основная проверка контракта.
//
// Пароль уходит в службу и обратно не возвращается: секреты не покидают её
// (мера S6). Клиенту сообщается только факт наличия секрета.
func TestResponsesCarryNoSecrets(t *testing.T) {
	s := newTestServer(t)

	put := putSOCKS5(t, s, "a", testPassword)
	if put.GetPassword() != "" {
		t.Errorf("ответ Put содержит пароль: %q", put.GetPassword())
	}
	if !put.GetHasSecrets() {
		t.Error("ответ Put не сообщает о наличии секрета")
	}

	list, err := s.List(context.Background(), &pb.ListProfilesRequest{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list.GetProfiles()) != 1 {
		t.Fatalf("профилей в ответе: %d", len(list.GetProfiles()))
	}
	got := list.GetProfiles()[0]
	if got.GetPassword() != "" {
		t.Errorf("ответ List содержит пароль: %q", got.GetPassword())
	}
	if !got.GetHasSecrets() {
		t.Error("ответ List не сообщает о наличии секрета")
	}
}

// TestHasSecretsIsFalseWithoutPassword: признак должен различать состояния,
// а не быть всегда истинным.
func TestHasSecretsIsFalseWithoutPassword(t *testing.T) {
	s := newTestServer(t)

	p := putSOCKS5(t, s, "a", "")
	if p.GetHasSecrets() {
		t.Error("профиль без пароля помечен как имеющий секрет")
	}
}

// TestPutWithEmptyPasswordKeepsExisting закрывает следствие того, что клиент
// не видит секретов.
//
// Переименование профиля присылает пустой пароль просто потому, что взять его
// клиенту неоткуда. Прямая замена стёрла бы пароль, и профиль перестал бы
// подключаться — причём в момент, никак не связанный с переименованием.
func TestPutWithEmptyPasswordKeepsExisting(t *testing.T) {
	s := newTestServer(t)
	putSOCKS5(t, s, "a", testPassword)

	resp, err := s.Put(context.Background(), &pb.PutProfileRequest{Profile: &pb.Profile{
		Id: "a", Name: "новое имя", Kind: pb.Kind_KIND_SOCKS5,
		Server: "example.org", Port: 1080, Username: "user", Password: "",
	}})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	renamed := resp.GetProfile()
	if renamed.GetName() != "новое имя" {
		t.Errorf("имя не изменилось: %q", renamed.GetName())
	}
	if !renamed.GetHasSecrets() {
		t.Fatal("пароль стёрт переименованием")
	}
}

// TestPutWithNewPasswordReplaces: непустой пароль обязан заменять прежний,
// иначе сменить пароль стало бы невозможно.
func TestPutWithNewPasswordReplaces(t *testing.T) {
	s := newTestServer(t)
	putSOCKS5(t, s, "a", testPassword)
	putSOCKS5(t, s, "a", "pwd-ipc-new-3d5f18a2")

	// Значение проверяем через хранилище: наружу оно не выдаётся.
	stored, ok := s.profiles.Get("a")
	if !ok {
		t.Fatal("профиль исчез")
	}
	if stored.Password != "pwd-ipc-new-3d5f18a2" {
		t.Errorf("пароль не заменён: %q", stored.Password)
	}
}

// TestPutRejectsKindChange: смена протокола меняет набор обязательных
// параметров, которых в контракте нет. Молчаливое согласие оставило бы
// профиль без ключей.
func TestPutRejectsKindChange(t *testing.T) {
	s := newTestServer(t)
	putSOCKS5(t, s, "a", testPassword)

	_, err := s.Put(context.Background(), &pb.PutProfileRequest{Profile: &pb.Profile{
		Id: "a", Name: "профиль a", Kind: pb.Kind_KIND_HYSTERIA2,
		Server: "example.org", Port: 1080,
	}})
	if err == nil {
		t.Fatal("смена типа профиля принята")
	}
}

// TestImportLink: разбор ссылки выполняется службой, а не клиентом.
func TestImportLink(t *testing.T) {
	s := newTestServer(t)

	resp, err := s.Import(context.Background(), &pb.ImportProfileRequest{
		Id:      "h1",
		Content: "hysteria2://secret-auth-value@vpn.example.org:8443?sni=example.org#Финляндия",
	})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}

	p := resp.GetProfile()
	if p.GetKind() != pb.Kind_KIND_HYSTERIA2 {
		t.Errorf("тип %v", p.GetKind())
	}
	if p.GetName() != "Финляндия" {
		t.Errorf("имя %q — фрагмент ссылки не использован", p.GetName())
	}
	if p.GetPassword() != "" {
		t.Error("ответ Import содержит секрет")
	}
	if !p.GetHasSecrets() {
		t.Error("ответ Import не сообщает о наличии секрета")
	}
}

// TestImportRejectsGarbage: ошибка разбора обязана доходить до пользователя,
// иначе он не поймёт, что не так со ссылкой.
func TestImportRejectsGarbage(t *testing.T) {
	s := newTestServer(t)

	_, err := s.Import(context.Background(), &pb.ImportProfileRequest{
		Id: "x", Content: "не ссылка и не конфигурация",
	})
	if err == nil {
		t.Fatal("нераспознанное содержимое принято")
	}
	if !strings.Contains(err.Error(), "не распознан") {
		t.Errorf("ошибка не объясняет причину: %v", err)
	}
}

// TestImportGeneratesID: пустой идентификатор означает «выдать самостоятельно».
//
// Придумывать идентификаторы на стороне клиента нельзя: только служба знает,
// какие уже заняты. Основой служит имя профиля — идентификатор виден
// пользователю в net-cli, и осмысленный удобнее случайного.
func TestImportGeneratesID(t *testing.T) {
	s := newTestServer(t)

	resp, err := s.Import(context.Background(), &pb.ImportProfileRequest{
		Content: "socks5://127.0.0.1:1080#Home Proxy",
	})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if got := resp.GetProfile().GetId(); got != "home-proxy" {
		t.Errorf("идентификатор %q, ожидался %q", got, "home-proxy")
	}
}

// TestImportGeneratedIDsDoNotCollide: два профиля с одинаковым именем —
// обычное дело. Второй обязан получить свой идентификатор, а не затереть
// первый.
func TestImportGeneratedIDsDoNotCollide(t *testing.T) {
	s := newTestServer(t)

	const link = "socks5://127.0.0.1:1080#Home Proxy"
	first, err := s.Import(context.Background(), &pb.ImportProfileRequest{Content: link})
	if err != nil {
		t.Fatalf("первый импорт: %v", err)
	}
	second, err := s.Import(context.Background(), &pb.ImportProfileRequest{Content: link})
	if err != nil {
		t.Fatalf("второй импорт: %v", err)
	}

	if first.GetProfile().GetId() == second.GetProfile().GetId() {
		t.Fatalf("оба профиля получили идентификатор %q — первый затёрт",
			first.GetProfile().GetId())
	}

	list, err := s.List(context.Background(), &pb.ListProfilesRequest{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list.GetProfiles()) != 2 {
		t.Errorf("профилей в хранилище: %d, ожидалось 2", len(list.GetProfiles()))
	}
}

// TestImportGeneratedIDFallsBackToKind: имя целиком кириллическое, и от него
// после отбора допустимых знаков ничего не остаётся. Идентификатор всё равно
// обязан получиться — пустой сделал бы профиль недоступным.
func TestImportGeneratedIDFallsBackToKind(t *testing.T) {
	s := newTestServer(t)

	resp, err := s.Import(context.Background(), &pb.ImportProfileRequest{
		Name: "Домашний сервер", Content: "socks5://127.0.0.1:1080",
	})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if got := resp.GetProfile().GetId(); got != "socks5" {
		t.Errorf("идентификатор %q, ожидался %q", got, "socks5")
	}
}

// TestSlug проверяет отбор знаков отдельно: правило неочевидно, а ошибка в
// нём даёт идентификаторы, которые неудобно набирать в net-cli.
func TestSlug(t *testing.T) {
	tests := []struct{ in, want string }{
		{"Home Proxy", "home-proxy"},
		{"ams1", "ams1"},
		{"  ..Server__2  ", "server-2"},
		{"Домашний", ""},
		{"---", ""},
		{"a-–-b", "a-b"},
	}

	for _, tc := range tests {
		if got := slug(tc.in); got != tc.want {
			t.Errorf("slug(%q) = %q, ожидалось %q", tc.in, got, tc.want)
		}
	}
}

// TestImportWgQuickGeneratesUsableID закрывает дефект, найденный при живой
// проверке интерфейса.
//
// Формат wg-quick своего имени не несёт, поэтому предварительный разбор
// подставлял вместо имени временный идентификатор — и он же становился
// настоящим. Профиль получал идентификатор «draft-import».
func TestImportWgQuickGeneratesUsableID(t *testing.T) {
	s := newTestServer(t)

	conf := `[Interface]
PrivateKey = aGVsbG8td29ybGQtZmFrZS1rZXktdmFsdWUtMDAwMDA=
Address = 10.0.0.2/32

[Peer]
PublicKey = cGVlci1mYWtlLXB1YmxpYy1rZXktdmFsdWUtMDAwMDA=
Endpoint = vpn.example.org:51820
AllowedIPs = 0.0.0.0/0
`

	resp, err := s.Import(context.Background(), &pb.ImportProfileRequest{Content: conf})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}

	got := resp.GetProfile().GetId()
	if strings.Contains(got, "draft") {
		t.Fatalf("идентификатор %q содержит след временного значения", got)
	}
	if got != "wireguard" {
		t.Errorf("идентификатор %q, ожидался %q", got, "wireguard")
	}
}

// --- режим работы -------------------------------------------------------------

// TestConnectDefaultsToProxyMode закрывает правило совместимости.
//
// Клиент, собранный до появления режимов, поля не заполняет —
// MODE_UNSPECIFIED. Истолковать это как ошибку значило бы сломать старых
// клиентов; истолковать как туннель — молча изменить маршрутизацию всей
// системы у тех, кто просил обычный прокси. Верно только одно прочтение.
func TestConnectDefaultsToProxyMode(t *testing.T) {
	if got, err := modeFromPB(pb.Mode_MODE_UNSPECIFIED); err != nil || got != corehost.ModeProxy {
		t.Errorf("MODE_UNSPECIFIED → (%q, %v), ожидался режим прокси", got, err)
	}
}

// TestModeRoundTrip: прямое и обратное преобразование обязаны совпадать.
//
// Одна таблица вместо двух switch именно для этого: расхождение иначе
// обнаруживается не при сборке, а при работе не в том режиме.
func TestModeRoundTrip(t *testing.T) {
	for _, m := range []corehost.Mode{corehost.ModeProxy, corehost.ModeTunnel} {
		got, err := modeFromPB(modeToPB(m))
		if err != nil {
			t.Errorf("режим %q: обратное преобразование: %v", m, err)
			continue
		}
		if got != m {
			t.Errorf("режим %q превратился в %q", m, got)
		}
	}
}

// TestUnknownModeRejected: значение вне контракта — это отказ, а не молчаливый
// переход к прокси.
func TestUnknownModeRejected(t *testing.T) {
	if _, err := modeFromPB(pb.Mode(9999)); err == nil {
		t.Error("неизвестный режим принят")
	}
}
