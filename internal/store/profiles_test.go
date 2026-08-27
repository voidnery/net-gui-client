package store

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bbesport/net-gui-client/internal/orchestration/profile"
	"github.com/bbesport/net-gui-client/internal/secretlog"
)

// Значения выдуманы. Пароль намеренно длинный и непохожий на слова из
// сообщений журнала: короткое значение маскировалось бы всюду и сделало бы
// проверку неинформативной.
const (
	passwordA = "pwd-alpha-7f3c9e21"
	passwordB = "pwd-bravo-1d8a4b60"
)

func socks5Profile(id, password string) profile.Profile {
	return profile.Profile{
		ID:       id,
		Name:     "профиль " + id,
		Kind:     profile.KindSOCKS5,
		Server:   "example.org",
		Port:     1080,
		Username: "user",
		Password: password,
	}
}

// newStore создаёт хранилище во временном каталоге с ОТДЕЛЬНЫМ реестром
// секретов: тесты не должны влиять друг на друга через реестр процесса.
func newStore(t *testing.T) (*Profiles, *secretlog.Registry) {
	t.Helper()

	registry := secretlog.New()
	s, err := openProfiles(filepath.Join(t.TempDir(), "profiles.json"), registry)
	if err != nil {
		t.Fatalf("открытие хранилища: %v", err)
	}
	return s, registry
}

func assertMasked(t *testing.T, r *secretlog.Registry, secret string) {
	t.Helper()
	if got := r.Mask("значение=" + secret); strings.Contains(got, secret) {
		t.Errorf("секрет не маскируется: %q", got)
	}
}

func assertNotMasked(t *testing.T, r *secretlog.Registry, secret string) {
	t.Helper()
	if got := r.Mask("значение=" + secret); !strings.Contains(got, secret) {
		t.Errorf("секрет всё ещё маскируется, хотя профиль удалён: %q", got)
	}
}

// TestPutRegistersSecret: секрет попадает в реестр при добавлении профиля.
func TestPutRegistersSecret(t *testing.T) {
	s, registry := newStore(t)

	if err := s.Put(socks5Profile("a", passwordA)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	assertMasked(t, registry, passwordA)
}

// TestOpenRegistersSecrets: секреты регистрируются при загрузке с диска.
//
// Это главный случай меры S7 при обычном запуске службы: профили приходят из
// файла, и ни один вызывающий код не «добавляет» их явно.
func TestOpenRegistersSecrets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profiles.json")

	writer, err := openProfiles(path, secretlog.New())
	if err != nil {
		t.Fatalf("открытие хранилища: %v", err)
	}
	if err := writer.Put(socks5Profile("a", passwordA)); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Повторное открытие — как при следующем запуске службы.
	registry := secretlog.New()
	if _, err := openProfiles(path, registry); err != nil {
		t.Fatalf("повторное открытие: %v", err)
	}
	assertMasked(t, registry, passwordA)
}

// TestRemoveForgetsSecret: секрет удалённого профиля перестаёт занимать место
// в реестре, который просматривается на каждой строке журнала.
func TestRemoveForgetsSecret(t *testing.T) {
	s, registry := newStore(t)

	if err := s.Put(socks5Profile("a", passwordA)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Remove("a"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	assertNotMasked(t, registry, passwordA)
}

// TestRemoveKeepsSharedSecret закрывает неочевидный случай.
//
// Один и тот же пароль вполне может стоять в двух профилях одного сервера.
// Снятие его вместе с первым удалённым профилем прекратило бы маскирование
// для второго — секрет остался бы в процессе, но перестал скрываться.
func TestRemoveKeepsSharedSecret(t *testing.T) {
	s, registry := newStore(t)

	if err := s.Put(socks5Profile("a", passwordA)); err != nil {
		t.Fatalf("Put a: %v", err)
	}
	if err := s.Put(socks5Profile("b", passwordA)); err != nil {
		t.Fatalf("Put b: %v", err)
	}
	if err := s.Remove("a"); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	assertMasked(t, registry, passwordA)
}

// TestPutReplacingForgetsOldSecret: при замене профиля прежний пароль больше
// не нужен в реестре, а новый обязан там оказаться.
func TestPutReplacingForgetsOldSecret(t *testing.T) {
	s, registry := newStore(t)

	if err := s.Put(socks5Profile("a", passwordA)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Put(socks5Profile("a", passwordB)); err != nil {
		t.Fatalf("Put замена: %v", err)
	}

	assertMasked(t, registry, passwordB)
	assertNotMasked(t, registry, passwordA)
}

// TestInvalidProfileRejected: в хранилище не попадает то, из чего нельзя
// собрать конфигурацию.
func TestInvalidProfileRejected(t *testing.T) {
	s, registry := newStore(t)

	bad := socks5Profile("a", passwordA)
	bad.Server = ""

	if err := s.Put(bad); err == nil {
		t.Fatal("некорректный профиль принят")
	}
	if registry.Len() != 0 {
		t.Errorf("секрет отвергнутого профиля попал в реестр")
	}
}

// --- мера S6: секреты на диске зашифрованы ----------------------------------

// TestSecretsAreEncryptedOnDisk — основная проверка меры S6.
//
// Смотрим не на API, а на сам файл: именно он попадает в резервные копии,
// в синхронизацию каталогов и в карантин антивируса.
func TestSecretsAreEncryptedOnDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profiles.json")

	s, err := openProfiles(path, secretlog.New())
	if err != nil {
		t.Fatalf("открытие хранилища: %v", err)
	}
	if err := s.Put(socks5Profile("a", passwordA)); err != nil {
		t.Fatalf("Put: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("чтение файла: %v", err)
	}
	if bytes.Contains(raw, []byte(passwordA)) {
		t.Fatal("пароль лежит в файле открытым текстом")
	}
	if !bytes.Contains(raw, []byte(secretPrefix)) {
		t.Error("в файле нет признака зашифрованного значения")
	}
	// Несекретные поля обязаны остаться читаемыми: файл должен поддаваться
	// осмотру глазами при разборе обращений.
	if !bytes.Contains(raw, []byte("example.org")) {
		t.Error("адрес сервера тоже зашифрован — файл стал нечитаемым без нужды")
	}
}

// TestLegacyPlaintextIsMigrated: файл, созданный до появления меры S6,
// читается и шифруется при ближайшей записи.
//
// Без этого обновление приложения выглядело бы как потеря всех профилей.
func TestLegacyPlaintextIsMigrated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profiles.json")

	legacy := fileFormat{Version: 1, Profiles: []profile.Profile{socks5Profile("a", passwordA)}}
	raw, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("подготовка файла: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("запись файла: %v", err)
	}

	registry := secretlog.New()
	s, err := openProfiles(path, registry)
	if err != nil {
		t.Fatalf("открытие унаследованного файла: %v", err)
	}

	got, ok := s.Get("a")
	if !ok {
		t.Fatal("профиль из унаследованного файла не прочитан")
	}
	if got.Password != passwordA {
		t.Errorf("пароль прочитан как %q", got.Password)
	}
	assertMasked(t, registry, passwordA)

	// Любая запись переводит файл в зашифрованный вид.
	if err := s.Put(socks5Profile("b", passwordB)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("повторное чтение файла: %v", err)
	}
	if bytes.Contains(after, []byte(passwordA)) {
		t.Error("унаследованный пароль остался открытым после записи")
	}
}

// TestUnreadableProfileIsReported: испорченный профиль не мешает остальным и
// не исчезает молча.
//
// Типичный случай — файл, перенесённый с другой машины: ключ DPAPI принадлежит
// машине, и расшифровать его там нельзя в принципе. Промолчать здесь означало
// бы показать пользователю список, в котором части профилей просто нет.
func TestUnreadableProfileIsReported(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profiles.json")

	s, err := openProfiles(path, secretlog.New())
	if err != nil {
		t.Fatalf("открытие хранилища: %v", err)
	}
	if err := s.Put(socks5Profile("good", passwordA)); err != nil {
		t.Fatalf("Put good: %v", err)
	}
	if err := s.Put(socks5Profile("bad", passwordB)); err != nil {
		t.Fatalf("Put bad: %v", err)
	}

	// Портим шифротекст одного профиля — как это сделал бы перенос файла
	// на другую машину.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("чтение файла: %v", err)
	}
	var f fileFormat
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("разбор файла: %v", err)
	}
	for i := range f.Profiles {
		if f.Profiles[i].ID == "bad" {
			f.Profiles[i].Password = secretPrefix + "0J3QtdCy0LDQu9C40LTQvdGL0Lkg0LHQu9C+0LE="
		}
	}
	raw, err = json.Marshal(f)
	if err != nil {
		t.Fatalf("сериализация: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("запись файла: %v", err)
	}

	reopened, err := openProfiles(path, secretlog.New())
	if err != nil {
		t.Fatalf("открытие не должно падать целиком: %v", err)
	}

	if _, ok := reopened.Get("good"); !ok {
		t.Error("исправный профиль потерян из-за соседнего испорченного")
	}
	if _, ok := reopened.Get("bad"); ok {
		t.Error("профиль с нерасшифровываемым секретом попал в список")
	}
	if len(reopened.LoadErrors()) != 1 {
		t.Fatalf("ошибок загрузки: %d, ожидалась 1", len(reopened.LoadErrors()))
	}
	if !strings.Contains(reopened.LoadErrors()[0].Error(), "bad") {
		t.Errorf("ошибка не называет профиль: %v", reopened.LoadErrors()[0])
	}
}
