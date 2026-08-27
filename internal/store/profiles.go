// Package store — хранилище профилей на диске.
//
// Это JSON-файл в каталоге данных службы, защищённом мерой S5 (запись
// недоступна непривилегированным пользователям).
//
// # Шифрование секретов
//
// Секретные поля профиля хранятся на диске зашифрованными средствами
// операционной системы (мера S6, internal/platform/secrets). Остальные поля
// остаются читаемыми: имя профиля и адрес сервера секретами не являются, а
// возможность заглянуть в файл глазами экономит часы при разборе обращений.
//
// Зашифрованное значение узнаётся по префиксу secretPrefix. Значение без
// префикса считается унаследованным открытым текстом и шифруется при
// ближайшей записи — так файл, созданный до появления меры S6, переносится
// без участия пользователя.
//
// # Регистрация секретов
//
// Хранилище — единственное место, через которое секреты профилей попадают в
// процесс. Поэтому именно здесь они вносятся в реестр маскирования
// (мера S7, internal/secretlog) и вычёркиваются при удалении профиля.
//
// Регистрация выполняется хранилищем, а не вызывающим кодом, намеренно:
// «забыли зарегистрировать» — это ровно тот способ утечки, который мера S7
// закрывает. Привязка к загрузке делает маскирование следствием самого факта
// появления секрета в процессе.
package store

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/bbesport/net-gui-client/internal/orchestration/profile"
	"github.com/bbesport/net-gui-client/internal/platform/secrets"
	"github.com/bbesport/net-gui-client/internal/secretlog"
)

// secretPrefix отмечает зашифрованное значение.
//
// Префикс нужен, чтобы отличать шифротекст от унаследованного открытого
// текста. Полагаться на «расшифруется или нет» нельзя: у CryptUnprotectData
// нет способа отличить «это не наш блоб» от «блоб повреждён», и попытка
// расшифровать обычный пароль дала бы ошибку, неотличимую от порчи файла.
const secretPrefix = "dpapi:"

// fileVersion — версия формата файла.
//
// 1 — секреты открытым текстом (до меры S6);
// 2 — секреты зашифрованы DPAPI.
//
// Чтение принимает обе: распознавание идёт по префиксу каждого поля, а не по
// версии файла. Версия здесь — пометка для человека, читающего файл.
const fileVersion = 2

// Profiles — потокобезопасное хранилище профилей.
type Profiles struct {
	path string

	// secrets — реестр маскирования журнала. Отдельное поле, а не обращение
	// к secretlog.Default() по месту, чтобы тесты могли подставить свой
	// реестр и не влиять друг на друга через общее состояние процесса.
	secrets *secretlog.Registry

	// loadErrors — профили, которые не удалось расшифровать при загрузке.
	//
	// Собираются, а не возвращаются первой же ошибкой: один испорченный
	// профиль не должен мешать работать с остальными. Служба сообщает о них
	// при запуске.
	loadErrors []error

	mu   sync.RWMutex
	data map[string]profile.Profile
}

type fileFormat struct {
	Version  int               `json:"version"`
	Profiles []profile.Profile `json:"profiles"`
}

// OpenProfiles открывает или создаёт хранилище по указанному пути.
//
// Секреты загруженных профилей вносятся в реестр маскирования процесса.
func OpenProfiles(path string) (*Profiles, error) {
	return openProfiles(path, secretlog.Default())
}

// openProfiles — вариант с явным реестром, для тестов.
func openProfiles(path string, secrets *secretlog.Registry) (*Profiles, error) {
	s := &Profiles{
		path:    path,
		secrets: secrets,
		data:    make(map[string]profile.Profile),
	}

	raw, err := os.ReadFile(path)
	switch {
	case os.IsNotExist(err):
		return s, nil // пустое хранилище — нормальный первый запуск
	case err != nil:
		return nil, fmt.Errorf("store: чтение %s: %w", path, err)
	}

	var f fileFormat
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("store: разбор %s: %w", path, err)
	}
	for _, stored := range f.Profiles {
		p, err := stored.TransformSecrets(decryptSecret)
		if err != nil {
			// Профиль остаётся недоступным, но остальные загружаются.
			// Чаще всего это файл, перенесённый с другой машины: ключ DPAPI
			// принадлежит машине, и там расшифровать его нельзя в принципе.
			s.loadErrors = append(s.loadErrors,
				fmt.Errorf("профиль %q недоступен: %w", stored.ID, err))
			continue
		}
		s.data[p.ID] = p
		s.secrets.Add(p.Secrets()...)
	}
	return s, nil
}

// LoadErrors возвращает ошибки, возникшие при загрузке отдельных профилей.
//
// Пустой список — обычное состояние. Непустой означает, что часть профилей
// не прочитана: вызывающий обязан сообщить об этом пользователю, иначе
// профиль просто исчезнет из списка без объяснения.
func (s *Profiles) LoadErrors() []error {
	return s.loadErrors
}

// encryptSecret шифрует значение для записи на диск.
func encryptSecret(v string) (string, error) {
	if strings.HasPrefix(v, secretPrefix) {
		return v, nil // уже зашифровано
	}
	blob, err := secrets.Protect([]byte(v))
	if err != nil {
		return "", err
	}
	return secretPrefix + base64.StdEncoding.EncodeToString(blob), nil
}

// decryptSecret восстанавливает значение, прочитанное с диска.
func decryptSecret(v string) (string, error) {
	if !strings.HasPrefix(v, secretPrefix) {
		// Унаследованный открытый текст: файл создан до меры S6.
		// Будет зашифрован при ближайшей записи.
		return v, nil
	}

	blob, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(v, secretPrefix))
	if err != nil {
		return "", fmt.Errorf("повреждён шифротекст: %w", err)
	}

	plain, err := secrets.Unprotect(blob)
	if err != nil {
		return "", err
	}
	// Расшифрованный буфер затирается сразу: строка ниже — уже отдельная
	// копия. Полной гарантии это не даёт (см. описание пакета secrets), но
	// лишняя копия секрета в куче живёт ощутимо дольше без этой строки.
	defer secrets.Zero(plain)

	return string(plain), nil
}

// List возвращает профили, упорядоченные по идентификатору.
// Устойчивый порядок важен: без него вывод CLI прыгал бы между запусками.
func (s *Profiles) List() []profile.Profile {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]profile.Profile, 0, len(s.data))
	for _, p := range s.data {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Get возвращает профиль по идентификатору.
func (s *Profiles) Get(id string) (profile.Profile, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.data[id]
	return p, ok
}

// Put добавляет или заменяет профиль. Профиль проверяется до записи —
// в хранилище не должно попадать то, из чего нельзя собрать конфиг.
func (s *Profiles) Put(p profile.Profile) error {
	if err := p.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	previous, existed := s.data[p.ID]
	s.data[p.ID] = p
	s.mu.Unlock()

	// Новые значения вносим ДО записи на диск: если flush упадёт, секрет уже
	// находится в процессе, и маскировать его нужно в любом случае.
	s.secrets.Add(p.Secrets()...)
	if existed {
		s.forgetUnused(previous)
	}
	return s.flush()
}

// Remove удаляет профиль. Удаление отсутствующего — не ошибка.
func (s *Profiles) Remove(id string) error {
	s.mu.Lock()
	removed, existed := s.data[id]
	delete(s.data, id)
	s.mu.Unlock()

	if existed {
		s.forgetUnused(removed)
	}
	return s.flush()
}

// forgetUnused вычёркивает из реестра те секреты выбывшего профиля, которые
// не встречаются больше ни в одном оставшемся.
//
// Проверка на использование другими профилями обязательна: один и тот же
// пароль вполне может стоять в двух профилях одного сервера, и снятие его
// вместе с первым из них прекратило бы маскирование для второго.
func (s *Profiles) forgetUnused(gone profile.Profile) {
	candidates := gone.Secrets()
	if len(candidates) == 0 {
		return
	}

	inUse := make(map[string]bool)
	s.mu.RLock()
	for _, p := range s.data {
		for _, v := range p.Secrets() {
			inUse[v] = true
		}
	}
	s.mu.RUnlock()

	for _, v := range candidates {
		if !inUse[v] {
			s.secrets.Forget(v)
		}
	}
}

// flush записывает хранилище на диск атомарно: сначала во временный файл,
// затем переименование. Иначе падение посреди записи оставило бы
// пользователя с обрезанным файлом и потерянными профилями.
func (s *Profiles) flush() error {
	stored := make([]profile.Profile, 0, len(s.data))
	for _, p := range s.List() {
		enc, err := p.TransformSecrets(encryptSecret)
		if err != nil {
			return fmt.Errorf("store: шифрование профиля %q: %w", p.ID, err)
		}
		stored = append(stored, enc)
	}

	f := fileFormat{Version: fileVersion, Profiles: stored}

	raw, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("store: сериализация: %w", err)
	}

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("store: создание каталога %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".profiles-*.tmp")
	if err != nil {
		return fmt.Errorf("store: временный файл: %w", err)
	}
	tmpName := tmp.Name()
	// Подчистить временный файл, если что-то пойдёт не так до переименования.
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return fmt.Errorf("store: запись: %w", err)
	}
	// Sync до Close: без него данные могут остаться в кэше ОС,
	// и внезапное отключение питания оставит пустой файл.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("store: сброс на диск: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("store: закрытие временного файла: %w", err)
	}

	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("store: переименование в %s: %w", s.path, err)
	}
	return nil
}
