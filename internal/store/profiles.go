// Package store — хранилище профилей на диске.
//
// В И-1 это простой JSON-файл. Требования меры S5 (каталог данных службы
// недоступен на запись непривилегированным пользователям) и S6 (секреты
// через DPAPI) реализуются в И-2 и И-4 соответственно; здесь заложена
// точка, куда они встанут.
package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/bbesport/net-gui-client/internal/orchestration/profile"
)

// Profiles — потокобезопасное хранилище профилей.
type Profiles struct {
	path string

	mu   sync.RWMutex
	data map[string]profile.Profile
}

type fileFormat struct {
	Version  int               `json:"version"`
	Profiles []profile.Profile `json:"profiles"`
}

// OpenProfiles открывает или создаёт хранилище по указанному пути.
func OpenProfiles(path string) (*Profiles, error) {
	s := &Profiles{path: path, data: make(map[string]profile.Profile)}

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
	for _, p := range f.Profiles {
		s.data[p.ID] = p
	}
	return s, nil
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
	s.data[p.ID] = p
	s.mu.Unlock()
	return s.flush()
}

// Remove удаляет профиль. Удаление отсутствующего — не ошибка.
func (s *Profiles) Remove(id string) error {
	s.mu.Lock()
	delete(s.data, id)
	s.mu.Unlock()
	return s.flush()
}

// flush записывает хранилище на диск атомарно: сначала во временный файл,
// затем переименование. Иначе падение посреди записи оставило бы
// пользователя с обрезанным файлом и потерянными профилями.
func (s *Profiles) flush() error {
	f := fileFormat{Version: 1, Profiles: s.List()}

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
