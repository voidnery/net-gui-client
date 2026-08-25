// Package profile — декларативная модель подключения.
//
// Это НАША модель, а не конфигурация ядра. Разделение принципиально и
// продиктовано мерой S3 из ADR-006: служба не принимает от клиента сырой
// конфиг ядра, только декларативное описание, из которого конфиг собирается
// внутри службы. Прецедент, ради которого это сделано, — CVE-2024-6975.
//
// Побочная выгода: модель переживает смену версии ядра и не тянет его
// внутреннюю терминологию в интерфейс пользователя.
package profile

import (
	"fmt"
	"net/netip"
	"strings"
)

// Kind — тип транспорта наружу.
type Kind string

const (
	KindSOCKS5 Kind = "socks5"
	// Остальные типы добавляются в И-4:
	// KindVLESS, KindHysteria2, KindAmneziaWG, KindTrojan, KindShadowsocks...
)

// Profile — описание одного пути наружу.
//
// Секретные поля (Password и будущие ключи) в И-4 переедут в защищённое
// хранилище по мере S6; здесь они лежат открыто временно и только для
// вертикального среза.
type Profile struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Kind     Kind   `json:"kind"`
	Server   string `json:"server"`
	Port     uint16 `json:"port"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

// Validate проверяет профиль перед тем, как из него будет собран конфиг ядра.
//
// Проверка обязательна и выполняется на стороне службы: это часть меры S3.
// Всё, что приходит извне, считается недоверенным, включая ввод собственного GUI.
func (p Profile) Validate() error {
	if strings.TrimSpace(p.ID) == "" {
		return fmt.Errorf("profile: пустой идентификатор")
	}
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("profile %q: пустое имя", p.ID)
	}
	switch p.Kind {
	case KindSOCKS5:
	default:
		return fmt.Errorf("profile %q: неподдерживаемый тип %q", p.ID, p.Kind)
	}
	if strings.TrimSpace(p.Server) == "" {
		return fmt.Errorf("profile %q: не задан адрес сервера", p.ID)
	}
	// Адрес может быть как IP, так и доменным именем — проверяем лишь то,
	// что это не мусор и не пустая строка с пробелами.
	if _, err := netip.ParseAddr(p.Server); err != nil && !isPlausibleHost(p.Server) {
		return fmt.Errorf("profile %q: некорректный адрес сервера %q", p.ID, p.Server)
	}
	if p.Port == 0 {
		return fmt.Errorf("profile %q: не задан порт", p.ID)
	}
	return nil
}

func isPlausibleHost(s string) bool {
	if len(s) > 253 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}
