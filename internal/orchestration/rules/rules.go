// Package rules — модель раздельной маршрутизации.
//
// Формализация требования T4 из анализа: заказчик описал «два режима», но по
// существу это одно и то же — действие по умолчанию плюс список исключений.
//
//	«Только выбранное через туннель»      → Default = Direct, правила → Proxy
//	«Всё через туннель, кроме выбранного» → Default = Proxy,  правила → Direct
//
// Плюс третье действие, необходимое технически: Block — для kill-switch и
// блокировки рекламы и телеметрии.
//
// В И-1 поддерживаются матчеры по домену и по IP/CIDR. Матчер по процессу,
// regex, GeoIP, порту и протоколу добавляются в И-7.
package rules

import (
	"fmt"
	"net/netip"
	"strings"
)

// Action — что сделать с соединением.
type Action string

const (
	ActionProxy  Action = "proxy"
	ActionDirect Action = "direct"
	ActionBlock  Action = "block"
)

// Matcher — предикат соединения. Пустой матчер недопустим.
type Matcher struct {
	// Domain — точное совпадение доменного имени.
	Domain []string `json:"domain,omitempty"`
	// DomainSuffix — совпадение по суффиксу: "example.com" покроет и "a.example.com".
	DomainSuffix []string `json:"domain_suffix,omitempty"`
	// IPCIDR — подсеть назначения в формате CIDR.
	IPCIDR []string `json:"ip_cidr,omitempty"`
}

func (m Matcher) isEmpty() bool {
	return len(m.Domain) == 0 && len(m.DomainSuffix) == 0 && len(m.IPCIDR) == 0
}

// Rule — правило маршрутизации.
type Rule struct {
	Matcher
	Action Action `json:"action"`
}

// Policy — политика маршрутизации целиком.
//
// Порядок правил значим: выигрывает ПЕРВОЕ совпадение. Так же ведёт себя
// ядро, и это осознанный выбор из 03-architecture.md §4.2 — семантику проще
// объяснить пользователю и проще отладить, чем «самое специфичное выигрывает».
type Policy struct {
	Default Action `json:"default"`
	Rules   []Rule `json:"rules,omitempty"`
}

// PolicyOnlySelected — «только выбранное через туннель».
// Всё идёт напрямую, кроме того, что явно перечислено.
func PolicyOnlySelected(rules ...Rule) Policy {
	return Policy{Default: ActionDirect, Rules: rules}
}

// PolicyAllExcept — «всё через туннель, кроме выбранного».
func PolicyAllExcept(rules ...Rule) Policy {
	return Policy{Default: ActionProxy, Rules: rules}
}

// Validate проверяет политику. Часть меры S3: всё, что придёт от клиента,
// проверяется до сборки конфигурации ядра.
func (p Policy) Validate() error {
	switch p.Default {
	case ActionProxy, ActionDirect:
	case ActionBlock:
		// Блокировка по умолчанию означала бы «запретить весь трафик».
		// Такое состояние существует, но задаётся политикой onAllDown
		// (И-10), а не пользовательским правилом маршрутизации.
		return fmt.Errorf("rules: действие по умолчанию не может быть %q", ActionBlock)
	default:
		return fmt.Errorf("rules: неизвестное действие по умолчанию %q", p.Default)
	}

	for i, r := range p.Rules {
		if err := r.validate(); err != nil {
			return fmt.Errorf("rules: правило #%d: %w", i+1, err)
		}
	}
	return nil
}

func (r Rule) validate() error {
	switch r.Action {
	case ActionProxy, ActionDirect, ActionBlock:
	default:
		return fmt.Errorf("неизвестное действие %q", r.Action)
	}
	if r.isEmpty() {
		return fmt.Errorf("пустой матчер: правило не может совпасть ни с чем")
	}
	for _, d := range append(append([]string{}, r.Domain...), r.DomainSuffix...) {
		if strings.TrimSpace(d) == "" {
			return fmt.Errorf("пустое доменное имя")
		}
	}
	for _, c := range r.IPCIDR {
		if _, err := netip.ParsePrefix(c); err != nil {
			return fmt.Errorf("некорректная подсеть %q: %w", c, err)
		}
	}
	return nil
}
