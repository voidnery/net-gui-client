package profile

import (
	"bufio"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// ParseWireGuardConf разбирает конфигурацию формата wg-quick.
//
// Поддерживаются как обычный WireGuard, так и AmneziaWG: различие только в
// наличии параметров обфускации (Jc, Jmin, Jmax, S1, S2, H1–H4). Тип
// профиля определяется по их наличию, а не по имени файла — имя может быть
// любым, а содержимое однозначно.
//
// Формат намеренно разбирается вручную, без сторонней библиотеки: он прост,
// а зависимость ради полусотни строк увеличивала бы поверхность проекта.
func ParseWireGuardConf(id, name, content string) (Profile, error) {
	var (
		section string
		iface   = struct {
			privateKey string
			addresses  []netip.Prefix
			dns        []string
			mtu        uint32
		}{}
		peer = struct {
			publicKey    string
			presharedKey string
			endpoint     string
			allowedIPs   []netip.Prefix
			keepalive    uint16
		}{}
		obfs    AmneziaParams
		hasObfs bool
	)

	scanner := bufio.NewScanner(strings.NewReader(content))
	lineNo := 0

	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())

		// Комментарии и пустые строки. В файлах AmneziaWG комментарии несут
		// пояснения вроде «must match server» — они нам не нужны.
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.Trim(line, "[]"))
			continue
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return Profile{}, fmt.Errorf("строка %d: ожидалось «ключ = значение», получено %q", lineNo, line)
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)

		switch section {
		case "interface":
			switch key {
			case "privatekey":
				iface.privateKey = value
			case "address":
				prefixes, err := parsePrefixList(value)
				if err != nil {
					return Profile{}, fmt.Errorf("строка %d, Address: %w", lineNo, err)
				}
				iface.addresses = prefixes
			case "dns":
				for _, s := range strings.Split(value, ",") {
					if s = strings.TrimSpace(s); s != "" {
						iface.dns = append(iface.dns, s)
					}
				}
			case "mtu":
				n, err := strconv.ParseUint(value, 10, 32)
				if err != nil {
					return Profile{}, fmt.Errorf("строка %d, MTU: %w", lineNo, err)
				}
				iface.mtu = uint32(n)

			// Параметры обфускации AmneziaWG.
			case "jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4":
				n, err := strconv.ParseUint(value, 10, 32)
				if err != nil {
					return Profile{}, fmt.Errorf("строка %d, %s: %w", lineNo, key, err)
				}
				hasObfs = true
				switch key {
				case "jc":
					obfs.Jc = int(n)
				case "jmin":
					obfs.Jmin = int(n)
				case "jmax":
					obfs.Jmax = int(n)
				case "s1":
					obfs.S1 = int(n)
				case "s2":
					obfs.S2 = int(n)
				case "h1":
					obfs.H1 = uint32(n)
				case "h2":
					obfs.H2 = uint32(n)
				case "h3":
					obfs.H3 = uint32(n)
				case "h4":
					obfs.H4 = uint32(n)
				}
			}

		case "peer":
			switch key {
			case "publickey":
				peer.publicKey = value
			case "presharedkey":
				peer.presharedKey = value
			case "endpoint":
				peer.endpoint = value
			case "allowedips":
				prefixes, err := parsePrefixList(value)
				if err != nil {
					return Profile{}, fmt.Errorf("строка %d, AllowedIPs: %w", lineNo, err)
				}
				peer.allowedIPs = prefixes
			case "persistentkeepalive":
				n, err := strconv.ParseUint(value, 10, 16)
				if err != nil {
					return Profile{}, fmt.Errorf("строка %d, PersistentKeepalive: %w", lineNo, err)
				}
				peer.keepalive = uint16(n)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return Profile{}, fmt.Errorf("чтение конфигурации: %w", err)
	}

	if peer.endpoint == "" {
		return Profile{}, fmt.Errorf("в конфигурации не задан Endpoint")
	}
	host, portStr, err := splitHostPort(peer.endpoint)
	if err != nil {
		return Profile{}, fmt.Errorf("Endpoint %q: %w", peer.endpoint, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return Profile{}, fmt.Errorf("Endpoint %q: некорректный порт: %w", peer.endpoint, err)
	}

	p := Profile{
		ID:     id,
		Name:   name,
		Kind:   KindWireGuard,
		Server: host,
		Port:   uint16(port),
		WireGuard: &WireGuardParams{
			PrivateKey:    iface.privateKey,
			Address:       iface.addresses,
			MTU:           iface.mtu,
			DNS:           iface.dns,
			PeerPublicKey: peer.publicKey,
			PresharedKey:  peer.presharedKey,
			AllowedIPs:    peer.allowedIPs,
			Keepalive:     peer.keepalive,
		},
	}

	// Тип определяется содержимым, а не именем файла: конфигурация с
	// параметрами обфускации — это AmneziaWG, без них — обычный WireGuard.
	if hasObfs {
		p.Kind = KindAmneziaWG
		p.WireGuard.Obfuscation = &obfs
	}

	return p, p.Validate()
}

func parsePrefixList(value string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// wg-quick допускает и голый адрес, и подсеть. Голый адрес означает
		// префикс с полной маской.
		if prefix, err := netip.ParsePrefix(part); err == nil {
			out = append(out, prefix)
			continue
		}
		addr, err := netip.ParseAddr(part)
		if err != nil {
			return nil, fmt.Errorf("некорректный адрес %q", part)
		}
		out = append(out, netip.PrefixFrom(addr, addr.BitLen()))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("пустой список адресов")
	}
	return out, nil
}

// splitHostPort разделяет «хост:порт», учитывая адреса IPv6 в скобках.
func splitHostPort(s string) (string, string, error) {
	if strings.HasPrefix(s, "[") {
		end := strings.LastIndex(s, "]")
		if end < 0 || end+2 >= len(s) || s[end+1] != ':' {
			return "", "", fmt.Errorf("некорректный адрес IPv6")
		}
		return s[1:end], s[end+2:], nil
	}
	host, port, ok := strings.Cut(s, ":")
	if !ok {
		return "", "", fmt.Errorf("не указан порт")
	}
	return host, port, nil
}
