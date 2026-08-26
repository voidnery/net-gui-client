// Command e3-awg-probe — стенд эксперимента E3.
//
// Вопрос эксперимента: совместима ли наша реализация обфускации AmneziaWG
// с настоящим сервером?
//
// Модульные тесты пакета internal/awg доказывают, что преобразование
// обратимо САМО СЕБЕ. Реализация, ошибочная относительно эталона, прошла бы
// их все и провалилась здесь. Настоящий ответ даёт только живой сервер.
//
// Метод:
//  1. разобрать файл конфигурации wg-quick;
//  2. поднять ядро с этим профилем и локальным прокси;
//  3. выполнить HTTP-запрос через прокси;
//  4. сравнить внешний IP-адрес с адресом без туннеля.
//
// Четвёртый шаг обязателен: успешный запрос сам по себе не доказывает, что
// трафик пошёл через туннель — он мог уйти напрямую.
package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"time"

	"github.com/bbesport/net-gui-client/internal/corehost"
	"github.com/bbesport/net-gui-client/internal/orchestration/profile"
	"github.com/bbesport/net-gui-client/internal/orchestration/rules"
)

// ipEndpoint возвращает внешний адрес обычным текстом.
const ipEndpoint = "http://ifconfig.me/ip"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "использование: e3-awg-probe <путь к .conf>")
		os.Exit(2)
	}
	if err := run(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, "\nFAIL:", err)
		os.Exit(1)
	}
}

func run(path string) error {
	fmt.Println("=== E3: совместимость обфускации AmneziaWG с живым сервером ===")

	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("чтение файла конфигурации: %w", err)
	}

	p, err := profile.ParseWireGuardConf("e3", "E3 probe", string(raw))
	if err != nil {
		return fmt.Errorf("разбор конфигурации: %w", err)
	}

	// ⚠️ Секреты не печатаются: файл содержит приватный ключ и PSK.
	fmt.Printf("\nПрофиль разобран:\n")
	fmt.Printf("  тип:       %s\n", p.Kind)
	fmt.Printf("  сервер:    %s:%d\n", p.Server, p.Port)
	fmt.Printf("  адрес:     %v\n", p.WireGuard.Address)
	fmt.Printf("  MTU:       %d\n", p.WireGuard.MTU)
	if o := p.WireGuard.Obfuscation; o != nil {
		fmt.Printf("  обфускация: Jc=%d Jmin=%d Jmax=%d S1=%d S2=%d\n",
			o.Jc, o.Jmin, o.Jmax, o.S1, o.S2)
		fmt.Printf("              H1=%d H2=%d H3=%d H4=%d\n", o.H1, o.H2, o.H3, o.H4)
	} else {
		fmt.Printf("  обфускация: нет (обычный WireGuard)\n")
	}

	// Шаг 1 — контрольный замер: внешний адрес БЕЗ туннеля.
	fmt.Print("\n[1] Внешний адрес без туннеля ... ")
	direct, err := externalIP(nil)
	if err != nil {
		return fmt.Errorf("контрольный замер не удался, эксперимент невалиден: %w", err)
	}
	fmt.Println(direct)

	// Шаг 2 — поднимаем ядро.
	port, err := freePort()
	if err != nil {
		return fmt.Errorf("подбор порта: %w", err)
	}

	fmt.Printf("[2] Запуск ядра, локальный прокси 127.0.0.1:%d ... ", port)
	core, err := corehost.Start(context.Background(), corehost.Config{
		ListenAddr: netip.MustParseAddr("127.0.0.1"),
		ListenPort: port,
		Profile:    p,
		Policy:     rules.PolicyAllExcept(),
	})
	if err != nil {
		return fmt.Errorf("запуск ядра: %w", err)
	}
	defer func() {
		if cerr := core.Close(); cerr != nil {
			fmt.Fprintln(os.Stderr, "предупреждение: остановка ядра:", cerr)
		}
	}()
	fmt.Println("готово")

	// Рукопожатие WireGuard занимает время; кроме того, перед ним уходят
	// мусорные пакеты.
	fmt.Print("[3] Ожидание установления туннеля ... ")
	time.Sleep(3 * time.Second)
	fmt.Println("готово")

	// Шаг 4 — основной замер.
	fmt.Print("[4] Внешний адрес ЧЕРЕЗ туннель ... ")
	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	tunneled, err := externalIP(proxyURL)
	if err != nil {
		fmt.Println("ОТКАЗ")
		return fmt.Errorf(`запрос через туннель не прошёл: %w

  Это означает, что рукопожатие с сервером не состоялось.
  Наиболее вероятные причины:
    • расхождение реализации обфускации с эталоном;
    • сервер недоступен или параметры устарели.

  Для диагностики запустите с подробным журналом ядра:
    set NETGUI_CORE_LOG=debug`, err)
	}
	fmt.Println(tunneled)

	fmt.Println("\n=== РЕЗУЛЬТАТ ===")
	if tunneled == direct {
		fmt.Println("❌ ОТРИЦАТЕЛЬНЫЙ: внешний адрес не изменился.")
		fmt.Println("   Запрос прошёл, но МИМО туннеля — маршрутизация не сработала.")
		return fmt.Errorf("трафик не пошёл через туннель")
	}

	fmt.Println("✅ ПОЛОЖИТЕЛЬНЫЙ: трафик идёт через туннель AmneziaWG.")
	fmt.Printf("   без туннеля: %s\n", direct)
	fmt.Printf("   через туннель: %s\n", tunneled)
	fmt.Println("\n   Обфускация совместима с эталонной реализацией: сервер принял")
	fmt.Println("   наши пакеты, рукопожатие состоялось, данные передаются.")
	return nil
}

func externalIP(proxy *url.URL) (string, error) {
	transport := &http.Transport{DisableKeepAlives: true}
	if proxy != nil {
		transport.Proxy = http.ProxyURL(proxy)
	}
	client := &http.Client{Transport: transport, Timeout: 20 * time.Second}

	resp, err := client.Get(ipEndpoint)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("код ответа %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 128))
	if err != nil {
		return "", err
	}
	return string(trimSpace(body)), nil
}

func trimSpace(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r' || b[len(b)-1] == ' ') {
		b = b[:len(b)-1]
	}
	return b
}

func freePort() (uint16, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return uint16(ln.Addr().(*net.TCPAddr).Port), nil
}
