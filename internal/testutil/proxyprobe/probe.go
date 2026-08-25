// Package proxyprobe — общие помощники тестов, обращающихся через локальный
// прокси приложения.
//
// Вынесены из тестов пакетов corehost и session, где до рефакторинга жили две
// почти одинаковые копии. Помощник маленький, но правило простое: как только
// у копии появляется вторая версия, расхождение — вопрос времени, а
// расхождение в тестовой оснастке даёт ложное чувство покрытия.
package proxyprobe

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// DefaultTimeout — предел ожидания одного запроса через прокси.
const DefaultTimeout = 10 * time.Second

// Get выполняет HTTP-запрос через локальный прокси и возвращает тело ответа.
//
// proxyAddr — адрес вида "127.0.0.1:1080".
func Get(proxyAddr, targetURL string) (string, error) {
	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		return "", fmt.Errorf("proxyprobe: разбор адреса прокси %q: %w", proxyAddr, err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			// Keep-alive выключен намеренно: иначе соединение переживает
			// запрос, и следующий случай табличного теста получит счётчик
			// прокси, испорченный предыдущим.
			DisableKeepAlives: true,
		},
		Timeout: DefaultTimeout,
	}

	resp, err := client.Get(targetURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("proxyprobe: код ответа %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	return string(body), err
}

// FreePort подбирает свободный TCP-порт на loopback-интерфейсе.
//
// Между возвратом порта и его занятием есть окно гонки. Для тестов это
// приемлемо; в рабочем коде порт подбирает session.Manager, который
// передаёт его ядру сразу.
func FreePort() (uint16, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("proxyprobe: подбор свободного порта: %w", err)
	}
	defer ln.Close()
	return uint16(ln.Addr().(*net.TCPAddr).Port), nil
}
