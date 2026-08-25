// Command testsrv-socks5 — тестовый SOCKS5-сервер для стенда разработки.
//
// Играет роль вышестоящего VPN-сервера, когда настоящий не нужен или
// недоступен. Ведёт журнал обращений, поэтому по его выводу видно, пошёл ли
// трафик через прокси — а это ровно то, что нужно проверять при отладке
// правил маршрутизации.
//
// Не входит в поставку продукта.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	testsocks "github.com/bbesport/net-gui-client/internal/testutil/socks5"
)

func main() {
	addr := flag.String("listen", "127.0.0.1:0", "адрес прослушивания; порт 0 — выбрать свободный")
	flag.Parse()

	srv, err := testsocks.StartOn(*addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	defer srv.Close()

	// Машиночитаемая строка в ASCII — чтобы скриптам не приходилось
	// разбирать человеческий текст, который зависит от кодировки консоли.
	fmt.Printf("LISTEN %s\n", srv.Addr())
	fmt.Println("журнал обращений выводится ниже. Ctrl+C для остановки.")

	// Печатаем только новые записи журнала.
	go func() {
		seen := 0
		for range time.Tick(300 * time.Millisecond) {
			targets := srv.Targets()
			for ; seen < len(targets); seen++ {
				fmt.Printf("  [%s] CONNECT %s\n",
					time.Now().Format("15:04:05"), targets[seen])
			}
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig

	fmt.Printf("\nвсего обслужено запросов: %d\n", srv.Count())
}
