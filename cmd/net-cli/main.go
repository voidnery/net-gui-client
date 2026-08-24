// Command net-cli — клиент управления службой net-svc.
//
// Принцип P1 (headless-first): CLI покрывает 100% функций GUI и является
// эталонным потребителем контракта gRPC. См. ADR-004.
//
// На итерации И-0 это заготовка: она существует, чтобы CI имел что собирать,
// и чтобы задать структуру, которая наполнится в И-1.
package main

import (
	"fmt"
	"os"
	"runtime"
)

// Version подставляется линкером при сборке:
//
//	go build -ldflags "-X main.Version=1.2.3"
//
// Пустое значение означает сборку из рабочего дерева, а не из релиза.
var Version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		// Ошибки идут в stderr, результат работы — в stdout.
		// Это позволяет использовать CLI в конвейерах и в интеграционных тестах.
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// run отделён от main, чтобы код был тестируемым: main умеет только
// завершать процесс, а вся логика живёт в функции, возвращающей error.
func run(args []string) error {
	if len(args) == 0 {
		usage()
		return nil
	}

	switch args[0] {
	case "version":
		fmt.Printf("net-cli %s (%s %s/%s)\n",
			Version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		return nil
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		return fmt.Errorf("unknown command %q (try 'net-cli help')", args[0])
	}
}

func usage() {
	fmt.Println(`net-cli — управление службой net-svc

Использование:
  net-cli <команда> [аргументы]

Команды:
  version    показать версию
  help       эта справка`)
}
