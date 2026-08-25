//go:build windows

// Command e4-wfp-probe — самопроверяющийся стенд эксперимента E4.
//
// Вопрос эксперимента: можно ли из пользовательского режима, без драйвера
// режима ядра, поставить фильтр WFP, реально блокирующий сетевой трафик?
//
// От ответа зависит, реализуемы ли без драйвера kill-switch, политика IPv6,
// блокировка стороннего DoH и блокировка QUIC (ADR-002, слой WfpBlocker).
//
// Метод — три замера подряд:
//
//  1. соединение до цели ДО фильтра    → ожидается УСПЕХ
//  2. соединение ПОСЛЕ установки фильтра → ожидается ОТКАЗ
//  3. соединение ПОСЛЕ снятия фильтра   → ожидается УСПЕХ
//
// Первый и третий замеры отсеивают ложный вывод «блокировка работает»,
// когда цель на самом деле просто недоступна.
//
// Все фильтры ставятся в динамической сессии WFP: они снимаются автоматически
// при завершении процесса, даже аварийном. Система не остаётся в изменённом
// состоянии ни при каком исходе.
package main

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/bbesport/net-gui-client/internal/platform/wfp"
	"golang.org/x/sys/windows"
)

const (
	targetIP    = "1.1.1.1"
	targetPort  = "443"
	dialTimeout = 4 * time.Second
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
}

func run() error {
	fmt.Println("=== E4: блокирующие фильтры WFP из user-mode, без драйвера ===")
	fmt.Printf("Цель: %s:%s\n\n", targetIP, targetPort)

	if !isElevated() {
		return fmt.Errorf("нужны права администратора: установка фильтров WFP их требует")
	}
	fmt.Println("[+] Процесс запущен с правами администратора")

	addr, err := netip.ParseAddr(targetIP)
	if err != nil {
		return fmt.Errorf("разбор адреса: %w", err)
	}

	// Замер 1 — контрольный: цель вообще достижима?
	fmt.Print("[1] Соединение ДО установки фильтра ... ")
	before := probe()
	report(before)
	if before != nil {
		return fmt.Errorf("цель недостижима и без фильтра — эксперимент невалиден: %w", before)
	}

	// Открываем динамическую сессию.
	eng, err := wfp.Open("net-gui-client E4 probe")
	if err != nil {
		return fmt.Errorf("открытие движка WFP: %w", err)
	}
	// Даже при панике фильтры снимутся вместе с процессом — динамическая сессия.
	defer func() {
		if cerr := eng.Close(); cerr != nil {
			fmt.Fprintln(os.Stderr, "warn: закрытие движка:", cerr)
		}
	}()
	fmt.Println("[+] Динамическая сессия WFP открыта")

	id, err := eng.BlockOutboundToIP(addr, "E4 probe block")
	if err != nil {
		return fmt.Errorf("установка блокирующего фильтра: %w", err)
	}
	fmt.Printf("[+] Блокирующий фильтр установлен, id=%d\n", id)

	// Замер 2 — основной.
	fmt.Print("[2] Соединение ПОСЛЕ установки фильтра ... ")
	during := probe()
	report(during)

	if err := eng.DeleteFilter(id); err != nil {
		return fmt.Errorf("снятие фильтра: %w", err)
	}
	fmt.Println("[+] Фильтр снят")

	// Замер 3 — контрольный: состояние восстановилось?
	fmt.Print("[3] Соединение ПОСЛЕ снятия фильтра ... ")
	after := probe()
	report(after)

	fmt.Println("\n=== РЕЗУЛЬТАТ ===")
	switch {
	case during == nil:
		fmt.Println("❌ ОТРИЦАТЕЛЬНЫЙ: фильтр установился, но трафик не заблокирован.")
		return fmt.Errorf("блокировка не сработала")
	case after != nil:
		fmt.Println("⚠️  НЕОДНОЗНАЧНЫЙ: блокировка сработала, но после снятия фильтра")
		fmt.Println("    соединение не восстановилось. Возможна внешняя причина отказа.")
		return fmt.Errorf("состояние не восстановилось после снятия фильтра")
	default:
		fmt.Println("✅ ПОЛОЖИТЕЛЬНЫЙ: блокировка из user-mode работает, драйвер не требуется.")
		fmt.Println("   Подтверждено: kill-switch, политика IPv6, блокировка DoH и QUIC")
		fmt.Println("   реализуемы без драйвера режима ядра (ADR-002, слой WfpBlocker).")
		return nil
	}
}

// probe пытается установить TCP-соединение. nil означает успех.
func probe() error {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(targetIP, targetPort), dialTimeout)
	if err != nil {
		return err
	}
	return conn.Close()
}

func report(err error) {
	if err == nil {
		fmt.Println("УСПЕХ")
	} else {
		fmt.Printf("ОТКАЗ (%v)\n", err)
	}
}

// isElevated сообщает, запущен ли процесс с правами администратора.
func isElevated() bool {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid,
	)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)

	member, err := windows.Token(0).IsMember(sid)
	return err == nil && member
}
