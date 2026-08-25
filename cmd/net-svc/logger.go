package main

import (
	"fmt"
	"io"
)

// logger — минимальный журнал с уровнями.
//
// Уровни нужны не для красоты. Отклонённое подключение (мера S2) — событие
// безопасности: администратор должен уметь отфильтровать такие записи в
// журнале событий Windows. Пока всё писалось одним уровнем Information,
// попытка обхода защиты терялась среди строк вида «служба запущена».
//
// Полноценная подсистема журналирования с фильтрами и экспортом появится
// в И-12 вместе с экраном «Журнал». Здесь — необходимый минимум.
type logger interface {
	Info(format string, args ...any)
	Warn(format string, args ...any)
	Error(format string, args ...any)
}

// consoleLogger пишет в обычный поток вывода — режим отладки.
type consoleLogger struct {
	out io.Writer
}

func newConsoleLogger(out io.Writer) *consoleLogger { return &consoleLogger{out: out} }

func (l *consoleLogger) Info(format string, args ...any) {
	fmt.Fprintf(l.out, format+"\n", args...)
}

func (l *consoleLogger) Warn(format string, args ...any) {
	fmt.Fprintf(l.out, "ПРЕДУПРЕЖДЕНИЕ: "+format+"\n", args...)
}

func (l *consoleLogger) Error(format string, args ...any) {
	fmt.Fprintf(l.out, "ОШИБКА: "+format+"\n", args...)
}

// discardLogger — журнал, который ничего не пишет.
type discardLogger struct{}

func (discardLogger) Info(string, ...any)  {}
func (discardLogger) Warn(string, ...any)  {}
func (discardLogger) Error(string, ...any) {}
