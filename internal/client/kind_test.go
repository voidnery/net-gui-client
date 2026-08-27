package client

import (
	"testing"

	pb "github.com/bbesport/net-gui-client/proto/netgui/v1"
)

// TestKindNameCoversContract закрывает дефект, найденный при живой проверке
// интерфейса: тип профиля добавили в контракт, а таблицу отображения — нет,
// и пользователь увидел «unknown» вместо «hysteria2».
//
// Проверка идёт по СГЕНЕРИРОВАННОЙ карте значений перечисления. Поэтому
// добавление нового типа в .proto само по себе роняет тест, и забыть про
// имя невозможно — список значений здесь не продублирован.
func TestKindNameCoversContract(t *testing.T) {
	for value, name := range pb.Kind_name {
		kind := pb.Kind(value)
		if kind == pb.Kind_KIND_UNSPECIFIED {
			continue // «не задано» осмысленного имени не имеет
		}

		if got := KindName(kind); got == "unknown" {
			t.Errorf("для %s (=%d) нет отображаемого имени", name, value)
		}
	}
}

// TestKindNameUnknownForUnspecified: значение вне контракта обязано давать
// «unknown», а не пустую строку — пустота в списке профилей выглядит как
// ошибка отрисовки.
func TestKindNameUnknownForUnspecified(t *testing.T) {
	if got := KindName(pb.Kind(9999)); got != "unknown" {
		t.Errorf("KindName для неизвестного значения = %q", got)
	}
}
