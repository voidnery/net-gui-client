package client

import pb "github.com/bbesport/net-gui-client/proto/netgui/v1"

// KindName возвращает отображаемое имя типа профиля.
//
// Единственное такое отображение на оба клиента — net-cli и net-gui.
// Раньше их было три: своё в службе, своё в CLI и своё в GUI. Расхождение
// обнаружилось ровно так, как и должно было: после добавления новых типов
// в контракт графический интерфейс показал импортированный профиль
// Hysteria2 как «unknown», потому что его копию таблицы никто не поправил.
//
// Имена совпадают со значениями profile.Kind внутри службы — так вывод
// net-cli, GUI и файла профилей читается одинаково.
func KindName(k pb.Kind) string {
	switch k {
	case pb.Kind_KIND_SOCKS5:
		return "socks5"
	case pb.Kind_KIND_HYSTERIA2:
		return "hysteria2"
	case pb.Kind_KIND_WIREGUARD:
		return "wireguard"
	case pb.Kind_KIND_AMNEZIAWG:
		return "amneziawg"
	case pb.Kind_KIND_VLESS:
		return "vless"
	default:
		return "unknown"
	}
}
