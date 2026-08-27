// Package sockstls — исходящее соединение SOCKS5 поверх TLS.
//
// # Зачем понадобился свой тип
//
// В sing-box исходящее соединение SOCKS не имеет секции TLS: в его
// option.SOCKSOutboundOptions такого поля нет, и добавить его снаружи
// невозможно. Между тем SOCKS5, завёрнутый в TLS, — рабочая и распространённая
// схема: она скрывает от наблюдателя сам факт использования SOCKS и защищает
// пароль, который в SOCKS5 передаётся открытым текстом.
//
// # Почему это не форк
//
// Реализация протокола SOCKS не переписана. Взят тот же socks.Client из sing,
// что использует само ядро, но ему передан диалер, оборачивающий соединение в
// TLS. Вся разница с обычным аутбаундом SOCKS — в одной строке, где
// создаётся диалер.
//
// Тип регистрируется в реестре аутбаундов перед сборкой ядра, см.
// corehost.Start. Точка расширения предусмотрена самим sing-box, поэтому
// форк ядра здесь не нужен — в отличие от обфускации AmneziaWG, где подмена
// вплетена в криптографию (ADR-001).
//
// # Ограничение: только TCP
//
// UDP через SOCKS5 работает по схеме UDP ASSOCIATE: управляющее соединение
// идёт по TCP, а сами данные — отдельным потоком UDP, который TLS не
// покрывает. Заворачивать управляющий канал в TLS, оставляя данные открытыми,
// значит создавать видимость защиты. Поэтому UDP отвергается явно.
package sockstls

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
)

// Type — имя типа в конфигурации ядра.
//
// Дефис в имени намеренный: он не может совпасть ни с одним встроенным типом
// sing-box, поэтому обновление ядра не приведёт к молчаливому перекрытию.
const Type = "socks-tls"

// Options — параметры аутбаунда.
//
// Встраивание option.SOCKSOutboundOptions даёт весь набор полей обычного
// SOCKS (адрес, версия, учётные данные, параметры диалера), а
// OutboundTLSOptionsContainer добавляет секцию TLS. Собственных полей здесь
// нет: любое расхождение с обычным SOCKS пришлось бы поддерживать вручную.
type Options struct {
	option.SOCKSOutboundOptions
	option.OutboundTLSOptionsContainer
}

// RegisterOutbound добавляет тип в реестр аутбаундов.
func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[Options](registry, Type, NewOutbound)
}

var _ adapter.Outbound = (*Outbound)(nil)

// Outbound — исходящее соединение SOCKS5 поверх TLS.
type Outbound struct {
	outbound.Adapter
	logger logger.ContextLogger
	client *socks.Client
}

// NewOutbound собирает аутбаунд.
func NewOutbound(
	ctx context.Context,
	router adapter.Router,
	logger log.ContextLogger,
	tag string,
	options Options,
) (adapter.Outbound, error) {
	if options.TLS == nil || !options.TLS.Enabled {
		// Без TLS этот тип не имеет смысла и лишь маскирует ошибку
		// конфигурации: получился бы обычный SOCKS под чужим именем.
		return nil, E.New(Type + ": секция TLS не задана; для SOCKS без TLS используйте тип socks")
	}

	baseDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}

	// Здесь и заключена вся разница с обычным аутбаундом SOCKS: клиент
	// протокола получает диалер, который поверх TCP устанавливает TLS.
	tlsDialer, err := tls.NewDialerFromOptions(ctx, logger, baseDialer, options.Server, *options.TLS)
	if err != nil {
		return nil, err
	}

	version := socks.Version5
	if options.Version != "" {
		version, err = socks.ParseVersion(options.Version)
		if err != nil {
			return nil, err
		}
		if version != socks.Version5 {
			// SOCKS4 не умеет аутентификацию и не встречается поверх TLS.
			// Отвергаем явно, а не молча понижаем версию.
			return nil, E.New(Type + ": поддерживается только SOCKS версии 5")
		}
	}

	return &Outbound{
		Adapter: outbound.NewAdapterWithDialerOptions(
			Type, tag, []string{N.NetworkTCP}, options.DialerOptions),
		logger: logger,
		client: socks.NewClient(
			tlsDialer, options.ServerOptions.Build(), version,
			options.Username, options.Password),
	}, nil
}

// DialContext открывает соединение к назначению через SOCKS-сервер.
func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination

	if N.NetworkName(network) != N.NetworkTCP {
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}

	h.logger.InfoContext(ctx, "outbound connection to ", destination)
	return h.client.DialContext(ctx, network, destination)
}

// ListenPacket отвергает UDP.
//
// Причина — в описании пакета: TLS покрывает только управляющее соединение
// SOCKS5, а данные UDP идут мимо него. Молчаливое согласие означало бы
// передачу трафика в открытом виде там, где пользователь выбрал защищённый
// профиль.
func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, E.New(Type + ": UDP не поддерживается (TLS не покрывает поток данных UDP ASSOCIATE)")
}
