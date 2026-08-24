module github.com/bbesport/net-gui-client

go 1.26

// net-core — форк sing-box (ADR-001). Директива replace подключается в И-1,
// когда форк будет создан. Module identity форка остаётся github.com/sagernet/sing-box,
// что делает ребейз на теги upstream механической операцией.
//
// replace github.com/sagernet/sing-box => ./net-core

require golang.org/x/sys v0.47.0
