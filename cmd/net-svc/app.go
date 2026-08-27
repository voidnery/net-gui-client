package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/bbesport/net-gui-client/internal/ipc"
	"github.com/bbesport/net-gui-client/internal/orchestration/session"
	"github.com/bbesport/net-gui-client/internal/platform/secdir"
	"github.com/bbesport/net-gui-client/internal/store"

	"google.golang.org/grpc"
)

// app — рабочее тело службы, общее для консольного режима и режима службы
// Windows. Разделение существует, чтобы отлаживать логику в консоли, не
// устанавливая службу на каждый прогон.
type app struct {
	log      logger
	manager  *session.Manager
	grpc     *grpc.Server
	listener net.Listener
	stopped  chan struct{}
}

// newApp собирает службу: проверяет окружение, открывает хранилище,
// поднимает канал управления.
func newApp(ctx context.Context, log logger) (*app, error) {
	installDir, err := installDir()
	if err != nil {
		return nil, err
	}

	// Мера S4: каталог, из которого запущена служба, не должен быть доступен
	// на запись непривилегированным пользователям.
	//
	// Это важнее, чем кажется. Служба работает под LocalSystem. Если её
	// исполняемый файл лежит там, куда может писать обычный пользователь, то
	// подмена файла даёт выполнение кода с правами SYSTEM при следующем
	// запуске — прямое повышение привилегий. Ровно так устроена CVE-2025-8069.
	//
	// Побочно от этого зависит и мера S2: проверка «клиент запущен из
	// доверенного каталога» бессмысленна, если в этот каталог может писать
	// кто угодно.
	if err := verifyInstallDir(installDir, log); err != nil {
		return nil, err
	}

	dataDir, err := ensureDataDir()
	if err != nil {
		return nil, err
	}

	// Мера S5: каталог данных не должен быть доступен на запись
	// непривилегированным пользователям. Провал проверки — отказ запуска.
	if err := verifyDataDir(dataDir, log); err != nil {
		return nil, err
	}

	profiles, err := store.OpenProfiles(filepath.Join(dataDir, "profiles.json"))
	if err != nil {
		return nil, err
	}
	// Профили, которые не удалось расшифровать, не отменяют запуск, но обязаны
	// быть названы: иначе они просто исчезнут из списка, и пользователь решит,
	// что приложение потеряло его настройки. Самая частая причина — файл
	// перенесён с другой машины, а ключ DPAPI принадлежит машине (мера S6).
	for _, e := range profiles.LoadErrors() {
		log.Warn("%v", e)
	}

	manager := session.NewManager(ctx)

	// Мера S2: клиент обязан быть запущен из каталога установки.
	// В режиме разработчика проверка отключается — двоичные файлы при
	// разработке лежат в рабочем дереве, а не в %ProgramFiles%.
	trustedDir := installDir
	if devMode {
		trustedDir = ""
	}

	ln, err := ipc.Listen(ipc.ListenOptions{
		TrustedDir: trustedDir,
		OnReject: func(info ipc.ClientInfo, err error) {
			// Молча отброшенное подключение неотличимо от «клиент не
			// запускается». Пишем в журнал всегда.
			//
			// Путь выводится через %s, а не %q: в Windows-путях %q удваивает
			// обратные слэши, и запись становится нечитаемой глазами — а
			// читать её будут именно глазами, при разборе инцидента.
			log.Warn("ОТКЛОНЕНО подключение: pid=%d путь=%s\n  причина: %v",
				info.PID, info.ImagePath, err)
		},
	})
	if err != nil {
		_ = manager.Close()
		return nil, err
	}

	grpcServer := grpc.NewServer()
	ipc.NewServer(Version, profiles, manager).Register(grpcServer)

	log.Info("net-svc %s", Version)
	log.Info("каталог установки:   %s", installDir)
	log.Info("каталог данных:      %s", dataDir)
	log.Info("канал управления:    %s", ipc.PipeName)
	if devMode {
		log.Warn("проверка клиентов ОТКЛЮЧЕНА (режим разработчика)")
	} else {
		log.Info("проверка клиентов:   включена, доверенный каталог %s", installDir)
	}

	return &app{
		log:      log,
		manager:  manager,
		grpc:     grpcServer,
		listener: ln,
		stopped:  make(chan struct{}),
	}, nil
}

// serve обслуживает канал управления до вызова stop.
func (a *app) serve() error {
	return a.grpc.Serve(a.listener)
}

// stop останавливает службу корректно: перестаёт принимать вызовы,
// затем гасит активную сессию.
func (a *app) stop() {
	select {
	case <-a.stopped:
		return
	default:
		close(a.stopped)
	}

	a.grpc.GracefulStop()

	// Сессия гасится ПОСЛЕ остановки приёма вызовов: иначе клиент успел бы
	// переподключиться между двумя действиями и оставить туннель поднятым
	// у остановленной службы.
	if err := a.manager.Close(); err != nil {
		a.log.Warn("остановка сессии: %v", err)
	}
}

// ensureDataDir создаёт каталог данных службы и возвращает его путь.
//
// Расположение зависит от режима:
//   - служба под LocalSystem — %ProgramData%\net-gui-client, общий для машины;
//   - режим разработчика — каталог текущего пользователя.
func ensureDataDir() (string, error) {
	var base string
	if devMode {
		var err error
		base, err = os.UserConfigDir()
		if err != nil {
			return "", fmt.Errorf("net-svc: определение каталога данных: %w", err)
		}
	} else {
		base = os.Getenv("ProgramData")
		if base == "" {
			return "", fmt.Errorf("net-svc: переменная окружения ProgramData не задана")
		}
	}

	dir := filepath.Join(base, "net-gui-client")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("net-svc: создание каталога %s: %w", dir, err)
	}

	// В режиме разработчика каталог данных лежит в профиле пользователя,
	// и ужесточать права там НЕЛЬЗЯ: список доступа из hardenedSDDL
	// оставляет только SYSTEM и администраторов, то есть отбирает у самого
	// разработчика доступ к его же файлам.
	//
	// Ошибка, допущенная здесь при первой реализации: Harden вызывался
	// всегда, а в devMode игнорировалась лишь ошибка. Права при этом
	// успешно применялись — и каталог профиля становился недоступен.
	if devMode {
		return dir, nil
	}

	// Права УСТАНАВЛИВАЮТСЯ, а не только проверяются. Каталог, созданный
	// внутри %ProgramData%, наследует от родителя право записи для группы
	// «Users» — то есть по умолчанию оказывается ровно в том состоянии,
	// против которого направлена мера S5.
	if err := secdir.Harden(dir); err != nil {
		return "", fmt.Errorf("net-svc: %w", err)
	}
	return dir, nil
}

// installDir возвращает каталог, из которого запущен исполняемый файл.
// Он же считается доверенным для клиентов (мера S2).
func installDir() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("net-svc: определение пути исполняемого файла: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		// Символическая ссылка на исполняемый файл — повод насторожиться,
		// но не повод падать: используем исходный путь.
		resolved = exe
	}
	return filepath.Dir(resolved), nil
}

// verifyDataDir выполняет проверку S5.
func verifyDataDir(dir string, log logger) error {
	err := secdir.Verify(dir)
	if err == nil {
		return nil
	}
	if devMode {
		log.Warn("режим разработчика: %v", err)
		return nil
	}
	return fmt.Errorf("net-svc: отказ запуска, мера S5: %w", err)
}

// verifyInstallDir выполняет проверку S4.
func verifyInstallDir(dir string, log logger) error {
	err := secdir.Verify(dir)
	if err == nil {
		return nil
	}
	if devMode {
		log.Warn("режим разработчика: %v", err)
		return nil
	}
	return fmt.Errorf(`net-svc: отказ запуска, мера S4.

  %v

  Служба работает с правами LocalSystem. Запуск из каталога, куда может
  писать обычный пользователь, означает, что подмена исполняемого файла
  даст выполнение произвольного кода с правами SYSTEM.

  Что делать:
    • для эксплуатации — установите продукт инсталлятором, он размещает
      файлы в %%ProgramFiles%% с корректными правами;
    • для разработки  — соберите с тегом devmode:
      go build -tags devmode ./cmd/net-svc`, err)
}
