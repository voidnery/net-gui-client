//go:build !windows

package secrets

// Protect и Unprotect на платформах без реализации возвращают ErrUnsupported.
//
// Заглушка намеренно не «пропускает данные как есть»: см. пояснение к
// ErrUnsupported. Реализация для Linux (Secret Service) и macOS (Keychain)
// появится вместе с поддержкой этих платформ (T9).

func Protect(plain []byte) ([]byte, error) { return nil, ErrUnsupported }

func Unprotect(blob []byte) ([]byte, error) { return nil, ErrUnsupported }
