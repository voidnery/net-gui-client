/**
 * Типы, приходящие из Go-части.
 *
 * Wails генерирует привязки в frontend/wailsjs, но собственные объявления
 * держим отдельно: сгенерированные файлы перезаписываются при каждой сборке
 * и не должны быть местом, куда смотрят разработчики фронтенда.
 *
 * Поля обязаны совпадать с тегами json в cmd/net-gui/app.go.
 */

export interface AppInfo {
  version: string;
  linked: boolean;
  serverVersion: string;
  apiVersion: number;
  compatible: boolean;
  problem: string;
}

/** Стабильные идентификаторы состояний. Перевод — в словаре i18n. */
export const SESSION_STATES = ['idle', 'connecting', 'connected', 'unlinked', 'unknown'] as const;

export type SessionState = (typeof SESSION_STATES)[number];

/**
 * Приводит состояние, пришедшее из Go, к известному значению.
 *
 * Wails описывает поле как string: контракт допускает, что служба окажется
 * новее интерфейса и пришлёт состояние, о котором здесь ещё не знают.
 * Приведение типом (`as SessionState`) эту возможность бы замолчало, и
 * интерфейс попытался бы показать перевод несуществующего ключа.
 *
 * Неизвестное значение вырождается в 'unknown' — состояние, для которого
 * подпись уже есть. Пользователь увидит «Неизвестно» вместо пустоты.
 */
export function asSessionState(s: string): SessionState {
  return (SESSION_STATES as readonly string[]).includes(s) ? (s as SessionState) : 'unknown';
}

/** Приводит статус, пришедший из Go, к типу интерфейса. */
export function toStatusView(
  s: { state: string; mode: string } & Omit<StatusView, 'state' | 'mode'>,
): StatusView {
  return { ...s, state: asSessionState(s.state), mode: asMode(s.mode) };
}

/**
 * Режим работы соединения.
 *
 * Различие существенное, и его нельзя прятать: в режиме прокси через туннель
 * идут только приложения, направленные на локальный порт; в режиме туннеля —
 * весь трафик системы.
 */
export const MODES = ['proxy', 'tunnel'] as const;

export type Mode = (typeof MODES)[number];

export function asMode(s: string): Mode {
  return (MODES as readonly string[]).includes(s) ? (s as Mode) : 'proxy';
}

export interface StatusView {
  state: SessionState;
  mode: Mode;
  profileId: string;
  listen: string;
  policy: string;
  ruleCount: number;
  error: string;
}

export interface ProfileView {
  id: string;
  name: string;
  kind: string;
  server: string;
  port: number;
  /**
   * Задан ли у профиля секрет.
   *
   * Самого секрета здесь нет и не будет: служба его не возвращает (мера S6).
   * Интерфейсу достаточно признака — показать «пароль задан» и не предлагать
   * подключаться профилем, у которого учётных данных нет вовсе.
   */
  hasSecrets: boolean;
}

/** Исход операции над профилем. Ошибка приходит значением, а не исключением. */
export interface ProfileResult {
  ok: boolean;
  profile: string;
  error: string;
}

/** Экраны приложения. Соответствуют карте навигации из 03-architecture.md §11.1. */
export type ScreenId =
  | 'connection'
  | 'profiles'
  | 'routing'
  | 'failover'
  | 'stats'
  | 'log'
  | 'settings';

export interface ScreenDef {
  id: ScreenId;
  labelKey: string;
  /** Итерация, в которой экран наполняется содержимым. */
  iteration: string;
}

/**
 * Карта навигации задана здесь целиком, включая ещё не реализованные
 * экраны. Так структура приложения видна с первого дня, а не собирается
 * по кусочкам: пользователь понимает, что его ждёт, а разработка —
 * куда встраивать следующую итерацию.
 */
export const SCREENS: ScreenDef[] = [
  { id: 'connection', labelKey: 'nav.connection', iteration: 'И-3' },
  { id: 'profiles', labelKey: 'nav.profiles', iteration: 'И-4' },
  { id: 'routing', labelKey: 'nav.routing', iteration: 'И-7' },
  { id: 'failover', labelKey: 'nav.failover', iteration: 'И-10' },
  { id: 'stats', labelKey: 'nav.stats', iteration: 'И-12' },
  { id: 'log', labelKey: 'nav.log', iteration: 'И-12' },
  { id: 'settings', labelKey: 'nav.settings', iteration: 'И-6' },
];
