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
export type SessionState = 'idle' | 'connecting' | 'connected' | 'unlinked' | 'unknown';

export interface StatusView {
  state: SessionState;
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
