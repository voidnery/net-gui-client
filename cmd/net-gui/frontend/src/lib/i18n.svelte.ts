/**
 * Каркас локализации.
 *
 * Введён на итерации И-3, хотя язык пока один. Причина в дефекте D7 из
 * 05-plan-revised.md: тексты начинают копиться с первого же экрана, и
 * ретрофит локализации по готовому интерфейсу — механическая работа на
 * несколько дней, которую полностью устраняет один день сейчас.
 *
 * Правило: в разметке НЕ должно быть литеральных строк, видимых
 * пользователю. Только t('ключ').
 */

export type Locale = 'ru' | 'en';

type Dict = Record<string, string>;

const ru: Dict = {
  'app.title': 'net-gui-client',

  'nav.connection': 'Подключение',
  'nav.profiles': 'Профили',
  'nav.routing': 'Маршрутизация',
  'nav.failover': 'Резервирование',
  'nav.stats': 'Статистика',
  'nav.log': 'Журнал',
  'nav.settings': 'Настройки',

  'state.idle': 'Отключено',
  'state.connecting': 'Подключение',
  'state.connected': 'Подключено',
  'state.unlinked': 'Нет связи со службой',
  'state.unknown': 'Неизвестно',

  'action.connect': 'Подключить',
  'action.disconnect': 'Отключить',
  'action.retry': 'Повторить',

  'conn.profile': 'Профиль',
  'conn.noProfiles': 'Профилей нет. Добавьте профиль через net-cli.',
  'conn.listen': 'Локальный прокси',
  'conn.policy': 'Политика',
  'conn.rules': 'Правил',
  'conn.hint': 'Направьте приложения на этот адрес — HTTP или SOCKS5.',

  'policy.all-except': 'Всё через туннель, кроме выбранного',
  'policy.only-selected': 'Только выбранное через туннель',

  'service.linked': 'Связь со службой установлена',
  'service.unlinked': 'Связь со службой потеряна',
  'service.version': 'Служба',
  'service.apiMismatch': 'Версии контракта расходятся — обновите ту сторону, что старее',

  'stub.title': 'Раздел в разработке',
  'stub.body': 'Этот экран появится в одной из следующих итераций.',
  'stub.iteration': 'Планируется в итерации',
};

/**
 * Английский словарь пока пуст: перевод выполняется в И-12.
 * Отсутствующий ключ отдаётся из русского словаря — интерфейс остаётся
 * рабочим, а непереведённые места видны сразу.
 */
const en: Dict = {};

const dicts: Record<Locale, Dict> = { ru, en };

class I18n {
  locale = $state<Locale>('ru');

  t(key: string): string {
    const dict = dicts[this.locale];
    return dict[key] ?? ru[key] ?? key;
  }

  setLocale(l: Locale) {
    this.locale = l;
  }
}

export const i18n = new I18n();

/** Короткая форма для разметки. */
export function t(key: string): string {
  return i18n.t(key);
}
