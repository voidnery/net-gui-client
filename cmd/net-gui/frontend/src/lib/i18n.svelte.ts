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

  'prof.title': 'Профили',
  'prof.empty': 'Профилей нет. Добавьте первый — ссылкой или файлом конфигурации.',
  'prof.add': 'Добавить профиль',
  'prof.source': 'Откуда',
  'prof.sourceLink': 'Ссылка',
  'prof.sourceFile': 'Файл конфигурации',
  'prof.link': 'Ссылка',
  'prof.linkHint': 'vless://, hysteria2://, hy2:// или socks5://',
  'prof.file': 'Файл',
  'prof.choose': 'Выбрать…',
  'prof.fileHint': 'Файл wg-quick для WireGuard и AmneziaWG.',
  'prof.name': 'Имя',
  'prof.nameHint': 'Необязательно. Пусто — взять из содержимого.',
  'prof.import': 'Импортировать',
  'prof.importing': 'Импорт…',
  'prof.imported': 'Профиль добавлен',
  'prof.secret': 'Учётные данные',
  'prof.secretYes': 'заданы',
  'prof.secretNo': 'нет',
  'prof.rename': 'Переименовать',
  'prof.remove': 'Удалить',
  'prof.removeConfirm': 'Удалить профиль «{name}»? Восстановить его будет нельзя.',
  'prof.save': 'Сохранить',
  'prof.cancel': 'Отмена',
  'prof.id': 'Идентификатор',
  'prof.idHint': 'Выдаётся службой. Используется в net-cli.',
  'prof.secretWarn': 'У профиля нет учётных данных — подключение, скорее всего, не пройдёт.',
  'prof.noSecretsShown': 'Пароли и ключи не показываются: служба их не выдаёт.',

  'conn.mode': 'Режим',
  'mode.proxy': 'Прокси — только направленные приложения',
  'mode.tunnel': 'Туннель — весь трафик системы',
  'mode.tunnelHint': 'Меняет маршрутизацию всей системы. Требует прав администратора у службы.',
  'conn.hintTunnel': 'Весь трафик системы идёт через туннель. Настраивать приложения не нужно.',

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

/** Значения для подстановки в строку: t('prof.removeConfirm', { name }). */
export type Params = Record<string, string | number>;

class I18n {
  locale = $state<Locale>('ru');

  /**
   * Возвращает строку по ключу, подставляя значения вместо {имя}.
   *
   * Подстановка нужна потому, что склеивать перевод из кусков нельзя: порядок
   * слов в разных языках разный, и «Удалить профиль » + name + «?» рассыпется
   * при первом же переводе. Целая строка с местом для подстановки переводится
   * как единое предложение.
   */
  t(key: string, params?: Params): string {
    const dict = dicts[this.locale];
    let s = dict[key] ?? ru[key] ?? key;

    if (params) {
      for (const [k, v] of Object.entries(params)) {
        s = s.split('{' + k + '}').join(String(v));
      }
    }
    return s;
  }

  setLocale(l: Locale) {
    this.locale = l;
  }
}

export const i18n = new I18n();

/** Короткая форма для разметки. */
export function t(key: string, params?: Params): string {
  return i18n.t(key, params);
}
