<script lang="ts">
  /**
   * Экран [2] Профили.
   *
   * Оформление намеренно минимальное: визуальный дизайн прорабатывается
   * отдельной итерацией. Здесь важны структура и поведение.
   *
   * Два решения, определяющие вид экрана:
   *
   * 1. Профиль СОЗДАЁТСЯ ИМПОРТОМ, а не заполнением полей. Форма «введите
   *    приватный ключ, адрес, MTU, Jc, Jmin, S1…» повторяла бы то, что уже
   *    записано в выданном файле, и переносить это руками — верный способ
   *    ошибиться в одном знаке и потом искать причину в сервере.
   *
   * 2. Секретов на экране НЕТ. Служба их не возвращает (мера S6), поэтому
   *    показывается только признак «учётные данные заданы». Поле «пароль» с
   *    точками, за которыми ничего нет, вводило бы в заблуждение.
   */
  import { t } from '../i18n.svelte';
  import type { ProfileView, ProfileResult } from '../types';

  let {
    profiles,
    linked,
    onImportLink,
    onImportFile,
    onChooseFile,
    onRename,
    onRemove,
  }: {
    profiles: ProfileView[];
    linked: boolean;
    onImportLink: (name: string, link: string) => Promise<ProfileResult>;
    onImportFile: (name: string, path: string) => Promise<ProfileResult>;
    onChooseFile: () => Promise<string>;
    onRename: (id: string, name: string) => Promise<ProfileResult>;
    onRemove: (id: string) => Promise<ProfileResult>;
  } = $props();

  type Source = 'link' | 'file';

  let source = $state<Source>('link');
  let link = $state('');
  let filePath = $state('');
  let newName = $state('');
  let busy = $state(false);
  let error = $state('');
  let notice = $state('');

  // Идентификатор переименовываемого профиля. Пусто — никто не редактируется.
  let editingId = $state('');
  let editingName = $state('');

  // Идентификатор профиля, для которого показано подтверждение удаления.
  //
  // Подтверждение встроено в строку, а не вызывается через window.confirm:
  // системный диалог в webview ведёт себя по-разному на разных платформах,
  // блокирует поток отрисовки и недоступен автоматической проверке. Своё
  // состояние лишено всех трёх недостатков.
  let confirmingId = $state('');

  const canImport = $derived(
    linked && !busy && (source === 'link' ? link.trim() !== '' : filePath !== ''),
  );

  function reset() {
    link = '';
    filePath = '';
    newName = '';
  }

  async function chooseFile() {
    error = '';
    const path = await onChooseFile();
    // Пустая строка означает, что диалог закрыли. Это не ошибка, и сообщать
    // о ней не о чем.
    if (path) {
      filePath = path;
      source = 'file';
    }
  }

  async function doImport() {
    busy = true;
    error = '';
    notice = '';
    try {
      const result =
        source === 'link'
          ? await onImportLink(newName.trim(), link.trim())
          : await onImportFile(newName.trim(), filePath);

      if (result.ok) {
        notice = t('prof.imported');
        reset();
      } else {
        error = result.error;
      }
    } finally {
      busy = false;
    }
  }

  function startRename(p: ProfileView) {
    editingId = p.id;
    editingName = p.name;
    error = '';
  }

  async function saveRename() {
    const name = editingName.trim();
    if (name === '') {
      return;
    }
    busy = true;
    error = '';
    try {
      const result = await onRename(editingId, name);
      if (result.ok) {
        editingId = '';
      } else {
        error = result.error;
      }
    } finally {
      busy = false;
    }
  }

  async function remove(id: string) {
    busy = true;
    error = '';
    try {
      const result = await onRemove(id);
      if (result.ok) {
        confirmingId = '';
      } else {
        error = result.error;
      }
    } finally {
      busy = false;
    }
  }
</script>

<section class="screen">
  <h2 class="title">{t('prof.title')}</h2>

  {#if profiles.length === 0}
    <p class="empty">{t('prof.empty')}</p>
  {:else}
    <ul class="list">
      {#each profiles as p (p.id)}
        <li class="item">
          {#if confirmingId === p.id}
            <div class="row">
              <span class="grow">{t('prof.removeConfirm', { name: p.name })}</span>
              <button class="btn danger" onclick={() => remove(p.id)} disabled={busy}>
                {t('prof.remove')}
              </button>
              <button class="btn" onclick={() => (confirmingId = '')} disabled={busy}>
                {t('prof.cancel')}
              </button>
            </div>
          {:else if editingId === p.id}
            <div class="row">
              <input
                class="input grow"
                bind:value={editingName}
                aria-label={t('prof.name')}
                onkeydown={(e) => e.key === 'Enter' && saveRename()}
              />
              <button class="btn" onclick={saveRename} disabled={busy || editingName.trim() === ''}>
                {t('prof.save')}
              </button>
              <button class="btn" onclick={() => (editingId = '')} disabled={busy}>
                {t('prof.cancel')}
              </button>
            </div>
          {:else}
            <div class="row">
              <div class="grow">
                <div class="name">{p.name}</div>
                <div class="meta">
                  <span class="kind">{p.kind}</span>
                  <span class="sep">·</span>
                  <span>{p.server}:{p.port}</span>
                  <span class="sep">·</span>
                  <span>{t('prof.id')}: <code>{p.id}</code></span>
                </div>
                <div class="meta">
                  {t('prof.secret')}:
                  {#if p.hasSecrets}
                    <span class="ok">{t('prof.secretYes')}</span>
                  {:else}
                    <span class="warn" title={t('prof.secretWarn')}>{t('prof.secretNo')}</span>
                  {/if}
                </div>
              </div>
              <button class="btn" onclick={() => startRename(p)} disabled={busy || !linked}>
                {t('prof.rename')}
              </button>
              <button
                class="btn danger"
                onclick={() => ((confirmingId = p.id), (editingId = ''))}
                disabled={busy || !linked}
              >
                {t('prof.remove')}
              </button>
            </div>
          {/if}
        </li>
      {/each}
    </ul>
    <p class="hint">{t('prof.noSecretsShown')}</p>
  {/if}

  <div class="add">
    <h3 class="subtitle">{t('prof.add')}</h3>

    <div class="field">
      <span class="label">{t('prof.source')}</span>
      <div class="choices">
        <label class="choice">
          <input type="radio" bind:group={source} value="link" />
          {t('prof.sourceLink')}
        </label>
        <label class="choice">
          <input type="radio" bind:group={source} value="file" />
          {t('prof.sourceFile')}
        </label>
      </div>
    </div>

    {#if source === 'link'}
      <label class="field">
        <span class="label">{t('prof.link')}</span>
        <input class="input" bind:value={link} placeholder={t('prof.linkHint')} spellcheck="false" />
      </label>
    {:else}
      <div class="field">
        <span class="label">{t('prof.file')}</span>
        <div class="row">
          <input class="input grow" value={filePath} readonly aria-label={t('prof.file')} />
          <button class="btn" onclick={chooseFile} disabled={busy}>{t('prof.choose')}</button>
        </div>
        <span class="hint">{t('prof.fileHint')}</span>
      </div>
    {/if}

    <label class="field">
      <span class="label">{t('prof.name')}</span>
      <input class="input" bind:value={newName} placeholder={t('prof.nameHint')} />
    </label>

    <div class="row">
      <button class="btn primary" onclick={doImport} disabled={!canImport}>
        {busy ? t('prof.importing') : t('prof.import')}
      </button>
      {#if notice}<span class="ok">{notice}</span>{/if}
    </div>

    {#if error}
      <pre class="error">{error}</pre>
    {/if}
  </div>
</section>

<style>
  .screen {
    display: flex;
    flex-direction: column;
    gap: 1.25rem;
    max-width: 46rem;
  }

  .title {
    margin: 0;
    font-size: 1.15rem;
  }
  .subtitle {
    margin: 0 0 0.5rem;
    font-size: 1rem;
  }

  .empty {
    margin: 0;
    opacity: 0.75;
  }

  .list {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 0.4rem;
  }

  .item {
    border: 1px solid rgba(128, 128, 128, 0.3);
    border-radius: 4px;
    padding: 0.6rem 0.75rem;
  }

  .row {
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  .grow {
    flex: 1;
    min-width: 0;
  }

  .name {
    font-weight: 600;
  }
  .meta {
    font-size: 0.8rem;
    opacity: 0.8;
    display: flex;
    flex-wrap: wrap;
    gap: 0.3rem;
    align-items: baseline;
  }
  .kind {
    font-family: monospace;
  }
  .sep {
    opacity: 0.4;
  }

  .add {
    border-top: 1px solid rgba(128, 128, 128, 0.3);
    padding-top: 1rem;
    display: flex;
    flex-direction: column;
    gap: 0.6rem;
  }

  .field {
    display: flex;
    flex-direction: column;
    gap: 0.2rem;
  }
  .label {
    font-size: 0.8rem;
    opacity: 0.8;
  }
  .hint {
    font-size: 0.78rem;
    opacity: 0.7;
    margin: 0;
  }

  .choices {
    display: flex;
    gap: 1rem;
  }
  .choice {
    display: flex;
    align-items: center;
    gap: 0.3rem;
    cursor: pointer;
  }

  .input {
    font: inherit;
    padding: 0.35rem 0.5rem;
    border: 1px solid rgba(128, 128, 128, 0.45);
    border-radius: 4px;
    background: transparent;
    color: inherit;
  }
  .input[readonly] {
    opacity: 0.75;
  }

  .btn {
    font: inherit;
    padding: 0.35rem 0.75rem;
    border: 1px solid rgba(128, 128, 128, 0.45);
    border-radius: 4px;
    background: transparent;
    color: inherit;
    cursor: pointer;
    white-space: nowrap;
  }
  .btn:hover:not(:disabled) {
    background: rgba(128, 128, 128, 0.15);
  }
  .btn:disabled {
    opacity: 0.5;
    cursor: default;
  }
  .btn.primary {
    font-weight: 600;
  }
  .btn.danger:hover:not(:disabled) {
    background: rgba(176, 0, 0, 0.12);
  }

  .ok {
    color: #3a8f3a;
  }
  .warn {
    color: #b06000;
  }

  .error {
    margin: 0;
    padding: 0.5rem 0.6rem;
    border: 1px solid rgba(176, 0, 0, 0.4);
    border-radius: 4px;
    white-space: pre-wrap;
    font-size: 0.85rem;
  }

  code {
    font-size: 0.95em;
  }
</style>
