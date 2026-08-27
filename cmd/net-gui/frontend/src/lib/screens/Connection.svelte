<script lang="ts">
  /**
   * Экран [1] Подключение — домашний экран приложения.
   *
   * Оформление намеренно минимальное: визуальный дизайн прорабатывается
   * отдельной итерацией. Здесь важна структура и живые данные.
   *
   * Принцип U2 из архитектуры («никаких молчаливых состояний»): пользователь
   * всегда видит, подключён ли он, через что именно и какая политика
   * применена. Поэтому на экране нет ни одного элемента без подписи.
   */
  import { t } from '../i18n.svelte';
  import { MODES, type StatusView, type ProfileView, type Mode } from '../types';

  let {
    status,
    profiles,
    linked,
    busy,
    onConnect,
    onDisconnect,
  }: {
    status: StatusView;
    profiles: ProfileView[];
    linked: boolean;
    busy: boolean;
    onConnect: (profileId: string, policy: string, mode: string) => void;
    onDisconnect: () => void;
  } = $props();

  let selectedProfile = $state('');
  let selectedPolicy = $state('all-except');

  // Умолчание — прокси, а не туннель.
  //
  // Туннель меняет маршрутизацию всей системы. Делать это умолчанием значило
  // бы менять поведение машины у того, кто просто нажал «Подключить».
  let selectedMode = $state<Mode>('proxy');

  // Если профиль не выбран вручную, берём первый из списка.
  $effect(() => {
    if (!selectedProfile && profiles.length > 0) {
      selectedProfile = profiles[0].id;
    }
  });

  const isConnected = $derived(status.state === 'connected');
  const isBusy = $derived(busy || status.state === 'connecting');
  const canAct = $derived(linked && !isBusy && (isConnected || selectedProfile !== ''));
</script>

<section class="screen">
  <div class="status-block">
    <div class="state-line" data-state={status.state}>
      <span class="dot" aria-hidden="true"></span>
      <span class="state-text">{t('state.' + status.state)}</span>
    </div>

    {#if status.error}
      <pre class="error">{status.error}</pre>
    {/if}
  </div>

  <div class="controls">
    <label class="field">
      <span class="label">{t('conn.profile')}</span>
      {#if profiles.length === 0}
        <span class="empty">{t('conn.noProfiles')}</span>
      {:else}
        <select bind:value={selectedProfile} disabled={isConnected || !linked}>
          {#each profiles as p (p.id)}
            <option value={p.id}>{p.name} — {p.server}:{p.port}</option>
          {/each}
        </select>
      {/if}
    </label>

    <label class="field">
      <span class="label">{t('conn.mode')}</span>
      <select bind:value={selectedMode} disabled={isConnected || !linked}>
        {#each MODES as m (m)}
          <option value={m}>{t('mode.' + m)}</option>
        {/each}
      </select>
      {#if selectedMode === 'tunnel' && !isConnected}
        <span class="warn-hint">{t('mode.tunnelHint')}</span>
      {/if}
    </label>

    <label class="field">
      <span class="label">{t('conn.policy')}</span>
      <select bind:value={selectedPolicy} disabled={isConnected || !linked}>
        <option value="all-except">{t('policy.all-except')}</option>
        <option value="only-selected">{t('policy.only-selected')}</option>
      </select>
    </label>

    <button
      class="primary"
      disabled={!canAct}
      onclick={() =>
        isConnected ? onDisconnect() : onConnect(selectedProfile, selectedPolicy, selectedMode)}
    >
      {isConnected ? t('action.disconnect') : t('action.connect')}
    </button>
  </div>

  {#if isConnected}
    <dl class="details">
      <dt>{t('conn.mode')}</dt>
      <dd>{t('mode.' + status.mode)}</dd>

      <dt>{t('conn.listen')}</dt>
      <dd><code>{status.listen}</code></dd>

      <dt>{t('conn.policy')}</dt>
      <dd>{status.policy ? t('policy.' + status.policy) : '—'}</dd>

      <dt>{t('conn.rules')}</dt>
      <dd>{status.ruleCount}</dd>
    </dl>
    <p class="hint">{status.mode === 'tunnel' ? t('conn.hintTunnel') : t('conn.hint')}</p>
  {/if}
</section>

<style>
  /* Оформление намеренно черновое — визуальный дизайн отдельной итерацией. */
  .warn-hint {
    font-size: 0.78rem;
    color: #b06000;
  }
  .screen {
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
  }

  .state-line {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    font-size: 1.4rem;
  }

  .dot {
    width: 0.8rem;
    height: 0.8rem;
    border-radius: 50%;
    background: #888;
    flex: none;
  }
  .state-line[data-state='connected'] .dot { background: #3a8f3a; }
  .state-line[data-state='connecting'] .dot { background: #c8a000; }
  .state-line[data-state='unlinked'] .dot { background: #a33; }

  .controls {
    display: flex;
    flex-direction: column;
    gap: 0.8rem;
    max-width: 34rem;
  }

  .field {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }

  .label {
    font-size: 0.85rem;
    opacity: 0.75;
  }

  select {
    padding: 0.4rem;
    font: inherit;
  }

  .primary {
    padding: 0.6rem 1.2rem;
    font: inherit;
    font-weight: 600;
    cursor: pointer;
    align-self: flex-start;
  }
  .primary:disabled { cursor: default; opacity: 0.5; }

  .details {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 0.4rem 1.2rem;
    margin: 0;
  }
  .details dt { opacity: 0.75; }
  .details dd { margin: 0; }

  .error {
    white-space: pre-wrap;
    margin: 0;
    padding: 0.6rem;
    font-size: 0.85rem;
    border-left: 3px solid #a33;
    opacity: 0.9;
  }

  .empty, .hint { opacity: 0.7; font-size: 0.9rem; }
</style>
