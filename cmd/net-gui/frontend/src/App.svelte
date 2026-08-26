<script lang="ts">
  /**
   * Оболочка приложения: навигация слева, экран справа, строка состояния снизу.
   *
   * ⚠️ Оформление намеренно черновое. Итерация И-3 даёт функциональный
   * каркас — структуру, живые данные, навигацию. Визуальный дизайн
   * прорабатывается отдельной итерацией по указанию заказчика.
   */
  import { t } from './lib/i18n.svelte';
  import { SCREENS, type ScreenId, type StatusView, type ProfileView, type AppInfo } from './lib/types';
  import Connection from './lib/screens/Connection.svelte';
  import Stub from './lib/screens/Stub.svelte';

  import { GetAppInfo, GetStatus, ListProfiles, Connect, Disconnect } from '../wailsjs/go/main/app';
  import { EventsOn } from '../wailsjs/runtime/runtime';

  let screen = $state<ScreenId>('connection');
  let status = $state<StatusView>({
    state: 'unlinked', profileId: '', listen: '', policy: '', ruleCount: 0, error: '',
  });
  let profiles = $state<ProfileView[]>([]);
  let info = $state<AppInfo | null>(null);
  let busy = $state(false);
  let problem = $state('');

  const linked = $derived(info?.linked ?? false);
  const current = $derived(SCREENS.find((s) => s.id === screen)!);

  async function refresh() {
    info = await GetAppInfo();
    status = await GetStatus();
    profiles = (await ListProfiles()) ?? [];
  }

  // Поток событий от службы. Именно ради него в ADR-004 выбран gRPC,
  // а не опрос: состояние приходит push'ом, интерфейс не «дёргает» службу.
  EventsOn('session:status', (s: StatusView) => {
    status = s;
  });

  EventsOn('service:link', async (e: { linked: boolean }) => {
    problem = e.linked ? '' : t('service.unlinked');
    await refresh();
  });

  EventsOn('app:problem', (e: { text: string }) => {
    problem = e.text;
  });

  $effect(() => {
    refresh();
  });

  async function handleConnect(profileId: string, policy: string) {
    busy = true;
    try {
      status = await Connect(profileId, policy);
      await refresh();
    } finally {
      busy = false;
    }
  }

  async function handleDisconnect() {
    busy = true;
    try {
      status = await Disconnect();
      await refresh();
    } finally {
      busy = false;
    }
  }
</script>

<div class="app">
  <nav class="nav">
    <div class="brand">{t('app.title')}</div>
    {#each SCREENS as s (s.id)}
      <button class="nav-item" class:active={screen === s.id} onclick={() => (screen = s.id)}>
        {t(s.labelKey)}
      </button>
    {/each}
  </nav>

  <main class="main">
    {#if screen === 'connection'}
      <Connection
        {status}
        {profiles}
        {linked}
        {busy}
        onConnect={handleConnect}
        onDisconnect={handleDisconnect}
      />
    {:else}
      <Stub title={t(current.labelKey)} iteration={current.iteration} />
    {/if}
  </main>

  <footer class="statusbar">
    <span class="link" class:ok={linked}>
      {linked ? t('service.linked') : t('service.unlinked')}
    </span>
    {#if info?.linked}
      <span class="sep">·</span>
      <span>{t('service.version')} {info.serverVersion}</span>
      {#if !info.compatible}
        <span class="sep">·</span>
        <span class="warn">{t('service.apiMismatch')}</span>
      {/if}
    {/if}
    {#if problem}
      <span class="sep">·</span>
      <span class="warn" title={problem}>{problem.split('\n')[0]}</span>
    {/if}
  </footer>
</div>

<style>
  .app {
    display: grid;
    grid-template-columns: 13rem 1fr;
    grid-template-rows: 1fr auto;
    grid-template-areas: 'nav main' 'status status';
    height: 100vh;
  }

  .nav {
    grid-area: nav;
    display: flex;
    flex-direction: column;
    gap: 0.15rem;
    padding: 0.75rem 0.5rem;
    border-right: 1px solid rgba(128, 128, 128, 0.3);
    overflow-y: auto;
  }

  .brand {
    font-weight: 700;
    padding: 0.4rem 0.6rem 0.8rem;
    opacity: 0.9;
  }

  .nav-item {
    text-align: left;
    padding: 0.45rem 0.6rem;
    border: none;
    background: transparent;
    font: inherit;
    color: inherit;
    cursor: pointer;
    border-radius: 4px;
  }
  .nav-item:hover { background: rgba(128, 128, 128, 0.15); }
  .nav-item.active { background: rgba(128, 128, 128, 0.28); font-weight: 600; }

  .main {
    grid-area: main;
    padding: 1.25rem 1.5rem;
    overflow-y: auto;
  }

  .statusbar {
    grid-area: status;
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.35rem 0.75rem;
    border-top: 1px solid rgba(128, 128, 128, 0.3);
    font-size: 0.8rem;
    opacity: 0.85;
  }
  .link::before { content: '○ '; }
  .link.ok::before { content: '● '; color: #3a8f3a; }
  .sep { opacity: 0.4; }
  .warn { color: #b06000; }
</style>
