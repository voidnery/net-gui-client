<script lang="ts">
  /**
   * Заглушка для экранов, которые появятся в следующих итерациях.
   *
   * Пустой экран без объяснений выглядит как ошибка. Заглушка честно
   * сообщает, что раздел ещё не готов, и называет итерацию — это
   * соответствует принципу U2 («никаких молчаливых состояний»).
   */
  import { t } from '../i18n.svelte';

  let { title, iteration }: { title: string; iteration: string } = $props();
</script>

<section class="stub">
  <h2>{title}</h2>
  <p class="lead">{t('stub.title')}</p>
  <p>{t('stub.body')}</p>
  <p class="meta">{t('stub.iteration')}: <strong>{iteration}</strong></p>
</section>

<style>
  .stub {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    max-width: 34rem;
  }
  h2 { margin: 0 0 0.5rem; font-size: 1.3rem; }
  .lead { font-weight: 600; margin: 0; }
  p { margin: 0; opacity: 0.85; }
  .meta { opacity: 0.6; font-size: 0.9rem; margin-top: 0.5rem; }
</style>
