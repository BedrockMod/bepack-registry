const MAX_BACKOFF_MS = 6 * 60 * 60 * 1000;

export function backoffFor(attempts) {
  return Math.min(60_000 * 2 ** Math.min(attempts, 6), MAX_BACKOFF_MS);
}

/**
 * Dispatch all due entries. Failures stay in the durable outbox with
 * exponential backoff; success is recorded only after GitHub returns 204.
 */
export async function runOnce({ store, dispatch, now = () => new Date(), logger = () => {} }) {
  const due = await store.due(now());
  let delivered = 0;
  for (const entry of due) {
    try {
      await dispatch(entry.payload);
      await store.recordSuccess(entry.key, now());
      delivered += 1;
      logger(`dispatched ${entry.key}`);
    } catch (error) {
      const next = new Date(now().getTime() + backoffFor(entry.attempts));
      await store.recordFailure(entry.key, {
        error: error?.message ?? String(error),
        nextAttemptAt: next,
        now: now(),
      });
      logger(`dispatch failed ${entry.key}: ${error?.message ?? error}`);
    }
  }
  return { due: due.length, delivered };
}

export function startWorker({ store, dispatch, intervalMs = 5000, logger = () => {} }) {
  let running = false;
  const tick = async () => {
    if (running) return;
    running = true;
    try {
      await runOnce({ store, dispatch, logger });
    } catch (error) {
      logger(`outbox tick failed: ${error?.message ?? error}`);
    } finally {
      running = false;
    }
  };
  const timer = setInterval(tick, intervalMs);
  timer.unref();
  return {
    timer,
    stop() { clearInterval(timer); },
    tick,
  };
}
