// node:test after hooks run in registration order and stop after a rejection.
// Own dependent resources in one hook so every close is awaited before removal.
export function cleanupAfter(t) {
  const callbacks = [];
  t.after(async () => {
    const errors = [];
    for (const callback of callbacks.reverse()) {
      try { await callback(); }
      catch (error) { errors.push(error); }
    }
    if (errors.length) throw new AggregateError(errors, "test resource cleanup failed");
  });
  return callback => callbacks.push(callback);
}
