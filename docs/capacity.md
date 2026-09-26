# 容量观察

这页只记录怎么采集指标，以及一份还没跑过的压测模板。它不给出「能支撑多少台设备」。仓库没有在生产 CT 上跑过这套矩阵，也没有改默认存储、SQLite 日志模式、每次操作新开连接，或互斥锁的结构。

## Counters

`core/metrics.ts` keeps fixed buckets and fixed status keys. It does not store commands, device identifiers, or response bodies.

- Mutex: wait, hold, current queue depth, and the high-water queue depth.
- Audit worker: queue depth, `queue_full`, `timeout`, and `task_failed`. A failed send releases its slot.
- Event loop: one delay sample, at most once a second, plus a sample when a snapshot is read.
- HTTP JSON responses: status keys `200`, `400`, `401`, `403`, `404`, `405`, `409`, `413`, `429`, `500`, `502`, `503`, and `other`.
- Route latency: fixed labels `state` (`GET /api/v1/state`) and `evaluate` (`POST /api/v1/evaluate`). Each sample is the handler time. The histogram is the p50/p95/p99 source. Paths, device ids, and bodies are not stored.

中文对应：互斥锁的等待、持有和队列深度；审计 worker 的队列与三类错误；事件循环延迟；上面列出的 HTTP 状态计数；`/state` 与 evaluate 的次数和延迟。成功响应不会因为计数被改成失败。互斥锁的排队方式没有改。

## Harness

Any supplied `--data-dir` is rejected before the harness creates or deletes a directory. It always makes a fresh directory under the system temp directory and deletes only that directory. It ignores `NMZP_DATA`. `--bind` must be loopback. The listen address for `--run-synthetic` is `127.0.0.1`.

`--dry-run` only contends the store mutex. It opens no socket. `validatesRoutes` is false. It is not a capacity measurement of the core.

```bash
node --experimental-strip-types scripts/bench-capacity.mjs --dry-run
```

`--run-synthetic` starts a local core on `127.0.0.1`, joins synthetic devices, and calls heartbeat, evaluate, and `/state`. Parameters are bounded: `--devices` 1..100, `--duration-ms` 50..2700000, `--storage window|sqlite`, `--concurrency` 1..16, `--poll-ms` 20..60000. The report's `routeCapacity` is `synthetic-loopback-only`. `productionCapacity` stays null. `matrix.executed` stays false.

This worktree ran only the tiny smoke below. It is not the audit matrix.

```bash
node --experimental-strip-types scripts/bench-capacity.mjs --run-synthetic --devices 1 --duration-ms 200 --storage window --concurrency 1 --poll-ms 50 --bind 127.0.0.1
```

## Matrix commands for an isolated Linux maintainer

Do not point these at a production data directory or a non-loopback address. The harness will reject `--data-dir`. Each command is one cell, not a measured result from this repository. Active ratio, evaluate rate, heartbeat jitter, faults, and the 5/30/10 minute timeline are not implemented as separate switches; duration is the only time bound. A 45 minute cell is `--duration-ms 2700000`.

```bash
node --experimental-strip-types scripts/bench-capacity.mjs --run-synthetic --devices 10 --duration-ms 2700000 --storage window --concurrency 2 --poll-ms 5000 --bind 127.0.0.1
node --experimental-strip-types scripts/bench-capacity.mjs --run-synthetic --devices 25 --duration-ms 2700000 --storage window --concurrency 4 --poll-ms 5000 --bind 127.0.0.1
node --experimental-strip-types scripts/bench-capacity.mjs --run-synthetic --devices 50 --duration-ms 2700000 --storage window --concurrency 8 --poll-ms 5000 --bind 127.0.0.1
node --experimental-strip-types scripts/bench-capacity.mjs --run-synthetic --devices 100 --duration-ms 2700000 --storage window --concurrency 8 --poll-ms 5000 --bind 127.0.0.1
node --experimental-strip-types scripts/bench-capacity.mjs --run-synthetic --devices 10 --duration-ms 2700000 --storage sqlite --concurrency 2 --poll-ms 5000 --bind 127.0.0.1
node --experimental-strip-types scripts/bench-capacity.mjs --run-synthetic --devices 25 --duration-ms 2700000 --storage sqlite --concurrency 4 --poll-ms 5000 --bind 127.0.0.1
node --experimental-strip-types scripts/bench-capacity.mjs --run-synthetic --devices 50 --duration-ms 2700000 --storage sqlite --concurrency 8 --poll-ms 5000 --bind 127.0.0.1
node --experimental-strip-types scripts/bench-capacity.mjs --run-synthetic --devices 100 --duration-ms 2700000 --storage sqlite --concurrency 8 --poll-ms 5000 --bind 127.0.0.1
```

Plot hook p99 and fallback rate only after a run that actually collects them. These commands record core `/state` and evaluate latency, heartbeat outcomes, mutex queue, and event-loop samples. They do not simulate the audit's active-ratio or fault matrix, and they do not produce a supported device count.

## Matrix template

Not executed by this repository:

| Axis | Values |
| --- | --- |
| Devices N | 10, 25, 50, 100 |
| Active ratio | 0, 0.2, 0.5, 1.0 |
| Evaluate rate per active device | 0.2, 1, 3 per second |
| Storage | window, prefilled to 2000, and sqlite |
| Heartbeat | jitter, or synchronized |
| Background | `/state` polling, periodic export, one policy PUT per 60 s, retention cleanup |
| Faults | I/O delay, SIGKILL, core downtime of 5 / 15 / 30 minutes, worker stuck past 30 s |
| Timeline | 5 min warmup, 30 min steady, 10 min recovery |

A real run belongs on a Linux CT of the production shape, with simulators on another machine. Plot hook p99 and fallback rate against evaluate requests per second. Do not convert an inflection point into a device count. That run has not been done here.
