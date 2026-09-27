# WP-04 hook startup baseline

- timestamp: 2026-09-27T00:36:57.216Z
- baselineSha: 0ea8f6eac4457c5e13b22b7130f64d48e3613927
- scriptSha256: df7d02a4856c8a673e57e021138e44eceb6cbde25ac1bc3ff058741ed352014d
- node: v24.15.0
- os: win32
- arch: arm64
- checkout: C:\Users\sxl\Desktop\NMZP\nmzp-wt\P0
- priorPacket: WP-04_EVIDENCE.md provisional superseded
- Fresh process is NOT after-reboot cold.
- Windows local synthetic measurement is not HOST_REAL tool enforcement.
- Online success requires GET /api/v1/state event id match plus decision allow|log and enforcement delivered. Fallback is classified separately and excluded from online percentiles.
- Offline success requires a fresh same-event outbox item (tool/decision/policyVersion) and hook-status ok for that eventId. Cache existence and no-cache low-risk allow are insufficient. Server receipts are absent because the owned server is closed.

## legacy-same-process-loopback-warm / window

- scenario: legacy-same-process-loopback-warm/window
- ok: true
- storageMode: window
- label: legacy-same-process-loopback-warm
- n: 10
- samples: 10
- nSuccess: 10
- nFailed: 0
- nFallback: 0
- rawMs: [25.225541999999905,25.350833999999963,25.436374999999998,26.288167000000044,26.522875,26.68154100000004,26.760749999999916,27.97475000000003,29.031499999999994,34.72395799999998]
- p50Ms: 26.522875
- p95Ms: 34.72395799999998
- maxMs: 34.72395799999998
- rawProtocolMs: [25.225541999999905,25.350833999999963,25.436374999999998,26.288167000000044,26.522875,26.68154100000004,26.760749999999916,27.97475000000003,29.031499999999994,34.72395799999998]
- p50ProtocolMs: 26.522875
- p95ProtocolMs: 34.72395799999998
- maxProtocolMs: 34.72395799999998
- rawExitMs: [25.225541999999905,25.350833999999963,25.436374999999998,26.288167000000044,26.522875,26.68154100000004,26.760749999999916,27.97475000000003,29.031499999999994,34.72395799999998]
- p50ExitMs: 26.522875
- p95ExitMs: 34.72395799999998
- maxExitMs: 34.72395799999998
- limitations: Same-process runHook plus receipt settlement on loopback; not subprocess startup. Online success requires GET /api/v1/state event id match plus decision allow|log and enforcement delivered. Fallback is classified separately and excluded from online percentiles. Fresh process is NOT after-reboot cold. Windows local synthetic measurement is not HOST_REAL tool enforcement.

## legacy-same-process-loopback-warm / sqlite

- scenario: legacy-same-process-loopback-warm/sqlite
- ok: true
- storageMode: sqlite
- label: legacy-same-process-loopback-warm
- n: 10
- samples: 10
- nSuccess: 10
- nFailed: 0
- nFallback: 0
- rawMs: [28.224917000000005,28.665499999999838,28.705083999999943,28.76241700000014,29.45654099999979,29.53254200000015,29.577583000000004,29.98916599999984,31.331916000000092,32.078209000000015]
- p50Ms: 29.45654099999979
- p95Ms: 32.078209000000015
- maxMs: 32.078209000000015
- rawProtocolMs: [28.224917000000005,28.665499999999838,28.705083999999943,28.76241700000014,29.45654099999979,29.53254200000015,29.577583000000004,29.98916599999984,31.331916000000092,32.078209000000015]
- p50ProtocolMs: 29.45654099999979
- p95ProtocolMs: 32.078209000000015
- maxProtocolMs: 32.078209000000015
- rawExitMs: [28.224917000000005,28.665499999999838,28.705083999999943,28.76241700000014,29.45654099999979,29.53254200000015,29.577583000000004,29.98916599999984,31.331916000000092,32.078209000000015]
- p50ExitMs: 29.45654099999979
- p95ExitMs: 32.078209000000015
- maxExitMs: 32.078209000000015
- limitations: Same-process runHook plus receipt settlement on loopback; not subprocess startup. Online success requires GET /api/v1/state event id match plus decision allow|log and enforcement delivered. Fallback is classified separately and excluded from online percentiles. Fresh process is NOT after-reboot cold. Windows local synthetic measurement is not HOST_REAL tool enforcement.

## subprocess-fresh-process-online-loopback

- scenario: subprocess-fresh-process-online-loopback
- ok: true
- n: 10
- nSuccess: 10
- nFailed: 0
- nFallback: 0
- cleanupIncomplete: false
- rawProtocolMs: [307.1384579999999,308.25112500000023,308.291416,312.24587500000007,313.12916700000005,315.8901249999999,318.6404580000003,321.0688339999997,328.8392080000003,331.90595899999994]
- p50ProtocolMs: 313.12916700000005
- p95ProtocolMs: 331.90595899999994
- maxProtocolMs: 331.90595899999994
- rawExitMs: [309.8768749999999,311.4241670000001,311.4543330000006,315.5971249999998,316.2210839999998,318.71291599999995,321.17258300000003,324.00199999999995,332.34854200000063,335.9848340000001]
- p50ExitMs: 316.2210839999998
- p95ExitMs: 335.9848340000001
- maxExitMs: 335.9848340000001
- limitations: Fresh process is NOT after-reboot cold. Loopback own server. Grok ordinary Read allow is empty stdout; protocol-return is stdout end and may coincide with process exit after settlement. Online success requires GET /api/v1/state event id match plus decision allow|log and enforcement delivered. Fallback is classified separately and excluded from online percentiles. Windows local synthetic measurement is not HOST_REAL tool enforcement.

## subprocess-fresh-process-offline-cached-policy

- scenario: subprocess-fresh-process-offline-cached-policy
- ok: true
- n: 10
- nSuccess: 10
- nFailed: 0
- nFallback: 0
- cacheProven: true
- cleanupIncomplete: false
- rawProtocolMs: [282.4255840000005,285.45245799999975,286.595542,301.04725000000053,305.1749579999996,335.54099999999926,339.39458300000024,369.2566249999991,374.0423330000003,378.69795799999974]
- p50ProtocolMs: 305.1749579999996
- p95ProtocolMs: 378.69795799999974
- maxProtocolMs: 378.69795799999974
- rawExitMs: [285.2174590000004,288.5960420000001,290.3895000000002,303.6113750000004,307.96858299999985,338.54520799999955,342.5295420000002,372.4837089999992,377.042375,381.24641599999995]
- p50ExitMs: 307.96858299999985
- p95ExitMs: 381.24641599999995
- maxExitMs: 381.24641599999995
- limitations: Fresh process is NOT after-reboot cold. Offline uses the same valid locally cached policy after the owned loopback server is closed. Grok ordinary Read allow is empty stdout; protocol-return is stdout end and may coincide with process exit after settlement. Offline success requires a fresh same-event outbox item (tool/decision/policyVersion) and hook-status ok for that eventId. Cache existence and no-cache low-risk allow are insufficient. Server receipts are absent because the owned server is closed. Windows local synthetic measurement is not HOST_REAL tool enforcement.

- fixtureRemoved: true

- cleanupIncomplete: false

## Unavailable cells

- scenario: reboot-first-sample
  status: NOT_RUN
  reason: Fresh process is not after-reboot cold. A human must run the supplied instructions after a real reboot.
- scenario: HOST_REAL-tool-enforcement
  status: NOT_RUN
  reason: Windows local synthetic measurement is not HOST_REAL tool enforcement.
- scenario: linux-subprocess-online
  status: NOT_RUN
  reason: Linux environment absent (platform=win32); no fabricated data.
- scenario: linux-subprocess-offline
  status: NOT_RUN
  reason: Linux environment absent (platform=win32); no fabricated data.

## Reboot-first-sample instructions (human only)

This script never reboots the host. After a real OS reboot, before other NMZP processes:

```
node --experimental-strip-types scripts/bench-hook.mjs --subprocess 1 --timeout-ms 15000
```

Record only the first sample as reboot-first-sample. Until a human does that, status is NOT_RUN.
