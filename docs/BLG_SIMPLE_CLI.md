# BLG simplified CLI (v0.8.6)

This CLI-only milestone keeps RPC API 8 compatibility with KPM v0.8.5 and makes the normal Boot Lifeguard path automatic.

After authenticated login:

1. EFISP Guard is registered when present;
2. a missing Recovery Pack triggers the first-run creation prompt;
3. an existing Pack is automatically prepared if KPM Cache/Map are not ready;
4. an already-ready KPM returns immediately without reloading 97 MiB.

Normal commands:

```text
blg status
blg setup
blg prepare
blg verify
blg release
```

- `setup`: drops the old cache, rebuilds the device-local pack, and prepares BLG.
- `prepare`: idempotently reaches CACHE READY RO + PLAN READY NO WRITE.
- `verify`: verifies disk Pack, KPM RAM SHA-256, and Image Map SHA-256.
- `release`: releases Cache/Map before SEALED.
- `advanced`: prints legacy low-level commands retained for testing.

Automatic preparation suppresses per-image SHA and upload lines but still reports the final ready state and timing.
