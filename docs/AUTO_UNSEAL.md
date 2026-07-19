# CLI v0.8.17.1 automatic unseal

KPMDynaLab intentionally permits only one SEALED analysis session at a time. Starting another target while SEALED would mix lineage, action statistics and containment state across sessions.

After a `run` target exits, CLI now queries `ACTIVE`:

- zero active tracked subjects: send `UNSEAL` automatically, then offer workdir cleanup;
- active descendants remain: preserve artifacts, keep SEALED, and print guidance to inspect `session active`.

This makes sequential runs work without a manual `unseal` in the ordinary case while preserving containment for daemonized descendants.

If a user attempts `run` during a manually sealed or lingering session, CLI prints two explicit lines:

```text
Operation not permitted: a session is already SEALED.
Hint: wait for descendants or run 'unseal' first.
```

Compatible with KPM v0.8.17, RPC API 19 and Event ABI 8. License: GPL-2.0-only.
