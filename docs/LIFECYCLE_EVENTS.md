# v0.8.12 lifecycle events

New Event ABI types:

```text
KPM_LOAD
CLI_LOGIN
CLI_LOGOUT
```

`KPM_LOAD` is appended after hooks and procfs initialize successfully. A failed partial load produces no successful load event.

`CLI_LOGIN` is appended only after verifier authentication succeeds. Failed authentication attempts are not included in this milestone.

`CLI_LOGOUT` is appended before the authenticated TGID is cleared. The CLI already sends `LOGOUT` on normal command-loop exit. Because the exiting CLI loses authorization, the logout record is normally visible on the next authenticated login/export.

Examples:

```text
KPM_LOAD   PASS  component=KPMDynaLab
CLI_LOGIN  PASS  pid=12345  scope=global
CLI_LOGOUT PASS  pid=12345  scope=global
```

`CLEAR`, Manager reset, ring wrap, KPM unload and reboot can remove lifecycle records just like other in-memory events.

RPC API 13 / Event ABI 6 force matching KPM and CLI, ensuring block-event task names are captured by the new KPM rather than silently pairing the new CLI with an older compatible component.

License: GPL-2.0-only.
