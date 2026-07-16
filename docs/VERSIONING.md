# Component compatibility protocol

KPMDynaLab versions three independent surfaces:

1. Product version — human-readable release/build version.
2. RPC API version — commands, authentication flow, and replies.
3. Event ABI version — binary `/proc/dynalab/events` record layout and semantics.

Current test values:

```text
RPC API:   6
Event ABI: 2
KPM:       0.8.3-ram-cache-test
CLI:       0.8.3-ram-cache-test
```

Before STATUS or LOGIN, CLI sends:

```text
HELLO <cli-rpc-api> <cli-event-abi>
```

Compatible KPM replies:

```text
OK HELLO <kpm-rpc-api> <kpm-event-abi> <kpm-product-version>
```

Failure replies:

```text
ERR KPM_OLD
ERR CLI_OLD
ERR PROTOCOL
```

The CLI refuses to prompt for a login password or issue analysis commands until HELLO succeeds. This prevents a newer CLI from parsing an older binary event layout or sending commands with changed semantics.

Compatibility policy is deliberately strict during development: Event ABI must match exactly. RPC API can later support a negotiated range, but the current KPM requires CLI API 6 and exposes API 6.

User-facing CLI diagnostics distinguish absence from incompatibility:

```text
KPM component is not loaded. Load KPMDynaLab first.
KPM component is outdated. Update the KPM component.
CLI component is outdated. Update the CLI.
```
