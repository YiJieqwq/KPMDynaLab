# v0.4 CLI device test

This build moves normal analysis control out of Manager CTL0 and into a static ARM64 CLI.

## Artifacts

- `KPMDynaLab-0.4.0-test.kpm`
- `dynalab-arm64`

## 1. Load the KPM

Unload older KPMDynaLab builds first, then load v0.4.0.

Expected nodes:

```sh
ls -l /proc/dynalab
# control (0600), events (0400)
```

Expected log:

```text
[dynalab] loaded: /proc/dynalab/control + events
```

## 2. Configure a CLI password through trusted Manager CTL0

Preferred test flow avoids passing plaintext through CTL0 logging.

Push the CLI, then generate a verifier:

```sh
chmod 755 /data/local/tmp/dynalab
/data/local/tmp/dynalab verifier
Password: ********
SETVER 0123456789abcdef
```

Copy the complete `SETVER ...` line into Manager → KPMDynaLab → Control. Expected output:

```text
OK SETVER
```

For convenience, raw `SETUP your-password` is also accepted in this test build, but current KernelPatch versions may log CTL0 arguments in dmesg.

Manager CTL0 is now limited to:

```text
STATUS
SETUP <password>
SETVER <16-hex-verifier>
RESET
RESET ALL
```

`RESET` stops the analysis and preserves the password. `RESET ALL` also removes the password.

## 3. Start CLI

```sh
su -c /data/local/tmp/dynalab
```

Expected:

```text
KPMDynaLab CLI v0.4.0-test
Kernel: READY AUTO OFF
Password: ********
Login successful. Type 'help'.
DynaLab>
```

Commands:

```text
status
profile auto
profile trace
profile expert
seal
stop
events
clear
run <program> [args]
help
exit
```

Example safe test:

```text
DynaLab> profile auto
OK PROFILE
DynaLab> run /data/local/tmp/device_smoke.sh
OK SEALED
...
[PASS] simulated success; backing data unchanged
...
#1 BLOCK_WRITE ... SIMULATE
DynaLab> stop
OK STOP
```

## Security behavior in this prototype

- `/proc/dynalab/*` is root-only.
- LOGIN binds the control session to the CLI TGID.
- Once SEALED, profile changes are refused.
- Killing the CLI does not unseal the KPM.
- Only a logged-in CLI `stop` or trusted Manager CTL0 `RESET` disarms interception.
- Event storage is a 256-record overwrite ring.
- Password input disables terminal echo and is zeroed after deriving the verifier.
- CLI marks itself non-dumpable.

The v0.4 verifier is intentionally a protocol placeholder, not final password cryptography. The threat model for this test is: configure and seal before launching the root sample. A later milestone replaces it with challenge/HMAC without changing the CLI workflow.
