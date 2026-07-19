# v0.8.17 error outcomes and interactive targets

## Exit action

A tracked `do_exit` with encoded status zero emits `EXIT PASS`. Any nonzero exit code or terminating signal emits `EXIT ERROR`. CLI decodes the status:

```text
EXIT ERROR ... code=127
EXIT ERROR ... signal=9
```

Post-run summaries include a red ERROR total. An invalid command inside a valid shell script is not a parser error in KPMDynaLab; it is a successful shell EXEC followed by a failed target exit.

## Interactive stdin

The gated target inherits the CLI terminal stdin, stdout and stderr. While the parent CLI waits, target prompts and reads operate directly on the same terminal. CLI prints:

```text
Target running; interactive stdin/stdout/stderr attached.
```

This supports ordinary line input, passwords and menus. Full job-control features such as PTY isolation, detach/reattach, scripted stdin capture and terminal transcript events remain future work.

## Contextual SEALED hints

`events clear` and `blg unload` pre-check KPM status. While SEALED they print two explicit lines:

```text
Operation not permitted: events clear is disabled while SEALED.
Hint: run 'unseal' first.
```

RPC API 19 / Event ABI 8. License: GPL-2.0-only.
