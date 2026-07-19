# v0.8.15 command semantics

Canonical CLI vocabulary now follows noun/action grouping:

```text
clear                  clear terminal screen only
events                  show resident event ring
events clear            clear event ring
events export           export event ring
mode auto|trace|expert  select containment mode
seal                    enter containment
unseal                  leave containment and return READY
session active          inspect tracked target/descendants
blg unload              unload the BLG RAM cache
```

Ambiguous prior names are removed from help. Transitional hidden aliases remain for one compatibility cycle:

```text
profile → mode
stop → unseal
active → session active
export → events export
blg release → blg unload
```

The kernel RPC accepts `UNSEAL` and returns `OK UNSEALED`; legacy `STOP` remains accepted for older clients. `exit` also asks to unseal and sends `UNSEAL` when a session is SEALED.

`clear` never touches kernel events. `events clear` retains the existing safety rule and is rejected while SEALED.

RPC API 17 / Event ABI 7. License: GPL-2.0-only.
