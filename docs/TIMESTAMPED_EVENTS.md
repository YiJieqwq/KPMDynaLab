# v0.8.10 timestamped events

Every binary event now carries two kernel-captured timestamps:

```text
realtime_ns   wall-clock nanoseconds since Unix epoch
monotonic_ns  monotonic nanoseconds since boot
```

Both values are captured in `add_event_for`, so block, reboot, process, file and gesture records all use the same timestamp policy.

CLI renders realtime in UTC/RFC3339 with millisecond precision and monotonic time as seconds since boot:

```text
2026-07-18T15:12:34.567Z mono=12345.678s
```

UTC avoids dependence on Android timezone configuration and remains unambiguous when logs are exported. Monotonic time remains valid for ordering and latency measurement even if wall time is corrected.

Kernel dmesg debug lines retain the kernel's own bracketed monotonic timestamp; they are not reformatted by KPM.

## Protocol

- RPC API: 12
- Event ABI: 5
- License: GPL-2.0-only

Old CLIs are intentionally rejected because the binary event record grew by two 64-bit fields.
