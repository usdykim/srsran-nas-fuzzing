# Minimal crashing input

The smallest input that triggers the over-read is **a single byte**:

```
0x0A        # decimal 10
```

## Why this crashes

- Byte 0 (`0x0A`) is read as the **claimed APN length = 10**.
- Only **1** byte was delivered.
- The parse loop tries to read bytes 1, 2, … up to the claimed length, so it
  reads byte index 1 — one past the end of the 1-byte buffer.
- Under ASan (with the exactly-sized heap buffer in the harness) this is a
  `heap-buffer-overflow READ` at `liblte_mme.cc:3381`.

## Recreate the reproducer file

```bash
printf '\x0a' > crash-input
./fuzz_apn crash-input     # reproduces the ASan report
```

libFuzzer originally saved this as `crash-adc83b19e793491b1c6ea0fd8b46cd9f32e592fc`
(the SHA-1 of the one-byte content). The raw binary file is intentionally not
committed; the `printf` above recreates it exactly.
