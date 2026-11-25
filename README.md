# srsRAN LTE NAS Parser Fuzzing — APN IE Over-read

A small defensive-security project: I built an in-process libFuzzer + AddressSanitizer
harness for srsRAN_4G's LTE **NAS message decoder** (`liblte_mme`), rediscovered a
**heap buffer over-read** in the *Access Point Name (APN)* information-element parser,
did the root-cause analysis, traced reachability, wrote a bounds-checking fix, and
verified the fix against the original crashing input.

> **Honest scope statement (please read).**
> This is **not** a novel CVE. It is an **independent rediscovery, via my own fuzzing
> pipeline, of a well-known class of NAS-parser memory bug.** The same bug class is
> tracked publicly in other cellular stacks (e.g. Magma `decode_access_point_name_ie`,
> CVE-2024-24416) and in academic fuzzing of srsLTE/openLTE NAS code. The value here
> is the *method and the analysis*, not a new disclosure. See
> [Prior art](#prior-art--this-is-a-known-bug-class) below.
>
> All work was done **entirely inside a local VirtualBox VM against my own installation
> of open-source srsRAN. No radio hardware and no RF transmission were involved.**

---

## TL;DR

| | |
|---|---|
| **Target** | `liblte_mme_unpack_access_point_name_ie()` in `lib/src/asn1/liblte_mme.cc` |
| **Bug** | Heap buffer **over-read**: the parser trusts a length byte *inside* the message and never checks it against the number of bytes actually delivered. |
| **Found by** | libFuzzer + AddressSanitizer harness calling the real decoder in-process (`harness/harness_apn.cc`) |
| **Time to first crash** | < 1 second |
| **Minimal crashing input** | a single byte: `0x0A` (claims a 10-byte name, delivers 1) |
| **Severity (honest)** | Robustness / latent bug. In the real build the message sits in a fixed 12 237-byte buffer, so the over-read stays in-bounds and does **not** crash production. ASan flags it because the harness uses a tightly-sized heap buffer. |
| **Fix** | Pass the real available length down to the parser and bounds-check every read (`harness/harness_apn_fixed.cc`, `fix/apn_bounds_check.patch`) |
| **Fix verified** | Fixed version handles the crashing input safely and survives a 20 s fuzzing run with zero ASan reports. |

---

## Why this is an interesting project for modem / SoC validation

- It exercises the exact skill a **modem protocol validation** or **SoC bring-up
  validation** engineer needs: feed malformed over-the-air control-plane messages into
  a parser and prove the parser is memory-safe.
- The bug class — *"trust a length field in the payload without checking it against the
  bytes you actually received"* — is the single most common memory-safety defect in
  protocol decoders (conceptually the same mistake as Heartbleed).
- It shows the **full professional cycle**: build a fuzzer → trigger → root-cause →
  assess reachability and real-world severity honestly → fix → regression-verify →
  **check prior art before claiming novelty.**

---

## Repository layout

```
srsran-nas-fuzzing/
├── README.md                     ← you are here
├── harness/
│   ├── harness_apn.cc            ← fuzzer that triggers the over-read in the REAL function
│   └── harness_apn_fixed.cc      ← the same parser logic, bounds-checked (the fix)
├── fix/
│   └── apn_bounds_check.patch    ← the core change expressed as a diff
├── docs/
│   ├── root-cause.md             ← line-by-line explanation of why it over-reads
│   └── reproduce.md              ← exact build + run commands (VM, ZMQ, no RF)
└── crash/
    └── crash-input.md            ← the minimal crashing input and how to recreate it
```

---

## Prior art — this IS a known bug class

I checked whether this was already reported **before** describing it as a finding
(this due-diligence step is itself part of the job).

- **Magma — `decode_access_point_name_ie` buffer overflow, CVE-2024-24416.** A crafted
  NAS packet overflows the APN decoder in a *different* 4G/5G core. Same function
  concept, independently assigned a CVE and fixed.
  <https://nvd.nist.gov/vuln/detail/CVE-2024-24416>
- **Magma — reachable assertion in the same area, CVE-2024-24424.**
  <https://nvd.nist.gov/vuln/detail/CVE-2024-24424>
- **Academic fuzzing of srsLTE / openLTE NAS parsing** ("Berserker", arXiv:2107.01912)
  reports buffer overflows in srsLTE NAS message parsing, and notes the parsing code
  derives from openLTE — which is exactly where `liblte_mme` comes from.
  <https://arxiv.org/pdf/2107.01912>

**Conclusion:** the APN/NAS parser over-read is a *recognized, cross-project* class of
bug. My srsRAN finding is a faithful instance of it, reproduced with my own tooling —
not a new disclosure.

---

## License / ethics

srsRAN_4G is AGPL-licensed open-source software. This repository contains only my own
harness code, a patch, and analysis notes; it does **not** redistribute srsRAN sources.
All testing was local, in a VM, with no RF emission.
