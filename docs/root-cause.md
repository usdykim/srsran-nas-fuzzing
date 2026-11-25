# Root-cause analysis — APN IE over-read

## Where

`liblte_mme_unpack_access_point_name_ie()` in
`lib/src/asn1/liblte_mme.cc` (~line 3369). The crashing read is at line 3381.

```c
// signature — note there is NO length parameter
LIBLTE_ERROR_ENUM liblte_mme_unpack_access_point_name_ie(uint8 **ie_ptr,
                                                         LIBLTE_MME_ACCESS_POINT_NAME_STRUCT *apn)

while (ie_idx < (*ie_ptr)[0] && str_cnt < LIBLTE_STRING_LEN) {   // (*ie_ptr)[0] = claimed length
    label_len = (*ie_ptr)[1 + ie_idx];                           // 3381: READ — can be past the end
    for (i = 0; i < label_len && str_cnt < LIBLTE_STRING_LEN; i++) {
        apn->apn[str_cnt] = (char)((*ie_ptr)[1 + ie_idx + i + 1]);
        str_cnt++;
    }
    ie_idx += label_len + 1;
    ...
}
```

## The two lengths

- **Claimed length** — `(*ie_ptr)[0]`, the first byte of the payload. This is
  attacker-controlled data from inside the message.
- **Delivered length** — the number of bytes the NAS message actually carried.
  This comes from the transmission framing (`msg->N_bytes`), **not** from the
  content. The decoder is never given it.

The loop iterates up to the **claimed** length and indexes into the buffer, but
nothing stops it at the **delivered** length. If an attacker sends a payload that
*says* "10 bytes of APN" but only ships 1 byte, the parser keeps reading bytes
2…10 — past the end of what was delivered.

## Why ASan catches it in the harness but not in the stock binary

In the real srsRAN build, every incoming NAS message is copied into a fixed
`LIBLTE_BYTE_MSG_STRUCT` whose buffer is `LIBLTE_MAX_MSG_SIZE_BYTES = 12237`
bytes. A 10-vs-1-byte over-read therefore lands on *leftover bytes inside that
same large buffer* — still in-bounds for the allocation, so no segfault. The
result is **silent garbage in the parsed APN string**, not a crash.

The harness copies each input into a heap buffer sized *exactly* to the input, so
the very first byte past the end is a real out-of-bounds access, which
AddressSanitizer reports immediately. This is a standard fuzzing technique:
shrink the buffer so latent over-reads become visible.

## Honest severity

- **Not** a remote crash in the shipped binary (fixed 12 KB buffer absorbs it).
- It **is** a genuine robustness / memory-safety defect: the parser trusts a
  length field in untrusted data without validating it against bytes received.
- Direction of reachability: the vulnerable message
  (*Activate Default EPS Bearer Context Request*) is **network → UE**, i.e. it
  comes from the core/base station toward the phone. A malicious or faulty base
  station is the relevant threat model.

## The fix (one sentence)

Give the decoder the real delivered length and make it stop reading at that
boundary — see `fix/apn_bounds_check.patch` and `harness/harness_apn_fixed.cc`.
