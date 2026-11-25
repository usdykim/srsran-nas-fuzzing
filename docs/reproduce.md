# How to reproduce

Everything below was run inside a local VirtualBox Ubuntu VM against a local
build of srsRAN_4G. **No RF hardware, no transmission** — the radio is the ZMQ
virtual RF, and the fuzzing targets a decoder function in-process (it does not
even need the stack running).

## 0. Prerequisites

```bash
sudo apt-get install -y clang cmake build-essential libfftw3-dev libmbedtls-dev \
                        libboost-program-options-dev libconfig++-dev libsctp-dev
# srsRAN_4G checked out at ~/srs/srsRAN_4G
```

## 1. Compile the NAS codec with ASan instrumentation

```bash
SRC=~/srs/srsRAN_4G
clang++ -c -std=c++17 -g -fsanitize=address,fuzzer-no-link \
        -I $SRC/lib/include \
        $SRC/lib/src/asn1/liblte_mme.cc -o /tmp/liblte_mme.o
```

## 2. Build the fuzzer (finds the bug)

```bash
clang++ -std=c++17 -g -fsanitize=address,fuzzer \
        -I $SRC/lib/include \
        harness/harness_apn.cc /tmp/liblte_mme.o -o fuzz_apn
```

## 3. Run it

```bash
./fuzz_apn -max_total_time=30 -max_len=256
```

Expected: AddressSanitizer reports a `heap-buffer-overflow READ of size 1` at
`liblte_mme.cc:3381`, typically in under a second, and libFuzzer writes a
`crash-<sha1>` file containing the minimal reproducer (a single `0x0A` byte).

## 4. Build and run the fixed version (verifies the fix)

```bash
clang++ -std=c++17 -g -fsanitize=address,fuzzer \
        -I $SRC/lib/include \
        harness/harness_apn_fixed.cc -o fuzz_apn_fixed

./fuzz_apn_fixed crash-<sha1>        # handled safely, exit 0, no ASan report
./fuzz_apn_fixed -max_total_time=20   # survives, no crash
```

## (Optional) the baseline LTE stack over ZMQ

For context, the same VM ran a full software LTE attach (srsepc + srsenb + srsue)
over ZMQ virtual radio with the channel emulator disabled — EPC/eNB/UE in one
box, UE pingable from the `ue1` network namespace. That is the environment the
APN message exists in; the fuzzing itself does not require it.
