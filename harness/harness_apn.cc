// harness_apn.cc
// -----------------------------------------------------------------------------
// In-process libFuzzer + AddressSanitizer harness for srsRAN_4G's LTE NAS
// Access Point Name (APN) information-element decoder.
//
// It calls the REAL, UNMODIFIED function:
//     liblte_mme_unpack_access_point_name_ie(uint8** ie_ptr, ...)
// which lives in lib/src/asn1/liblte_mme.cc (~line 3369).
//
// The decoder reads a length byte out of the message and then reads that many
// bytes, WITHOUT ever being told how many bytes were actually delivered. When
// the claimed length exceeds the delivered length, it reads past the buffer.
// ASan catches this because we give it a heap buffer sized exactly to the input.
//
// Build (inside the srsRAN_4G tree, SRC=~/srs/srsRAN_4G):
//   clang++ -c -std=c++17 -g -fsanitize=address,fuzzer-no-link \
//           -I $SRC/lib/include $SRC/lib/src/asn1/liblte_mme.cc -o /tmp/liblte_mme.o
//   clang++ -std=c++17 -g -fsanitize=address,fuzzer \
//           -I $SRC/lib/include harness_apn.cc /tmp/liblte_mme.o -o fuzz_apn
//
// Run:
//   ./fuzz_apn -max_total_time=30
//
// Result: crashes in < 1 s at liblte_mme.cc:3381 (heap-buffer-overflow READ).
// Minimal crashing input: a single byte 0x0A.
// -----------------------------------------------------------------------------

#include "srsran/asn1/liblte_mme.h"
#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;

    // Copy the fuzzer input into a heap buffer sized EXACTLY to `size`, so that
    // any read past byte `size-1` is a real out-of-bounds access ASan can see.
    uint8_t *buf = (uint8_t *)malloc(size);
    memcpy(buf, data, size);

    uint8_t *p = buf;
    LIBLTE_MME_ACCESS_POINT_NAME_STRUCT apn;

    // Call the real decoder. Note: it takes NO length argument — that missing
    // length is the whole bug.
    liblte_mme_unpack_access_point_name_ie(&p, &apn);

    free(buf);
    return 0;
}
