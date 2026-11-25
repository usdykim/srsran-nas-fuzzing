// harness_apn_fixed.cc
// -----------------------------------------------------------------------------
// The SAME APN decoding logic as liblte_mme_unpack_access_point_name_ie(), but
// FIXED: the function is told the real number of bytes available (`avail`) and
// checks "does this byte actually exist?" before every single read.
//
// This is the regression target that proves the fix works. It handles the
// original crashing input safely and survives sustained fuzzing with no ASan
// report.
//
// Build:
//   clang++ -std=c++17 -g -fsanitize=address,fuzzer \
//           -I $SRC/lib/include harness_apn_fixed.cc -o fuzz_apn_fixed
// Run:
//   ./fuzz_apn_fixed crash-input          # handled safely, exit 0
//   ./fuzz_apn_fixed -max_total_time=20    # survives, no crash
// -----------------------------------------------------------------------------

#include "srsran/asn1/liblte_mme.h"
#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstring>

// FIXED version: same parsing logic, but it receives the real length (`avail`)
// and bounds-checks every read against it.
static int fixed_unpack_apn(uint8_t *ie, size_t avail,
                            LIBLTE_MME_ACCESS_POINT_NAME_STRUCT *apn) {
    if (ie == NULL || apn == NULL || avail < 1) return -1;

    uint32_t ie_idx = 0, str_cnt = 0, i, label_len;
    while (ie_idx < ie[0] && str_cnt < LIBLTE_STRING_LEN) {
        if ((size_t)(1 + ie_idx) >= avail) break;              /* <-- THE FIX */
        label_len = ie[1 + ie_idx];
        for (i = 0; i < label_len && str_cnt < LIBLTE_STRING_LEN; i++) {
            if ((size_t)(1 + ie_idx + i + 1) >= avail) break;  /* <-- THE FIX */
            apn->apn[str_cnt] = (char)ie[1 + ie_idx + i + 1];
            str_cnt++;
        }
        ie_idx += label_len + 1;
        if (ie_idx < ie[0] && str_cnt < LIBLTE_STRING_LEN) {
            apn->apn[str_cnt] = '.';
            str_cnt++;
        }
    }
    if (str_cnt < LIBLTE_STRING_LEN) apn->apn[str_cnt] = '\0';
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;
    uint8_t *buf = (uint8_t *)malloc(size);
    memcpy(buf, data, size);

    LIBLTE_MME_ACCESS_POINT_NAME_STRUCT apn;
    fixed_unpack_apn(buf, size, &apn);   // pass the REAL length

    free(buf);
    return 0;
}
