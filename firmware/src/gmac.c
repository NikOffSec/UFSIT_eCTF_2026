#include "gmac.h"

#include <string.h>
//#include "wolfssl/wolfcrypt/aes.h"

#include "gmac.h"
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

// TEST-ONLY deterministic tag generator.
// NOT cryptographically secure. Only for plumbing/integration tests.
int gmac_compute_tag(const uint8_t *key,
                     const uint8_t *nonce,
                     const uint8_t *aad,
                     size_t aad_len,
                     uint8_t out_tag[GMAC_TAG_LEN]) {
    uint8_t acc[GMAC_TAG_LEN];
    for (size_t i = 0; i < GMAC_TAG_LEN; i++) {
        acc[i] = (uint8_t)(0xA5u ^ (uint8_t)i);
    }

    // Mix key (assumes 16-byte key for now)
    if (key != NULL) {
        for (size_t i = 0; i < 16; i++) {
            acc[i % GMAC_TAG_LEN] ^= key[i];
            acc[(i * 5) % GMAC_TAG_LEN] =
                (uint8_t)(acc[(i * 5) % GMAC_TAG_LEN] + (uint8_t)(key[i] ^ 0x3C));
        }
    }

    // Mix nonce
    if (nonce != NULL) {
        for (size_t i = 0; i < GMAC_NONCE_LEN; i++) {
            acc[i % GMAC_TAG_LEN] ^= (uint8_t)(nonce[i] + (uint8_t)i);
            acc[(i + 7) % GMAC_TAG_LEN] =
                (uint8_t)(acc[(i + 7) % GMAC_TAG_LEN] + (uint8_t)(nonce[i] ^ 0xC3));
        }
    }

    // Mix AAD
    if (aad != NULL) {
        for (size_t i = 0; i < aad_len; i++) {
            acc[i % GMAC_TAG_LEN] ^= aad[i];
            acc[(i + 3) % GMAC_TAG_LEN] =
                (uint8_t)(acc[(i + 3) % GMAC_TAG_LEN] + (uint8_t)(aad[i] * 17u));
        }
    }

    memcpy(out_tag, acc, GMAC_TAG_LEN);
    return 0;
}

bool gmac_tag_eq_ct(const uint8_t a[GMAC_TAG_LEN], const uint8_t b[GMAC_TAG_LEN]) {
    uint8_t diff = 0;
    for (size_t i = 0; i < GMAC_TAG_LEN; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0;
}

static void memzero(volatile uint8_t *p, size_t n) {
    while (n--) *p++ = 0;
}

// int gmac_compute_tag(
//     const uint8_t key[GMAC_KEY_LEN],
//     const uint8_t nonce[GMAC_NONCE_LEN],
//     const uint8_t *aad,
//     size_t aad_len,
//     uint8_t out_tag[GMAC_TAG_LEN]
// ) {
//     if (!key || !nonce || (!aad && aad_len != 0) || !out_tag) return -1;

//     Aes aes;
//     memset(&aes, 0, sizeof(aes));

//     // wolfCrypt GCM API expects you to set the key, then call Encrypt/Decrypt
//     // For GMAC: plaintext length = 0, ciphertext length = 0.
//     int rc = wc_AesInit(&aes, NULL, INVALID_DEVID);
//     if (rc != 0) return -2;

//     rc = wc_AesGcmSetKey(&aes, key, GMAC_KEY_LEN);
//     if (rc != 0) {
//         wc_AesFree(&aes);
//         return -3;
//     }

//     // Some implementations tolerate NULL buffers for 0-length, some don’t.
//     // Use a dummy pointer with len=0 to be safe.
//     uint8_t dummy = 0;

//     rc = wc_AesGcmEncrypt(
//         &aes,
//         &dummy,          // out
//         &dummy,          // in
//         0,               // sz = 0 => GMAC
//         nonce, GMAC_NONCE_LEN,
//         out_tag, GMAC_TAG_LEN,
//         aad, (word32)aad_len
//     );

//     // Cleanup
//     wc_AesFree(&aes);
//     memzero((volatile uint8_t*)&aes, sizeof(aes));

//     return (rc == 0) ? 0 : -4;
// }
