#include "gmac.h"

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/error-crypt.h"

static void secure_memzero(void *p, size_t n) {
    volatile uint8_t *vp = (volatile uint8_t *)p;
    while (n--) {
        *vp++ = 0;
    }
}

int gmac_compute_tag(
    const uint8_t key[GMAC_KEY_LEN],
    const uint8_t nonce[GMAC_NONCE_LEN],
    const uint8_t *aad,
    size_t aad_len,
    uint8_t out_tag[GMAC_TAG_LEN]
) {
    if (key == NULL || nonce == NULL || out_tag == NULL) {
        return -1;
    }
    if (aad == NULL && aad_len != 0) {
        return -2;
    }

    /* wolfCrypt uses word32 for lengths in this API */
    if (aad_len > 0xFFFFFFFFu) {
        return -3;
    }

    Aes aes;
    int rc;

    memset(&aes, 0, sizeof(aes));

    /* Bare-metal safe init */
    rc = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (rc != 0) {
        secure_memzero(&aes, sizeof(aes));
        return -10;
    }

    rc = wc_AesGcmSetKey(&aes, key, GMAC_KEY_LEN);
    if (rc != 0) {
        wc_AesFree(&aes);
        secure_memzero(&aes, sizeof(aes));
        return -11;
    }

    /*
     * GMAC = GCM with zero-length plaintext.
     * Some implementations are picky about NULL in/out even when len==0,
     * so give a valid dummy pointer.
     */
    uint8_t dummy = 0;

    rc = wc_AesGcmEncrypt(
        &aes,
        &dummy,                       /* out */
        &dummy,                       /* in */
        0,                            /* plaintext length = 0 => GMAC */
        nonce, GMAC_NONCE_LEN,
        out_tag, GMAC_TAG_LEN,
        aad, (word32)aad_len
    );

    wc_AesFree(&aes);
    secure_memzero(&aes, sizeof(aes));

    if (rc != 0) {
        return -12;
    }

    return 0;
}

bool gmac_tag_eq_ct(const uint8_t a[GMAC_TAG_LEN], const uint8_t b[GMAC_TAG_LEN]) {
    uint8_t diff = 0;
    for (size_t i = 0; i < GMAC_TAG_LEN; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0;
}
