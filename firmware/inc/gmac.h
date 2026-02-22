#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define GMAC_NONCE_LEN 12
#define GMAC_TAG_LEN   16
#define GMAC_KEY_LEN   16

// Compute GMAC tag = GCM(key, nonce, aad, aad_len, plaintext_len=0)
int gmac_compute_tag(
    const uint8_t key[GMAC_KEY_LEN],
    const uint8_t nonce[GMAC_NONCE_LEN],
    const uint8_t *aad,
    size_t aad_len,
    uint8_t out_tag[GMAC_TAG_LEN]
);

// Constant-time compare for tags
bool gmac_tag_eq_ct(const uint8_t a[GMAC_TAG_LEN], const uint8_t b[GMAC_TAG_LEN]);
