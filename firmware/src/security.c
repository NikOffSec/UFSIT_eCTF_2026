/**
 * @file security.c
 * @author Samuel Meyers
 * @brief Stub file to hold security checks
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026 Embedded CTF (eCTF).
 * This code is being provided only for educational purposes for the 2026 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "security.h"
#include "host_messaging.h"
#include "secrets.h"
#include "simple_trng.h"
#include "gmac.h"

#define NONCE_CACHE_SLOTS 32

typedef struct {
    bool used;
    uint16_t sender_id;
    uint8_t nonce[GMAC_NONCE_LEN];
} nonce_entry_t;

static nonce_entry_t g_nonce_cache[NONCE_CACHE_SLOTS];
static uint8_t g_nonce_rr_idx = 0;

/**********************************************************
 ******************** HELPER FUNCTIONS ********************
 **********************************************************/

static bool ct_mem_eq(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return (diff == 0);
}

// Constant-time compare helper that returns 1 if equal, 0 otherwise
static uint8_t ct_eq(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }

    // Convert diff==0 to 1, else 0 (branchless-ish)
    uint8_t x = (uint8_t)(diff | (uint8_t)(0u - diff));
    return (uint8_t)((x >> 7) ^ 1u);
}

// Crude fault-hardening consistency check
static uint8_t harden_decision(uint8_t ok) {
    volatile uint8_t a = ok;
    volatile uint8_t b = ok;
    volatile uint8_t inv = (uint8_t)(ok ^ 1u);

    // If a glitch flips one value, consistency check fails -> return 0
    uint8_t consistent = (uint8_t)((a == b) & (a ^ inv));
    return (uint8_t)(consistent & a);
}

/**********************************************************
 ********************* CORE FUNCTIONS *********************
 **********************************************************/

// Reject exact nonce replay per sender_id, otherwise accept and cache
bool nonce_accept(uint16_t sender_id, const uint8_t *nonce, size_t nonce_len) {
    if (nonce == NULL || nonce_len != GMAC_NONCE_LEN) {
        return false;
    }

    // Reject exact replay for same sender
    for (size_t i = 0; i < NONCE_CACHE_SLOTS; i++) {
        if (!g_nonce_cache[i].used) continue;
        if (g_nonce_cache[i].sender_id != sender_id) continue;

        if (ct_mem_eq(g_nonce_cache[i].nonce, nonce, GMAC_NONCE_LEN)) {
            return false; // replay detected
        }
    }

    // Insert into first free slot
    for (size_t i = 0; i < NONCE_CACHE_SLOTS; i++) {
        if (!g_nonce_cache[i].used) {
            g_nonce_cache[i].used = true;
            g_nonce_cache[i].sender_id = sender_id;
            memcpy(g_nonce_cache[i].nonce, nonce, GMAC_NONCE_LEN);
            return true;
        }
    }

    // Cache full -> overwrite round-robin
    g_nonce_cache[g_nonce_rr_idx].used = true;
    g_nonce_cache[g_nonce_rr_idx].sender_id = sender_id;
    memcpy(g_nonce_cache[g_nonce_rr_idx].nonce, nonce, GMAC_NONCE_LEN);
    g_nonce_rr_idx = (uint8_t)((g_nonce_rr_idx + 1u) % NONCE_CACHE_SLOTS);

    return true;
}

// Fill arbitrary-length buffer using repeated 32-bit TRNG outputs
int trng_get_bytes(uint8_t *out, size_t len) {
    if (out == NULL) return -1;

    size_t i = 0;
    while (i < len) {
        uint32_t r = (uint32_t)trng_generate();

        // Pack little-endian bytes from the 32-bit word
        out[i++] = (uint8_t)(r & 0xFFu);
        if (i < len) out[i++] = (uint8_t)((r >> 8) & 0xFFu);
        if (i < len) out[i++] = (uint8_t)((r >> 16) & 0xFFu);
        if (i < len) out[i++] = (uint8_t)((r >> 24) & 0xFFu);
    }

    return 0;
}

bool check_pin(unsigned char *pin) {
    print_debug("Checking PIN\n");

    if (pin == NULL) return false;

    const uint8_t *ref = (const uint8_t *)HSM_PIN;
    const uint8_t *in  = (const uint8_t *)pin;

    // Redundant checks to make single-fault bypass harder
    uint8_t eq1 = ct_eq(in, ref, PIN_LENGTH);
    uint8_t eq2 = ct_eq(in, ref, PIN_LENGTH);

    uint8_t ok = (uint8_t)(eq1 & eq2);
    ok = harden_decision(ok);

    return (ok != 0u);
}

bool validate_permission(uint16_t group_id, permission_enum_t perm) {
    char output_buf[128] = {0};

    sprintf(output_buf, "Checking %c permissions for group: %hx\n", perm, group_id);
    print_debug(output_buf);

    for (uint8_t i = 0; i < MAX_PERMS; i++) {
        // Convention: unused slots have group_id == 0
        if (global_permissions[i].group_id == 0) {
            continue;
        }

        if (global_permissions[i].group_id == group_id) {
            switch (perm) {
                case PERM_READ:
                    return global_permissions[i].read;
                case PERM_WRITE:
                    return global_permissions[i].write;
                case PERM_RECEIVE:
                    return global_permissions[i].receive;
                default:
                    return false;
            }
        }
    }

    // Group not found => deny by default
    return false;
}
