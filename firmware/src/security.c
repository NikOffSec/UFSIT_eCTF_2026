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
#include "security.h"
#include "host_messaging.h"
#include "secrets.h"
#include "simple_crypto.h"

// A constant time comparison function
// Returns 0 if they are not equal, returns 1 if they are
static uint8_t ct_eq(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    uint8_t x = (uint8_t)(diff | (uint8_t)(0u - diff));
    return (uint8_t)((x >> 7) ^ 1u);
}

// Very crude fault hardening: verify the descision is internall consistent
static uint8_t harden_decision(uint8_t ok) { 
    volatile uint8_t a = ok;
    volatile uint8_t b = ok;
    volatile uint8_t inv = (uint8_t)(ok ^ 1u);

    // If a glitch flips one value, consistency check fails --> return 0
    uint8_t consistent = (uint8_t)((a == b) & ((a ^ inv) ));
    return (uint8_t)(consistent & a);
}

bool check_pin(unsigned char *pin) {
    print_debug("Checking PIN\n");
    if (pin == NULL) return false;

    const uint8_t *ref = (const uint8_t *)HSM_PIN;
    const uint8_t *in  = (const uint8_t *)pin;

    // Reduntant checks to secure against fault injection
    uint8_t eq1 = ct_eq(in, ref, PIN_LENGTH);
    uint8_t eq2 = ct_eq(in, ref, PIN_LENGTH);

    uint8_t ok = (uint8_t)(eq1 & eq2);
    ok = harden_decision(ok);

    return ok ? true : false;
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

static uint8_t perm_flags(const group_permission_t *p) {
    return (uint8_t)((p->read ? 1u : 0u) |
                     (p->write ? 2u : 0u) |
                     (p->receive ? 4u : 0u));
}

static size_t pack_permissions_sorted(const group_permission_t *in, size_t n,
                                      uint8_t *out, size_t out_cap) {
    // Make a local copy and sort it (n is small: MAX_PERMS=8)
    group_permission_t tmp[MAX_PERMS];
    size_t m = 0;

    for (size_t i = 0; i < n; i++) {
        if (in[i].group_id == 0) continue;   // your current sentinel
        tmp[m++] = in[i];
    }

    // insertion sort (m <= 8)
    for (size_t i = 1; i < m; i++) {
        group_permission_t key = tmp[i];
        size_t j = i;
        while (j > 0 && tmp[j-1].group_id > key.group_id) {
            tmp[j] = tmp[j-1];
            j--;
        }
        tmp[j] = key;
    }

    size_t need = m * 3;
    if (out_cap < need) return 0;

    for (size_t i = 0; i < m; i++) {
        uint16_t gid = tmp[i].group_id;
        out[i*3 + 0] = (uint8_t)(gid >> 8);
        out[i*3 + 1] = (uint8_t)(gid & 0xFF);
        out[i*3 + 2] = perm_flags(&tmp[i]);
    }
    return need;
}
