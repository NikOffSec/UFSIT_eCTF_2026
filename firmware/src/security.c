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
    uint8_t eq1 = ct_eq(in, ref, PIN_LEN);
    uint8_t eq2 = ct_eq(in, ref, PIN_LEN);

    uint8_t ok = (uint8_t)(eq1 & eq2);
    ok = harden_decision(ok);

    return ok ? true : false;
}

bool validate_permission(uint16_t group_id, permission_enum_t perm) {
    char output_buf[128] = {0};

    sprintf(output_buf, "Checking %c permissions for group: %hx\n", perm, group_id);
    print_debug(output_buf);

    // TODO: the reference design doesn't implement *ANY* security.
    // This function currently does nothing. Your team should add the
    // appropriate security checks here to implement the security
    // requirements.
    return true;
}
