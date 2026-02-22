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
#include "simple_timer.h"
#include <math.h>

bool check_pin(unsigned char *pin) {

    print_debug(HSM_PIN);
    print_debug(pin);

    //Ensure that length is the same (would otherwise have issues with longer pin than HSM_PIN)
    if(fmin(strlen(pin)-1, 6) > strlen(HSM_PIN)-1){
        timer_wait_5s();
        return false;
    }
    
    // -1 is because sizeof(HSM_PIN) returns 7 however we don't care about null term
    if(memcmp(pin, HSM_PIN, sizeof(HSM_PIN) - 1)) {
        timer_wait_5s();
        return false;
    }

    return true;
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
