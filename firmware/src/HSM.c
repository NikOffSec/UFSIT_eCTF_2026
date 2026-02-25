/**
 * @file    HSM.c
 * @author  Samuel Meyers
 * @brief   Boot code and main function for the HSM
 * @date    2026
 *
 * This source file is part of an example system for MITRE's 2026
 * Embedded CTF (eCTF). This code is being provided only for
 * educational purposes for the 2026 MITRE eCTF competition, and may not
 * meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

/*********************** INCLUDES *************************/
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>

#include "simple_flash.h"
#include "host_messaging.h"
#include "commands.h"
#include "filesystem.h"
#include "ti_msp_dl_config.h"
#include "status_led.h"
#include "simple_uart.h"

#include "simple_trng.h"
#include "simple_timer.h"

/* Code between this #ifdef and the subsequent #endif will
 * be ignored by the compiler if CRYPTO_EXAMPLE is not set in
 * the Makefile. */
#ifdef CRYPTO_EXAMPLE
/* The simple crypto example included with the reference design is
 * intended to be an example of how you *may* use cryptography in your
 * design. You are not limited nor required to use this interface in
 * your design. It is recommended for newer teams to start by only using
 * the simple crypto library until they have a working design. */
#include "simple_crypto.h"
#endif  // CRYPTO_EXAMPLE

/**********************************************************
 ************************ GLOBALS *************************
 **********************************************************/

static unsigned char uart_buf[MAX_MSG_SIZE];

/**********************************************************
 ********************* CORE FUNCTIONS *********************
 **********************************************************/

/** @brief Initializes peripherals for system boot.
 */
void init() {

    #include "ti_msp_dl_config.h"

    static void tamper_bor_nmi_init(void) {
        /*
        * Choose a BOR threshold level that generates early BOR indication (NMI path),
        * not immediate hard reset-only behavior. BOR1/2/3 are the "warning" levels;
        * BOR0 is the hard BOR floor.
        *
        * Start with LEVEL_3 (most sensitive warning) for testing, then tune.
        */
        DL_SYSCTL_setBORThreshold(DL_SYSCTL_BOR_THRESHOLD_LEVEL_3);

        /*
        * This applies the threshold and clears prior BOR violation status indications.
        */
        DL_SYSCTL_activateBORThreshold();

        /*
        * Clear stale pending BOR NMI status before enabling handling logic.
        */
        DL_SYSCTL_clearNonMaskableInterruptStatus(DL_SYSCTL_NMI_BORLVL);
    }

    // Initialize all of the hardware components
    SYSCFG_DL_init();

    void init() {
        SYSCFG_DL_init();

        tamper_bor_nmi_init();

        init_fs();

        if (trng_init()) {
            while (1) { }
        }

        if (timer_init()) {
            while (1) { }
        }
    }

    init_fs();

    if (trng_init()) {
        while (1) {
            //print_error("ERROR: TRNG CAN'T INIT");
        }
    }

    if (timer_init()) {
        while (1) {
            //print_error("ERROR: COUNTER CAN'T INIT");
        }
    }
}

/**********************************************************
 *********************** MAIN LOOP ************************
 **********************************************************/

int main(void) {
    char output_buf[128] = {0};
    msg_type_t cmd;
    int result;
    uint16_t pkt_len;

    // initialize the device
    init();

    void main(void)
    {
    SYSCFG_DL_init();

    tamper_latch_init_if_needed();

    if (tamper_latch_is_tripped()) {
        /* Restricted mode: no transfers, no secrets, blink LED forever */
        enter_tamper_lock_mode();
    }

    /* normal init / command loop */
    }

    // process commands forever
    while (1) {

        // Clear the input buffer so that sensitive data from a past session can't be yoinked!
        memset(uart_buf, 0, sizeof(uart_buf));

        print_debug("Ready\n");

        STATUS_LED_ON();

        // Fix buffer overflow from command line
        pkt_len = sizeof(uart_buf);
<<<<<<< HEAD
        result = read_packet(CONTROL_INTERFACE, &cmd, uart_buf, &pkt_len);
        
        if (tamper_latch_is_tripped()) {
            enter_tamper_lock_mode();
        }
=======
        result = read_packet(CONTROL_INTERFACE, &cmd, &uart_buf, &pkt_len);
>>>>>>> 7828ddc89816c41bc209393d170af6e31a623c7f

        if (result != MSG_OK) {
            STATUS_LED_OFF();
            switch (result) {
            case MSG_BAD_PTR:
                print_error("Bad cmd pointer\n");
                break;
            case MSG_NO_ACK:
                print_error("Failed to receive ACK from host\n");
                break;
            case MSG_BAD_LEN:
                print_error("Received bad length\n");
                break;
            default:
                print_error("Failed to receive cmd from host\n");
                break;
            }
            continue;
        }

        // Handle the requested command
        switch (cmd) {

        // Handle list command
        case LIST_MSG:
#ifdef CRYPTO_EXAMPLE
            // Run the crypto example
            // TODO: Remove this from your design before competition submission
            crypto_example();
#endif  // CRYPTO_EXAMPLE
            STATUS_LED_OFF();
            list(pkt_len, &uart_buf);
            break;

        // Handle read command
        case READ_MSG:
            STATUS_LED_OFF();
            read(pkt_len, &uart_buf);
            break;

        // Handle write command
        case WRITE_MSG:
            STATUS_LED_OFF();
            write(pkt_len, &uart_buf);
            break;

        // Handle receive command
        case RECEIVE_MSG:
            STATUS_LED_OFF();
            receive(pkt_len, &uart_buf);
            break;

        // Handle interrogate command
        case INTERROGATE_MSG:
            STATUS_LED_OFF();
            interrogate(pkt_len, &uart_buf);
            break;

        // Handle listen command
        case LISTEN_MSG:
            STATUS_LED_OFF();
            listen(pkt_len, &uart_buf);
            break;

        // Handle bad command
        default:
            STATUS_LED_OFF();
            sprintf(output_buf, "Invalid Command: %c\n", cmd);
            //print_error(output_buf);
            break;
        }
    }
}
