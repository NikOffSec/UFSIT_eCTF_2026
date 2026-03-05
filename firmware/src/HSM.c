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

#include "ecc_perm_check.h"

#include "simple_flash.h"
#include "host_messaging.h"
#include "commands.h"
#include "filesystem.h"
#include "ti_msp_dl_config.h"
#include "status_led.h"
#include "simple_uart.h"
#include "simple_trng.h"
#include "simple_timer.h"

/* Tamper / brownout latch support */
#include "tamper_latch.h"
#include "tamper_lock.h"
#include "tamper_nmi.h"

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

/** @brief Initializes peripherals for system boot. */
void init(void)
{
    SYSCFG_DL_init();

    /* Re-apply BOR warning threshold after SysConfig sets BOR0 */
    tamper_bor_nmi_init();

    /* Initialize/read battery-backed latch */
    tamper_latch_init_if_needed();

    /* Fail closed if a prior brownout tamper event latched */
    if (tamper_latch_is_tripped()) {
        enter_tamper_lock_mode();  // never returns
    }

    init_fs();

    if (trng_init()) {
        while (1) { }
    }

    if (timer_init()) {
        while (1) { }
    }
}

/**********************************************************
 *********************** MAIN LOOP ************************
 **********************************************************/

int main(void)
{
    char output_buf[128] = {0};
    msg_type_t cmd;
    int result;
    uint16_t pkt_len;

    /* initialize the device */
    init();

    /* process commands forever */
    while (1) {
        /* Fail closed if tamper latch trips during runtime */
        if (tamper_latch_is_tripped()) {
            enter_tamper_lock_mode();  // never returns
        }

        /* Clear input buffer so sensitive data from a past session isn't retained */
        memset(uart_buf, 0, sizeof(uart_buf));

        print_debug("Ready\n");
        STATUS_LED_ON();

        /* Bound packet length to input buffer size */
        pkt_len = sizeof(uart_buf);

        /* IMPORTANT: pass uart_buf (not &uart_buf) */
        result = read_packet(CONTROL_INTERFACE, &cmd, uart_buf, &pkt_len);

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

        /* Check tamper again after receiving a packet (defense-in-depth) */
        if (tamper_latch_is_tripped()) {
            enter_tamper_lock_mode();  // never returns
        }

        /* Handle the requested command */
        switch (cmd) {

        case LIST_MSG:
#ifdef CRYPTO_EXAMPLE
            /* Run the crypto example
             * TODO: Remove this from your design before competition submission */
            crypto_example();
#endif  // CRYPTO_EXAMPLE

            uint8_t proof[16] = {0xaa};
            uint8_t sig[64] = {0};
            memset(sig, 0, 64);
            int r = demonstrate_permission(0x1234, proof, sig);

            if (r != 0) {
                print_error("Perm check error!");
                print_hex_debug(&r, sizeof(r));
            }
            
            STATUS_LED_OFF();
            list(pkt_len, &uart_buf);
            break;

        case READ_MSG:
            STATUS_LED_OFF();
            read(pkt_len, &uart_buf);
            break;

        case WRITE_MSG:
            STATUS_LED_OFF();
            write(pkt_len, &uart_buf);
            break;

        case RECEIVE_MSG:
            STATUS_LED_OFF();
            receive(pkt_len, &uart_buf);
            break;

        case INTERROGATE_MSG:
            STATUS_LED_OFF();
            interrogate(pkt_len, &uart_buf);
            break;

        case LISTEN_MSG:
            STATUS_LED_OFF();
            listen(pkt_len, &uart_buf);
            break;

        default:
            STATUS_LED_OFF();
            /* Cast to int for safer formatting regardless of msg_type_t underlying type */
            snprintf(output_buf, sizeof(output_buf), "Invalid Command: 0x%02X\n", (unsigned int)cmd);
            print_error(output_buf);
            break;
        }
    }
}