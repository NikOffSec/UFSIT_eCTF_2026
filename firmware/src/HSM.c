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

static unsigned char uart_buf[10000];

/**********************************************************
 ********************* CORE FUNCTIONS *********************
 **********************************************************/

/** @brief Initializes peripherals for system boot.
 */
void init() {
    // Initialize all of the hardware components
    SYSCFG_DL_init();

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

    // process commands forever
    while (1) {

        // Clear the input buffer so that sensitive data from a past session can't be yoinked!
        memset(uart_buf, 0, sizeof(uart_buf));

        print_debug("Ready\n");

        STATUS_LED_ON();

        uint32_t len = 0;

        // Fix buffer overflow from command line
        result = read_packet(CONTROL_INTERFACE, &cmd, &len, sizeof(uint32_t));
        result = read_packet(CONTROL_INTERFACE, &cmd, &uart_buf, sizeof(uint32_t));

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

        // Handle write command
        case WRITE_MSG:
            STATUS_LED_OFF();
            for (int i = 0; i < len; i++) {
                uart_writebyte(uart_id, ((uint8_t *)&uart_buf)[i]);
            }

            fflush(stdout);
            break;

        // Handle read command
        case READ_MSG:
            STATUS_LED_OFF();
            listen(pkt_len, &uart_buf);
            for (i = 0; i < len; i++) {
                ((uint8_t *)buf)[i] = result;
            }
            break;



        // Handle list command
        case LIST_MSG:
            STATUS_LED_OFF();
            list(pkt_len, &uart_buf);
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
