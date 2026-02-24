#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "commands.h"
#include "host_messaging.h"
#include "simple_uart.h"
#include "security.h"
#include "ti_msp_dl_config.h" // needed for LED GPIOs / SysConfig symbols

static void secure_bzero(void *ptr, size_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) {
        *p++ = 0;
    }
}

/*
 * Optional global sensitive buffers to wipe.
 * If these are file-static elsewhere, remove these externs and wipe locally there instead.
 */
extern uint8_t uart_buf[];   // if defined globally in commands.c or messaging layer
extern uint8_t msg_buf[];    // only if you actually have this
extern size_t uart_buf_len;  // only if you actually have this

// Optional: one-time host notification payload
typedef struct {
    uint8_t code;
} tamper_error_t;

#define TAMPER_ERR_CODE 0xE1

static void tamper_notify_host_once(void)
{
    tamper_error_t e;
    e.code = TAMPER_ERR_CODE;

    (void)write_packet(CONTROL_INTERFACE, DEBUG_MSG, &e, sizeof(e));
}

static void tamper_blink_forever(void)
{
    while (1) {
#ifdef GPIO_LEDS_USER_LED_1_PIN
        DL_GPIO_togglePins(GPIO_LEDS_PORT, GPIO_LEDS_USER_LED_1_PIN);
#endif
        timer_wait_5s();  // you already use this; slow blink is fine
    }
}

/*
 * Enter permanent/restricted tamper lock mode.
 * This never returns.
 */
void enter_tamper_lock_mode(void)
{
    // Stop interrupts briefly while we wipe / notify (optional but recommended)
    __disable_irq();

    // Wipe obvious volatile state if accessible
#ifdef uart_buf
    secure_bzero(uart_buf, sizeof(uart_buf));
#endif
#ifdef msg_buf
    secure_bzero(msg_buf, sizeof(msg_buf));
#endif

    // If you maintain parser length state / globals, zero them too
#ifdef uart_buf_len
    uart_buf_len = 0;
#endif

    __enable_irq();

    // Optional one-time host notification so your team knows why it “died”
    tamper_notify_host_once();

    // From here on: fail closed.
    // Do NOT process host or transfer commands.
    // Do NOT call check_pin(), read/write/receive/interrogate handlers, etc.
    tamper_blink_forever();

    // Unreachable
    while (1) { }
}