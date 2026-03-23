#include "simple_timer.h"
#include "ti_msp_dl_config.h"
#include "tamper_lock.h"

void enter_tamper_lock_mode(void)
{
    __disable_irq();

    // Fail closed forever. No command processing.
    while (1) {
#ifdef GPIO_LEDS_USER_LED_1_PIN
        DL_GPIO_togglePins(GPIO_LEDS_PORT, GPIO_LEDS_USER_LED_1_PIN);
#endif
        timer_wait_5s();
        print_error("FAULT INJECTION DETECTED");
    }
}