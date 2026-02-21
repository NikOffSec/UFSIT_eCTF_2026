#include "simple_timer.h"
#include "host_messaging.h"
#include "status_led.h"

int timer_init() {

    print_debug("[DEBUG] Awakening the Timer module.");

    DL_TimerG_reset(TIMER_0_INST);
    DL_TimerG_enablePower(TIMER_0_INST);
    delay_cycles(POWER_STARTUP_DELAY);

    if (!(DL_Timer_isPowerEnabled(TIMER_0_INST))) {
        print_debug("[DEBUG] Timer power not working. Abort");
        return -1;
    }

    DL_TimerG_setClockConfig(TIMER_0_INST, (DL_TimerG_ClockConfig*)&gTIMER_0ClockConfig);
    DL_TimerG_initTimerMode(TIMER_0_INST, (DL_TimerG_TimerConfig*)&gTIMER_0TimerConfig);
    DL_Timer_setCounterRepeatMode(TIMER_0_INST, DL_TIMER_REPEAT_MODE_DISABLED);
    DL_TimerG_enableInterrupt(TIMER_0_INST , DL_TIMERG_INTERRUPT_ZERO_EVENT);
    DL_TimerG_enableClock(TIMER_0_INST);

    print_debug("Waiting for initial Timer setup");
    //DL_TimerG_startCounter(TIMER_0_INST);
    unsigned int temp = -1;
    char output_buf[128] = {0};
    while(DL_Timer_isRunning(TIMER_0_INST)) {
        temp = DL_Timer_getRawInterruptStatus(TIMER_0_INST, 0xFFFFFFFF);
        snprintf(output_buf, sizeof(output_buf)-1, "[DEBUG] Timer Status: %08x", temp); print_debug(output_buf);

    }
    print_debug("Timer Finished!");

    return 0;
}