#include "simple_timer.h"
#include "host_messaging.h"
#include "status_led.h"

int timer_init() {

    print_debug("[DEBUG] Awakening the Counter module.");

    if (!(DL_Timer_isPowerEnabled(TIMER_0_INST))) {
        return -1;
    }

    DL_TimerG_setClockConfig(TIMER_0_INST, (DL_TimerG_ClockConfig*)&gTIMER_0ClockConfig);
    DL_TimerG_initTimerMode(TIMER_0_INST, (DL_TimerG_TimerConfig*)&gTIMER_0TimerConfig);
    DL_TimerG_enableInterrupt(TIMER_0_INST , DL_TIMERG_INTERRUPT_ZERO_EVENT);
    DL_TimerG_enableClock(TIMER_0_INST);

    print_debug("Waiting for initial Timer setup");
    DL_TimerG_startCounter(TIMER_0_INST);
    while(DL_Timer_isRunning(TIMER_0_INST))
    print_debug("Timer Finished!");

    return 0;
}