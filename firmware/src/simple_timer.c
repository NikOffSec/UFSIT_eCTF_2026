#include "simple_timer.h"
#include "host_messaging.h"
#include "status_led.h"

int timer_init() {

    //print_debug("[DEBUG] Awakening the Timer module.");

    DL_TimerG_reset(TIMER_0_INST);
    DL_TimerG_enablePower(TIMER_0_INST);
    delay_cycles(POWER_STARTUP_DELAY);

    if (!(DL_Timer_isPowerEnabled(TIMER_0_INST))) {
        //print_debug("[DEBUG] Timer power not working. Abort");
        return -1;
    }

    DL_TimerG_setClockConfig(TIMER_0_INST, (DL_TimerG_ClockConfig*)&gTIMER_0ClockConfig);
    DL_TimerG_initTimerMode(TIMER_0_INST, (DL_TimerG_TimerConfig*)&gTIMER_0TimerConfig);
    DL_Timer_setCounterRepeatMode(TIMER_0_INST, DL_TIMER_REPEAT_MODE_DISABLED);
    DL_TimerG_enableInterrupt(TIMER_0_INST , DL_TIMERG_INTERRUPT_ZERO_EVENT);
    DL_TimerG_enableClock(TIMER_0_INST);

    //print_debug("[DEBUG] Timer set up!");

    return 0;
}

void timer_wait_5s() {
    //print_debug("[DEBUG] 5s Timer start");
    DL_TimerG_startCounter(TIMER_0_INST);
    while(DL_Timer_isRunning(TIMER_0_INST));
    //print_debug("[DEBUG] 5s Timer Finished!");
    return;
}