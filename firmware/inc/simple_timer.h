#include <ti/devices/msp/msp.h>
#include <ti/driverlib/dl_timer.h>
#include "ti_msp_dl_config.h"

#include "host_messaging.h"

// Constant Clock and Timer Config structs for passing to the function

static const DL_TimerG_ClockConfig gTIMER_0ClockConfig = {
    .clockSel    = DL_TIMER_CLOCK_MFCLK,
    .divideRatio = DL_TIMER_CLOCK_DIVIDE_8,
    .prescale    = 0U,
};

static const DL_TimerG_TimerConfig gTIMER_0TimerConfig = {
    .period     = TIMER_0_INST_LOAD_VALUE, //This is a period for 5 seconds with a divide of 8 and clock of 32 MHz
    .timerMode  = DL_TIMER_TIMER_MODE_ONE_SHOT,
    .startTimer = DL_TIMER_STOP,
};

int timer_init();