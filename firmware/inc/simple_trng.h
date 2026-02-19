#include <ti/devices/msp/msp.h>
#include <ti/driverlib/dl_trng.h>
#include "ti_msp_dl_config.h"

#include "host_messaging.h"

int trng_init();
unsigned int trng_generate();
