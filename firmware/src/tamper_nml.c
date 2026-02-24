#include <stdint.h>
#include "ti_msp_dl_config.h"

void fi_shutdown(void);  // your fail-closed routine

void NMI_Handler(void)
{
    DL_SYSCTL_NMI_IIDX cause;

    /*
     * Read highest-priority pending SYSCTL NMI source.
     * In this case we care about BORLVL.
     */
    cause = DL_SYSCTL_getPendingNonMaskableInterrupt();

    if (cause == DL_SYSCTL_NMI_IIDX_BORLVL) {
        /*
         * Clear the BOR NMI source so we don’t bounce/re-enter weirdly
         */
        DL_SYSCTL_clearNonMaskableInterruptStatus(DL_SYSCTL_NMI_BORLVL);

        /*
         * Latch tamper flag (battery-backed memory)
         */

        fi_shutdown();   // never return
    }

    /*
     * If some other NMI source triggered, fail closed anyway.
     */
    fi_shutdown();
}