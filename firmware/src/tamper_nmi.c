#include "ti_msp_dl_config.h"
#include "tamper_latch.h"
#include "tamper_lock.h"

void tamper_bor_nmi_init(void)
{
    // Must run AFTER SYSCFG_DL_init(), because SysConfig sets BOR level 0.
    DL_SYSCTL_setBORThreshold(DL_SYSCTL_BOR_THRESHOLD_LEVEL_3);
    DL_SYSCTL_activateBORThreshold();

    // Clear stale pending BOR NMI before normal operation
    DL_SYSCTL_clearNonMaskableInterruptStatus(DL_SYSCTL_NMI_BORLVL);
}

void NMI_Handler(void)
{
    DL_SYSCTL_NMI_IIDX cause = DL_SYSCTL_getPendingNonMaskableInterrupt();

    if (cause == DL_SYSCTL_NMI_IIDX_BORLVL) {
        // Latch first while power is still above collapse point
        tamper_latch_trip();

        // Then clear pending status if possible
        DL_SYSCTL_clearNonMaskableInterruptStatus(DL_SYSCTL_NMI_BORLVL);
    } else {
        // Optional policy:
        // either ignore non-BOR NMI, or fail closed on any NMI.
        // For your competition use-case, failing closed is reasonable.
        tamper_latch_trip();
    }

    // Never return to normal execution after a tamper event
    enter_tamper_lock_mode();
}
