#include "simple_trng.h"
#include "host_messaging.h"

int trng_init() {

    char output_buf[128] = {0};

    print_debug("[DEBUG] Awakening the TRNG module");

    // 1. Enable the TRNG by setting the ENABLE bit together with the KEY in the TRNG PWREN register.
    DL_TRNG_enablePower(TRNG);
    
    // 2. Configure the TRNG clock divider to ensure that the TRNG functional clock is within the allowable range (10MHz typical, see the device data sheet for additional detail). The clock divider is configured by programming the required value to the RATIO field of the CLKDIVIDE register. As an example, if MCLK is 80MHz, the RATIO field shall be set to 0x7 (divide-by-8) to provide a 10MHz functional clock to the TRNG module.
    DL_TRNG_setClockDivider(TRNG, TRNG_CLKDIVIDE_RATIO_DIV_BY_2);
    
    // 3. Verify that the TRNG interrupts are disabled (interrupt mask bits are cleared to mask interrupts).
    DL_TRNG_disableInterrupt(TRNG, 0xF);
    
    // 4. Move the TRNG from the default OFF state to the NORM_FUNC state by writing the NORM_FUNC command (0x3) to the CMD field in the CTL register of the TRNG.
    DL_TRNG_sendCommand(TRNG, DL_TRNG_CMD_NORM_FUNC);
    // Wait for the IRQ_CMD_DONE interrupt flag to be set, indicating that the CMD completed.
    while(!(DL_TRNG_isCommandDone(TRNG)));
    DL_TRNG_clearInterruptStatus(TRNG, DL_TRNG_INTERRUPT_CMD_DONE_EVENT);

    // 5. Run the digital block start-up self-test routine to ensure the TRNG digital is functioning properly:
    //  a. Move the TRNG from the NORM_FUNC state to the TEST_DIG state by writing the TEST_DIG command (0x1) to the CMD field in the CTL register.
    DL_TRNG_sendCommand(TRNG, DL_TRNG_CMD_TEST_DIG);
    // Wait for the IRQ_CMD_DONE interrupt flag to be set, indicating that the digital self-test has completed.
    while(!(DL_TRNG_isCommandDone(TRNG)));
    DL_TRNG_clearInterruptStatus(TRNG, DL_TRNG_INTERRUPT_CMD_DONE_EVENT);
    //  b. Check that all 8 digital tests passed be ensuring the DIG_TEST field in the TEST_RESULTS register are set (DIG_TEST=0xFF).
    delay_cycles(1024*8); // 8 tests * 1,024 cycles/test
    if (DL_TRNG_getDigitalHealthTestResults(TRNG) != DL_TRNG_DIGITAL_HEALTH_TEST_SUCCESS) {
        snprintf(output_buf, sizeof(output_buf)-1, "[DEBUG] Digital Block start-up self-test failed TEST_RESULTS: %08x", DL_TRNG_getDigitalHealthTestResults(TRNG)); print_debug(output_buf);
        return 1;
    }
    else {
        snprintf(output_buf, sizeof(output_buf)-1, "[DEBUG] Digital Block start-up self-test succeed TEST_RESULTS: %08x", DL_TRNG_getDigitalHealthTestResults(TRNG)); print_debug(output_buf);
    }
    //  c. After the digital test, the TRNG will return to the NORM_FUNC state automatically.
    
    // 6. Run the analog block start-up self-test routine to ensure that the TRNG analog is functioning properly:
    //  a. Move the TRNG from the NORM_FUNC state to the TEST_ANA state by writing the TEST_ANA command (0x2) to the CMD field in the CTL register.
    DL_TRNG_sendCommand(TRNG, DL_TRNG_CMD_TEST_ANA);
    //  Wait for the IRQ_CMD_DONE interrupt flag to be set, indicating that the analog self-test has completed.
    while(!(DL_TRNG_isCommandDone(TRNG)));
    DL_TRNG_clearInterruptStatus(TRNG, DL_TRNG_INTERRUPT_CMD_DONE_EVENT);
    //  b. Check that the analog test passed by verifying that the ANA_TEST bit in the TEST_RESULTS register was set.
    delay_cycles(4096); // 1 tests * 4,096 cycles/test
    if (DL_TRNG_getAnalogHealthTestResults(TRNG) != DL_TRNG_ANALOG_HEALTH_TEST_SUCCESS) {
        print_debug("[DEBUG] Analog Block start-up self-test failed!");
        //  c. After the analog test, if the test passed the TRNG will return to the NORM_FUNC state automatically. If the test failed, the TRNG enters the ERR state and must be brought to the OFF state before attempting to use it again.
        DL_TRNG_clearInterruptStatus(TRNG, DL_TRNG_INTERRUPT_HEALTH_FAIL_EVENT);
        DL_TRNG_sendCommand(TRNG, TRNG_CTL_CMD_PWR_OFF);
        print_debug("[DEBUG] Powering Off the TRNG...");
        while(!(DL_TRNG_isCommandDone(TRNG)));
        DL_TRNG_clearInterruptStatus(TRNG, DL_TRNG_INTERRUPT_CMD_DONE_EVENT);
        print_debug("[DEBUG] TRNG Powered Off");
        return 1;
    }
    else {
        print_debug("[DEBUG] Analog Block start-up self-test succeed!");
    }

    snprintf(output_buf, sizeof(output_buf)-1, "[DEBUG] State after analog test TRNG: %d", DL_TRNG_getCurrentState(TRNG)); print_debug(output_buf);

    // 7. Configure the TRNG for normal operation after running start-up self-tests:
    //  a. Clear the IRQ_CAPTURED_RDY_IRQ status by setting the corresponding ICLR bit, as this may have been set during the self-tests performed earlier.
    DL_TRNG_clearInterruptStatus(TRNG, DL_TRNG_INTERRUPT_CAPTURE_RDY_EVENT);
    //  b. Set the decimation rate to the desired value by programming the new decimation rate into the DECIM_RATE field of the CTL register, 
    DL_TRNG_setDecimationRate(TRNG, DL_TRNG_DECIMATION_RATE_4);
    //  followed by sending the NORM_FUNC command again (by writing 0x3 to the CMD field in the CTL register). A decimation rate of 4 (DECIM_RATE=0x3) or greater is recommended.
    DL_TRNG_sendCommand(TRNG, DL_TRNG_CMD_NORM_FUNC);
    while(!(DL_TRNG_isCommandDone(TRNG)));
    DL_TRNG_clearInterruptStatus(TRNG, DL_TRNG_INTERRUPT_CMD_DONE_EVENT);
    //  c. Enable the health fail interrupt by setting the IRQ_HEALTH_FAIL bit in the IMASK register.
    // TODO: LOOK INTO THIS LATER
    //  d. Enable the data captured interrupt by setting the IRQ_CAPTURED_RDY bit in the IMASK register.
    DL_TRNG_enableInterrupt(TRNG, DL_TRNG_INTERRUPT_CAPTURE_RDY_EVENT);

    // 8. Wait for the first IRQ_CAPTURED_RDY IRQ, and read the DATA_CAPTURE register. This value (the first value read from DATA_CAPTURE after running a startup self-test) is not a true random value and must be read and discarded before collecting true random data from the DATA_CAPTURE register.
    while(!(DL_TRNG_isCaptureReady(TRNG)));
    DL_TRNG_getCapture(TRNG);
    DL_TRNG_clearInterruptStatus(TRNG, DL_TRNG_INTERRUPT_CAPTURE_RDY_EVENT);

    // 9. When the IRQ_CAPTURED_RDY IRQ is again asserted, random bits are available for read-out in the DATA_CAPTURE register.
    // 10. If the IRQ_HEALTH_FAIL IRQ is asserted, a low entropy condition was found and the TRNG will have automatically switched to the ERR state to stop operation. To exit the ERR state, clear the IRQ_HEALTH_FAIL interrupt. Then, transition the TRNG to the OFF state by sending an OFF command (0x0) to the CMD field in the CTL register. Wait for the IRQ_CMD_DONE interrupt flag to be set, then return to step #2 to power up the TRNG again to test if sufficient entropy is again available.
    // TODO: LOOK INTO THIS LATER
    
    DL_TRNG_getCurrentState(TRNG);
    snprintf(output_buf, sizeof(output_buf)-1, "[DEBUG] State after initialization TRNG: %d", DL_TRNG_getCurrentState(TRNG)); print_debug(output_buf);

    return 0;
}

unsigned int trng_generate() {

    if (DL_TRNG_isHealthTestFail(TRNG)) {

        // Check for false positive health fail
        print_debug("[DEBUG] Runtime Health Check Fail Detected!");
        
        // 1. Clear the IRQ_HEALTH_FAIL interrupt
        DL_TRNG_clearInterruptStatus(TRNG, DL_TRNG_INTERRUPT_HEALTH_FAIL_EVENT);

        // 2. Power off the TRNG
        DL_TRNG_sendCommand(TRNG, TRNG_CTL_CMD_PWR_OFF);
        print_debug("[DEBUG] Powering Off the TRNG...");
        while(!(DL_TRNG_isCommandDone(TRNG)));
        DL_TRNG_clearInterruptStatus(TRNG, DL_TRNG_INTERRUPT_CMD_DONE_EVENT);
        print_debug("[DEBUG] TRNG Powered Off");

        // 3. Power on the TRNG to normal mode again
        //  a. If the health failure is not asserted again, the TRNG can be used
        //  b. If the health test fails a second time, go to step 1 and attempt to run the test a third time
        //  c. If the health test fails a third time, there is catastrophic entropy loss and the TRNG should not be used
        if (trng_init() != 0) {
            print_debug("[DEBUG] TRNG Re-initialize fail, attempting second reboot.");
            if (trng_init() != 0) {
                print_debug("[DEBUG] TRNG Module failed to re-initialize second time. Catastrophic entropy loss detected. System now Stalling");
                while(1);
            }
            else {
                print_debug("[DEBUG] TRNG Module second re-initialize success. Module back online.");
            }
        }
        else {
            print_debug("[DEBUG] TRNG Module re-initialize success. Module back online.");
        }
    }

    unsigned int temp = -1;
    while(!(DL_TRNG_isCaptureReady(TRNG)));
    temp = DL_TRNG_getCapture(TRNG);
    DL_TRNG_clearInterruptStatus(TRNG, DL_TRNG_INTERRUPT_CAPTURE_RDY_EVENT);
    return temp;
}