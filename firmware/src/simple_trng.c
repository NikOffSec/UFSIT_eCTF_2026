#include "simple_trng.h"
#include "host_messaging.h"

void trng_init() {

    char output_buf[128] = {0};

    print_debug("Awakening the TRNG module\n");

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

    // 5. Run the digital block start-up self-test routine to ensure the TRNG digital is functioning properly:
    //  a. Move the TRNG from the NORM_FUNC state to the TEST_DIG state by writing the TEST_DIG command (0x1) to the CMD field in the CTL register.
    DL_TRNG_sendCommand(TRNG, DL_TRNG_CMD_TEST_DIG);
    // Wait for the IRQ_CMD_DONE interrupt flag to be set, indicating that the digital self-test has completed.
    while(!(DL_TRNG_isCommandDone(TRNG)));
    //  b. Check that all 8 digital tests passed be ensuring the DIG_TEST field in the TEST_RESULTS register are set (DIG_TEST=0xFF).
    DL_TRNG_clearInterruptStatus(TRNG, DL_TRNG_INTERRUPT_CMD_DONE_EVENT);
    delay_cycles(100000); // 8 tests * 1,024 cycles/test, testing with 100,000
    unsigned int temp = DL_TRNG_getDigitalHealthTestResults(TRNG);
    if (temp != DL_TRNG_DIGITAL_HEALTH_TEST_SUCCESS) {
        snprintf(output_buf, sizeof(output_buf)-1, "Digital Block start-up self-test failed TEST_RESULTS: %08x\n", temp); print_debug(output_buf);
    }
    else {
        snprintf(output_buf, sizeof(output_buf)-1, "Digital Block start-up self-test succeed TEST_RESULTS: %08x\n", temp); print_debug(output_buf);
    }
    //  c. After the digital test, the TRNG will return to the NORM_FUNC state automatically.




    snprintf(output_buf, sizeof(output_buf)-1, "Command read from TRNG: %d\n", DL_TRNG_getIssuedCommand(TRNG)); print_debug(output_buf);

/*
6. Run the analog block start-up self-test routine to ensure that the TRNG analog is functioning properly:
a. Move the TRNG from the NORM_FUNC state to the TEST_ANA state by writing the TEST_ANA
command (0x2) to the CMD field in the CTL register. Wait for the IRQ_CMD_DONE interrupt flag to be
set, indicating that the analog self-test has completed.
b. Check that the analog test passed by verifying that the ANA_TEST bit in the TEST_RESULTS register
was set.
c. After the analog test, if the test passed the TRNG will return to the NORM_FUNC state automatically. If
the test failed, the TRNG enters the ERR state and must be brought to the OFF state before attempting
to use it again.
7. Configure the TRNG for normal operation after running start-up self-tests:
TRNG www.ti.com
852 MSPM0 L-Series 32MHz Microcontrollers SLAU847E – OCTOBER 2022 – REVISED MAY 2025
Submit Document Feedback
Copyright © 2025 Texas Instruments Incorporated
a. Clear the IRQ_CAPTURED_RDY_IRQ status by setting the corresponding ICLR bit, as this may have
been set during the self-tests performed earlier.
b. Set the decimation rate to the desired value by programming the new decimation rate into the
DECIM_RATE field of the CTL register, followed by sending the NORM_FUNC command again (by
writing 0x3 to the CMD field in the CTL register). A decimation rate of 4 (DECIM_RATE=0x3) or greater
is recommended.
c. Enable the health fail interrupt by setting the IRQ_HEALTH_FAIL bit in the IMASK register.
d. Enable the data captured interrupt by setting the IRQ_CAPTURED_RDY bit in the IMASK register.
8. Wait for the first IRQ_CAPTURED_RDY IRQ, and read the DATA_CAPTURE register. This value (the first
value read from DATA_CAPTURE after running a startup self-test) is not a true random value and must be
read and discarded before collecting true random data from the DATA_CAPTURE register.
9. When the IRQ_CAPTURED_RDY IRQ is again asserted, random bits are available for read-out in the
DATA_CAPTURE register.
10. If the IRQ_HEALTH_FAIL IRQ is asserted, a low entropy condition was found and the TRNG will
have automatically switched to the ERR state to stop operation. To exit the ERR state, clear the
IRQ_HEALTH_FAIL interrupt. Then, transition the TRNG to the OFF state by sending an OFF command
(0x0) to the CMD field in the CTL register. Wait for the IRQ_CMD_DONE interrupt flag to be set, then return
to step #2 to power up the TRNG again to test if sufficient entropy is again available.
*/

    return;
}

//unsigned int trng_generate() {

//}