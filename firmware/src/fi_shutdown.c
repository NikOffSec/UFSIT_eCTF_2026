#include <stdint.h>
#include <stdbool.h>

#include <ti/driverlib/dl_scratchpad.h>   // Scratchpad API wrappers
#include <ti/driverlib/dl_lfss.h>         // Underlying LFSS APIs/types
#include "ti_msp_dl_config.h"             

#define TL_WORD_IDX          DL_SCRATCHPAD_MEM_WORD_0
#define TL_MAGIC_BYTE_IDX    DL_SCRATCHPAD_MEM_BYTE_0
#define TL_FLAG_BYTE_IDX     DL_SCRATCHPAD_MEM_BYTE_1
#define TL_INV_BYTE_IDX      DL_SCRATCHPAD_MEM_BYTE_2
#define TL_CKSUM_BYTE_IDX    DL_SCRATCHPAD_MEM_BYTE_3

#define TL_MAGIC_VALUE       0xA5u
#define TL_FLAG_CLEAR        0x00u
#define TL_FLAG_TRIPPED      0x01u

//HELPER FUNCTIONS:
static uint8_t tl_checksum(uint8_t magic, uint8_t flag, uint8_t inv)
{
    return (uint8_t)(magic ^ flag ^ inv ^ 0x5Au);
}

static void tl_write_record(uint8_t flag)
{
    uint8_t inv = (uint8_t)~flag;
    uint8_t cks = tl_checksum(TL_MAGIC_VALUE, flag, inv);

    /* Replace LFSS with your actual LFSS base symbol if needed */
    DL_ScratchPad_writeDataByte(LFSS, TL_WORD_IDX, TL_MAGIC_BYTE_IDX, TL_MAGIC_VALUE);
    DL_ScratchPad_writeDataByte(LFSS, TL_WORD_IDX, TL_FLAG_BYTE_IDX,  flag);
    DL_ScratchPad_writeDataByte(LFSS, TL_WORD_IDX, TL_INV_BYTE_IDX,   inv);
    DL_ScratchPad_writeDataByte(LFSS, TL_WORD_IDX, TL_CKSUM_BYTE_IDX, cks);
}

static bool tl_read_record(uint8_t *flag_out)
{
    uint8_t magic = DL_ScratchPad_readDataByte(LFSS, TL_WORD_IDX, TL_MAGIC_BYTE_IDX);
    uint8_t flag  = DL_ScratchPad_readDataByte(LFSS, TL_WORD_IDX, TL_FLAG_BYTE_IDX);
    uint8_t inv   = DL_ScratchPad_readDataByte(LFSS, TL_WORD_IDX, TL_INV_BYTE_IDX);
    uint8_t cks   = DL_ScratchPad_readDataByte(LFSS, TL_WORD_IDX, TL_CKSUM_BYTE_IDX);

    if (magic != TL_MAGIC_VALUE) return false;
    if ((uint8_t)~flag != inv) return false;
    if (tl_checksum(magic, flag, inv) != cks) return false;
    if (!(flag == TL_FLAG_CLEAR || flag == TL_FLAG_TRIPPED)) return false;

    *flag_out = flag;
    return true;
}

/* Call early at boot */
void tamper_latch_init_if_needed(void)
{
    uint8_t flag;
    if (!tl_read_record(&flag)) {
        tl_write_record(TL_FLAG_CLEAR);
    }
}

bool tamper_latch_is_tripped(void)
{
    uint8_t flag;
    if (!tl_read_record(&flag)) {
        /* Corrupt/uninitialized scratchpad? Fail-safe to tripped is safer. */
        return true;
    }
    return (flag == TL_FLAG_TRIPPED);
}

void tamper_latch_trip(void)
{
    tl_write_record(TL_FLAG_TRIPPED);
}

void tamper_latch_clear(void)
{
    tl_write_record(TL_FLAG_CLEAR);
}

void NMI_Handler(void)
{
    // Optionally inspect NMI cause here first (BOR-related cause only)
    tamper_latch_trip();

    // Immediately fail closed
    enter_tamper_lock_mode();
}