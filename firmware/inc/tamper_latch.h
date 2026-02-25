#ifndef TAMPER_LATCH_H
#define TAMPER_LATCH_H

#include <stdbool.h>

void tamper_latch_init_if_needed(void);
bool tamper_latch_is_tripped(void);
void tamper_latch_trip(void);
void tamper_latch_clear(void);

#endif