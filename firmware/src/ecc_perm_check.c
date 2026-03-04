#include "security.h"


// sign the proof with your ecc key for that group
int demonstraite_permission(uint16_t group, uint8_t *proof) {


    return 0;
}

int check_permission(uint16_t group, uint8_t *original_proof, uint8_t *provided_signature_bytes){
    return 0;
}

int generate_proof(uint8_t *proof) {
    return trng_get_bytes(proof, PROOF_SIZE);
}