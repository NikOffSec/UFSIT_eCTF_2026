#ifndef ECC_PERM_H
#define ECC_PERM_H

#define PROOF_SIZE 16

struct group_key_pair {
    const uint32_t group;
    const uint8_t *public;
    const uint8_t *private;
};


int demonstrate_permission(uint32_t group, uint8_t *proof, uint8_t *proof_signature);

int check_permission(uint32_t group, uint8_t *original_proof_bytes, uint8_t *provided_signature);

/*
Generate the proof to send to the other HSM
This is just random bytes of PROOF_SIZE
*/
int generate_proof(uint8_t *proof);

#endif // ECC_PERM_H

