
#define PROOF_SIZE 16

struct group_key_pair {
    const uint16_t group;
    const uint8_t *public;
    const uint8_t *private;
};


int demonstraite_permission(uint16_t group, uint8_t *proof);


int check_permission(uint16_t group, uint8_t *original_proof, uint8_t *provided_signature_bytes);

/*
Generate the proof to send to the other HSM
*/
int generate_proof(uint8_t *proof);

