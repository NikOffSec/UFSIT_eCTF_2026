#include <stdint.h>

#include "wolfssl/wolfcrypt/ed25519.h"

#include "ecc_perm_check.h"
#include "security.h"
#include "secrets.h"
#include "host_messaging.h"

int get_key_index(uint32_t group) {
    // no compiled permissions
    if(PERSONAL_GROUP_COUNT == 0)
        return -1;

    int i;
    for(i = 0; i < PERSONAL_GROUP_COUNT; i++) {
        if(personal_key_pairs[i].group == group) {
            break;
        }
    }

    if(i == PERSONAL_GROUP_COUNT)
        return -1;

    return i;
}

// sign the proof with your ecc key for that group
int demonstraite_permission(uint32_t group, uint8_t *proof, uint8_t *proof_signature) {

    int i;

    if((i = get_key_index(group)) == -1)
        return -1;

    // no private key, no recieve perm
    if(personal_key_pairs[i].private == NULL) 
        return -2;

    // NOTE: this part can be done at boot time to lower stack use dynamically
    ed25519_key key;
    wc_ed25519_init(&key);

    if(wc_ed25519_import_private_key_ex(personal_key_pairs[i].private, 32, personal_key_pairs[i].public, 32, &key, 1)) {
        return -3;
    }

    if(wc_ed25519_check_key(&key)) {
        print_error("key bad!");
        return -4;
    }
    word32 sigLen = ED25519_SIG_SIZE;
    if(wc_ed25519_sign_msg_ex(proof, 16, proof_signature, &sigLen,
                                 &key, Ed25519, NULL, 0))
        return -5;

    return 0;
}

int check_permission(uint32_t group, uint8_t *original_proof, uint8_t *provided_signature_bytes){

    int i;
    
    if((i = get_key_index(group)) == -1)
        return -1;

    return 0;
}

int generate_proof(uint8_t *proof) {
    return trng_get_bytes(proof, PROOF_SIZE);
}