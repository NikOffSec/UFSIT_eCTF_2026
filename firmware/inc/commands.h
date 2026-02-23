/**
 * @file commands.h
 * @author Samuel Meyers
 * @brief eCTF command handlers
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026 Embedded CTF (eCTF).
 * This code is being provided only for educational purposes for the 2026 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#ifndef __COMMANDS_H__
#define __COMMANDS_H__

#include "secrets.h"
#include "security.h"
#include "stdint.h"
#include "simple_flash.h"
#include "filesystem.h"
#include <string.h>

#ifdef CRYPTO_EXAMPLE
#include "simple_crypto.h"
#endif

#define pkt_len_t uint16_t
#define RECEIVE_RESPONSE_HASH_LEN 16

#define GMAC_NONCE_LEN 12
#define GMAC_TAG_LEN   16
#define PERM_BLOB_MAX  (MAX_PERMS * 3)   // group_id(2) + flags(1) per entry

// Pin will be 6 hex characters 0-9,a-f
typedef unsigned char pin_t[6];

// can support the largest struct size message size of the device for in place encryption/decryption
#define MAX_COMMAND_SIZE 8272
//TODO: THIS WILL NOT WORK WITH LARGER MESSAGES; TEMP FIX BECAUSE WE WERE OVERFLOWING THE STACK
extern uint8_t tmp_command_buffer[100];

#define MAX_MSG_SIZE sizeof(write_command_t)

// calculates the length of a list packet based on the number of files listed
#define LIST_PKT_LEN(num_files) (sizeof(num_files) + ((MAX_NAME_SIZE + sizeof(group_id_t) + sizeof(slot_t)) * num_files))

#pragma pack(push, 1) // Tells the compiler not to pad the struct members
// for more information on what struct padding does, see:
// https://www.gnu.org/software/c-intro-and-ref/manual/html_node/Structure-Layout.html

/**********************************************************
 ******************** FILE STRUCTS ************************
 **********************************************************/

typedef struct {
    slot_t slot;
    group_id_t group_id;
    char name[MAX_NAME_SIZE];
} file_metadata_t;

/**********************************************************
 ******************** COMMAND STRUCTS *********************
 **********************************************************/

typedef struct {
    pin_t pin;
} list_command_t;

typedef struct {
    pin_t pin;
    slot_t slot;
} read_command_t;

typedef struct {
    pin_t pin;
    slot_t slot;
    group_id_t group_id;
    char name[MAX_NAME_SIZE];
    uint8_t uuid[UUID_SIZE];
    uint16_t contents_len;
    uint8_t contents[MAX_CONTENTS_SIZE];
} write_command_t;

typedef struct {
    pin_t pin;
    slot_t read_slot;
    slot_t write_slot;
} receive_command_t;

/*
 * Canonical receive request message (GMAC-authenticated AAD-based protocol).
 * Tag authenticates the request metadata and permission blob.
 */
typedef struct {
    uint16_t sender_id;                 // stable per-firmware-image ID
    slot_t slot;
    uint8_t nonce[GMAC_NONCE_LEN];      // sender nonce / freshness value
    uint8_t perm_blob_len;              // actual bytes used in perm_blob
    uint8_t perm_blob[PERM_BLOB_MAX];   // packed permissions (gid_hi, gid_lo, flags)
    uint8_t tag[GMAC_TAG_LEN];          // GMAC over AAD (everything except tag)
} receive_request_t;

// Keep response type only if current receive/listen implementation still uses it
typedef struct {
    uint8_t uuid[UUID_SIZE];
    uint32_t internal_random_number;
    file_t file;
    uint8_t padding[4];
    uint8_t hash[RECEIVE_RESPONSE_HASH_LEN];
} receive_response_t;

typedef struct {
    pin_t pin;
} interrogate_command_t;

/**********************************************************
 ******************** RESPONSE STRUCTS ********************
 **********************************************************/

typedef struct {
    uint32_t n_files;
    file_metadata_t metadata[MAX_FILE_COUNT];
} list_response_t;

typedef struct {
    char name[MAX_NAME_SIZE];
    uint8_t contents[MAX_CONTENTS_SIZE];
} read_response_t;

#pragma pack(pop) // Tells the compiler to resume padding struct members

/** @brief Perform the list operation */
int list(uint16_t pkt_len, uint8_t *buf);

/** @brief Perform the read operation */
int read(uint16_t pkt_len, uint8_t *buf);

/** @brief Perform the write operation */
int write(uint16_t pkt_len, uint8_t *buf);

/** @brief Perform the receive operation */
int receive(uint16_t pkt_len, uint8_t *buf);

/** @brief Perform the interrogate operation */
int interrogate(uint16_t pkt_len, uint8_t *buf);

/** @brief Perform the listen operation */
int listen(uint16_t pkt_len, uint8_t *buf);

#endif // __COMMANDS_H__
