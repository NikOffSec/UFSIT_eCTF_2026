/**
 * @file commands.c
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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "host_messaging.h"
#include "commands.h"
#include "filesystem.h"
#include "gmac.h"
#include "secrets.h"
#include "simple_trng.h"
#include "simple_timer.h"   // for nonce_accept(...) if your replay cache lives here

/* IMPORTANT COMPONENTS FROM HSM.c */
static file_t current_file; /* retained to minimize diffs; currently unused */

/* If commands.h still defines tmp_command_buffer directly, do NOT define it here.
 * Prefer changing commands.h to:
 *   extern uint8_t tmp_command_buffer[MAX_COMMAND_SIZE];
 * and keep this definition here.
 */

// ===== GMAC test mode (TEMPORARY) =====
// 1 = deterministic nonce, replay checks disabled (for integration testing only)
#define GMAC_TEST_MODE_NO_NONCE 0

#if GMAC_TEST_MODE_NO_NONCE
#warning "GMAC test mode enabled: deterministic nonce + replay disabled. NOT FOR COMPETITION USE."
#endif

#ifndef HSM_ID
#define HSM_ID 0x0001
#endif

// ---- Attack simulation flags (TEST ONLY) ----
// Choose ONE at a time.
// #define ATTACK_FLIP_TAG_BIT
// #define ATTACK_SPOOF_SENDER_ID
// #define ATTACK_TAMPER_SLOT
// #define ATTACK_REPLAY_DUPLICATE_SEND

/**********************************************************
 ******************** HELPER FUNCTIONS ********************
 **********************************************************/

static int get_request_nonce(uint8_t nonce[GMAC_NONCE_LEN]) {
#if GMAC_TEST_MODE_NO_NONCE
    // Deterministic evolving nonce for testing GMAC plumbing without TRNG
    static uint32_t test_ctr = 1;
    memset(nonce, 0, GMAC_NONCE_LEN);
    nonce[8]  = (uint8_t)(test_ctr >> 24);
    nonce[9]  = (uint8_t)(test_ctr >> 16);
    nonce[10] = (uint8_t)(test_ctr >> 8);
    nonce[11] = (uint8_t)(test_ctr);
    test_ctr++;
    return 0;
#else
    return trng_get_bytes(nonce, GMAC_NONCE_LEN);
#endif
}

// Replay checker wrapper for test mode
static bool nonce_accept_test(uint16_t sender_id, const uint8_t *nonce, size_t nonce_len) {
    (void)sender_id;
    (void)nonce;
    (void)nonce_len;
#if GMAC_TEST_MODE_NO_NONCE
    return true;   // TEMP: disable replay checks in test mode
#else
    return nonce_accept(sender_id, nonce, nonce_len);
#endif
}

// Local strnlen helper function to fix linker issue
static size_t bounded_strnlen_local(const char *s, size_t max_len) {
    size_t i = 0;
    if (s == NULL) return 0;
    while (i < max_len && s[i] != '\0') {
        i++;
    }
    return i;
}

/** @brief List out the files on the system.
 *      To be utilized by list and interrogate
 *
 *  @param file_list A pointer to the list_response_t variable in
 *      which to store the results
 */
void generate_list_files(list_response_t *file_list) {
    file_list->n_files = 0;
    file_t temp_file;

    for (uint8_t i = 0; i < MAX_FILE_COUNT; i++) {
        if (is_slot_in_use(i)) {
            read_file(i, &temp_file);

            file_list->metadata[file_list->n_files].slot = i;
            file_list->metadata[file_list->n_files].group_id = temp_file.group_id;
            strncpy(file_list->metadata[file_list->n_files].name,
                    (char *)&temp_file.name,
                    MAX_NAME_SIZE - 1);
            file_list->metadata[file_list->n_files].name[MAX_NAME_SIZE - 1] = '\0';

            file_list->n_files++;
        }
    }
}

static uint8_t perm_flags(const group_permission_t *p) {
    return (uint8_t)((p->read ? 1u : 0u) |
                     (p->write ? 2u : 0u) |
                     (p->receive ? 4u : 0u));
}

static size_t pack_permissions_sorted(const group_permission_t *in, size_t n,
                                      uint8_t *out, size_t out_cap) {
    group_permission_t tmp[MAX_PERMS];
    size_t m = 0;

    for (size_t i = 0; i < n; i++) {
        if (in[i].group_id == 0) continue; // sentinel for unused
        tmp[m++] = in[i];
    }

    // insertion sort by group_id (MAX_PERMS is tiny)
    for (size_t i = 1; i < m; i++) {
        group_permission_t key = tmp[i];
        size_t j = i;
        while (j > 0 && tmp[j - 1].group_id > key.group_id) {
            tmp[j] = tmp[j - 1];
            j--;
        }
        tmp[j] = key;
    }

    size_t need = m * 3u; // gid_hi, gid_lo, flags
    if (out_cap < need) return 0;

    for (size_t i = 0; i < m; i++) {
        uint16_t gid = tmp[i].group_id;
        out[i * 3 + 0] = (uint8_t)(gid >> 8);
        out[i * 3 + 1] = (uint8_t)(gid & 0xFF);
        out[i * 3 + 2] = perm_flags(&tmp[i]);
    }

    return need;
}

static size_t build_receive_request_aad(const receive_request_t *req,
                                        uint8_t *out, size_t out_cap) {
    // AAD fields:
    // sender_id (2) | slot (2) | perm_blob_len (1) | perm_blob (...)
    // Nonce is not included here because it is passed as the GCM nonce/IV.
    size_t need = 2u + 2u + 1u + (size_t)req->perm_blob_len;
    if (out_cap < need) return 0;

    size_t off = 0;

    out[off++] = (uint8_t)(req->sender_id >> 8);
    out[off++] = (uint8_t)(req->sender_id & 0xFF);

    out[off++] = (uint8_t)(((uint16_t)req->slot) >> 8);
    out[off++] = (uint8_t)(((uint16_t)req->slot) & 0xFF);

    out[off++] = req->perm_blob_len;

    memcpy(&out[off], req->perm_blob, req->perm_blob_len);
    off += req->perm_blob_len;

    return off;
}

static bool requester_has_receive_perm_for_group(const receive_request_t *req, uint16_t group_id) {
    if (req->perm_blob_len > PERM_BLOB_MAX) return false;
    if ((req->perm_blob_len % 3u) != 0u) return false;

    for (size_t i = 0; i < req->perm_blob_len; i += 3u) {
        uint16_t gid = ((uint16_t)req->perm_blob[i] << 8) | (uint16_t)req->perm_blob[i + 1];
        uint8_t flags = req->perm_blob[i + 2];

        if (gid == group_id) {
            return ((flags & 0x04u) != 0u); // receive bit
        }
    }
    return false;
}

/**********************************************************
 ******************** COMMAND HANDLERS ********************
 **********************************************************/

/** @brief Perform the list operation */
int list(uint16_t pkt_len, uint8_t *uart_buf) {
    (void)pkt_len;
    list_command_t *command = (list_command_t*)uart_buf;
    list_response_t file_list;

    if (!check_pin(command->pin)) {
        print_error("Invalid pin");
        timer_wait_5s();
        return -1;
    }

    memset(&file_list, 0, sizeof(file_list));
    generate_list_files(&file_list);

    pkt_len_t length = LIST_PKT_LEN(file_list.n_files);
    write_packet(CONTROL_INTERFACE, LIST_MSG, &file_list, length);
    return 0;
}

/** @brief Perform the read operation */
int read(uint16_t pkt_len, uint8_t *buf) {
    (void)pkt_len;
    read_command_t *command = (read_command_t*)buf;
    read_response_t file_info;
    file_t curr_file;

    if (!check_pin(command->pin)) {
        print_error("Invalid pin");
        timer_wait_5s();
        return -1;
    }

    memset(&file_info, 0, sizeof(read_response_t));

    if (read_file(command->slot, &curr_file) < 0) {
        //print_error("Failed to read file");
        return -1;
    }

    /*size_t name_len = bounded_strnlen_local((const char*)curr_file.name, MAX_NAME_SIZE);
    if (name_len >= MAX_NAME_SIZE) {
        //print_error("Invalid file name");
        return -1;
    }*/

    memcpy(file_info.name, &curr_file.name, sizeof(file_info.name));
    memcpy(file_info.contents, &curr_file.contents, curr_file.contents_len);

    if (!validate_permission(curr_file.group_id, PERM_READ)) {
        //print_error("Invalid permission");
        return -1;
    }

    pkt_len_t length = (pkt_len_t)(MAX_NAME_SIZE + curr_file.contents_len);
    write_packet(CONTROL_INTERFACE, READ_MSG, &file_info, length);
    return 0;
}

/** @brief Perform the write operation */
int write(uint16_t pkt_len, uint8_t *buf) {
    write_command_t *command = (write_command_t*)buf;
    file_t curr_file;

    if (!check_pin(command->pin)) {
        print_error("Invalid pin");
        timer_wait_5s();
        return -1;
    }

    if (!validate_permission(command->group_id, PERM_WRITE)) {
        //print_error("Invalid permission");
        return -1;
    }

    // Added parsing checks to create_file; it can fail if UART parsing violates struct fields
    if (create_file(
            &curr_file,
            command->group_id,
            command->name,
            command->contents_len,
            command->contents,
            pkt_len) != 0) {
        //print_error("Error creating file");
        return -1;
    }

    if (write_file(command->slot, &curr_file, command->uuid) < 0) {
        //print_error("Error writing file");
        return -1;
    }

    write_packet(CONTROL_INTERFACE, WRITE_MSG, NULL, 0);
    return 0;
}

/** @brief Perform the receive operation */
int receive(uint16_t pkt_len, uint8_t *buf) {
    (void)pkt_len;
    receive_command_t *command = (receive_command_t *)buf;
    receive_request_t request;
    receive_response_t recv_resp;
    msg_type_t cmd;
    uint16_t len_recv_msg;

    if (!check_pin(command->pin)) {
        print_error("Invalid pin");
        timer_wait_5s();
        return -1;
    }

    memset(&request, 0, sizeof(request));
    memset(&recv_resp, 0, sizeof(recv_resp));

    // Build request to neighbor
    request.sender_id = HSM_ID;
    request.slot = command->read_slot;

    size_t perm_blob_len = pack_permissions_sorted(
        global_permissions, MAX_PERMS, request.perm_blob, sizeof(request.perm_blob));
    if (perm_blob_len == 0 && MAX_PERMS > 0) {
        //print_error("Packing permissions failed");
        return -1;
    }
    request.perm_blob_len = (uint8_t)perm_blob_len;

    if (get_request_nonce(request.nonce) != 0) {
        //print_error("Nonce generation failed");
        return -1;
    }

    // Build AAD and compute GMAC
    uint8_t aad[2 + 2 + 1 + PERM_BLOB_MAX];
    size_t aad_len = build_receive_request_aad(&request, aad, sizeof(aad));
    if (aad_len == 0) {
        //print_error("AAD build failed");
        return -1;
    }

    if (gmac_compute_tag(GMAC_KEY, request.nonce, aad, aad_len, request.tag) != 0) {
        //print_error("GMAC tag generation failed");
        return -1;
    }

#ifdef ATTACK_FLIP_TAG_BIT
    request.tag[0] ^= 0x01;
    print_debug("[ATTACK] Flipped 1 bit in GMAC tag");
#endif

#ifdef ATTACK_SPOOF_SENDER_ID
    request.sender_id ^= 0x0001;
    print_debug("[ATTACK] Spoofed sender_id after GMAC generation");
#endif

#ifdef ATTACK_TAMPER_SLOT
    request.slot ^= 0x01;
    print_debug("[ATTACK] Tampered slot after GMAC generation");
#endif

    // Send authenticated request
    write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, (void *)&request, sizeof(receive_request_t));

#ifdef ATTACK_REPLAY_DUPLICATE_SEND
    print_debug("[ATTACK] Re-sending exact same RECEIVE packet for replay test");
    write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, (void *)&request, sizeof(receive_request_t));
#endif

    // Receive file response (legacy response struct retained for compatibility)
    len_recv_msg = sizeof(recv_resp);
    if (read_packet(TRANSFER_INTERFACE, &cmd, &recv_resp, &len_recv_msg) != MSG_OK) {
        //print_error("Failed to receive response");
        return -1;
    }

    if (cmd != RECEIVE_MSG) {
        //print_error("Opcode mismatch");
        return -1;
    }

    if (len_recv_msg < sizeof(recv_resp.uuid) + sizeof(recv_resp.internal_random_number)) {
        //print_error("Receive response too short");
        return -1;
    }

    if (write_file(command->write_slot, &recv_resp.file, recv_resp.uuid) < 0) {
        //print_error("Writing received file failed");
        return -1;
    }

    write_packet(CONTROL_INTERFACE, RECEIVE_MSG, NULL, 0);
    return 0;
}

/** @brief Perform the interrogate operation */
int interrogate(uint16_t pkt_len, uint8_t *buf) {
    (void)pkt_len;
    interrogate_command_t *command = (interrogate_command_t*)buf;
    msg_type_t cmd;
    list_response_t final_list_buf;
    uint16_t len_recv_msg;

    if (!check_pin(command->pin)) {
        print_error("Invalid pin");
        timer_wait_5s();
        return -1;
    }

    write_packet(TRANSFER_INTERFACE, INTERROGATE_MSG, NULL, 0);

    len_recv_msg = sizeof(final_list_buf);
    if (read_packet(TRANSFER_INTERFACE, &cmd, &final_list_buf, &len_recv_msg) != MSG_OK) {
        //print_error("Failed to receive interrogate response");
        return -1;
    }

    if (cmd != INTERROGATE_MSG) {
        //print_error("Opcode mismatch");
        return -1;
    }

    write_packet(CONTROL_INTERFACE, INTERROGATE_MSG, &final_list_buf, len_recv_msg);
    return 0;
}

/** @brief Perform the listen operation */
int listen(uint16_t pkt_len, uint8_t *buf) {
    (void)pkt_len;
    (void)buf;

    uint8_t uart_buf[MAX_MSG_SIZE > sizeof(receive_request_t) ? MAX_MSG_SIZE : sizeof(receive_request_t)];
    msg_type_t cmd;
    pkt_len_t write_length, read_length;
    list_response_t file_list;
    receive_response_t recv_resp;
    const filesystem_entry_t *metadata;

    read_length = sizeof(uart_buf);

    memset(uart_buf, 0, sizeof(uart_buf));
    if (read_packet(TRANSFER_INTERFACE, &cmd, uart_buf, &read_length) != MSG_OK) {
        //print_error("listen: failed to read transfer packet");
        return -1;
    }

    switch (cmd) {
        case INTERROGATE_MSG: {
            memset(&file_list, 0, sizeof(file_list));
            generate_list_files(&file_list);

            write_length = LIST_PKT_LEN(file_list.n_files);
            write_packet(TRANSFER_INTERFACE, INTERROGATE_MSG, &file_list, write_length);
            break;
        }

        case RECEIVE_MSG: {
            receive_request_t req;
            uint8_t aad[2 + 2 + 1 + PERM_BLOB_MAX];
            uint8_t expected_tag[GMAC_TAG_LEN];
            size_t aad_len;

            memset(&req, 0, sizeof(req));
            memset(&recv_resp, 0, sizeof(recv_resp));

            // For now require a full fixed-size receive_request_t packet
            if (read_length != sizeof(receive_request_t)) {
                //print_error("RECEIVE request bad length");
                return -1;
            }

            memcpy(&req, uart_buf, sizeof(req));

            if (req.perm_blob_len > PERM_BLOB_MAX || (req.perm_blob_len % 3u) != 0u) {
                //print_error("Invalid permission blob length");
                return -1;
            }

            aad_len = build_receive_request_aad(&req, aad, sizeof(aad));
            if (aad_len == 0) {
                //print_error("AAD build failed");
                return -1;
            }

            if (gmac_compute_tag(GMAC_KEY, req.nonce, aad, aad_len, expected_tag) != 0) {
                //print_error("GMAC compute failed");
                return -1;
            }

            if (!gmac_tag_eq_ct(expected_tag, req.tag)) {
                //print_error("GMAC verify failed");
                return -1;
            }

            // Replay protection after successful tag verify (prevents cache poisoning)
            if (!nonce_accept_test(req.sender_id, req.nonce, GMAC_NONCE_LEN)) {
                //print_error("Replay detected");
                return -1;
            }

            if ((uint16_t)req.slot >= MAX_FILE_COUNT) {
                //print_error("Invalid slot");
                return -1;
            }

            if (read_file(req.slot, &recv_resp.file) < 0) {
                //print_error("Failed to read file");
                return -1;
            }

            // Sender-side local policy: this board must be allowed to transfer this group
            if (!validate_permission(recv_resp.file.group_id, PERM_RECEIVE)) {
                //print_error("Local policy denies transfer for file group");
                return -1;
            }

            // Requester-side claimed perms (authenticated by GMAC)
            if (!requester_has_receive_perm_for_group(&req, recv_resp.file.group_id)) {
                //print_error("Requester lacks RECEIVE permission for file group");
                return -1;
            }

            metadata = get_file_metadata(req.slot);
            if (metadata == NULL) {
                //print_error("Getting metadata failed");
                return -1;
            }

            memcpy(&recv_resp.uuid, &metadata->uuid, UUID_SIZE);

            // Retained field for compatibility with existing struct
            recv_resp.internal_random_number = 0;

            // NOTE: Response is not yet GMAC-protected here.
            // This gets the GMAC request path working first.
            write_length = sizeof(receive_response_t);
            write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, &recv_resp, write_length);
            break;
        }

        default:
            //print_error("listen: unsupported transfer opcode");
            return -1;
    }

    // Blank success message for host-side listen command semantics
    write_packet(CONTROL_INTERFACE, LISTEN_MSG, NULL, 0);
    return 0;
}
