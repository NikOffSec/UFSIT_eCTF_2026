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

#include "host_messaging.h"
#include "commands.h"
#include "filesystem.h"
#include "gmac.h"
#include "secrets.h"

/* IMPORTANT COMPONENTS FROM HSM.c */
// extern file_t hsm_status[MAX_FILE_COUNT];
static file_t current_file;

// ===== GMAC test mode (TEMPORARY) =====
// 1 = deterministic nonce, replay checks disabled (for integration testing only)
#define GMAC_TEST_MODE_NO_NONCE 1

#if GMAC_TEST_MODE_NO_NONCE
#warning "GMAC test mode enabled: deterministic nonce + replay disabled. NOT FOR COMPETITION USE."
#endif

#ifndef HSM_ID
#define HSM_ID 0x0001
#endif

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

// Stub replay checker for test mode
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

/**********************************************************
 ******************** HELPER FUNCTIONS ********************
 **********************************************************/

/** @brief List out the files on the system.
 *      To be utilized by list and interrogate
 *
 *  @param file_list A pointer to the list_response_t variable in
 *      which to store the results
 */
void generate_list_files(list_response_t *file_list) {
    file_list->n_files = 0;
    file_t temp_file;

    // Loop through all files on the system
    for (uint8_t i = 0; i < MAX_FILE_COUNT; i++) {
        // Check if the file is in use
        if (is_slot_in_use(i)) {
            read_file(i, &temp_file);

            file_list->metadata[file_list->n_files].slot = i;
            file_list->metadata[file_list->n_files].group_id = temp_file.group_id;
            strcpy(file_list->metadata[file_list->n_files].name, (char *)&temp_file.name);
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
        if (in[i].group_id == 0) continue; // your sentinel for unused
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

    size_t need = m * 3;
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
    // NOTE: nonce is NOT included here because it is passed as the GCM nonce/IV.
    // If you want extra binding, you can include it too, but then both sides must match exactly.
    size_t need = 2 + sizeof(slot_t) + 1 + req->perm_blob_len;
    if (out_cap < need) return 0;

    size_t off = 0;
    out[off++] = (uint8_t)(req->sender_id >> 8);
    out[off++] = (uint8_t)(req->sender_id & 0xFF);

    // slot_t is likely uint16_t, but encode explicitly
    out[off++] = (uint8_t)(((uint16_t)req->slot) >> 8);
    out[off++] = (uint8_t)(((uint16_t)req->slot) & 0xFF);

    out[off++] = req->perm_blob_len;

    memcpy(&out[off], req->perm_blob, req->perm_blob_len);
    off += req->perm_blob_len;

    return off;
}

/**********************************************************
 ******************** COMMAND HANDLERS ********************
 **********************************************************/

/** @brief Perform the list operation
 *
 *  @param pkt_len The length of the incoming packet
 *  @param buf A pointer the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
*/
int list(uint16_t pkt_len, uint8_t *buf) {
    list_command_t *command = (list_command_t*)buf;
    list_response_t file_list;

    memset(&file_list, 0, sizeof(file_list));

    // copy relevant fields into the final struct
    generate_list_files(&file_list);

    if (!check_pin(command->pin)) {
        print_error("Invalid pin");
        return -1;
    }

    // write success packet with list
    pkt_len_t length = LIST_PKT_LEN(file_list.n_files);
    write_packet(CONTROL_INTERFACE, LIST_MSG, &file_list, length);
    return 0;
}


/** @brief Perform the read operation
 *
 *  @param pkt_len The length of the incoming packet
 *  @param buf A pointer the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
*/
int read(uint16_t pkt_len, uint8_t *buf) {
    read_command_t *command = (read_command_t*)buf;
    read_response_t file_info;
    file_t curr_file;

    if (!check_pin(command->pin)) {
        print_error("Invalid pin");
        return -1;
    }

    // zeroizing memory is a pretty good practice
    memset(&file_info, 0, sizeof(read_response_t));

    if (read_file(command->slot, &curr_file) < 0) {
        print_error("Failed to read file");
        return -1;
    }
    // copy structure of the persistent file
    memcpy(file_info.name, &curr_file.name, strlen(curr_file.name));
    memcpy(file_info.contents, &curr_file.contents, curr_file.contents_len);

    if (!validate_permission(curr_file.group_id, PERM_READ)) {
        print_error("Invalid permission");
        return -1;
    }

    // write a success message with the file information
    pkt_len_t length = MAX_NAME_SIZE + curr_file.contents_len;
    write_packet(CONTROL_INTERFACE, READ_MSG, &file_info, length);
    return 0;
}


/** @brief Perform the write operation
 *
 *  @param pkt_len The length of the incoming packet
 *  @param buf A pointer the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
*/
int write(uint16_t pkt_len, uint8_t *buf) {
    write_command_t *command = (write_command_t*)buf;
    int ret;
    file_t curr_file;

    if (!check_pin(command->pin)) {
        print_error("Invalid pin");
        return -1;
    }

    if (!validate_permission(command->group_id, PERM_WRITE)) {
        print_error("Invalid permission");
        return -1;
    }

    create_file(
        &curr_file,
        command->group_id,
        command->name,
        command->contents_len,
        command->contents
    );

    // Store the file persistently
    if (write_file(command->slot, &curr_file, command->uuid) < 0) {
        print_error("Error storing file");
        return -1;
    }

    // Success message with an empty body
    write_packet(CONTROL_INTERFACE, WRITE_MSG, NULL, 0);
    return 0;
}


/** @brief Perform the receive operation
 *
 *  @param pkt_len The length of the incoming packet
 *  @param buf A pointer the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
*/
int receive(uint16_t pkt_len, uint8_t *buf) {
    receive_command_t *command = (receive_command_t *)buf;
    receive_request_t request;
    receive_response_t recv_resp;
    msg_type_t cmd;
    uint16_t len_recv_msg;
    int ret;

    if (!check_pin(command->pin)) {
        print_error("Invalid pin");
        return -1;
    }

    // zeroize the buffers we will use
    memset(&recv_resp, 0, sizeof(recv_resp));
    memset(&request, 0, sizeof(request));

    // prep request to neighbor
    request.sender_id = HSM_ID;   // add this macro in secrets.h or config
    request.slot = command->read_slot;

    // Build canonical permission blob
    size_t perm_blob_len = pack_permissions_sorted(global_permissions, MAX_PERMS,
                                                request.perm_blob, sizeof(request.perm_blob));
    if (perm_blob_len == 0 && MAX_PERMS > 0) {
        print_error("Packing permissions failed");
        return -1;
    }
    request.perm_blob_len = (uint8_t)perm_blob_len;

    // Temp nonce retriever
    if (get_request_nonce(request.nonce) != 0) {
    print_error("Nonce generation failed");
    return -1;
    }
    // Build AAD and compute GMAC
    uint8_t aad[2 + 2 + 1 + PERM_BLOB_MAX];
    size_t aad_len = build_receive_request_aad(&request, aad, sizeof(aad));
    if (aad_len == 0) {
        print_error("AAD build failed");
        return -1;
    }

if (gmac_compute_tag(GMAC_KEY, request.nonce, aad, aad_len, request.tag) != 0) {
    print_error("GMAC tag generation failed");
    return -1;
}

    // request the file from the neighboring device
    write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, (void *)&request, sizeof(receive_request_t));

    // set essentially no limit to the receive message size
    len_recv_msg = 0xffff;

    // recieve the response message
    read_packet(TRANSFER_INTERFACE, &cmd, &recv_resp, &len_recv_msg);
    if (cmd != RECEIVE_MSG) {
        print_error("Opcode mismatch");
        return -1;
    }

    // write that file into the file system
    if (write_file(command->write_slot, &recv_resp.file, recv_resp.uuid) < 0) {
        print_error("Writing received file failed");
        return -1;
    }
    // empty success message
    write_packet(CONTROL_INTERFACE, RECEIVE_MSG, NULL, 0);
    return 0;
}


/** @brief Perform the interrogate operation
 *
 *  @param pkt_len The length of the incoming packet
 *  @param buf A pointer to the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
 */
int interrogate(uint16_t pkt_len, uint8_t *buf) {
    interrogate_command_t *command = (interrogate_command_t*)buf;
    msg_type_t cmd;
    list_response_t final_list_buf;
    uint16_t len_recv_msg;

    // pin check
    if (!check_pin(command->pin)) {
        print_error("Invalid pin");
        return -1;
    }

    // request the file list from the neighboring device
    write_packet(TRANSFER_INTERFACE, INTERROGATE_MSG, NULL, 0);

    // TODO: the reference design does not implement *ANY* security **CHANGE LIMIT**
    // set essentially no limit to the receive message size
    len_recv_msg = 0xffff;

    // recieve the response message
    read_packet(TRANSFER_INTERFACE, &cmd, &final_list_buf, &len_recv_msg);
    if (cmd != INTERROGATE_MSG) {
        print_error("Opcode mismatch");
        return -1;
    }

    // return the final list to the user
    write_packet(CONTROL_INTERFACE, INTERROGATE_MSG, &final_list_buf, len_recv_msg);
    return 0;
}


/** @brief Perform the listen operation
 *
 * @return 0 upon success. A negative value on error.
*/
int listen(uint16_t pkt_len, uint8_t *buf) {
    uint8_t uart_buf[MAX_MSG_SIZE > sizeof(receive_request_t) ? MAX_MSG_SIZE : sizeof(receive_request_t)];
    msg_type_t cmd;
    pkt_len_t write_length, read_length;
    list_response_t file_list;
    receive_request_t *command;
    receive_response_t recv_resp;
    const filesystem_entry_t *metadata;

    read_length = sizeof(uart_buf);

    // Receive a packet from a neighboring hsm
    memset(uart_buf, 0, sizeof(uart_buf));
    read_packet(TRANSFER_INTERFACE, &cmd, uart_buf, &read_length);

    switch (cmd) {
        case INTERROGATE_MSG:
            // zeroize the buffers we will use
            memset(&file_list, 0, sizeof(file_list));

            // generate a list of files for the other device
            generate_list_files(&file_list);

            // TODO: the reference design does not implement *ANY* security
            // you will want to add something here to comply with SR1

            // send the list of files on this device
            write_length = LIST_PKT_LEN(file_list.n_files);
            write_packet(TRANSFER_INTERFACE, INTERROGATE_MSG, &file_list, write_length);
            break;
                case RECEIVE_MSG: {
            // get the request
            command = (receive_request_t *)uart_buf;

            // Basic bounds check on perm blob len
            if (command->perm_blob_len > PERM_BLOB_MAX) {
                print_error("Invalid permission blob length");
                return -1;
            }

            // Optional: sanity-check packet length for RECEIVE request
            // (helps catch malformed packets)
            if (read_length < (pkt_len_t)(sizeof(receive_request_t) - PERM_BLOB_MAX + command->perm_blob_len)) {
                print_error("RECEIVE packet too short");
                return -1;
            }

            // Replay protection (stubbed in test mode)
            if (!nonce_accept_test(command->sender_id, command->nonce, GMAC_NONCE_LEN)) {
                print_error("Replay detected");
                return -1;
            }

            // Rebuild AAD and verify GMAC tag
            uint8_t aad[2 + 2 + 1 + PERM_BLOB_MAX];
            size_t aad_len = build_receive_request_aad(command, aad, sizeof(aad));
            if (aad_len == 0) {
                print_error("AAD build failed");
                return -1;
            }

            uint8_t expected_tag[GMAC_TAG_LEN];
            if (gmac_compute_tag(GMAC_KEY, command->nonce, aad, aad_len, expected_tag) != 0) {
                print_error("GMAC compute failed");
                return -1;
            }

            if (!gmac_tag_eq_ct(expected_tag, command->tag)) {
                print_error("GMAC verify failed");
                return -1;
            }

            // Read the requested file FIRST (needed to know its group_id)
            if (read_file(command->slot, &recv_resp.file) < 0) {
                print_error("Failed to read file");
                return -1;
            }

            // Local policy enforcement (safer than trusting requester perms)
            if (!validate_permission(recv_resp.file.group_id, PERM_RECEIVE)) {
                print_error("Local policy denies receive/send");
                return -1;
            }

            metadata = get_file_metadata(command->slot);
            if (metadata == NULL) {
                print_error("Getting metadata failed");
                return -1;
            }

            memcpy(&recv_resp.uuid, &metadata->uuid, UUID_SIZE);

            // send the file to the neighbor hsm
            write_length = sizeof(receive_response_t);
            write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, &recv_resp, write_length);
            break;
        }

    // blank success message
    write_packet(CONTROL_INTERFACE, LISTEN_MSG, NULL, 0);
    return 0;
}
