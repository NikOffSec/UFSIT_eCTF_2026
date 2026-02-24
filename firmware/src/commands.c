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

#define INTR_REQ_DOMAIN "INTRQv1"
#define INTR_REQ_DOMAIN_LEN 7
#define INTR_RESP_DOMAIN "INTRSv1"
#define INTR_RESP_DOMAIN_LEN 7

// ---- Attack simulation flags (TEST ONLY) ----
// Choose ONE at a time.
// #define ATTACK_FLIP_TAG_BIT
// #define ATTACK_SPOOF_SENDER_ID
// #define ATTACK_TAMPER_SLOT
// #define ATTACK_REPLAY_DUPLICATE_SEND

/**********************************************************
 ******************** HELPER FUNCTIONS ********************
 **********************************************************/

static size_t build_interrogate_request_aad(const interrogate_request_t *req,
                                            uint8_t *out, size_t out_cap) {
    size_t need = INTR_REQ_DOMAIN_LEN + 2u + 4u;
    if (out_cap < need) return 0;

    size_t off = 0;
    memcpy(&out[off], INTR_REQ_DOMAIN, INTR_REQ_DOMAIN_LEN);
    off += INTR_REQ_DOMAIN_LEN;

    out[off++] = (uint8_t)(req->sender_id >> 8);
    out[off++] = (uint8_t)(req->sender_id & 0xFF);

    // NEW: ctr (big-endian)
    out[off++] = (uint8_t)(req->ctr >> 24);
    out[off++] = (uint8_t)(req->ctr >> 16);
    out[off++] = (uint8_t)(req->ctr >> 8);
    out[off++] = (uint8_t)(req->ctr & 0xFF);

    return off;
}

static size_t build_interrogate_response_aad(const interrogate_request_t *req,
                                             const interrogate_response_t *resp,
                                             uint8_t *out, size_t out_cap) {
    // Only authenticate the populated list bytes, not the whole fixed struct.
    if (resp->list.n_files > MAX_FILE_COUNT) return 0;

    size_t list_len = LIST_PKT_LEN(resp->list.n_files);
    size_t need = INTR_RESP_DOMAIN_LEN + 2u + 2u + 4u + GMAC_NONCE_LEN + list_len;

    if (out_cap < need) return 0;

    size_t off = 0;
    memcpy(&out[off], INTR_RESP_DOMAIN, INTR_RESP_DOMAIN_LEN);
    off += INTR_RESP_DOMAIN_LEN;

    // req.sender_id
    out[off++] = (uint8_t)(req->sender_id >> 8);
    out[off++] = (uint8_t)(req->sender_id & 0xFF);

    // resp.responder_id
    out[off++] = (uint8_t)(resp->responder_id >> 8);
    out[off++] = (uint8_t)(resp->responder_id & 0xFF);

    // NEW: resp.ctr (big-endian)
    out[off++] = (uint8_t)(resp->ctr >> 24);
    out[off++] = (uint8_t)(resp->ctr >> 16);
    out[off++] = (uint8_t)(resp->ctr >> 8);
    out[off++] = (uint8_t)(resp->ctr & 0xFF);

    // existing bind to request
    memcpy(&out[off], req->nonce, GMAC_NONCE_LEN);
    off += GMAC_NONCE_LEN;

    // authenticate only meaningful list bytes
    memcpy(&out[off], &resp->list, list_len);
    off += list_len;

    return off;
}

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

#define RX_RESP_DOMAIN "RXRESPv1"
#define RX_RESP_DOMAIN_LEN 8

static size_t build_receive_response_aad(const receive_request_t *req,
                                         const receive_response_t *resp,
                                         uint8_t *out, size_t out_cap) {
    // AAD layout (explicit serialization):
    // "RXRESPv1" |
    // req.sender_id (2) |
    // req.slot (2) |
    // resp.uuid (16) |
    // file.group_id (2) |
    // file.contents_len (2) |
    // file.name (32) |
    // file.contents (contents_len)
    //
    // NOTE: resp.nonce is NOT included here because it's passed as GMAC nonce.

    uint16_t contents_len = resp->file.contents_len;
    if (contents_len > MAX_CONTENTS_SIZE) return 0;

    size_t need = RX_RESP_DOMAIN_LEN
        + 2u  // req.sender_id
        + 2u  // resp.responder_id
        + 4u  // resp.ctr   NEW
        + 2u  // req.slot
        + UUID_SIZE
        + 2u  // group_id
        + 2u  // contents_len
        + MAX_NAME_SIZE
        + (size_t)contents_len
        + GMAC_NONCE_LEN;

    if (out_cap < need) return 0;

    size_t off = 0;

    memcpy(&out[off], RX_RESP_DOMAIN, RX_RESP_DOMAIN_LEN);
    off += RX_RESP_DOMAIN_LEN;

    // req sender.id
    out[off++] = (uint8_t)(req->sender_id >> 8);
    out[off++] = (uint8_t)(req->sender_id & 0xFF);

    // NEW: resp.responder_id
    out[off++] = (uint8_t)(resp->responder_id >> 8);
    out[off++] = (uint8_t)(resp->responder_id & 0xFF);

    // NEW: resp.ctr (big-endian)
    out[off++] = (uint8_t)(resp->ctr >> 24);
    out[off++] = (uint8_t)(resp->ctr >> 16);
    out[off++] = (uint8_t)(resp->ctr >> 8);
    out[off++] = (uint8_t)(resp->ctr & 0xFF);

    // req.slot (existing)
    out[off++] = (uint8_t)(((uint16_t)req->slot) >> 8);
    out[off++] = (uint8_t)(((uint16_t)req->slot) & 0xFF);

    memcpy(&out[off], req->nonce, GMAC_NONCE_LEN);
    off += GMAC_NONCE_LEN;

    memcpy(&out[off], resp->uuid, UUID_SIZE);
    off += UUID_SIZE;

    out[off++] = (uint8_t)(resp->file.group_id >> 8);
    out[off++] = (uint8_t)(resp->file.group_id & 0xFF);

    out[off++] = (uint8_t)(contents_len >> 8);
    out[off++] = (uint8_t)(contents_len & 0xFF);

    memcpy(&out[off], resp->file.name, MAX_NAME_SIZE);
    off += MAX_NAME_SIZE;

    memcpy(&out[off], resp->file.contents, contents_len);
    off += contents_len;

    return off;
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
    size_t need = 2u + 4u + 2u + 1u + req->perm_blob_len;
    if (out_cap < need) return 0;

    size_t off = 0;

    out[off++] = (uint8_t)(req->sender_id >> 8);
    out[off++] = (uint8_t)(req->sender_id & 0xFF);

    // NEW: ctr (big-endian)
    out[off++] = (uint8_t)(req->ctr >> 24);
    out[off++] = (uint8_t)(req->ctr >> 16);
    out[off++] = (uint8_t)(req->ctr >> 8);
    out[off++] = (uint8_t)(req->ctr & 0xFF);

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
int list(uint16_t pkt_len, uint8_t *buf) {
    (void)pkt_len;
    list_command_t *command = (list_command_t*)buf;
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

    if (pkt_len != sizeof(receive_command_t)) return -1;
    if ((uint16_t)command->read_slot >= MAX_FILE_COUNT) return -1;
    if ((uint16_t)command->write_slot >= MAX_FILE_COUNT) return -1;

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
    uint8_t aad[2 + 4 + 2 + 1 + PERM_BLOB_MAX];
    request.ctr = replay_ctr_next_local();
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
    if (read_packet(TRANSFER_INTERFACE, &cmd, &recv_resp, &len_recv_msg) != MSG_OK) return -1;

    if (cmd != RECEIVE_MSG) return -1;
    if (len_recv_msg != sizeof(receive_response_t)) return -1;

    if (recv_resp.file.contents_len > MAX_CONTENTS_SIZE) {
        //print_error("Receive response file too large");
        return -1;
    }

    // Build expected response AAD bound to the original request we sent
    uint8_t resp_aad[RX_RESP_DOMAIN_LEN + 2 + 2 + 4 + 2 + GMAC_NONCE_LEN + UUID_SIZE + 2 + 2 + MAX_NAME_SIZE + MAX_CONTENTS_SIZE];
    uint8_t expected_resp_tag[GMAC_TAG_LEN];

    size_t resp_aad_len = build_receive_response_aad(&request, &recv_resp, resp_aad, sizeof(resp_aad));
    if (resp_aad_len == 0) {
        //print_error("Receive response AAD build failed");
        return -1;
    }

    if (gmac_compute_tag(GMAC_KEY, recv_resp.nonce, resp_aad, resp_aad_len, expected_resp_tag) != 0) {
        //print_error("Receive response GMAC compute failed");
        return -1;
    }

    if (!gmac_tag_eq_ct(expected_resp_tag, recv_resp.tag)) {
        //print_error("Receive response GMAC verify failed");
        return -1;
    }
    if (!replay_ctr_accept(recv_resp.responder_id, recv_resp.ctr)) return -1;

    if (cmd != RECEIVE_MSG) {
        //print_error("Opcode mismatch");
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
    if (pkt_len != sizeof(interrogate_command_t)) return -1;

    interrogate_command_t *command = (interrogate_command_t*)buf;
    interrogate_request_t req;
    interrogate_response_t resp;
    msg_type_t cmd;
    uint16_t len_recv_msg;

    if (!check_pin(command->pin)) {
        print_error("Invalid pin");
        timer_wait_5s();
        return -1;
    }

    memset(&req, 0, sizeof(req));
    memset(&resp, 0, sizeof(resp));

    // Build authenticated interrogate request
    req.sender_id = HSM_ID;
    req.ctr = replay_ctr_next_local();

    if (get_request_nonce(req.nonce) != 0) return -1;

    uint8_t req_aad[INTR_REQ_DOMAIN_LEN + 20];
    size_t req_aad_len = build_interrogate_request_aad(&req, req_aad, sizeof(req_aad));
    if (req_aad_len == 0) return -1;

    if (gmac_compute_tag(GMAC_KEY, req.nonce, req_aad, req_aad_len, req.tag) != 0) return -1;

    write_packet(TRANSFER_INTERFACE, INTERROGATE_MSG, &req, sizeof(req));

    // Read authenticated interrogate response
    len_recv_msg = sizeof(resp);
    if (read_packet(TRANSFER_INTERFACE, &cmd, &resp, &len_recv_msg) != MSG_OK) return -1;

    if (cmd != INTERROGATE_MSG) return -1;
    if (len_recv_msg != sizeof(interrogate_response_t)) return -1;
    if (resp.list.n_files > MAX_FILE_COUNT) return -1;

    // Verify response GMAC
    uint8_t expected_tag[GMAC_TAG_LEN];
    uint8_t resp_aad[INTR_RESP_DOMAIN_LEN + 2 + 20 + GMAC_NONCE_LEN + sizeof(list_response_t)];
    size_t resp_aad_len = build_interrogate_response_aad(&req, &resp, resp_aad, sizeof(resp_aad));
    if (resp_aad_len == 0) return -1;

    if (gmac_compute_tag(GMAC_KEY, resp.nonce, resp_aad, resp_aad_len, expected_tag) != 0) return -1;
    if (!gmac_tag_eq_ct(expected_tag, resp.tag)) return -1;
    if (!replay_ctr_accept(resp.responder_id, resp.ctr)) return -1;

    // Optional but recommended: replay protect response
    if (!nonce_accept_test(resp.responder_id, resp.nonce, GMAC_NONCE_LEN)) return -1;

    // Forward only the list payload back to host (legacy host protocol preserved)
    pkt_len_t host_len = (pkt_len_t)LIST_PKT_LEN(resp.list.n_files);
    write_packet(CONTROL_INTERFACE, INTERROGATE_MSG, &resp.list, host_len);
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
            interrogate_request_t req;
            interrogate_response_t resp;
            uint8_t expected_req_tag[GMAC_TAG_LEN];
            uint8_t req_aad[INTR_REQ_DOMAIN_LEN + 2 + 4];
            uint8_t resp_aad[INTR_RESP_DOMAIN_LEN + 2 + 2 + 4 + GMAC_NONCE_LEN + sizeof(list_response_t)];
            size_t req_aad_len, resp_aad_len;

            if (read_length != sizeof(interrogate_request_t)) return -1;

            memset(&req, 0, sizeof(req));
            memset(&resp, 0, sizeof(resp));
            memcpy(&req, uart_buf, sizeof(req));

            resp.responder_id = HSM_ID;
            resp.ctr = replay_ctr_next_local();

            // Verify interrogate request GMAC
            req_aad_len = build_interrogate_request_aad(&req, req_aad, sizeof(req_aad));
            if (req_aad_len == 0) return -1;

            if (gmac_compute_tag(GMAC_KEY, req.nonce, req_aad, req_aad_len, expected_req_tag) != 0) return -1;
            if (!gmac_tag_eq_ct(expected_req_tag, req.tag)) return -1;
            if (!replay_ctr_accept(req.sender_id, req.ctr)) return -1;

            // Replay protect request
            if (!nonce_accept_test(req.sender_id, req.nonce, GMAC_NONCE_LEN)) return -1;

            // Build list payload
            resp.responder_id = HSM_ID;
            memset(&resp.list, 0, sizeof(resp.list));
            generate_list_files(&resp.list);

            // Sign response
            if (get_request_nonce(resp.nonce) != 0) return -1;

            resp_aad_len = build_interrogate_response_aad(&req, &resp, resp_aad, sizeof(resp_aad));
            if (resp_aad_len == 0) return -1;

            if (gmac_compute_tag(GMAC_KEY, resp.nonce, resp_aad, resp_aad_len, resp.tag) != 0) return -1;

            write_packet(TRANSFER_INTERFACE, INTERROGATE_MSG, &resp, sizeof(resp));
            break;
        }   
        case RECEIVE_MSG: {
            receive_request_t req;
            uint8_t aad[2 + 4 + 2 + 1 + PERM_BLOB_MAX];
            uint8_t expected_tag[GMAC_TAG_LEN];
            size_t aad_len;

            memset(&req, 0, sizeof(req));
            memset(&recv_resp, 0, sizeof(recv_resp));

            recv_resp.responder_id = HSM_ID;
            recv_resp.ctr = replay_ctr_next_local();

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
            if (!replay_ctr_accept(req.sender_id, req.ctr)) return -1;

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

            // Generate response GMAC nonce
            if (get_request_nonce(recv_resp.nonce) != 0) {
                //print_error("Response nonce generation failed");
                return -1;
            }

            // Build response AAD
            uint8_t resp_aad[RX_RESP_DOMAIN_LEN + 2 + 2 + 4 + 2 + GMAC_NONCE_LEN + UUID_SIZE + 2 + 2 + MAX_NAME_SIZE + MAX_CONTENTS_SIZE];
            size_t resp_aad_len = build_receive_response_aad(&req, &recv_resp, resp_aad, sizeof(resp_aad));
            if (resp_aad_len == 0) {
                //print_error("Response AAD build failed");
                return -1;
            }

            // Compute response GMAC tag
            if (gmac_compute_tag(GMAC_KEY, recv_resp.nonce, resp_aad, resp_aad_len, recv_resp.tag) != 0) {
                //print_error("Response GMAC generation failed");
                return -1;
            }

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
