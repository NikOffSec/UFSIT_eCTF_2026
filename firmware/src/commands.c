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

/* IMPORTANT COMPONENTS FROM HSM.c */
// extern file_t hsm_status[MAX_FILE_COUNT];
static file_t current_file;

int trng_generate(){
    return 1;
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
            strncpy(file_list->metadata[file_list->n_files].name, (char *)&temp_file.name, MAX_NAME_SIZE - 1);
            //strcpy(file_list->metadata[file_list->n_files].name, (char *)&temp_file.name);
            file_list->n_files++;
        }
    }
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
    
    // TODO - UFSIT - COLE - check
    if(strlen(curr_file.name) > MAX_NAME_SIZE) {
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

    // UFSIT
    // Added parsing checks to create_file, it can fail if parsing from UART violates struct feilds
    if(create_file(
        &curr_file,
        command->group_id,
        command->name,
        command->contents_len,
        command->contents,
        pkt_len) != 0) {
        print_error("Error creating file");
        return -1;
    }

    // Store the file persistently
    if (write_file(command->slot, &curr_file, command->uuid) < 0) {
        print_error("Error writing file");
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
    receive_request_setup_t command_setup;
    receive_request_t request;
    receive_response_t recv_resp;
    msg_type_t cmd;
    uint16_t len_recv_msg;
    uint32_t setup_random_number = 0;
    uint32_t internal_random_number = trng_generate();
    int ret;
    uint16_t read_length;
    uint8_t hash_stack[HASH_SIZE];

    if (!check_pin(command->pin)) {
        print_error("Invalid pin");
        return -1;
    }

    // First, tell the HSM you are communicating with that you want to start a recieve file transfer
    memset(&tmp_command_buffer, 0, sizeof(receive_request_setup_t));
    write_packet(TRANSFER_INTERFACE, RECEIVE_SETUP_MSG, (void *)&tmp_command_buffer, sizeof(receive_request_setup_t));

    read_length = sizeof(receive_request_setup_t);
    read_packet(TRANSFER_INTERFACE, &cmd, tmp_command_buffer, &read_length);

    if(cmd != RECEIVE_SETUP_MSG) {
        print_error("receive: did not get RECEIVE_SETUP_MSG got something else");
        return -1;
    }

    // decrypt the uart_buf
    decrypt_sym(tmp_command_buffer, sizeof(receive_request_setup_t), AES_KEY, (uint8_t*)&command_setup);

    // MD5 check the number
    hash((uint8_t*)&command_setup, 4, (uint8_t*)&hash_stack);

    if(memcmp(command_setup.hash, hash_stack, HASH_SIZE) != 0) {
        print_error("RECV: Hash check failed!");
        return -1;
    }

    char testing_buf[100] = {0};
                
    snprintf(testing_buf, sizeof(testing_buf)-1, "command_setup.random_number == %d", command_setup.random_number);
    print_debug(testing_buf);

    // This int is used to avoid replay attacks
    setup_random_number = command_setup.random_number;

    // zeroize the buffers we will use
    memset(&recv_resp, 0, sizeof(recv_resp));
    memset(&request, 0, sizeof(request));

    // prep request to neighbor
    request.setup_random_number = setup_random_number;
    request.internal_random_number = internal_random_number;
    request.slot = command->read_slot;
    memcpy(&request.permissions, &global_permissions, sizeof(group_permission_t) * MAX_PERMS);

    // Calculate the md5 hash of receive_request_t, subtract out the size of the hash
    hash((uint8_t*)&request, sizeof(receive_request_t) - HASH_SIZE, (uint8_t*)&request.hash);

    // Encrypt the receive_request_t command
    encrypt_sym((void*)&request, sizeof(receive_request_t), AES_KEY, tmp_command_buffer);
    
    print_hex_debug(tmp_command_buffer, 16);
    // request the file from the neighboring device
    write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, (void *)&tmp_command_buffer, sizeof(receive_request_t));

    print_debug("WROTE REQUEST PACKET TO TRANSFER INTERFACE");

    while(1);

    // set essentially no limit to the receive message size
    // TODO - fix
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

    // I don't think this needs to be modified at all - Cole
    // TODO - check to see if the interegate command should be sending over a pin
    // I don't think it needs to

    // pin check
    if (!check_pin(command->pin)) {
        print_error("Invalid pin");
        return -1;
    }

    // request the file list from the neighboring device
    write_packet(TRANSFER_INTERFACE, INTERROGATE_MSG, NULL, 0);

    // UFSIT - cole - check to make sure that this is right
    len_recv_msg = sizeof(list_response_t);

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
    uint8_t uart_buf[sizeof(receive_request_t)];
    msg_type_t cmd;
    pkt_len_t write_length, read_length;
    list_response_t file_list;
    receive_request_t *command;
    receive_request_setup_t request_setup;
    receive_response_t recv_resp;
    const filesystem_entry_t *metadata;
    uint8_t hash_stack[HASH_SIZE];

    read_length = sizeof(uart_buf);

    // Receive a packet from a neighboring hsm
    memset(uart_buf, 0, sizeof(uart_buf));
    read_packet(TRANSFER_INTERFACE, &cmd, uart_buf, &read_length);

    switch (cmd) {
        case INTERROGATE_MSG:

            /*
            https://rules.ectf.mitre.org/2026/specs/host_interface.html#interrogate-files
            This is a pin protected function. The HSM should reach out via UART1 to a neighbor HSM to receive a list of files on that device. The interrogate files functionality must return a list of all files that the neighbor HSM contains for which the local HSM has receive permissions. The body of the response will contain a list of files and their associated metadata. Communication between the two devices may be design-specific.
            */

            // TODO - INTERROGATE should send over the persmissions of the device making the request

            // zeroize the buffers we will use
            memset(&file_list, 0, sizeof(file_list));

            // generate a list of files for the other device
            generate_list_files(&file_list);

            // send the list of files on this device
            write_length = LIST_PKT_LEN(file_list.n_files);
            write_packet(TRANSFER_INTERFACE, INTERROGATE_MSG, &file_list, write_length);
            break;
        case RECEIVE_SETUP_MSG: // was RECEIVE_MSG
            // get the request
            /*
            https://rules.ectf.mitre.org/2026/specs/host_interface.html#receive-file
            This is a pin protected function. The HSM should reach out via UART1 to a neighbor HSM to receive a file from that device. If the HSM has permissions to receive the group, the HSM should write the file to the device.
            */

            // zero buffer
            memset(&request_setup, 0, sizeof(request_setup));

            // generate session int so reply attacks don't work
            request_setup.random_number = trng_generate();

            // Calcuate the hash of the int and store it in the struct
            hash((uint8_t*)&request_setup, 4, (uint8_t*)&request_setup.hash);

            // Encrypt the request message
            encrypt_sym((uint8_t*)&request_setup, sizeof(request_setup), AES_KEY, tmp_command_buffer);

            write_packet(TRANSFER_INTERFACE, RECEIVE_SETUP_MSG, (void *)&tmp_command_buffer, sizeof(receive_request_setup_t));

            // Get back the message from the user where they 
            read_packet(TRANSFER_INTERFACE, &cmd, uart_buf, &read_length);

            if(cmd != RECEIVE_MSG) {
                print_error("receive: did not get RECEIVE_SETUP_MSG got something else");
                return -1;
            }

            decrypt_sym(uart_buf, sizeof(receive_request_t), AES_KEY, tmp_command_buffer);

            command = (receive_request_t*)&tmp_command_buffer;

            print_hex_debug(tmp_command_buffer, 16);
            
            char testing_buf[100] = {0};
                
            snprintf(testing_buf, sizeof(testing_buf)-1, "command->setup_random_number == %d", command->setup_random_number);
            print_debug(testing_buf);

            if (request_setup.random_number != command->setup_random_number) {
                print_error("LISTEN: Setup random number different from the one I gave the other HSM!");
                return -1;
            }

            hash((uint8_t*)&tmp_command_buffer, sizeof(receive_request_t) - HASH_SIZE - 7, (uint8_t*)&hash_stack);

            if(memcmp(command->hash, hash_stack, HASH_SIZE) != 0) {
                print_error("LISTEN: Hash check failed!");
                return -1;
            }

            print_debug("HASH CHECK WENT THROUGH");
            
            while(1);

            // TODO: the reference design does not implement *ANY* security
            // you will want to add something here to comply with SR1
            // I think group ID parsing goes here??? Back by ed25519 keys.

            // if this read fails, the other device will not receive a response and
            // may need to be reset before further testing can occur
            

            // Sanity checking
            if (command->slot > MAX_FILE_COUNT) {
                print_error("LISTEN: recv a slot higher then number of possible slots");
                return -1;
            }

            if (read_file(command->slot, &recv_resp.file) < 0) {
                print_error("Failed to read file");
                return -1;
            }

            metadata = get_file_metadata(command->slot);
            if (metadata == NULL) {
                print_error("Getting metadata failed");
                return -1;
            }

            // Find which group ID the file belongs to
            int i = 0;

            // Check to see if the sending board has that group ID
            for (; i <= MAX_PERMS ; i++) {
                
                // If we have looped through every loop element and it doesn't have it, then the board doesn't have the right group to read the file so exit
                if (i == MAX_PERMS) {
                    print_error("The board did not have the right group to access the file");
                    return -1;
                }

                if(command->permissions[i].group_id == recv_resp.file.group_id) {
                    break;
                }
            }

            // Check to see if the sending board has the correct group ID permissions to recieve the file
            if(command->permissions[i].receive != true) {
                print_error("Permission Check Failed");
                return -1;
            }

            memcpy(&recv_resp.uuid, &metadata->uuid, UUID_SIZE);

            // send the file to the neighbor hsm
            write_length = sizeof(receive_response_t);
            write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, &recv_resp, write_length);
            break;
        default:
            print_error("Bad message type");
            return -1;
    }

    // blank success message
    write_packet(CONTROL_INTERFACE, LISTEN_MSG, NULL, 0);
    return 0;
}
