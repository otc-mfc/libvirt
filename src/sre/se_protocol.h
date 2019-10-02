/*
 * Copyright(c) 2019 Lockheed Martin Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated 
 * documentation files (the "Software"), to deal in the Software without restriction, including without limitation 
 * the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and 
 * to permit persons to whom the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of 
 * the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO 
 * THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, 
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE 
 * SOFTWARE.
 */

#ifndef SE_PROTOCOL_H
#define SE_PROTOCOL_H
#define MAX_RESP_STRING_LENGTH 50
#include "domain_format.h"

/*
 * Generic Protocol for communicating between the Security Engine and a
 * Security Engine Controller guest:
 *  1) Controller sends packet
 *    - type
 *    - payload size
 *    - payload
 *  2) Security Engine sends packet back
 *    - type = SE status
 *    - payload size
 *    - status
 *    - payload
 *
 * Type, payload size, and payload will change depending on the interaction
 * being performed. E.g. when commanded to create a domain, the packets will
 * look like so:
 *  1) Controller sends packet
 *    - CMD_CREATE_DOMAIN 
 *    - sizeof(domain)
 *    - domain
 *  2) Security Engine sends packet back
 *    - SE_STATUS
 *    - sizeof(error string)
 *    - hypercall_status_t
 *    - error string (if applicable)
 */

/* Defines the status type */
typedef enum {

    STATUS_OK = 0,         /**< Status is OK                    */

    STATUS_ERROR,          /**< An error was flagged            */

    STATUS_BAD_ALLOC_ERROR /**< An incorrect allocator was used */
} status_t;

typedef enum {
    SE_STATUS = 0,
    SE_DATA,
    CMD_AUTH_DOMAIN_HEADER,
    CMD_CREATE_DOMAIN,
    CMD_DESTROY_DOMAIN,
    REQ_DOMAIN_STATUS,
    CMD_CREATE_DEFERRED,
    SE_DONE,
    REQ_SYS_INFO,
} se_packet_type_t;

typedef enum {
    GUEST_RUNNING = 0,
    GUEST_SHUTDOWN,
    GUEST_ERROR
} guest_status_t;

typedef struct {

    uint32_t total_cores;                                /**< Number of cores */

    uint32_t avail_cores;                                /**< Number of available cores */

    uint8_t core_mask[(MAX_NUMBER_OF_CORES + 7) / 8];    /**< Number of cores */

    uint32_t num_ht;                                     /**< Hyperthread count 1,2...more? */

    uint32_t num_numa_nodes;                             /**< Number of numa nodes */

    uint32_t num_sub_numa_clusters;                      /**< Number of sub numa clusters */
} sys_info_cpu_t;

/******************************************************************************/

/**
 *
 * @brief Structure for system info provided via SE 
 *
 ******************************************************************************/
typedef struct {
    sys_info_cpu_t cpu_info;

    uint64_t total_mem;                          /**< Total memory in guest pool*/

    uint64_t avail_mem;                          /**< Total memory available in guest pool*/
} sre_sys_info_t;

typedef enum {
    FL_DOMAIN = 0,
    FL_SCRIPT
} fl_create_t;

typedef enum {
    GUEST_STATE = 0,
    GUEST_MEM
} guest_status_req_type_t;

typedef struct {
    se_packet_type_t type;
    uint32_t size;
} __attribute__ ((packed)) se_packet_header_t;

/**< Packet header, type = SE_STATUS */
typedef struct {

    status_t status;  /**< Create or destroy status code*/
    guest_id_t guest_id;

    char error_string[MAX_RESP_STRING_LENGTH];      /**< Error string correlated with the status code, if applicable */
} __attribute__ ((packed)) se_status_t;

typedef struct {

    uint8_t *domain_payload;  /**< Buffer that contains a domain binary including signature */
} __attribute__ ((packed)) se_domain_create_t;

typedef struct {

    guest_id_t domain_id;          /**< Target domain ID */

    shutdown_mode_t shutdown_mode; /**< Shutdown mode */
} __attribute__ ((packed)) se_domain_destroy_t;

typedef struct {
    guest_status_t status;

    char name_string[MAX_RESP_STRING_LENGTH];      /**< Guest name */
} __attribute__ ((packed)) se_domain_status_t;

typedef struct {
    domain_header_t domain_header;
} __attribute__ ((packed)) se_domain_auth_header_t;

typedef struct {
    sre_sys_info_t system_info;
} __attribute__ ((packed)) se_system_info_t;

typedef struct {
    uint8_t response_status;
} __attribute__ ((packed)) se_data_response_t;


#endif
