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

#ifndef DOMAIN_FORMAT_H
#define DOMAIN_FORMAT_H

#include <stdint.h>
#include "sre_internal_types.h"
#include "sre_internal_policy.h"

/** Used to uniquely identify a guest **/
typedef int32_t guest_id_t;

#define MAX_NUM_PORTALS 512

#define MAX_PATH_LENGTH 4096
#define MAX_BOOTLINE_LENGTH 4096
#define MAX_NUMBER_OF_CORES 512

/******************************************************************************/

/**
 * brief The maximum length of domain file ID.
 *
 ******************************************************************************/
#define DOMAIN_FILE_ID_LENGTH 8

/******************************************************************************/

/**
 * @brief The domain header file ID.
 *
 ******************************************************************************/
#define DOMAIN_HEADER_FILE_ID "LM_D_HDR"

/******************************************************************************/

/**
 * @brief The maximum length of the file signature.
 *
 ******************************************************************************/
#define DOMAIN_SIGNATURE_NUM_BYTES 64

/******************************************************************************/

/**
 * @brief Domain version number.
 *
 ******************************************************************************/
#define DOMAIN_DEF_VERSION_NUMBER 9

/******************************************************************************/

/**
 * @brief The maximum length of the VM name.
 *
 ******************************************************************************/
#define MAX_GUEST_NAME_SIZE 20

#define MAX_GUEST_UUID_SIZE 37

#define SHA256_NUM_BYTES 32  /** 256 bit sha */

#define GUEST_CORE_BITMAP_SIZE (MAX_NUMBER_OF_CORES / 8)

/** @brief domain options bit field*/
typedef union {

    uint32_t val;               /**< Holistic view of the options value */

    struct {

        uint32_t compressed:1;         /**< Set if the domain is compressed */

        uint32_t dynamic_policy:1;     /**< Set if the domain has dynamic policy else all the policy is sigend */

        uint32_t unused:29;            /**< Unused bits */
    } opts;
} domain_options_t;

#define DOMAIN_COMPRESSED 1
#define DOMAIN_TENANT_SIGNED 2
#define DOMAIN_DYNAMIC_POLICY 4

/******************************************************************************/

/**
 * @brief Define the manifest footer which contains the file signature.
 *
 ******************************************************************************/
typedef struct __attribute__ ((packed)) {

    uint8_t data[DOMAIN_SIGNATURE_NUM_BYTES];  /**< File signature. */
} domain_header_signature_t;

/******************************************************************************/

/**
 * @brief Define the domain hash data.
 *
 ******************************************************************************/
typedef struct __attribute__ ((packed)) {

    uint8_t data[SHA256_NUM_BYTES];  /**< File signature. */
} domain_hash_data_t;

typedef struct __attribute__ ((packed)) {

    uint32_t total_size;                   /**< Total size of domain file */
    uint8_t fileId[DOMAIN_FILE_ID_LENGTH];  /**< File name, this is nNot zero terminated. */
    uint32_t signed_size;                   /**< Signed size of domain */
    uint32_t domain_size;                   /**< total size of domain */
    uint32_t compressed_size;               /**< Size of compressed/non-dynamic part of of domain */
    uint64_t version;                       /**< Version number which is set to DOMAIN_DEF_VERSION_NUMBER. */
    domain_options_t options;               /**< Domain file options */
} domain_header_info_t;

/******************************************************************************/

/**
 * @brief Defines the Domain data header. This contains the inforamtion 
   about the proceeding domain to be sent to the security engine.
 *
 ******************************************************************************/
typedef struct __attribute__ ((packed)) {
    domain_header_info_t domain_info;
    domain_hash_data_t domain_hash;         /**< Hash of domain binary following this header*/
} domain_header_data_t;

typedef struct __attribute__ ((packed)) {
    domain_header_data_t data;
    domain_header_signature_t signature;
} domain_header_t;


/******************************************************************************/

/**
 * @brief Defines the manifest data structure for VM.
 *
 ******************************************************************************/
typedef struct __attribute__ ((packed)) {

    guest_type_t guest_type;                    /**< Guest type (ELF, Linux, VxWorks, etc..). */
    guest_mode_t guest_mode;                    /**< Guest mode  */
    uint64_t ram_size;                          /**< Ram size */
    uint64_t cache_ways;                        /**< Cache ways to be assigned to the guest */
    uint64_t hash_page_threshold;               /**< Hash page threshold. */
    uint16_t num_cores;                         /**< Number of vCPUs */
    uint8_t cores[GUEST_CORE_BITMAP_SIZE];      /**< CPU assignment bitmap */
    policy_settings_t policy_settings;          /**< Policy settings */
    uint32_t numSections;                       /**< VM memory sections. */
    uint32_t numPCIDevices;                     /**< Number of PCIe devices is used. */
    uint32_t numPortalDevices;                  /**< Number of portal devices is used. */
    uint32_t numDynamicPortalDevices;           /**< Number of dynamic portals. */
    uint32_t numDynamicSections;                 /**< VM dynamic memory sections. */
    guest_rsvd_phys_memory_t rsv_memory_base;   /**< Reserved memory allocating for GDT and TR. */
    uint64_t boot_vector;                       /**< Boot vector for Linux guest. */
    uint64_t boot_param_address;                /**< Boot parameter address for Linux guest */
} domain_def_t;

/******************************************************************************/

/**
 * @brief Defines manifest data section attributes.
 *
 ******************************************************************************/
typedef struct __attribute__ ((packed)) {

    uint64_t section_address;     /**< Section address. */
    uint64_t section_size;        /**< Section size. */
    uint64_t data_offset;         /**< Offset of the given data within the region. */
    uint64_t num_bytes_present;   /**< Number of bytes present in the array below. */
    uint8_t permissions;          /** Memory permissions. */
    uint8_t section_data[];       /**< Data sections. */
} domain_data_section_t;

/******************************************************************************/

/**
 * @brief PCIe device format define.
 *
 ******************************************************************************/
typedef pci_device_info_t domain_pci_device_t;

/******************************************************************************/

/**
 * @brief Defines the manifest portal settings.
 *
 ******************************************************************************/
typedef portal_device_info_t domain_portal_device_t;

/******************************************************************************/

/**
 * @brief Defines the dynamic policy for domains.
 *
 ******************************************************************************/
typedef struct __attribute__ ((packed)) {

    char domain_name[MAX_GUEST_NAME_SIZE];      /**< Guest name */
    char domain_uuid[MAX_GUEST_UUID_SIZE];      /**< Guest UUID */
} domain_dynamic_section_t;

typedef struct {
    domain_header_t domain_header;
    domain_def_t definition;
    domain_data_section_t *data_sections;
    domain_pci_device_t *pci_devices;

    domain_portal_device_t *portal_devices;     /**< List of portals to use for static portals*/
    domain_dynamic_section_t dynamic_policy;
    domain_data_section_t *unsigned_data_sections;

    domain_portal_device_t *dynamic_portal_devices;    /**< List of portals to use for dynamic nics */
    domain_hash_data_t domain_hash;
} __attribute__ ((packed)) domain_t;

#endif  /** DOMAIN_FORMAT_H **/
