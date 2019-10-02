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

#ifndef SRE_INTERNAL_TYPES_H
#define SRE_INTERNAL_TYPES_H
#include "sre_internal_policy.h"

#define NUM_BARE_BOOT_GDT_ENTRIES  5
#define NUM_LINUX_BOOT_GDT_ENTRIES 6

typedef struct {
    uint32_t vendor_id;
    uint32_t device_id;
    uint32_t class_code;        /* Full 32-bit includes RevID */
    uint32_t function_number;
    uint32_t instance_number;
    uint32_t translated_vendor_id;
    uint32_t translated_device_id;
    uint32_t is_dma_enabled;
    uint32_t rom_bar_passthrough;
    uint32_t is_device_required;
} pci_device_info_t;

#define guest_mode_remove_attributes(a) (a&(~MEMORY_ENCRYPTED_GUEST))

/******************************************************************************/

/**
 * @brief LPC definition:
 *  1) Violation-Report-Kill: Kill guest on port access
 *  2) Allow: read/write access to port
 *  3) Violation-Report-Continue: Report, discard written data, return 0 on read
 *  4) Allow, Null: Discard written data, return 0 on read
 *
 ******************************************************************************/
typedef enum {

    POL_LPC_VIOLATE_REPORT_KILL = POL_VIOLATE_REPORT_KILL,            /**< Reports and shuts down the guest. */

    POL_LPC_ALLOW_PASSTHROUGH = POL_ALLOW_PASSTHROUGH,                /**< Gives the guest the physical control of the device. */

    POL_LPC_VIOLATE_REPORT_CONTINUE = POL_VIOLATE_REPORT_CONTINUE,     /**< Null emulation, reports but no action is required. */

    POL_LPC_ALLOW_NULL = POL_ALLOW_NULL                               /**< No action is required. */
} pol_lpc_state_t;

/******************************************************************************/

/**
 * @brief The maximum number of custom I/O ports to define in manifests.
 *
 ******************************************************************************/
#define POL_CUSTOM_IO_PORT_MAX 16

/******************************************************************************/

/**
 * @brief Policy definition of custom I/O ports.
 *  1) Allow, Passthrough:  The I/O port is assigned to a guest with full control of the device.
 *  2) Allow, Null:  Null emulation, no action is required.
 *
 ******************************************************************************/
typedef enum {

    POL_CUSTOM_IO_ALLOW_PASSTHROUGH = POL_ALLOW_PASSTHROUGH,  /**< Assigned full control of device to guest. */

    POL_CUSTOM_IO_ALLOW_NULL = POL_ALLOW_NULL                 /**< 0 value is returned on read, and write is ignored. */
} pol_custom_io_state_t;

/******************************************************************************/

/**
 * @brief Policy definition of the custom I/O port.
 *
 ******************************************************************************/
typedef struct __attribute__ ((packed)) {

    uint16_t port;                /**< Custom I/O port number. */
    uint16_t range_size;          /**< Custom I/O port range size. */
    pol_custom_io_state_t state;  /**< Custom I/O state action. */
} pol_custom_io_settings_t;

/******************************************************************************/

/**
 * @brief Policy definition of the Virtual Emulated Device settings.
 *  1) Assigned to a guest: Guest is assigned to receive an event report from the hypervisor.
 *  2) Not assigned: default value. Event is not reported to the guest.
 *
 ******************************************************************************/
typedef enum {

    POL_VIRT_DEV_UNASSIGNED = 0, /**< Default value. Event is not reported to this guest */

    POL_VIRT_DEV_ASSIGNED = 1     /**< Guest is assigned to receive an event report from the hypervisor. */
} pol_virt_device_settings_t;

/******************************************************************************/

/**
 *
 * @brief Convenience pairing of serial port policy state and target port
 *
 ******************************************************************************/
typedef struct __attribute__ ((packed)) {

    pol_hw_state_t policy;    /**< Policy setting of the serial port */
    uint32_t target_port;     /**< Target serial port of the virtual serial port */
} pol_serial_port_t;

/******************************************************************************/

/**
 *
 * @brief Convenience pairing of HVC policy and target port
 *
 ******************************************************************************/
typedef struct __attribute__ ((packed)) {

    pol_virt_device_settings_t policy;  /**< Policy setting for the HVC device */
    uint32_t target_port;   /**< Target serial port of the virtual serial port */
} pol_hvc_t;

/******************************************************************************/

/**
 *
 * @brief Convenience pairing of Event Reporter policy and timeout value
 *
 ******************************************************************************/
typedef struct __attribute__ ((packed)) {

    pol_virt_device_settings_t policy;  /**< Policy setting for the Event Reporter device */
    uint64_t timeout_ms;   /**< Timeout value in milliseconds to wait for response */
} pol_event_reporter_t;

/******************************************************************************/

/**
 * @brief Data structure containing the hardware device settings in the manifest.
 *
 ******************************************************************************/
typedef struct __attribute__ ((packed)) {

    pol_serial_port_t serial_port[MAX_NUM_SERIAL_PORTS];        /**< Serial port settings. */
    pol_lpc_state_t lpc;                                        /**< LPC settings. */
    pol_custom_io_settings_t custom_io[POL_CUSTOM_IO_PORT_MAX]; /**< Custom I/O settings. */
    pol_event_reporter_t event_reporter;                        /**< Event reporter settings. */
    pol_virt_device_settings_t instrumentation_reporter;        /**< Instrumentation reporter settings. */
    pol_virt_device_settings_t instrumentation_target;          /**< Instrumentation target settings. */
    pol_hvc_t hvc;                                              /**< Virtual Emulated Device settings. */
    pol_virt_hw_state_t reset;                                  /**< Reset feature. */
    pol_rtc_t rtc;                                              /**< RTC settings. */
} policy_hw_settings_t;

/******************************************************************************/

/**
 * @brief Policy definition of Exception.
 *
 ******************************************************************************/
typedef enum {

    POL_EXCEPTION_VIOLATE_KILL = POL_VIOLATE_KILL,                      /**< Shuts down the guest without any event reporting. */

    POL_EXCEPTION_VIOLATE_REPORT_KILL = POL_VIOLATE_REPORT_KILL,        /**< Reports the event and shuts down the guest. */

    POL_EXCEPTION_ALLOW_NULL = POL_ALLOW_NULL,                          /**< No action is required. */

    POL_EXCEPTION_VIOLATE_REPORT_CONTINUE = POL_VIOLATE_REPORT_CONTINUE,/**< Reports the exception without shutdown the guest. */

    POL_EXCEPTION_ALLOW = POL_ALLOW                                     /**< Injects the exception to the guest. */
} pol_exception_state_t;

/******************************************************************************/

/**
 * @brief Definition of Exception settings.
 *
 ******************************************************************************/
typedef struct __attribute__ ((packed)) {

    pol_exception_state_t de;                 /**< Divide Error. */
    pol_exception_state_t of;                 /**< Overflow. */
    pol_exception_state_t br;                 /**< Bound Range Exceeded. */
    pol_exception_state_t ud;                 /**< Undefined Opcode. */

    pol_exception_state_t nm;                 /**< No Math Co-processor. */
    pol_exception_state_t df;                 /**< Double Fault. */
    pol_exception_state_t np;                 /**< Segment Not Present. */
    pol_exception_state_t ss;                 /**< Stack Segment Fault. */

    pol_exception_state_t gp;                 /**< General Protection Fault. */
    pol_exception_state_t pf;                 /**< Page Fault. */
    pol_exception_state_t mf;                 /**< Math Fault. */
    pol_exception_state_t ac;                 /**< Alignment Check. */

    pol_exception_state_t mc;                 /**< Machine Check */
    pol_exception_state_t xf;                 /**< SIMD Floating Point Numeric Error. */
    pol_exception_state_t bp;                 /**< Breakpoint. */
} policy_exception_settings_t;

/******************************************************************************/

/**
 * @brief Policy definition of Guest Software Debugger (GDB support).
 *  1) Violation-Report-Kill: Software debugger feature is not allowed.
 *     If policy is violated, the event will be reported and guest will be killed.
 *  2) Allow:  This allows guest to use the software debug feature.
 *
 ******************************************************************************/
typedef enum {

    POL_SWDBG_VIOLATE_REPORT_KILL = POL_VIOLATE_REPORT_KILL, /**< Reports the event and shuts down the guest. */

    POL_SWDBG_ALLOW = POL_ALLOW                              /**< Software debugging feature is availabel to the guest. */
} pol_swdbg_state_t;

/******************************************************************************/

/**
 * @brief Policy definition of Host overhead monitoring feature.
 *
 ******************************************************************************/

typedef enum {

    POL_OVERHEAD_MON_VIOLATE_REPORT_KILL = POL_VIOLATE_REPORT_KILL,  /**< Reports the event and shuts down the guest. */

    POL_OVERHEAD_MON_ALLOW = POL_ALLOW                               /**< Host overhead monitor feature is allowed to the guest. */
} pol_overhead_mon_state_t;

/******************************************************************************/

/**
 * @brief Policy definition of Performance Monitoring feature:
 *  1) Violation-Report-Kill:  reports the event and shuts down the guest
 *  2) Allow-Null: Emulate as if the processor does not support performance monitoring.
 *  3) Allow: Direct pass-through to a guest.
 *  4) (Future) Allow: Shared between multiple guests.
 *
 ******************************************************************************/
typedef enum {

    POL_PERFMON_ALLOW_PASSTHROUGH = POL_ALLOW,                   /**< Gives control of physical device to a guest. */

    POL_PERFMON_VIOLATE_REPORT_KILL = POL_VIOLATE_REPORT_KILL,   /**< Reports the event and shuts down the guest. */

    POL_PERFMON_ALLOW_NULL = POL_VIOLATE_REPORT_CONTINUE,  /**< Reports the event. */

    POL_PERFMON_ALLOW_SHARED,                                                           /* +TODO: implement perfmon shared with multiple guest *//**< Device is shared by all guests. */

    POL_PERFMON_MAX                                               /**< maximum perfmon policy definition. */
} pol_perfmon_state_t;

/******************************************************************************/

/**
 * @brief Policy definition of Thermal Alarm/Monitoring feature.
 * 1) Violation-Report-Kill: reports event and shuts down the guest.
 * 2) Allow: allows guest to configure thermal thresholds/alarms.
 *
 ******************************************************************************/
typedef enum {

    POL_THERMAL_MON_VIOLATE_REPORT_KILL = POL_VIOLATE_REPORT_KILL,  /**< Reports the event and shuts down the guest. */

    POL_THERMAL_MON_ALLOW = POL_ALLOW                               /**< Allows the guest to configure thermal thresholds.*/
} pol_thermal_mon_state_t;

/******************************************************************************/

/**
 * @brief Policy definition of Power Management feature.
 * 1) Violation-Report-Kill: reports the event and shuts down the guest.
 * 2) Allow-Null: Emulate as if the processor does not support power management.
 *
 ******************************************************************************/
typedef enum {

    POL_POWER_MGMNT_VIOLATE_REPORT_KILL = POL_VIOLATE_REPORT_KILL,  /**< reports the event and shuts down the guest. */

    POL_POWER_MGMNT_ALLOW_NULL = POL_ALLOW_NULL                     /**< Null emulation, no action is required. */
} pol_power_mgmnt_state_t;

/******************************************************************************/

/**
 * @brief Definition of feature settings in the manifest.
 *
 ******************************************************************************/
typedef struct __attribute__ ((packed)) {

    pol_swdbg_state_t sw_debugger;               /**< Guest software debugger*/
    pol_overhead_mon_state_t overhead_monitor;   /**< Host overhead monitoring*/
    pol_perfmon_state_t perfmon;                 /**< Performance monitor */
    pol_thermal_mon_state_t thermal_mon;         /**< Thermal monitor - future */
    pol_power_mgmnt_state_t power_mgmnt;         /**< Power management - future*/
} policy_features_t;

/******************************************************************************/

/**
 * @brief Definition of the manifest settings.
 *
 ******************************************************************************/
typedef struct __attribute__ ((packed)) policy_manifest_settings_struct_t {

    policy_hw_settings_t hw_settings;      /**< Device settings. */
    policy_exception_settings_t exception; /**< Exception settings. */
    policy_features_t features;            /**< Feature settings. */
} policy_settings_t;

typedef enum {
    POLICY_VIRT_HW_INVALID = 0,
    POLICY_VIRT_HW_LPC,
    POLICY_VIRT_HW_RESET,
    POLICY_VIRT_HW_EVENT_REPORTER,
    POLICY_VIRT_HW_INSTRUMENTATION_REPORTER,
    POLICY_VIRT_HW_INSTRUMENTATION_TARGET,
    POLICY_VIRT_HW_HVC,
    POLICY_VIRT_HW_RTC,
    POLICY_VIRT_HW_MAX
} policy_virt_hw_t;

typedef struct portal_device_info_struct_t {
    uint8_t portalType;
    int32_t portalChannel;
    uint32_t portalMemory;
    uint64_t macAddress;
} portal_device_info_t;

typedef struct {
    uint64_t gdt_base;
    uint64_t tr_base;
} guest_rsvd_phys_memory_t;

typedef struct {
    uint64_t id;
    uint64_t start_addr;
    uint64_t size;
    uint8_t mem_type;
} memory_region_t;

/* Intel Architecture guest physical memory region type */
typedef enum {
    IVT_MR = 0,                 /* Reserved (Real mode IVT, BIOS data area */
    GDT_MR,                     /* GDT */
    TR_MR,                      /* TSS */
    UNUSED1_MR,                 /* Free */
    BOOT_LOADER_MR,             /* Boot loader */
    UNUSED2_MR,                 /* Free */
    KN_CODE_LOAD_LO_MR,         /* For protected-mode code to be loaded */
    EBDA_MR,                    /* EBDA */
    VGA_MR,                     /* RAM - VGA display area */
    VIDEO_MR,                   /* ROM - Video BIOS, unusable space */
    MISC_MR,                    /* ROM - Mapped HW and misc. */
    ACPI_TABLES_MR,             /* ROM - ACPI tables */
    KN_LOAD_SETUP_MR,
    KN_LOAD_MR,                 /* For Linux kernel load address */
    KN_LOAD_INITRD_MR,          /* For Linux kernel load initrd address */
    KN_LOAD_TOTAL_MR,           /* For Linux kernel load address */
    PCIE_MR,                    /* Reserved for PCIE memory configuration */
    DMA_MR,                     /* Reserved for DMA  */
    IOAPIC_MR,                  /* Reserved for IOAPIC */
    LAPIC_MR,                   /* Reserved for Local APIC */
    BOOT_FLASH_MR,              /* Reserved for boot flash */
    EXTRA_MR,                   /* Extra mem region */
    DRAM_LO_MR,                 /* Represents free memory up to TOLUD */
    DRAM_HI_MR,                 /* Represents free memory above 4GB */
    MAX_IA_MR
} ia_memory_region_type_t;

#endif /** SRE_INTERNAL_TYPES_H */
