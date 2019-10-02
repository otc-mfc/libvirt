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

#ifndef SRE_INTERNAL_POLICY_H
#define SRE_INTERNAL_POLICY_H

/******************************************************************************/

/**
 * @brief Policy definitions:
 *  1) Violation, Report and Kill: reports the event and shuts down the guest.
 *  2) Allow: Hardware or feature is available.
 *  3) Violation Report and Continue: reports the event without shutting down the guest.
 *  4) Allow-Null: no report nor shutting down the guest.
 *  5) Violation and Kill: shuts down the guest without event reporting.
 *
 ******************************************************************************/

#define  POL_VIOLATE_REPORT_KILL      0   /**< Violation: report and kill. */

#define  POL_ALLOW                    1   /**< Allow, no report. */

#define  POL_VIOLATE_REPORT_CONTINUE  2   /**< Violation: null emulation, report and continue. */

#define  POL_ALLOW_NULL               3   /**< Allow, null emulation (discard and continue). */

#define  POL_VIOLATE_KILL             4   /**< Violation: kill but no report. */

/******************************************************************************/

/**
 * @brief Policy hardware emulation definitions:
 *  Device is assigned for passthrough which gives control of physical device to a guest.
 *  Device is shared by all guests.
 *
 ******************************************************************************/

#define  POL_ALLOW_PASSTHROUGH        5   /**< Exclusively assign to a guest. */

#define  POL_ALLOW_SHARED             6   /**< Shared by all guests. */

/******************************************************************************/

/**
 * @brief Policy definition for Hardware devices. This applies for serial port
 *        assignment, etc...
 *
 *******************************************************************************/
typedef enum {

    POL_HW_ALLOW_PASSTHROUGH = POL_ALLOW_PASSTHROUGH,               /**< Allow, exclusive passthrough. */

    POL_HW_ALLOW_SHARED = POL_ALLOW_SHARED,                         /**< Allow, shared */

    POL_HW_VIOLATE_REPORT_KILL = POL_VIOLATE_REPORT_KILL,           /**< Violation, Report and Kill. */

    POL_HW_VIOLATE_REPORT_CONTINUE = POL_VIOLATE_REPORT_CONTINUE,   /**< Violation, Report and Continue. */

    POL_HW_ALLOW_NULL = POL_ALLOW_NULL,                             /**< Allow, null emulation */

    POL_HW_VIOLATE_KILL = POL_VIOLATE_KILL,                         /**< Violation, and Kill */
} pol_hw_state_t;

/******************************************************************************/

/**
 * @brief Policy definition for Virtual Hardware Devices:
 *  1) Allow: HW is available for the guest.
 *  2) Violation, Report and Kill: reports and shuts down the guest.
 *  3) Violation, Report and Continue: reports without shutting down the guest.
 *  4) Allow-Null: Null emulation is provided by the host.  No action is required.
 *  5) Violation, and Kill: shuts down the guest without reporting the event.
 *
 ******************************************************************************/
typedef enum {

    POL_VIRT_HW_ALLOW = POL_ALLOW,                                      /**< Allow, meaning HW is available */

    POL_VIRT_HW_VIOLATE_REPORT_KILL = POL_VIOLATE_REPORT_KILL,          /**< Reports and shuts down the guest. */

    POL_VIRT_HW_VIOLATE_REPORT_CONTINUE = POL_VIOLATE_REPORT_CONTINUE,  /**< Reports but no shutdown the guest. */

    POL_VIRT_HW_ALLOW_NULL = POL_ALLOW_NULL,                            /**< Null emulation, no action is required. */

    POL_VIRT_HW_VIOLATE_KILL = POL_VIOLATE_KILL,                        /**< Shuts down the guest without reporting the event. */
} pol_virt_hw_state_t;

/******************************************************************************/

/**
 * @brief CMOS RTC definition:
 *  Allow: read/write access to CMOS RTC device
 *
 ******************************************************************************/
typedef enum {

    POL_RTC_ALLOW = POL_ALLOW,                                          /**< Guest will use the emulated vRTC */

    POL_RTC_ALLOW_PASSTHROUGH = POL_ALLOW_PASSTHROUGH,                  /**< Gives the guest control of the on-board device. */
} pol_rtc_t;

/******************************************************************************/

/**
 * @brief Total number of serial ports.
 *
 ******************************************************************************/
#define MAX_NUM_SERIAL_PORTS 4

/******************************************************************************/

/**
 * @brief Defines the serial value.
 *  com1 (ttyS0) = 0.
 *  com2 (ttyS1) = 1.
 *  com3 (ttyS2) = 2.
 *  com4 (ttyS3) = 3.
 *
 ******************************************************************************/

#define com1 0  /**< Serial port com1 (ttyS0). */

#define com2 1  /**< Serial port com2 (ttyS1). */

#define com3 2  /**< Serial port com3 (ttyS2). */

#define com4 3  /**< Serial port com4 (ttyS3). */

typedef enum {
    ELF_GUEST_TYPE = 0,
    VMLINUZ_GUEST_TYPE = 1,
    VXWORKS_GUEST_TYPE = 2,
    BIOS_GUEST_TYPE = 3,
    MAX_GUEST_TYPE
} guest_type_t;

/* Guest can be either 64 bit long mode or 32 bit unrestricted mode
 * (unpaged protected mode)
 */

#define GET_GUEST_EXECUTION_MODE(a) (a&0x7)
typedef enum {
    UNRESTRICTED_REALMODE_GUEST = 0,
    UNRESTRICTED_PROTECTED_GUEST = 1,

    MEMORY_ENCRYPTED_GUEST = 8,
    PAGED_GUEST = 16,
    CROSS_NUMA_NODES_GUEST = 32,
    RESERVE_HT_SIBLING_CORES_GUEST = 64
} guest_mode_t;

typedef enum {
    FORCE_SHUTDOWN = 0,
    ACPI_PWR_BUTTON_SHUTDOWN = 1
} shutdown_mode_t;

typedef enum portal_types_t {
    PORTAL_SE,
    PORTAL_PIPE,
    PORTAL_IP_NETWORK,
    PORTAL_VIRTIO_NET,
    PORTAL_SRE_NET
} portal_type;

typedef enum {
    PAGING_OFF,
    PAGING_ON,
    PAGING_ENCRYPT,
} pagingMode_t;

typedef enum {
    POLICY_EXC_DE,
    POLICY_EXC_OF,
    POLICY_EXC_BR,
    POLICY_EXC_UD,
    POLICY_EXC_NM,
    POLICY_EXC_DF,
    POLICY_EXC_NP,
    POLICY_EXC_SS,
    POLICY_EXC_GP,
    POLICY_EXC_PF,
    POLICY_EXC_MF,
    POLICY_EXC_AC,
    POLICY_EXC_MC,
    POLICY_EXC_XF,
    POLICY_EXC_BP,
    POLICY_EXC_MAX
} policy_exc_t;

#endif  /** SRE_INTERNAL_POLICY_H */
