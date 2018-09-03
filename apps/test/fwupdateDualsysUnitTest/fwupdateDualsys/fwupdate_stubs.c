/**
 * @file fwupdate_stubs.c
 *
 * Stub functions required for firmware update tests.
 *
 * Copyright (C) Sierra Wireless Inc.
 */

#include "legato.h"
#include <stdint.h>
#include "cwe_local.h"
#include "partition_local.h"
#include "pa_fwupdate_dualsys.h"
#include "pa_flash.h"
#include "pa_patch.h"


//--------------------------------------------------------------------------------------------------
/**
 * Static variable for simulating PA API error code
 */
//--------------------------------------------------------------------------------------------------
static le_result_t ReturnCode = LE_OK;

//--------------------------------------------------------------------------------------------------
/**
 * Static variable for simulating systems synchronization state
 */
//--------------------------------------------------------------------------------------------------
static bool IsSyncLocal = true;

//--------------------------------------------------------------------------------------------------
/**
 * Static variable for simulating system operation
 */
//--------------------------------------------------------------------------------------------------
static bool Sync = false;

//--------------------------------------------------------------------------------------------------
/**
 * Release the flash access after a SW update
 *
 * @return
 *      - LE_OK    on success
 *      - LE_FAULT on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_fwupdate_CompleteUpdate
(
    void
)
{
    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Function which indicates if a Sync operation is needed (swap & sync operation)
 *
 * @return
 *      - LE_OK            on success
 *      - LE_UNSUPPORTED   the feature is not supported
 *      - LE_FAULT         on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_fwupdate_DualSysCheckSync
(
    bool* isSyncReqPtr ///< [OUT] Indicates if synchronization is requested
)
{
    *isSyncReqPtr = Sync;
    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Function which set the Sync operation
 *
 * @return none
 */
//--------------------------------------------------------------------------------------------------
void pa_fwupdateSimu_SetDualSysSync
(
    bool sync ///< [IN] Indicates if synchronization is requested
)
{
    Sync = sync;
}

//--------------------------------------------------------------------------------------------------
/**
 * Request the flash access for a SW update
 *
 * @return
 *      - LE_OK          on success
 *      - LE_UNAVAILABLE the flash access is not granted for SW update
 *      - LE_FAULT       on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_fwupdate_RequestUpdate
(
    void
)
{
    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Get the firmware update status label
 *
 * @return
 *      - The address of the FW update status description matching the given status.
 *      - NULL if the given status is invalid.
 */
//--------------------------------------------------------------------------------------------------
const char *pa_fwupdate_GetUpdateStatusLabel
(
    pa_fwupdate_InternalStatus_t status    ///< [IN] Firmware update status
)
{
    const char *FwUpdateStatusLabel[] =
    {
        "No bad image found",               // PA_FWUPDATE_INTERNAL_STATUS_OK
        "sbl",                              // PA_FWUPDATE_INTERNAL_STATUS_SBL
        "mibib",                            // PA_FWUPDATE_INTERNAL_STATUS_MIBIB
        "Reserved1",                        // PA_FWUPDATE_INTERNAL_STATUS_RESERVED1
        "sedb"     ,                        // PA_FWUPDATE_INTERNAL_STATUS_SEDB
        "Reserved2",                        // PA_FWUPDATE_INTERNAL_STATUS_RESERVED2
        "tz_1",                             // PA_FWUPDATE_INTERNAL_STATUS_TZ1
        "tz_2",                             // PA_FWUPDATE_INTERNAL_STATUS_TZ2
        "rpm_1",                            // PA_FWUPDATE_INTERNAL_STATUS_RPM1
        "rpm_2",                            // PA_FWUPDATE_INTERNAL_STATUS_RPM2
        "modem_1",                          // PA_FWUPDATE_INTERNAL_STATUS_MODEM1
        "modem_2",                          // PA_FWUPDATE_INTERNAL_STATUS_MODEM2
        "aboot_1",                          // PA_FWUPDATE_INTERNAL_STATUS_LK1
        "aboot_2",                          // PA_FWUPDATE_INTERNAL_STATUS_LK2
        "boot_1",                           // PA_FWUPDATE_INTERNAL_STATUS_KERNEL1
        "boot_2",                           // PA_FWUPDATE_INTERNAL_STATUS_KERNEL2
        "system_1",                         // PA_FWUPDATE_INTERNAL_STATUS_ROOT_FS1
        "system_2",                         // PA_FWUPDATE_INTERNAL_STATUS_ROOT_FS2
        "lefwkro_1",                        // PA_FWUPDATE_INTERNAL_STATUS_USER_DATA1
        "lefwkro_2",                        // PA_FWUPDATE_INTERNAL_STATUS_USER_DATA2
        "customer0",                        // PA_FWUPDATE_INTERNAL_STATUS_CUST_APP1
        "customer1",                        // PA_FWUPDATE_INTERNAL_STATUS_CUST_APP2
        "Download in progress",             // PA_FWUPDATE_INTERNAL_STATUS_DWL_ONGOING
        "Download failed",                  // PA_FWUPDATE_INTERNAL_STATUS_DWL_FAILED
        "Download timeout",                 // PA_FWUPDATE_INTERNAL_STATUS_DWL_TIMEOUT
        "Swap and mark good ongoing",       // PA_FWUPDATE_INTERNAL_STATUS_SWAP_MG_ONGOING
        "Swap ongoing",                     // PA_FWUPDATE_INTERNAL_STATUS_SWAP_ONGOING
        "Unknown status"                    // PA_FWUPDATE_INTERNAL_STATUS_UNKNOWN
    };

    // Check parameters
    if (status > PA_FWUPDATE_INTERNAL_STATUS_UNKNOWN)
    {
        LE_ERROR("Invalid status parameter (%d)!", (int)status);
        // Always return a status label.
        status = PA_FWUPDATE_INTERNAL_STATUS_UNKNOWN;
    }

    // Point to the matching label.
    return FwUpdateStatusLabel[status];
}

//--------------------------------------------------------------------------------------------------
/**
 * Update some variables in SSDATA to indicate that systems are not synchronized
 *
 * @return
 *      - LE_OK on success
 *      - LE_FAULT on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_fwupdate_SetUnsyncState
(
    void
)
{
    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Update some variables in SSDATA to indicate that systems are synchronized
 *
 * @return
 *      - LE_OK on success
 *      - LE_FAULT on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_fwupdate_SetSyncState
(
    void
)
{
    return ReturnCode;
}

//--------------------------------------------------------------------------------------------------
/**
 * This API is to be called to set the SW update state in SSDATA
 *
 * @return
 *      - LE_OK on success
 *      - LE_FAULT on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_fwupdate_SetState
(
    pa_fwupdate_state_t state   ///< [IN] state to set
)
{
    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Indicates if active and update systems are synchronized
 *
 * @return
 *      - LE_OK on success
 *      - LE_FAULT on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_fwupdate_GetSystemState
(
    bool *isSync
)
{
    *isSync = IsSyncLocal;
    return ReturnCode;
}

//--------------------------------------------------------------------------------------------------
/**
 * Set the stub synchronization state
 *
 * @return None
 */
//--------------------------------------------------------------------------------------------------
void pa_fwupdateSimu_SetSystemState
(
    bool isSync
)
{
    IsSyncLocal = isSync;
}

//--------------------------------------------------------------------------------------------------
/**
 * Set the return state for pa_fwupdate_GetSystemState API
 *
 * @return None
 */
//--------------------------------------------------------------------------------------------------
void pa_fwupdateSimu_SetReturnVal
(
    le_result_t result
)
{
    ReturnCode = result;
}

//--------------------------------------------------------------------------------------------------
/**
 * Program the partitions to become active and update systems
 *
 * @return
 *      - LE_OK             on success
 *      - LE_UNSUPPORTED    the feature is not supported
 *      - LE_FAULT          on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_fwupdate_SetActiveSystem
(
    pa_fwupdate_System_t systemArray[PA_FWUPDATE_SUBSYSID_MAX],
                         ///< [IN] System array for "modem/lk/linux" partition groups
    bool isSyncReq       ///< [IN] Indicate if a synchronization is requested after the swap
)
{
    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * request the modem to apply the NVUP files in UD system
 *
 * @return
 *      - LE_OK             on success
 *      - LE_UNSUPPORTED    the feature is not supported
 *      - LE_FAULT          on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_fwupdate_NvupApply
(
    void
)
{
    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Return the last internal update status.
 *
 * @return
 *      - LE_OK on success
 *      - LE_BAD_PARAMETER Invalid parameter
 *      - LE_FAULT on failure
 *      - LE_UNSUPPORTED not supported
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_fwupdate_GetInternalUpdateStatus
(
    pa_fwupdate_InternalStatus_t *statusPtr, ///< [OUT] Returned update status
    char *statusLabelPtr,                    ///< [OUT] String matching the status
    size_t statusLabelLength                 ///< [IN] Maximum length of the status description
)
{
    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Set bad image flag preventing concurrent partition access
 *
 * @return
 *      - LE_OK             on success
 *      - LE_FAULT          on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_fwupdate_SetBadImage
(
    uint64_t badImageMask,  ///< [IN] image to be written according to bitmask
    bool isBad              ///< [IN] true to set bad image flag, false to clear it
)
{
    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Kick a watchdog on the chain.
 */
//--------------------------------------------------------------------------------------------------
void le_wdogChain_Kick
(
    uint32_t watchdog
)
{
}

//--------------------------------------------------------------------------------------------------
/**
 * request the modem to delete the NVUP files in UD system
 *
 * @return
 *      - LE_OK             on success
 *      - LE_UNSUPPORTED    the feature is not supported
 *      - LE_FAULT          on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_fwupdate_NvupDelete
(
    void
)
{
    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Check if the the last swap has been requested by a Legato API
 *
 * @return
 *      - LE_OK            on success
 *      - LE_UNSUPPORTED   the feature is not supported
 *      - LE_BAD_PARAMETER bad parameter
 *      - LE_FAULT         else
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_fwupdate_IsSwapRequestedByLegato
(
    bool* isLegatoSwapReqPtr   ///< [OUT] Set to true if the swap is requested by a Legato API
)
{
    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Write a NVUP file in UD system
 *
 * @return
 *      - LE_OK             on success
 *      - LE_UNSUPPORTED    the feature is not supported
 *      - LE_FAULT          on failure
 *      - others            Depending of the underlying operations
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_fwupdate_NvupWrite
(
    size_t length,                      ///< [IN] data length
    const uint8_t* dataPtr,             ///< [IN] input data
    bool isEnd                          ///< [IN] flag to indicate the end of the file
)
{
    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Sierra bsPatch function.
 *
 * @return
 *      - LE_OK             on success
 *      - others            Depending of the underlying operations
 */
//--------------------------------------------------------------------------------------------------
le_result_t bsPatch
(
    pa_patch_Context_t *patchContextPtr,
                            ///< [IN] Context for the patch
    char *patchfile,        ///< [IN] File containing the patch
    uint32_t *crc32Ptr,     ///< [OUT] Pointer to return the CRC32 of the patch applied
    bool lastPatch,         ///< [IN] True if this is the last patch in this context
    bool forceClose         ///< [IN] Force close of device and resources
)
{
    return LE_OK;
}
