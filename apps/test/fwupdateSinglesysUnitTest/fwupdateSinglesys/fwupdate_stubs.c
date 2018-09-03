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
#include "pa_fwupdate_singlesys.h"
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
    pa_fwupdate_InternalStatus_t *statusPtr ///< [OUT] Returned update status
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

//--------------------------------------------------------------------------------------------------
/**
 * Set bad image flag preventing concurrent partition access
 *
 * @return
 *      - LE_OK            The request was accepted
 *      - LE_BAD_PARAMETER The parameter is invalid
 *      - LE_FAULT         If an error occurs
 */
//--------------------------------------------------------------------------------------------------
le_result_t partition_SetBadImage
(
    cwe_ImageType_t imageType,        ///< [IN] CWE image type to set/clear bad image flag for
    bool isBad                        ///< [IN] True to set bad image flag, false to clear it
)
{
    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Get the MTD number and partition name belonging to a image type. If the inDual parameter is true,
 * the MTD is looked into the passive partition matrix. If inDual is false, it is looked into the
 * active (initial boot) partition matrix.
 * The MTD name and the write size of the partition are also returned as output parameters.
 *
 * @return
 *      - The MTD number belonging the image type for the boot system (dual or initial)
 *      - 1 if initial boot system is 2,
 *      - -1 in case of failure
 */
//--------------------------------------------------------------------------------------------------
int partition_GetMtdFromImageType
(
    cwe_ImageType_t partName,         ///< [IN] Partition enumerate to get
    bool inDual,                      ///< [IN] true for the dual partition, false for the active
    char** mtdNamePtr,                ///< [OUT] Pointer to the real MTD partition name
    bool *isLogical,                  ///< [OUT] true if the partition is logical (TZ or RPM)
    bool *isDual                      ///< [OUT] true if the upper partition is concerned (TZ2 or
                                      ///<       RPM2), false in case of lower partition
)
{
    return 0;
}

//--------------------------------------------------------------------------------------------------
/**
 * Open SWIFOTA partition
 *
 * @return
 *      - LE_OK             on success
 *      - LE_UNSUPPORTED    the feature is not supported
 *      - LE_DUPLICATE      parition is already opened
 *      - LE_FAULT          on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_fwupdate_OpenSwifota
(
    void
)
{

    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Close SWIFOTA partition
 *
 * @return
 *      - LE_OK             on success
 *      - LE_UNSUPPORTED    the feature is not supported
 *      - LE_FAULT          on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_fwupdate_CloseSwifota
(
    void
)
{
    return LE_OK;
}
