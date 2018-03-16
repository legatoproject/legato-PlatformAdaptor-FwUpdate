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
#include "fwupdate_stubs.h"
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
 * Pool for flash MTD descriptors. It is created by the first call to pa_flash_Open
 */
//--------------------------------------------------------------------------------------------------
static le_mem_PoolRef_t FlashMtdDescPool = NULL;

//--------------------------------------------------------------------------------------------------
/**
 * Set failed status for flashEccStats.
 */
//--------------------------------------------------------------------------------------------------
static bool FailedState = false;


//--------------------------------------------------------------------------------------------------
/**
 * Dummy function to replace system calls.
 */
//--------------------------------------------------------------------------------------------------
int MySystem
(
    const char *command
)
{
    if (0 == strcmp(command, "/sbin/reboot"))
    {
        return -1;
    }

    return 0x6400;
}

//--------------------------------------------------------------------------------------------------
/**
 * Get flash information.
 *
 * @return
 *      - LE_OK            On success
 *      - LE_BAD_PARAMETER If infoPtr is NULL
 *      - LE_UNSUPPORTED   If the flash informations cannot be read
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_flash_GetInfo
(
    int mtdNum,
    pa_flash_Info_t* infoPtr,
    bool isLogical,
    bool isDual
)
{
    return LE_OK;
}

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
        "Unknown status"                    // PA_FWUPDATE_INTERNAL_STATUS_UNKNOWN
    };

    // Point to the matching label.
    return FwUpdateStatusLabel[PA_FWUPDATE_INTERNAL_STATUS_OK];
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
 * Open a flash for the given operation and return a descriptor
 *
 * @return
 *      - LE_OK            On success
 *      - LE_BAD_PARAMETER If desc is NULL or if mode is not correct
 *      - LE_FAULT         On failure
 *      - LE_UNSUPPORTED   If the flash device cannot be opened
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_flash_Open
(
    int mtdNum,
    pa_flash_OpenMode_t mode,
    pa_flash_Desc_t* descPtr,
    pa_flash_Info_t** infoPtr
)
{
    pa_flash_MtdDesc_t *mtdDescPtr;

    if( NULL == FlashMtdDescPool )
    {
        // Allocate the pool for MTD descriptors
        FlashMtdDescPool = le_mem_CreatePool("FlashMtdDescPool",
                                               sizeof(pa_flash_MtdDesc_t));
        le_mem_ExpandPool(FlashMtdDescPool, 2);
    }

    // Allocate and fill the MTD descriptor
    mtdDescPtr = (pa_flash_MtdDesc_t*)le_mem_ForceAlloc(FlashMtdDescPool);
    memset(mtdDescPtr, 0x0, sizeof(pa_flash_MtdDesc_t));
    mtdDescPtr->fd = 1;
    mtdDescPtr->mtdNum = mtdNum;
    mtdDescPtr->scanDone = false;
    mtdDescPtr->markBad = true;

    mtdDescPtr->mtdInfo.ubi = true;
    mtdDescPtr->mtdInfo.nbBlk = 1;
    mtdDescPtr->mtdInfo.nbLeb = 1;

    // Validate the MTD descriptor
    mtdDescPtr->magic = (pa_flash_Desc_t)mtdDescPtr;
    *descPtr = (pa_flash_Desc_t)mtdDescPtr;

    mtdDescPtr->mtdInfo.writeSize = 1;
    mtdDescPtr->mtdInfo.eraseSize = 4;
    mtdDescPtr->mtdInfo.size = 4;

    if( infoPtr )
    {
        *infoPtr = &(mtdDescPtr->mtdInfo);
    }

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
 * Check if the partition is an UBI container and all blocks belonging to this partition are valid.
 *
 * @return
 *      - LE_OK            On success
 *      - LE_BAD_PARAMETER If desc is NULL or is not a valid descriptor
 *      - LE_FAULT         On failure
 *      - LE_IO_ERROR      If a flash IO error occurs
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_flash_CheckUbi
(
    pa_flash_Desc_t desc,    ///< [IN]  Private flash descriptor
    bool *isUbiPtr           ///< [OUT] true if the partition is an UBI container, false otherwise
)
{
    *isUbiPtr = false;
    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Get the ECC and bad blocks statistics
 *
 * @return
 *      - LE_OK            On success
 *      - LE_BAD_PARAMETER If desc is NULL or isBadBlockPtr is NULL
 *      - LE_FAULT         On failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_flash_GetEccStats
(
    pa_flash_Desc_t      desc,       ///< [IN] Private flash descriptor
    pa_flash_EccStats_t *eccStatsPtr ///< [IN] Pointer to copy the ECC and bad blocks statistics
)
{
    eccStatsPtr->corrected = 1;

    if (true == FailedState)
    {
        eccStatsPtr->failed = 1;
    }
    else
    {
        eccStatsPtr->failed = 0;
    }

    eccStatsPtr->badBlocks = 0;
    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Set the ECC failed state for pa_flash_GetEccStats API
 *
 * @return None
 */
//--------------------------------------------------------------------------------------------------
void pa_flashSimu_SetEccStatsFailed
(
    bool state
)
{
    FailedState = state;
}

//--------------------------------------------------------------------------------------------------
/**
 * Scan a flash and produce a list of LEB and PEB. If no bad block is found, LEB = PEB
 * If not called, the functions "work" with PEB
 * After called, the functions "work" with LEB
 *
 * @return
 *      - LE_OK            On success
 *      - LE_BAD_PARAMETER If desc is NULL
 *      - LE_FAULT         On failure
 *      - LE_OUT_OF_RANGE  If the partition is too big to fit in LebToPeb array
 *      - LE_NOT_PERMITTED If the LEB is not linked to a PEB
 *      - LE_IO_ERROR      If a flash IO error occurs
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_flash_Scan
(
    pa_flash_Desc_t desc,
    pa_flash_LebToPeb_t **lebToPebPtr
)
{
    pa_flash_MtdDesc_t *descPtr = (pa_flash_MtdDesc_t *)desc;
    uint32_t peb, leb;

    if( (!descPtr) || (descPtr->magic != desc) )
    {
        return LE_BAD_PARAMETER;
    }

    if( descPtr->mtdInfo.nbBlk > PA_FLASH_MAX_LEB )
    {
        return LE_OUT_OF_RANGE;
    }

    // Reset the LEB to PEB array and set number of LEB = PEB
    memset( descPtr->lebToPeb, PA_FLASH_ERASED_VALUE, sizeof(descPtr->lebToPeb) );
    descPtr->mtdInfo.nbLeb = descPtr->mtdInfo.nbBlk;
    descPtr->scanDone = false;

    leb = 0;
    for( peb = 0; peb < descPtr->mtdInfo.nbBlk; peb++ )
    {
        // Register a new LEB on this PEB
        descPtr->lebToPeb[leb] = peb;
        leb++;
    }

    descPtr->scanDone = true;
    // Update the number of leb
    descPtr->mtdInfo.nbLeb = leb;
    LE_INFO("MTD %d: LEB %u PEB %u\n", descPtr->mtdNum, leb, peb );

    if( lebToPebPtr )
    {
        // If resquested by caller, return a pointer to the LEB to PEB array
        *lebToPebPtr = (pa_flash_LebToPeb_t*)&descPtr->lebToPeb[0];
    }

    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Set the current read/write position of the flash to the given block
 *
 * @return
 *      - LE_OK            On success
 *      - LE_BAD_PARAMETER If desc is NULL
 *      - LE_FAULT         On failure
 *      - LE_OUT_OF_RANGE  If the block is outside the partition
 *      - LE_NOT_PERMITTED If the LEB is not linked to a PEB
 *      - LE_IO_ERROR      If a flash IO error occurs
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_flash_SeekAtBlock
(
    pa_flash_Desc_t desc,
    uint32_t blockIndex
)
{
    pa_flash_MtdDesc_t *descPtr = (pa_flash_MtdDesc_t *)desc;
    uint32_t peb = blockIndex;
    int rc;

    if( (!descPtr) || (descPtr->magic != desc) )
    {
        return LE_BAD_PARAMETER;
    }

    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Read data starting the given block. If a Bad block is detected,
 * the error LE_IO_ERROR is returned and operation is aborted.
 * Note that the length should not be greater than eraseSize
 *
 * @return
 *      - LE_OK            On success
 *      - LE_BAD_PARAMETER If desc is NULL or dataPtr is NULL
 *      - LE_FAULT         On failure
 *      - LE_OUT_OF_RANGE  If the block is outside the partition
 *      - LE_NOT_PERMITTED If the LEB is not linked to a PEB
 *      - LE_IO_ERROR      If a flash IO error occurs
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_flash_ReadAtBlock
(
    pa_flash_Desc_t desc,
    uint32_t blockIndex,
    uint8_t *dataPtr,
    size_t dataSize
)
{
    pa_flash_MtdDesc_t *descPtr = (pa_flash_MtdDesc_t *)desc;
    le_result_t res;

    if( (!descPtr) || (descPtr->magic != desc) || (!dataPtr) )
    {
        return LE_BAD_PARAMETER;
    }

    res = pa_flash_SeekAtBlock( desc, blockIndex );
    if( LE_OK == res)
    {
        res = pa_flash_Read( desc, dataPtr, dataSize );
    }

    return res;
}

//--------------------------------------------------------------------------------------------------
/**
 * Read the data starting at current position.
 * Note that the length should not be greater than eraseSize
 *
 * @return
 *      - LE_OK            On success
 *      - LE_BAD_PARAMETER If desc is NULL or dataPtr is NULL
 *      - LE_FAULT         On failure
 *      - LE_OUT_OF_RANGE  If the block is outside the partition
 *      - LE_NOT_PERMITTED If the LEB is not linked to a PEB
 *      - LE_IO_ERROR      If a flash IO error occurs
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_flash_Read
(
    pa_flash_Desc_t desc,
    uint8_t *dataPtr,
    size_t dataSize
)
{
    pa_flash_MtdDesc_t *descPtr = (pa_flash_MtdDesc_t *)desc;
    uint32_t peb;
    le_result_t res;

    if( (!descPtr) || (descPtr->magic != desc) || (!dataPtr) )
    {
        return LE_BAD_PARAMETER;
    }

    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Erase the given block. If LE_IO_ERROR is returned, the block should be assumed as bad
 *
 * @return
 *      - LE_OK            On success
 *      - LE_BAD_PARAMETER If desc is NULL
 *      - LE_FAULT         On failure
 *      - LE_OUT_OF_RANGE  If the block is outside the partition
 *      - LE_NOT_PERMITTED If the LEB is not linked to a PEB
 *      - LE_IO_ERROR      If a flash IO error occurs
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_flash_EraseBlock
(
    pa_flash_Desc_t desc,
    uint32_t blockIndex
)
{
    pa_flash_MtdDesc_t *descPtr = (pa_flash_MtdDesc_t *)desc;

    if( (!descPtr) || (descPtr->magic != desc) )
    {
        return LE_BAD_PARAMETER;
    }

    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Write data starting the given block. If a Bad block is detected,
 * the error LE_IO_ERROR is returned and operation is aborted.
 * Note that the block should be erased before the first write (pa_flash_EraseAtBlock)
 * Note that the length should be a multiple of writeSize and should not be greater than eraseSize
 *
 * @return
 *      - LE_OK            On success
 *      - LE_BAD_PARAMETER If desc is NULL or dataPtr is NULL
 *      - LE_FAULT         On failure
 *      - LE_OUT_OF_RANGE  If the block is outside the partition
 *      - LE_NOT_PERMITTED If the LEB is not linked to a PEB
 *      - LE_IO_ERROR      If a flash IO error occurs
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_flash_WriteAtBlock
(
    pa_flash_Desc_t desc,
    uint32_t blockIndex,
    uint8_t *dataPtr,
    size_t dataSize
)
{
    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Close a flash descriptor
 *
 * @return
 *      - LE_OK            On success
 *      - LE_BAD_PARAMETER If desc is NULL or not a valid flash descriptor
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_flash_Close
(
    pa_flash_Desc_t desc
)
{
    return LE_OK;
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
 * Check if the given block is marked bad. The isBadBlockPtr is set to true if bad, false if good
 *
 * @return
 *      - LE_OK            On success
 *      - LE_BAD_PARAMETER If desc is NULL
 *      - LE_FAULT         On failure
 *      - LE_OUT_OF_RANGE  If the block is outside the partition
 *      - LE_NOT_PERMITTED If the LEB is not linked to a PEB
 *      - LE_IO_ERROR      If a flash IO error occurs
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_flash_CheckBadBlock
(
    pa_flash_Desc_t desc,
    uint32_t blockIndex,
    bool *isBadBlock
)
{
    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Set the current pointer of the flash to the given offset
 *
 * @return
 *      - LE_OK            On success
 *      - LE_BAD_PARAMETER If desc is NULL
 *      - LE_FAULT         On failure
 *      - LE_OUT_OF_RANGE  If the block is outside the partition
 *      - LE_NOT_PERMITTED If the LEB is not linked to a PEB
 *      - LE_IO_ERROR      If a flash IO error occurs
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_flash_SeekAtOffset
(
    pa_flash_Desc_t desc,
    off_t offset
)
{
    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Write the data starting at current position. If the write operation fails, try to erase the
 * block and re do the write. If the erase fails, the error LE_IO_ERROR is returned and operation
 * is aborted.
 * Note that the block should be erased before the first write (pa_flash_EraseAtBlock)
 * Note that the length should be a multiple of writeSize and should not be greater than eraseSize
 *
 * @return
 *      - LE_OK            On success
 *      - LE_BAD_PARAMETER If desc is NULL or dataPtr is NULL
 *      - LE_FAULT         On failure
 *      - LE_OUT_OF_RANGE  If the block is outside the partition
 *      - LE_NOT_PERMITTED If the LEB is not linked to a PEB
 *      - LE_IO_ERROR      If a flash IO error occurs
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_flash_Write
(
    pa_flash_Desc_t desc,
    uint8_t *dataPtr,
    size_t dataSize
)
{
    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * pa_flash_CheckUbiMagic - check if the buffer contains the UBI magic number
 *
 * @return
 *      - LE_OK             On success and found the magic number in buffer
 *      - LE_NOT_FOUND      Cannot find the magic number in buffer
 *      - LE_BAD_PARAMETER  If desc is NULL or is not a valid descriptor
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_flash_CheckUbiMagic
(
    void *data,          ///< [IN] buffer to check
    uint32_t pattern     ///< [IN] the pattern to check
)
{
    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * pa_flash_CalculateDataLength - calculate how much real data is stored in the buffer
 *
 * This function calculates how much "real data" is stored in @data and
 * returns the length @dataSize (align with pages size). Continuous 0xFF bytes at the end
 * of the buffer are not considered as "real data".
 *
 * @return
 *      - LE_OK             On success
 *      - LE_BAD_PARAMETER  If desc is NULL or is not a valid descriptor
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_flash_CalculateDataLength
(
    int pageSize,      ///< [IN] min I/O of the device
    const void *data,  ///< [IN] a buffer with the contents of the physical eraseblock
    uint32_t *dataSize ///< [INOUT] input : the buffer length
                       ///<         output: real data length align with pages size
)
{
    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Scan a partition for the UBI volume ID given. Update the LebToPeb array field with LEB for this
 * volume ID.
 *
 * @return
 *      - LE_OK            On success
 *      - LE_BAD_PARAMETER If desc is NULL or is not a valid descriptor
 *      - LE_FAULT         On failure
 *      - LE_OUT_OF_RANGE  If the UBI volume ID is over its permitted values
 *      - LE_IO_ERROR      If a flash IO error occurs
 *      - LE_FORMAT_ERROR  If the flash is not in UBI format
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_flash_ScanUbi
(
    pa_flash_Desc_t desc,     ///< [IN] Private flash descriptor
    uint32_t        ubiVolId  ///< [IN] UBI volume ID
)
{
    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Read data from an UBI volume starting the given block. If a Bad block is detected,
 * the error LE_IO_ERROR is returned and operation is aborted.
 *
 * @return
 *      - LE_OK            On success
 *      - LE_BAD_PARAMETER If desc is NULL or dataPtr or dataSizePtr is NULL
 *      - LE_FAULT         On failure
 *      - LE_OUT_OF_RANGE  If the block is outside the partition
 *      - LE_NOT_PERMITTED If the LEB is not linked to a PEB
 *      - LE_IO_ERROR      If a flash IO error occurs
 *      - LE_FORMAT_ERROR  If the flash is not in UBI format
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_flash_ReadUbiAtBlock
(
    pa_flash_Desc_t desc,        ///< [IN] Private flash descriptor
    uint32_t        leb,         ///< [IN] LEB to read
    uint8_t*        dataPtr,     ///< [IN] Pointer to data to be read
    size_t*         dataSizePtr  ///< [IN][OUT] Pointer to size to read
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
