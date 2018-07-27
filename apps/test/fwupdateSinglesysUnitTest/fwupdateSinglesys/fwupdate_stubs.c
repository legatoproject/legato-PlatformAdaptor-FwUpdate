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

// //--------------------------------------------------------------------------------------------------
// /**
//  * Program the partitions to become active and update systems
//  *
//  * @return
//  *      - LE_OK             on success
//  *      - LE_UNSUPPORTED    the feature is not supported
//  *      - LE_FAULT          on failure
//  */
// //--------------------------------------------------------------------------------------------------
// le_result_t pa_fwupdate_SetActiveSystem
// (
//     pa_fwupdate_System_t systemArray[PA_FWUPDATE_SUBSYSID_MAX],
//                          ///< [IN] System array for "modem/lk/linux" partition groups
//     bool isSyncReq       ///< [IN] Indicate if a synchronization is requested after the swap
// )
// {
//     return LE_OK;
// }

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
le_result_t pa_flash_ScanUbiAtOffset
(
    pa_flash_Desc_t desc,     ///< [IN] Private flash descriptor
    off_t           offset,   ///< [IN]  Base offset for the UBI
    uint32_t        ubiVolId  ///< [IN] UBI volume ID
)
{
    return LE_FORMAT_ERROR;
}

//--------------------------------------------------------------------------------------------------
/**
 * Create UBI partition
 *
 * @return
 *      - LE_OK            On success
 *      - LE_BAD_PARAMETER If desc is NULL or is not a valid descriptor
 *      - LE_BUSY          If desc refers to an UBI volume or an UBI partition
 *      - LE_IO_ERROR      If a flash IO error occurs
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_flash_CreateUbiAtOffset
(
    pa_flash_Desc_t desc,           ///< [IN] Private flash descriptor
    off_t           offset,         ///< [IN] Base offset for the UBI
    bool            isForcedCreate  ///< [IN] If set to true the UBI partition is overwriten and the
                                    ///<      previous content is lost
)
{
    return LE_FAULT;
}

//--------------------------------------------------------------------------------------------------
/**
 * Write data to an UBI volume starting the given block. If a Bad block is detected,
 * the error LE_IO_ERROR is returned and operation is aborted.
 * Note that the length should be a multiple of writeSize
 *
 * @return
 *      - LE_OK            On success
 *      - LE_BAD_PARAMETER If desc is NULL or dataPtr is NULL
 *      - LE_FAULT         On failure
 *      - LE_OUT_OF_RANGE  If the block is outside the partition or no block free to extend
 *      - LE_NOT_PERMITTED If the LEB is not linked to a PEB
 *      - LE_IO_ERROR      If a flash IO error occurs
 *      - LE_FORMAT_ERROR  If the flash is not in UBI format
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_flash_WriteUbiAtBlock
(
    pa_flash_Desc_t desc,     ///< [IN] Private flash descriptor
    uint32_t leb,             ///< [IN] LEB to write
    uint8_t *dataPtr,         ///< [IN] Pointer to data to be written
    size_t dataSize,          ///< [IN] Size to be written
    bool isExtendUbiVolume    ///< [IN] True if the volume may be extended by one block if write
                              ///<      is the leb is outside the current volume
)
{
    return LE_FAULT;
}

//--------------------------------------------------------------------------------------------------
/**
 * Get the current logical or physical block and position and the absolute offset in the flash
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
le_result_t pa_flash_Tell
(
    pa_flash_Desc_t desc,     ///< [IN] Private flash descriptor
    uint32_t* blockIndexPtr,  ///< [OUT] Current Physical or Logical block
    off_t* offsetPtr,         ///< [OUT] Current Physical or Logical offset
    off_t* absOffsetPtr       ///< [OUT] Current absolute offset
)
{
    return LE_FAULT;
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
le_result_t pa_flash_SeekAtAbsOffset
(
    pa_flash_Desc_t desc,
    off_t offset
)
{
    return LE_FAULT;
}

//--------------------------------------------------------------------------------------------------
/**
 * Get UBI offset
 *
 * @return
 *      - LE_OK            On success
 *      - LE_BAD_PARAMETER If desc is NULL or is not a valid descriptor
 *      - LE_FORMAT_ERROR  If the flash is not in UBI format
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_flash_GetUbiOffset
(
    pa_flash_Desc_t desc,         ///< [IN] Private flash descriptor
    off_t*          ubiOffsetPtr  ///< [OUT] Offset where the UBI starts
)
{
    return LE_FAULT;
}

//--------------------------------------------------------------------------------------------------
/**
 * Get UBI volume type and name
 *
 * @return
 *      - LE_OK            On success
 *      - LE_BAD_PARAMETER If desc is NULL or is not a valid descriptor
 *      - LE_FORMAT_ERROR  If the flash is not in UBI format
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_flash_GetUbiTypeAndName
(
    pa_flash_Desc_t desc,         ///< [IN] Private flash descriptor
    uint32_t*       volTypePtr,   ///< [OUT] Type of the volume
    char            volName[PA_FLASH_UBI_MAX_VOLUMES]
                                  ///< [OUT] Name of the volume
)
{
    return LE_FAULT;
}

//--------------------------------------------------------------------------------------------------
/**
 * Get UBI volume information
 *
 * @return
 *      - LE_OK            On success
 *      - LE_BAD_PARAMETER If desc is NULL or is not a valid descriptor
 *      - LE_FORMAT_ERROR  If the flash is not in UBI format
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_flash_GetUbiInfo
(
    pa_flash_Desc_t desc,         ///< [IN] Private flash descriptor
    uint32_t*       freeBlockPtr, ///< [OUT] Free blocks number in the UBI partition
    uint32_t*       volBlockPtr,  ///< [OUT] Allocated blocks number belonging to the volume
    uint32_t*       volSizePtr    ///< [OUT] Real volume size
)
{
    return LE_FAULT;
}

//--------------------------------------------------------------------------------------------------
/**
 * Clear the scanned list of LEB and set all to PEB
 * After called, the functions "work" with PEB
 *
 * @return
 *      - LE_OK            On success
 *      - LE_BAD_PARAMETER If desc is NULL
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_flash_Unscan
(
    pa_flash_Desc_t desc      ///< [IN] Private flash descriptor
)
{
    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Adjust (reduce) the UBI volume size to the given size.
 *
 * @return
 *      - LE_OK            On success
 *      - LE_BAD_PARAMETER If desc is NULL or is not a valid descriptor
 *      - LE_FAULT         On failure
 *      - LE_IO_ERROR      If a flash IO error occurs
 *      - LE_FORMAT_ERROR  If the flash is not in UBI format
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_flash_AdjustUbiSize
(
    pa_flash_Desc_t desc,     ///< [IN] Private flash descriptor
    size_t newSize            ///< [IN] Final size of the UBI volume
)
{
    return LE_FAULT;
}

//--------------------------------------------------------------------------------------------------
/**
 * Create UBI volume
 *
 * @return
 *      - LE_OK            On success
 *      - LE_BAD_PARAMETER If desc is NULL or is not a valid descriptor
 *      - LE_FORMAT_ERROR  If the flash is not in UBI format
 *      - LE_DUPLICATE     If the volume name or volume ID already exists
 *      - LE_IO_ERROR      If a flash IO error occurs
 *      - LE_NO_MEMORY     If a volume requires more PEBs than the partition size
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_flash_CreateUbiVolume
(
    pa_flash_Desc_t desc,      ///< [IN] Private flash descriptor
    uint32_t ubiVolId,         ///< [IN] UBI volume ID
    const char* ubiVolNamePtr, ///< [IN] UBI volume name
    uint32_t ubiVolType,       ///< [IN] UBI volume type: dynamic or static
    uint32_t ubiVolSize        ///< [IN] UBI volume size (for dynamic volumes only)
)
{
    return LE_FAULT;
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
