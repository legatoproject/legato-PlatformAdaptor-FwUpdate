/**
 * @file pa_flash_mtd.c
 *
 * Implementation of low level flash access
 *
 * Copyright (C) Sierra Wireless Inc.
 *
 */

#include "legato.h"
#include "pa_flash.h"
#include "pa_flash_local.h"
#include "interfaces.h"
#include <mtd/mtd-user.h>

//--------------------------------------------------------------------------------------------------
/**
 * Generic path and name to MTD information entries: /sys/class/mtd/...
 */
//--------------------------------------------------------------------------------------------------
#define PA_FLASH_SYS_CLASS_MTD "/sys/class/mtd/mtd%d/"

//--------------------------------------------------------------------------------------------------
/**
 * Length for building MTD informations entries name
 * "/sys/class/mtd/mtd" "NNN" "/" "...." "\0"
 */
//--------------------------------------------------------------------------------------------------
#define PA_FLASH_SYS_CLASS_MTD_LENGTH (19 + 3 + 1 + 12 + 1)

//--------------------------------------------------------------------------------------------------
/**
 * Generic name for the MTD devices
 */
//--------------------------------------------------------------------------------------------------
#define PA_FLASH_DEVICE        "/dev/mtd%d"

//--------------------------------------------------------------------------------------------------
/**
 * Length for building MTD devices name
 * "/dev" "/mtd" "NNN" "\0"
 */
//--------------------------------------------------------------------------------------------------
#define PA_FLASH_DEVICE_LENGTH (4 + 4 + 3 + 1)

//--------------------------------------------------------------------------------------------------
/**
 * Pool for flash MTD descriptors. It is created by the first call to pa_flash_Open
 */
//--------------------------------------------------------------------------------------------------
static le_mem_PoolRef_t FlashMtdDescPool = NULL;

//--------------------------------------------------------------------------------------------------
/**
 * Get the valid offset and PEB (Physical Erase Block) of inside the current flash
 * device. Skip the bad block and seek to the next good block. This is done only if
 * the current offset is on an erase block frontier.
 *
 * @return
 *      - LE_OK            On success
 *      - LE_BAD_PARAMETER If one of descPtr, offsetPtr or pebPtr is NULL
 *      - LE_FAULT         If other errors
 *      - LE_OUT_OF_RANGE  If no good block is available
 *      - LE_IO_ERROR      If IO error occurs on flash device
 */
//--------------------------------------------------------------------------------------------------
static le_result_t GetBlock
(
    pa_flash_MtdDesc_t *descPtr, ///< [IN] MTD device descriptor
    off_t *offsetPtr,            ///< [OUT] valid offset inside the flash partition
    uint32_t *pebPtr             ///< [OUT] valid physical erase block
)
{
    off_t pOffset;
    uint32_t peb;
    int rc;

    if( (!descPtr) || (!offsetPtr) || (!pebPtr) )
    {
        return LE_BAD_PARAMETER;
    }

    pOffset = lseek(descPtr->fd, 0, SEEK_CUR);
    if( -1 == pOffset )
    {
        LE_ERROR("MTD %d: lseek fails for retrieve offset: %m\n",
                 descPtr->mtdNum);
        return (EIO == errno) ? LE_IO_ERROR : LE_FAULT;
    }
    pOffset -= (off_t)descPtr->mtdInfo.startOffset;
    peb = (uint32_t)pOffset / descPtr->mtdInfo.eraseSize;

    if( !((uint32_t)pOffset & (descPtr->mtdInfo.eraseSize - 1)) )
    {
        while( peb < descPtr->mtdInfo.nbBlk )
        {
            loff_t blkOff = (((loff_t)peb) * descPtr->mtdInfo.eraseSize)
                                + descPtr->mtdInfo.startOffset;

            rc = ioctl(descPtr->fd, MEMGETBADBLOCK, &blkOff);
            if( -1 == rc )
            {
                LE_ERROR("MTD %d: MEMGETBADBLOCK fails for peb %u offset %"PRIx64": %m",
                         descPtr->mtdNum, peb, (uint64_t)blkOff);
                return (EIO == errno) ? LE_IO_ERROR : LE_FAULT;
            }
            if( rc )
            {
                LE_WARN("MTD %d: Skipping bad block: %u\n", descPtr->mtdNum, peb );
                peb++;
            }
            else
            {
                break;
            }
        }
        if( peb == descPtr->mtdInfo.nbBlk )
        {
            LE_CRIT("MTD %d: No more good block !", descPtr->mtdNum);
            return LE_OUT_OF_RANGE;
        }
        pOffset = ((off_t)peb * descPtr->mtdInfo.eraseSize)
                      + descPtr->mtdInfo.startOffset;
        rc = lseek(descPtr->fd, pOffset, SEEK_SET);
        if( -1 == rc )
        {
            LE_ERROR("MTD %d: lseek fails for peb %u offset %lx: %m\n",
                     descPtr->mtdNum, peb, pOffset);
            return (EIO == errno) ? LE_IO_ERROR : LE_FAULT;
        }
    }

    *pebPtr = peb;
    *offsetPtr = pOffset;
    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Get flash information
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
    pa_flash_Info_t *infoPtr,
    bool isLogical,
    bool isDual
)
{
    FILE *mtdFdPtr;
    char mtd[PA_FLASH_SYS_CLASS_MTD_LENGTH];
    char *crPtr;

    if( !infoPtr )
    {
        return LE_BAD_PARAMETER;
    }

    memset( infoPtr, 0, sizeof(pa_flash_Info_t) );

    // If MTD number is valid, try to read the partition size
    snprintf( mtd, sizeof(mtd), PA_FLASH_SYS_CLASS_MTD "size", mtdNum );
    mtdFdPtr = fopen( mtd, "r" );
    if( NULL == mtdFdPtr )
    {
        LE_ERROR( "Unable to read page size for mtd %d: %m\n", mtdNum );
        return LE_UNSUPPORTED;
    }
    fscanf( mtdFdPtr, "%u", &(infoPtr->size) );
    fclose( mtdFdPtr );

    // If MTD number is valid, try to read the partition write size
    snprintf( mtd, sizeof(mtd), PA_FLASH_SYS_CLASS_MTD "writesize", mtdNum );
    mtdFdPtr = fopen( mtd, "r" );
    if( NULL == mtdFdPtr )
    {
        LE_ERROR( "Unable to read write size for mtd %d: %m\n", mtdNum );
        return LE_UNSUPPORTED;
    }
    fscanf( mtdFdPtr, "%u", &(infoPtr->writeSize) );
    fclose( mtdFdPtr );

    // If MTD number is valid, try to read the partition erase size
    snprintf( mtd, sizeof(mtd), PA_FLASH_SYS_CLASS_MTD "erasesize", mtdNum );
    mtdFdPtr = fopen( mtd, "r" );
    if( NULL == mtdFdPtr )
    {
        LE_ERROR( "Unable to read erase size for mtd %d: %m\n", mtdNum );
        return LE_UNSUPPORTED;
    }
    fscanf( mtdFdPtr, "%u", &(infoPtr->eraseSize) );
    fclose( mtdFdPtr );

    // If MTD number is valid, try to read the partition name
    snprintf( mtd, sizeof(mtd), PA_FLASH_SYS_CLASS_MTD "name", mtdNum );
    mtdFdPtr = fopen( mtd, "r" );
    if( NULL == mtdFdPtr )
    {
        LE_ERROR( "Unable to read partition name for mtd %d: %m\n", mtdNum );
        return LE_UNSUPPORTED;
    }
    fgets( infoPtr->name, PA_FLASH_MAX_INFO_NAME, mtdFdPtr );
    fclose( mtdFdPtr );
    crPtr = strchr( infoPtr->name, '\n' );
    if( crPtr )
    {
        *crPtr = '\0';
    }

    if( isLogical )
    {
        infoPtr->size /= 2;
    }

    infoPtr->nbBlk = infoPtr->size / infoPtr->eraseSize;
    infoPtr->nbLeb = infoPtr->nbBlk;
    infoPtr->startOffset = (isLogical && isDual) ? infoPtr->size : 0;

    LE_INFO("MTD %d \"%s\": size %x (nbBlk %u), writeSize %x, eraseSize %x\n",
            mtdNum,
            infoPtr->name,
            infoPtr->size,
            infoPtr->nbBlk,
            infoPtr->writeSize,
            infoPtr->eraseSize);
    if( isLogical )
    {
        LE_INFO("MTD %d: Logical %d Dual %d startOffset %x\n",
                mtdNum, isLogical, isDual, infoPtr->startOffset);
    }

    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Retrieve flash information of opening a flash device
 *
 * @return
 *      - LE_OK            On success
 *      - LE_BAD_PARAMETER If desc is NULL or not a valid flash descriptor or infoPtr is NULL
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_flash_RetrieveInfo
(
    pa_flash_Desc_t desc,     ///< [IN] Private flash descriptor
    pa_flash_Info_t **infoPtr ///< [IN] Pointer to copy the flash information
)
{
    pa_flash_MtdDesc_t *descPtr = (pa_flash_MtdDesc_t *)desc;

    if( (!descPtr) || (descPtr->magic != desc) || (!infoPtr) )
    {
        return LE_BAD_PARAMETER;
    }

    *infoPtr = &(descPtr->mtdInfo);
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
    pa_flash_MtdDesc_t *descPtr = (pa_flash_MtdDesc_t *)desc;
    struct mtd_ecc_stats eccStats;
    int ret;

    if( (!descPtr) || (descPtr->magic != desc) || (!eccStatsPtr) )
    {
        return LE_BAD_PARAMETER;
    }

    ret = ioctl(descPtr->fd, ECCGETSTATS, &eccStats);
    if( -1 == ret )
    {
        LE_ERROR("MTD %d: ECCGETSTATS fails: %m", descPtr->mtdNum);
        return LE_FAULT;
    }
    eccStatsPtr->corrected = eccStats.corrected;
    eccStatsPtr->failed = eccStats.failed;
    eccStatsPtr->badBlocks = eccStats.badblocks;

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
    pa_flash_Desc_t *descPtr,
    pa_flash_Info_t **infoPtr
)
{
    char mtd[PA_FLASH_DEVICE_LENGTH];
    pa_flash_MtdDesc_t *mtdDescPtr;
    int omode, fd;
    le_result_t rc;
    bool isLogical = (mode & PA_FLASH_OPENMODE_LOGICAL) ? true : false;
    bool isDual = ((mode & PA_FLASH_OPENMODE_LOGICAL_DUAL) != PA_FLASH_OPENMODE_LOGICAL);
    bool isUbi = (mode & PA_FLASH_OPENMODE_UBI) ? true : false;
    bool markBad = (mode & PA_FLASH_OPENMODE_MARKBAD) ? true : false;

    if( !descPtr )
    {
        return LE_BAD_PARAMETER;
    }

    switch( mode & (PA_FLASH_OPENMODE_READONLY |
                    PA_FLASH_OPENMODE_WRITEONLY |
                    PA_FLASH_OPENMODE_READWRITE) )
    {
        case PA_FLASH_OPENMODE_READONLY:
             omode = O_RDONLY;
             break;

        case PA_FLASH_OPENMODE_WRITEONLY:
             omode = O_WRONLY;
             break;

        case PA_FLASH_OPENMODE_READWRITE:
             omode = O_RDWR;
             break;

        default:
             return LE_BAD_PARAMETER;
    }

    // Open the flash MTD device
    snprintf( mtd, sizeof(mtd), PA_FLASH_DEVICE, mtdNum );
    fd = open( mtd, omode );
    if( 0 > fd )
    {
        LE_ERROR("Open of MTD %d fails: %m\n", mtdNum);
        return LE_UNSUPPORTED;
    }
    if( NULL == FlashMtdDescPool )
    {
        // Allocate the pool for MTD descriptors
        FlashMtdDescPool = le_mem_CreatePool("FlashMtdDescPool",
                                               sizeof(pa_flash_MtdDesc_t));
        le_mem_ExpandPool(FlashMtdDescPool, 2);
    }
    // Allocate and fill the MTD descriptor
    mtdDescPtr = (pa_flash_MtdDesc_t*)le_mem_ForceAlloc(FlashMtdDescPool);
    memset(mtdDescPtr, 0, sizeof(pa_flash_MtdDesc_t));
    mtdDescPtr->fd = fd;
    mtdDescPtr->mtdNum = mtdNum;
    mtdDescPtr->scanDone = false;
    mtdDescPtr->markBad = markBad;
    rc = pa_flash_GetInfo( mtdNum, &(mtdDescPtr->mtdInfo), isLogical, isDual );
    if( LE_OK != rc )
    {
        close(mtdDescPtr->fd);
        le_mem_Release(mtdDescPtr);
        return rc;
    }

    mtdDescPtr->mtdInfo.ubi = isUbi;
    mtdDescPtr->ubiVolumeId = (uint32_t)-1;
    // Clear the LEB to PEB array
    memset( &(mtdDescPtr->lebToPeb), -1, sizeof(mtdDescPtr->lebToPeb));

    if( infoPtr )
    {
        *infoPtr = &(mtdDescPtr->mtdInfo);
    }

    // Validate the MTD descriptor
    mtdDescPtr->magic = (pa_flash_Desc_t)mtdDescPtr;
    *descPtr = (pa_flash_Desc_t)mtdDescPtr;

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
    pa_flash_MtdDesc_t *descPtr = (pa_flash_MtdDesc_t *)desc;

    if( (!descPtr) || (descPtr->magic != desc) )
    {
        return LE_BAD_PARAMETER;
    }
    // Close and release the MTD descriptor
    descPtr->magic = NULL;
    close(descPtr->fd);
    le_mem_Release(descPtr);

    return LE_OK;
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
    loff_t blkOff;
    int rc;

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
        blkOff = (peb * descPtr->mtdInfo.eraseSize)
                     + descPtr->mtdInfo.startOffset;

        // For all PEB belonging to the flash partition, check if bad and
        // register it as LEB if good, skip it if bad
        rc = ioctl(descPtr->fd, MEMGETBADBLOCK, &blkOff);
        if( -1 == rc )
        {
            LE_ERROR("MTD %d: MEMGETBADBLOCK fails for block %u, offset %"PRIx64": %m",
                     descPtr->mtdNum, peb, (uint64_t)blkOff);
            memset( descPtr->lebToPeb, PA_FLASH_ERASED_VALUE, sizeof(descPtr->lebToPeb) );
            return (EIO == errno) ? LE_IO_ERROR : LE_FAULT;
        }
        if( 0 == rc )
        {
            // Register a new LEB on this PEB
            descPtr->lebToPeb[leb] = peb;
            leb++;
        }
        else
        {
            LE_WARN("MTD %d: Skipping bad block: %u\n", descPtr->mtdNum, peb );
        }
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
    pa_flash_Desc_t desc
)
{
    pa_flash_MtdDesc_t *descPtr = (pa_flash_MtdDesc_t *)desc;

    if( (!descPtr) || (descPtr->magic != desc) )
    {
        return LE_BAD_PARAMETER;
    }

    if( descPtr->scanDone )
    {
        // Reset the LEB to PEB array and set number of LEB = PEB
        memset( descPtr->lebToPeb, PA_FLASH_ERASED_VALUE, sizeof(descPtr->lebToPeb) );
        descPtr->mtdInfo.nbLeb = descPtr->mtdInfo.nbBlk;
        // Back to PEB access
        descPtr->scanDone = false;
    }
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
    pa_flash_MtdDesc_t *descPtr = (pa_flash_MtdDesc_t *)desc;
    loff_t blkOff;
    uint32_t peb = blockIndex;
    int rc;

    if( (!descPtr) || (descPtr->magic != desc) || (!isBadBlock) )
    {
        return LE_BAD_PARAMETER;
    }

    if( blockIndex >= descPtr->mtdInfo.nbLeb )
    {
        return LE_OUT_OF_RANGE;
    }

    if( descPtr->scanDone )
    {
        // LEB access, fetch the PEB linked to the LEB
        peb = descPtr->lebToPeb[blockIndex];
        if(-1 == peb )
        {
            return LE_NOT_PERMITTED;
        }
    }

    // Compute the block offset of the PEB and add the startOffset of the
    // logical partition
    blkOff = (peb * descPtr->mtdInfo.eraseSize) + descPtr->mtdInfo.startOffset;
    rc = ioctl(descPtr->fd, MEMGETBADBLOCK, &blkOff);
    if( -1 == rc )
    {
        LE_ERROR("MTD %d: MEMGETBADBLOCK fails for block %u (peb %u), offset %"PRIx64": %m",
                 descPtr->mtdNum, blockIndex, peb, (uint64_t)blkOff);
        return (EIO == errno) ? LE_IO_ERROR : LE_FAULT;
    }
    // Update the isBadBlock parameter: 0 = false : good block, 1 = true : bad block
    *isBadBlock = (rc ? true : false);

    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Mark the given block to bad
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
le_result_t pa_flash_MarkBadBlock
(
    pa_flash_Desc_t desc,
    uint32_t blockIndex
)
{
    pa_flash_MtdDesc_t *descPtr = (pa_flash_MtdDesc_t *)desc;
    loff_t blkOff;
    uint32_t peb = blockIndex;

    if( (!descPtr) || (descPtr->magic != desc) )
    {
        return LE_BAD_PARAMETER;
    }

    if( blockIndex >= descPtr->mtdInfo.nbLeb )
    {
        return LE_OUT_OF_RANGE;
    }

    if( descPtr->scanDone )
    {
        if (blockIndex >= PA_FLASH_MAX_LEB)
        {
            return LE_OUT_OF_RANGE;
        }
        // LEB access, fetch the PEB linked to the LEB
        peb = descPtr->lebToPeb[blockIndex];
        if( -1 == peb )
        {
            return LE_NOT_PERMITTED;
        }
    }

    // Compute the block offset of the PEB and add the startOffset of the
    // logical partition
    blkOff = (peb * descPtr->mtdInfo.eraseSize) + descPtr->mtdInfo.startOffset;
    if( -1 == ioctl(descPtr->fd, MEMSETBADBLOCK, &blkOff) )
    {
        LE_ERROR("MTD %d: MEMSETBADBLOCK fails for block %u (peb %u), offset %"PRIx64": %m",
                 descPtr->mtdNum, blockIndex, peb, (uint64_t)blkOff);
        return (EIO == errno) ? LE_IO_ERROR : LE_FAULT;
    }
    LE_INFO("MTD %d: Marked bad block %u (peb %u)\n", descPtr->mtdNum, blockIndex, peb);

    return ( descPtr->scanDone ) ? pa_flash_Scan( desc, NULL ) : LE_OK;
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
    struct erase_info_user eraseMe;
    pa_flash_MtdDesc_t *descPtr = (pa_flash_MtdDesc_t *)desc;
    uint32_t peb, leb = blockIndex;
    le_result_t res;
    int rc;
    bool retry;

    if( (!descPtr) || (descPtr->magic != desc) )
    {
        return LE_BAD_PARAMETER;
    }

    if( blockIndex >= descPtr->mtdInfo.nbLeb )
    {
        return LE_OUT_OF_RANGE;
    }

    do
    {
        retry = false;
        peb = leb;
        if( descPtr->scanDone )
        {
            if (leb >= PA_FLASH_MAX_LEB)
            {
                return LE_OUT_OF_RANGE;
            }
            // LEB access, fetch the PEB linked to the LEB
            peb = descPtr->lebToPeb[leb];
            if( -1 == peb )
            {
                return LE_NOT_PERMITTED;
            }
        }

        // Compute the block offset of the PEB and add the startOffset of the
        // logical partition
        eraseMe.start = (peb * descPtr->mtdInfo.eraseSize) + descPtr->mtdInfo.startOffset;
        eraseMe.length = descPtr->mtdInfo.eraseSize;
        rc = ioctl(descPtr->fd, MEMERASE, &eraseMe);
        if( -1 == rc )
        {
            LE_ERROR("MTD %d: MEMERASE fails for block %u offset %x: %m",
                     descPtr->mtdNum, peb, eraseMe.start);
            if( (-1 == rc) && (EIO == errno) && descPtr->markBad )
            {
                // Retrieve the LEB if scanDone, else use directly the PEB
                res = pa_flash_MarkBadBlock( desc, (descPtr->scanDone ? leb : peb) );
                if( LE_OK != res )
                {
                    return res;
                }
                if( descPtr->scanDone )
                {
                    retry = true;
                }
            }
            else
            {
                return (EIO == errno) ? LE_IO_ERROR : LE_FAULT;
            }
        }
        else
        {
            if( -1 == lseek( descPtr->fd, (off_t)eraseMe.start, SEEK_SET ) )
            {
                LE_ERROR("MTD %d: lseek fails at peb %u offset %x: %m",
                         descPtr->mtdNum, peb, eraseMe.start);
                return (EIO == errno) ? LE_IO_ERROR : LE_FAULT;
            }
        }
    }
    while( retry );

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
    pa_flash_MtdDesc_t *descPtr = (pa_flash_MtdDesc_t *)desc;
    uint32_t peb, blockIndex;
    off_t pOffset;
    int rc;

    if( (!descPtr) || (descPtr->magic != desc) )
    {
        return LE_BAD_PARAMETER;
    }

    if( offset > descPtr->mtdInfo.size )
    {
        return LE_OUT_OF_RANGE;
    }

    // Compute the LEB related to the given ofsfet
    blockIndex = (offset / descPtr->mtdInfo.eraseSize );
    peb = blockIndex;
    if( descPtr->scanDone )
    {
        // LEB access, fetch the PEB linked to the LEB
        peb = descPtr->lebToPeb[blockIndex];
        if( -1 == peb )
        {
            return LE_NOT_PERMITTED;
        }
    }

    // Compute the block offset of the PEB and add the startOffset of the
    // logical partition and add the remaining offset, because the given
    // offset may be not aligned to an erase block frontier
    pOffset = (off_t)(peb * descPtr->mtdInfo.eraseSize)
                  + descPtr->mtdInfo.startOffset
                  + ((uint32_t)offset & (descPtr->mtdInfo.eraseSize - 1));
    rc = lseek(descPtr->fd, pOffset, SEEK_SET);
    if( -1 == rc )
    {
        LE_ERROR("MTD %d: lseek fails at peb %u offset %lx: %m",
                 descPtr->mtdNum, peb, pOffset);
        return (EIO == errno) ? LE_IO_ERROR : LE_FAULT;
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
    off_t pOffset;
    int rc;

    if( (!descPtr) || (descPtr->magic != desc) )
    {
        return LE_BAD_PARAMETER;
    }

    if( blockIndex >= descPtr->mtdInfo.nbBlk )
    {
        return LE_OUT_OF_RANGE;
    }

    if( descPtr->scanDone )
    {
        // LEB access, fetch the PEB linked to the LEB
        peb = descPtr->lebToPeb[blockIndex];
        if( -1 == peb )
        {
            return LE_NOT_PERMITTED;
        }
    }

    // Compute the block offset of the PEB and add the startOffset of the
    // logical partition
    pOffset = (off_t)(peb * descPtr->mtdInfo.eraseSize) + descPtr->mtdInfo.startOffset;
    rc = lseek(descPtr->fd, pOffset, SEEK_SET);
    if( -1 == rc )
    {
        LE_ERROR("MTD %d: lseek fails at peb %u offset %lx: %m",
                 descPtr->mtdNum, peb, pOffset);
        return (EIO == errno) ? LE_IO_ERROR : LE_FAULT;
    }
    return LE_OK;
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
    off_t pOffset;
    int rc, rdSize, totalSize;
    le_result_t res;

    if( (!descPtr) || (descPtr->magic != desc) || (!dataPtr) )
    {
        return LE_BAD_PARAMETER;
    }

    if( dataSize > descPtr->mtdInfo.eraseSize )
    {
        return LE_OUT_OF_RANGE;
    }

    totalSize = 0;
    do
    {
        res = GetBlock( descPtr, &pOffset, &peb );
        if( LE_OK != res )
        {
            return res;
        }

        rdSize = descPtr->mtdInfo.eraseSize - (pOffset & (descPtr->mtdInfo.eraseSize - 1));
        if( rdSize > (dataSize - totalSize) )
        {
            rdSize = dataSize - totalSize;
        }

        LE_DEBUG("MTD %d : peb %u pOffset %lx rdSize %d totalSize %d",
                 descPtr->mtdNum, peb, pOffset, rdSize, totalSize);
        do
        {
            rc = read(descPtr->fd, dataPtr + totalSize, rdSize);
            if( (-1 == rc) && (EINTR != errno) )
            {
                LE_ERROR("MTD %d: read fails (%d) for peb %u offset %lx: %m",
                         descPtr->mtdNum, rc, peb, pOffset);
                return (EIO == errno) ? LE_IO_ERROR : LE_FAULT;
            }
        }
        while( rc == -1 );
        totalSize += rc;
    }
    while( totalSize != dataSize );

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
    pa_flash_MtdDesc_t *descPtr = (pa_flash_MtdDesc_t *)desc;
    uint32_t peb;
    off_t pOffset;
    bool tryWrite;
    int rc;
    le_result_t res;

    if( (!descPtr) || (descPtr->magic != desc) || (!dataPtr) )
    {
        return LE_BAD_PARAMETER;
    }

    if( dataSize > descPtr->mtdInfo.eraseSize )
    {
        return LE_OUT_OF_RANGE;
    }

    size_t remain = (dataSize & (descPtr->mtdInfo.writeSize - 1));
    uint8_t padBlock[ descPtr->mtdInfo.writeSize ];
    int32_t nbWrite = dataSize / descPtr->mtdInfo.writeSize;
    if( remain )
    {
        memcpy( padBlock, dataPtr + (dataSize & (~(descPtr->mtdInfo.writeSize - 1))), remain );
        memset( padBlock + remain, 0xFF, descPtr->mtdInfo.writeSize - remain );
        remain = descPtr->mtdInfo.writeSize - remain;
    }

    tryWrite = false;
    do
    {
        res = GetBlock( descPtr, &pOffset, &peb );
        if( LE_OK != res )
        {
            return res;
        }

        do
        {
            while( nbWrite > 0 )
            {
                rc = write(descPtr->fd, dataPtr, descPtr->mtdInfo.writeSize);
                if( (-1 == rc) || (rc != descPtr->mtdInfo.writeSize) )
                {
                    LE_ERROR("MTD %d: write fails (%d) at peb %u offset %lx: %m",
                             descPtr->mtdNum, rc, peb, pOffset);
                    if( (-1 == rc) && (EIO == errno) &&
                        (!((uint32_t)pOffset & (descPtr->mtdInfo.eraseSize - 1))) )
                    {
                        int iLeb, leb = -1;

                        if( descPtr->scanDone )
                        {
                            // Retrieve the LEB from PEB
                            for( iLeb = 0; iLeb < descPtr->mtdInfo.nbLeb; iLeb++ )
                            {
                                if( peb == descPtr->lebToPeb[iLeb] )
                                {
                                    leb = iLeb;
                                    break;
                                }
                            }
                            if( -1 == leb )
                            {
                                LE_CRIT("No LEB found for PEB %u", peb);
                                return LE_IO_ERROR;
                            }
                        }
                        res = pa_flash_EraseBlock( desc, (descPtr->scanDone ? leb : peb) );
                        if( LE_OK != res )
                        {
                            return res;
                        }
                        tryWrite = (false == tryWrite);
                    }
                    else
                    {
                        return (EIO == errno) ? LE_IO_ERROR : LE_FAULT;
                    }
                }
                else
                {
                    dataPtr += descPtr->mtdInfo.writeSize;
                    nbWrite--;
                }
            }
            if( remain )
            {
                dataPtr = padBlock;
                remain = 0;
                nbWrite = 1;
            }
        } while( nbWrite > 0 );
    } while( tryWrite && (peb < descPtr->mtdInfo.nbBlk) );
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

    if( blockIndex >= descPtr->mtdInfo.nbBlk )
    {
        return LE_OUT_OF_RANGE;
    }

    if( dataSize > descPtr->mtdInfo.eraseSize )
    {
        return LE_OUT_OF_RANGE;
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
    pa_flash_MtdDesc_t *descPtr = (pa_flash_MtdDesc_t *)desc;
    le_result_t res;

    if( (!descPtr) || (descPtr->magic != desc) || (!dataPtr) )
    {
        return LE_BAD_PARAMETER;
    }

    if( blockIndex >= descPtr->mtdInfo.nbBlk )
    {
        return LE_OUT_OF_RANGE;
    }

    if( dataSize > descPtr->mtdInfo.eraseSize )
    {
        return LE_OUT_OF_RANGE;
    }

    res = pa_flash_SeekAtBlock( desc, blockIndex );
    if( LE_OK == res)
    {
        res = pa_flash_Write( desc, dataPtr, dataSize );
    }

    return res;
}

