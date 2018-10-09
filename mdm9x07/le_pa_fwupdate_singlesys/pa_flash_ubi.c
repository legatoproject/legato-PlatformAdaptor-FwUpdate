/**
 * @file pa_flash_ubi.c
 *
 * Implementation of UBI low level flash access
 *
 * Copyright (C) Sierra Wireless Inc.
 *
 */

#include <endian.h>
#include "legato.h"
#include "flash-ubi.h"
#include "pa_flash.h"
#include "pa_flash_local.h"

// Need some internal config values from the kernel configuration
// Because there is no entry in /sys or /proc to read these values
#ifdef LEGATO_EMBEDDED
#include <linux/../../src/kernel/include/generated/autoconf.h>
#endif

#define LE_DEBUG2 LE_DEBUG
#define LE_DEBUG3(b) \
            LE_DEBUG("%X %X %X %X %X %X %X %X", \
                    (b)[0], (b)[1], (b)[2], (b)[3], (b)[4], (b)[5], (b)[6], (b)[7]);

//--------------------------------------------------------------------------------------------------
/**
 * Maximum expected bad eraseblock count per 1024 eraseblocks on the whole MTD device.
 * By default, the value is 20.
 */
//--------------------------------------------------------------------------------------------------
#ifdef CONFIG_MTD_UBI_BEB_LIMIT
#define UBI_BEB_LIMIT CONFIG_MTD_UBI_BEB_LIMIT
#else
#define UBI_BEB_LIMIT 20
#endif

//--------------------------------------------------------------------------------------------------
/**
 * Setting the invalidity of the PEB (valid values from 0 to N)
 */
//--------------------------------------------------------------------------------------------------
#define INVALID_UBI_VOLUME   (uint32_t)-1

//--------------------------------------------------------------------------------------------------
/**
 * Setting the invalidity of the PEB (valid values from 0 to N)
 */
//--------------------------------------------------------------------------------------------------
#define INVALID_PEB           (uint32_t)-1

//--------------------------------------------------------------------------------------------------
/**
 * Setting the invalidity of the Erase Counter (valid values from 0 to UBI_MAX_ERASECOUNTER)
 */
//--------------------------------------------------------------------------------------------------
#define INVALID_ERASECOUNTER  (uint64_t)-1

//--------------------------------------------------------------------------------------------------
/**
 * Define the value of erased 32-bits  (all bits to 1)
 */
//--------------------------------------------------------------------------------------------------
#define ERASED_VALUE_32        0xFFFFFFFFU

//--------------------------------------------------------------------------------------------------
/**
 * Do not take size into account
 */
//--------------------------------------------------------------------------------------------------
#define UBI_NO_SIZE            0xFFFFFFFFU

//--------------------------------------------------------------------------------------------------
/**
 * Define the number of write blocks used by headers for a PEB
 */
//--------------------------------------------------------------------------------------------------
#define PEB_HDR_NB_BLOCKS   2

//--------------------------------------------------------------------------------------------------
/**
 * Pool for the blocks required for UBI low level functions
 */
//--------------------------------------------------------------------------------------------------
static le_mem_PoolRef_t UbiBlockPool = NULL;

//--------------------------------------------------------------------------------------------------
/**
 * Update the UBI absolute offset. If given offset is -1, takes the current flash offset.
 * The offset should belong to the current partition and it must remain enough space to keep at
 * least 3 PEBs free (2 PEBS for VTBL and at least 1 PEB of data).
 * Except the special value -1, the offset cannot be negative.
 * The fields UBI absolute offset, base PEB and offset in PEB are updated inside the descPtr
 * structure if the function succeeds.
 *
 * @return
 *     -1 if the offset is not inside a valid range
 */
//--------------------------------------------------------------------------------------------------
static off_t UpdateUbiAbsOffset
(
    pa_flash_MtdDesc_t* descPtr, ///< [IN] File descriptor to the flash device
    off_t offset                 ///< [IN] Base offset for the UBI
)
{
    pa_flash_Info_t *infoPtr = &descPtr->mtdInfo;

    if( -1 == offset )
    {
        offset = lseek(descPtr->fd, 0, SEEK_CUR);
        if( -1 == offset )
        {
            LE_ERROR("MTD%d: lseek fails to get current offset: %m", descPtr->mtdNum);
            return -1;
        }
    }
    if( infoPtr->nbLeb < 4 )
    {
        LE_ERROR("MTD%d: cannot reserve 4 PEBs for UBI at offset %lx", descPtr->mtdNum, offset);
        return -1;
    }

    // Keep at least 4 PEB frees for VTBL (2) and DATA (1). Like offset may overlap accross 2 PEBs,
    // this requires another PEB.
    if( (offset < 0) || (offset > (infoPtr->eraseSize * (infoPtr->nbLeb - 4))) )
    {
        LE_ERROR("MTD%d: offset %lx is over MTD size - 4 PEBs: %u",
                 descPtr->mtdNum, offset, infoPtr->nbLeb);
        return -1;
    }

    // Update the absolute offset, base PEB and offset in PEB
    descPtr->ubiAbsOffset = offset;
    descPtr->ubiOffsetInPeb = (offset & (infoPtr->eraseSize - 1));
    descPtr->ubiBasePeb = (offset / infoPtr->eraseSize);
    LE_DEBUG("MTD%d: UBI absolute offset %lx, base PEB %u, offset in PEB %lx",
             descPtr->mtdNum, descPtr->ubiAbsOffset, descPtr->ubiBasePeb, descPtr->ubiOffsetInPeb);
    return offset;
}

//--------------------------------------------------------------------------------------------------
/**
 * Erase a block with the UBI absolute offset
 */
//--------------------------------------------------------------------------------------------------
static le_result_t FlashEraseBlock
(
    pa_flash_Desc_t desc,       ///< [IN] File descriptor to the flash device
    uint32_t peb                ///< [IN] PEB to erase
)
{
    pa_flash_MtdDesc_t *descPtr = (pa_flash_MtdDesc_t *)desc;

    if( descPtr->ubiAbsOffset )
    {
        // For UBI at ubiAbsOffset, the pa_flash_EraseBlock() is called by FlashWrite(). It needs
        // to read the 2 PEBs, copy the data, erase the 2 PEBs and write them.
        return LE_OK;
    }
    return pa_flash_EraseBlock(desc, peb);
}

//--------------------------------------------------------------------------------------------------
/**
 * Seek to an offset with the UBI absolute offset
 */
//--------------------------------------------------------------------------------------------------
static le_result_t FlashSeekAtOffset
(
    pa_flash_Desc_t desc,       ///< [IN] File descriptor to the flash device
    off_t offset                ///< [IN] Physical offset to seek
)
{
    pa_flash_MtdDesc_t *descPtr = (pa_flash_MtdDesc_t *)desc;

    if( descPtr->ubiAbsOffset )
    {
        LE_DEBUG2("offset %lx -> %lx", offset, offset + descPtr->ubiOffsetInPeb);
        // Offset is assumed to be inside a PEB. Just add the offset in this PEB
        return pa_flash_SeekAtOffset(desc, offset + descPtr->ubiOffsetInPeb);
    }
    return pa_flash_SeekAtOffset(desc, offset);
}

//--------------------------------------------------------------------------------------------------
/**
 * Seek to PEB with the UBI absolute offset
 */
//--------------------------------------------------------------------------------------------------
static le_result_t FlashSeekAtBlock
(
    pa_flash_Desc_t desc,       ///< [IN] File descriptor to the flash device
    uint32_t peb                ///< [IN] PEB to seek
)
{
    pa_flash_MtdDesc_t *descPtr = (pa_flash_MtdDesc_t *)desc;

    if( descPtr->ubiAbsOffset )
    {
        LE_DEBUG2("peb %x-> %lx", peb, peb * descPtr->mtdInfo.eraseSize+ descPtr->ubiOffsetInPeb);
        // This is a PEB. Just add the offset in this PEB
        return pa_flash_SeekAtOffset(desc,
                                     peb * descPtr->mtdInfo.eraseSize + descPtr->ubiOffsetInPeb);
    }
    return pa_flash_SeekAtBlock(desc, peb);
}

//--------------------------------------------------------------------------------------------------
/**
 * Read data with the UBI absolute offset
 */
//--------------------------------------------------------------------------------------------------
static le_result_t FlashRead
(
    pa_flash_Desc_t desc,       ///< [IN] File descriptor to the flash device
    uint8_t* ptr,               ///< [IN] Pointer to data to be read
    size_t size                 ///< [IN] Size of data to read
)
{
    pa_flash_MtdDesc_t *descPtr = (pa_flash_MtdDesc_t *)desc;

    if( descPtr->ubiAbsOffset )
    {
        uint8_t* blockPtr = le_mem_ForceAlloc(UbiBlockPool);
        off_t offset, offInPeb;
        uint32_t peb;
        le_result_t res;
        size_t szLowerPeb = size, szUpperPeb = 0;

        if( size > descPtr->mtdInfo.eraseSize )
        {
            res = LE_OUT_OF_RANGE;
            goto error;
        }

        // Get the current physical offset
        offset = lseek(descPtr->fd, 0, SEEK_CUR);
        peb = offset / descPtr->mtdInfo.eraseSize;
        offInPeb = offset & (descPtr->mtdInfo.eraseSize - 1);

        // The data to read may overlaps on two PEB. So compute the size for the lower PEB
        // and the upper PEB. If the upper PEB size is 0, no upper PEB will be needed.
        // In all cases, a lower PEB is required.
        if( (offInPeb + size) > descPtr->mtdInfo.eraseSize )
        {
            szLowerPeb = descPtr->mtdInfo.eraseSize - offInPeb;
            szUpperPeb = size - szLowerPeb;
        }

        LE_DEBUG2("size %zx offset %lx, peb %x offInPeb %lx szLowerPeb %zx szUpperPeb %zx",
                  size, offset, peb, offInPeb, szLowerPeb, szUpperPeb);
        res = pa_flash_SeekAtBlock(desc, peb);
        LE_DEBUG2("Seek %x", peb);
        if (LE_OK != res)
        {
            goto error;
        }
        res = pa_flash_Read(desc,
                            blockPtr,
                            descPtr->mtdInfo.eraseSize);
        LE_DEBUG2("Read %x", peb);
        if (LE_OK != res)
        {
            goto error;
        }
        LE_DEBUG3(blockPtr);
        memcpy(ptr, blockPtr + offInPeb, szLowerPeb);

        // Do we need an upper PEB ?
        if( szUpperPeb )
        {
            res = pa_flash_SeekAtBlock(desc, peb + 1);
            LE_DEBUG2("Seek %x", peb + 1);
            if (LE_OK != res)
            {
                goto error;
            }
            res = pa_flash_Read(desc,
                                blockPtr,
                                descPtr->mtdInfo.eraseSize);
            LE_DEBUG2("Read %x", peb + 1);
            if (LE_OK != res)
            {
                goto error;
            }
            LE_DEBUG3(blockPtr);
            memcpy(ptr + szLowerPeb, blockPtr, szUpperPeb);
        }

error:
        le_mem_Release(blockPtr);
        return res;
    }
    return pa_flash_Read(desc, ptr, size);
}

//--------------------------------------------------------------------------------------------------
/**
 * Write data with the UBI absolute offset
 */
//--------------------------------------------------------------------------------------------------
static le_result_t FlashWrite
(
    pa_flash_Desc_t desc,       ///< [IN] File descriptor to the flash device
    uint8_t* ptr,               ///< [IN] Pointer to data to be written
    size_t size                 ///< [IN] Size of data to write
)
{
    pa_flash_MtdDesc_t *descPtr = (pa_flash_MtdDesc_t *)desc;

    if( descPtr->ubiAbsOffset )
    {
        uint8_t* blockPtr = le_mem_ForceAlloc(UbiBlockPool);
        off_t offset, offInPeb;
        uint32_t peb;
        le_result_t res;
        size_t szLowerPeb = size, szUpperPeb = 0;

        if( size > descPtr->mtdInfo.eraseSize )
        {
            res = LE_OUT_OF_RANGE;
            goto error;
        }

        // Get the current physical offset
        offset = lseek(descPtr->fd, 0, SEEK_CUR);
        peb = offset / descPtr->mtdInfo.eraseSize;
        offInPeb = offset & (descPtr->mtdInfo.eraseSize - 1);

        // The data to write may overlaps on two PEB. So compute the size for the lower PEB
        // and the upper PEB. If the upper PEB size is 0, no upper PEB will be needed.
        // In all cases, a lower PEB is required.
        if( (offInPeb + size) > descPtr->mtdInfo.eraseSize )
        {
            szLowerPeb = descPtr->mtdInfo.eraseSize - offInPeb;
            szUpperPeb = size - szLowerPeb;
        }

        LE_DEBUG2("size %zx offset %lx, peb %x offInPeb %lx szLowerPeb %zx szUpperPeb %zx",
                  size, offset, peb, offInPeb, szLowerPeb, szUpperPeb);
        res = pa_flash_SeekAtBlock(desc, peb);
        LE_DEBUG2("Seek %x", peb);
        if (LE_OK != res)
        {
            goto error;
        }
        res = pa_flash_Read(desc,
                            blockPtr,
                            descPtr->mtdInfo.eraseSize);
        LE_DEBUG2("Read %x", peb);
        if (LE_OK != res)
        {
            goto error;
        }
        LE_DEBUG3(blockPtr);
        memcpy(blockPtr + offInPeb, ptr, szLowerPeb);
        LE_DEBUG2("Erase %x", peb);
        res = pa_flash_EraseBlock(desc, peb);
        if (LE_OK != res)
        {
            goto error;
        }
        LE_DEBUG2("Seek %x", peb);
        res = pa_flash_SeekAtBlock(desc, peb);
        if (LE_OK != res)
        {
            goto error;
        }
        LE_DEBUG2("Write %x", peb);
        LE_DEBUG3(blockPtr);
        res = pa_flash_Write(desc, blockPtr, descPtr->mtdInfo.eraseSize);
        if (LE_OK != res)
        {
            goto error;
        }

        // Do we need an upper PEB ?
        if( szUpperPeb )
        {
            res = pa_flash_SeekAtBlock(desc, peb + 1);
            LE_DEBUG2("Seek %x", peb + 1);
            if (LE_OK != res)
            {
                goto error;
            }
            res = pa_flash_Read(desc,
                                blockPtr,
                                descPtr->mtdInfo.eraseSize);
            LE_DEBUG2("Read %x", peb + 1);
            if (LE_OK != res)
            {
                goto error;
            }
            LE_DEBUG3(blockPtr);
            memcpy(blockPtr, ptr + szLowerPeb, szUpperPeb);
            LE_DEBUG2("Erase %x", peb + 1);
            res = pa_flash_EraseBlock(desc, peb + 1);
            if (LE_OK != res)
            {
                goto error;
            }
            LE_DEBUG2("Write %x", peb + 1);
            LE_DEBUG3(blockPtr);
            res = pa_flash_WriteAtBlock(desc, peb + 1, blockPtr, descPtr->mtdInfo.eraseSize);
            if (LE_OK != res)
            {
                goto error;
            }
        }
error:
        le_mem_Release(blockPtr);
        return res;
    }
    return pa_flash_Write(desc, ptr, size);
}

//--------------------------------------------------------------------------------------------------
/**
 * Write data at given PEB with the UBI absolute offset
 */
//--------------------------------------------------------------------------------------------------
static le_result_t FlashWriteAtBlock
(
    pa_flash_Desc_t desc,       ///< [IN] File descriptor to the flash device
    uint32_t peb,               ///< [IN] PEB to write
    uint8_t* ptr,               ///< [IN] Pointer to data to be written
    size_t size                 ///< [IN] Size of data to write
)
{
    pa_flash_MtdDesc_t *descPtr = (pa_flash_MtdDesc_t *)desc;

    if( descPtr->ubiAbsOffset )
    {
        le_result_t res;

        // This is a PEB. Just add the offset in this PEB
        res = pa_flash_SeekAtOffset(desc,
                                    peb * descPtr->mtdInfo.eraseSize + descPtr->ubiOffsetInPeb);
        if (LE_OK != res)
        {
            return res;
        }
        LE_DEBUG2("size %zx peb %x offset %lx",
                  size, peb, peb * descPtr->mtdInfo.eraseSize + descPtr->ubiOffsetInPeb);
        return FlashWrite(desc, ptr, size);
    }
    return pa_flash_WriteAtBlock(desc, peb, ptr, size);
}

//--------------------------------------------------------------------------------------------------
/**
 * Update the free size for an ubi volume
 */
//--------------------------------------------------------------------------------------------------
static void UpdateVolFreeSize
(
    pa_flash_Info_t* infoPtr  ///< pointer to flash informations
)
{
    infoPtr->ubiVolFreeSize = infoPtr->ubiPebFreeCount * (infoPtr->eraseSize -
                                                          (PEB_HDR_NB_BLOCKS * infoPtr->writeSize));
}

//--------------------------------------------------------------------------------------------------
/**
 * Create a new EC header
 */
//--------------------------------------------------------------------------------------------------
static void CreateEcHeader
(
    pa_flash_MtdDesc_t* descPtr,          ///< [IN] Private flash descriptor
    struct ubi_ec_hdr* ecHdrPtr           ///< [IN] Pointer to a UBI EC header
)
{
    pa_flash_Info_t* infoPtr = &descPtr->mtdInfo;
    uint32_t crc;

    memset(ecHdrPtr, 0, sizeof(*ecHdrPtr));
    ecHdrPtr->magic = htobe32(UBI_EC_HDR_MAGIC);
    ecHdrPtr->version = UBI_VERSION;
    ecHdrPtr->vid_hdr_offset = htobe32(infoPtr->writeSize);
    ecHdrPtr->data_offset = htobe32(2 * infoPtr->writeSize);
    ecHdrPtr->image_seq = htobe32(UBI_IMAGE_SEQ_BASE);
    crc = le_crc_Crc32( (uint8_t *)ecHdrPtr, UBI_EC_HDR_SIZE_CRC, LE_CRC_START_CRC32 );
    ecHdrPtr->hdr_crc = htobe32(crc);

}

//--------------------------------------------------------------------------------------------------
/**
 * Create a VID header with the volume ID
 */
//--------------------------------------------------------------------------------------------------
static void CreateVidHeader
(
    pa_flash_MtdDesc_t* descPtr,          ///< [IN] Private flash descriptor
    struct ubi_vid_hdr* vidHdrPtr,        ///< [IN] Pointer to a UBI VID header
    uint32_t            leb,              ///< [IN] Logical block number in the volume chain
    uint32_t            reservedPebs      ///< [IN] Number of blocks reserved for the volume
)
{
    uint32_t crc;

    // Create a new VID header with the volume ID
    memset(vidHdrPtr, 0, sizeof(struct ubi_vid_hdr));
    vidHdrPtr->magic = htobe32(UBI_VID_HDR_MAGIC);
    vidHdrPtr->version = UBI_VERSION;
    vidHdrPtr->vol_type = descPtr->vtblPtr->vol_type;
    vidHdrPtr->vol_id = htobe32(descPtr->ubiVolumeId);
    vidHdrPtr->lnum = htobe32(leb);
    if( descPtr->vtblPtr->vol_type == UBI_VID_STATIC )
    {
        vidHdrPtr->used_ebs = htobe32(reservedPebs);
    }
    crc = le_crc_Crc32( (uint8_t *)vidHdrPtr, UBI_VID_HDR_SIZE_CRC, LE_CRC_START_CRC32 );
    vidHdrPtr->hdr_crc = htobe32(crc);
}

//--------------------------------------------------------------------------------------------------
/**
 * Get a new block into the UBI partition with the lowest eraseCount or at least lower that the
 * given eraseCount
 *
 * @return
 *      - LE_OK            On success
 *      - LE_FAULT         On failure
 *      - others           Depending of the flash operations
 */
//--------------------------------------------------------------------------------------------------
static le_result_t GetNewBlock
(
    pa_flash_Desc_t desc,       ///< [IN] File descriptor to the flash device
    uint8_t*        blockPtr,   ///< [IN] Temporary block buffer to use for reading and return
                                ///< [IN] the ec header and vid header
    uint64_t*       ecPtr,      ///< [IN][OUT] Current erase count value and returned value
                                ///< [IN][OUT] if set to -1, this block is blank
    uint32_t*       pebPtr      ///< [OUT] PEB found
)
{
    pa_flash_MtdDesc_t* descPtr = (pa_flash_MtdDesc_t *)desc;
    pa_flash_Info_t* infoPtr = &descPtr->mtdInfo;
    uint64_t ec, pec = INVALID_ERASECOUNTER;
    struct ubi_ec_hdr *ecHdrPtr;
    struct ubi_vid_hdr *vidHdrPtr;
    off_t blkOff;
    int ieb, peb = -1;
    bool isBad;
    uint32_t badBlkCnt = 0;
    int32_t badBlkDiff;
    le_result_t res;

    if( infoPtr->nbLeb <= descPtr->ubiBasePeb )
    {
        return LE_OUT_OF_RANGE;
    }

    for( ieb = descPtr->ubiBasePeb; ieb < infoPtr->nbLeb; ieb++ )
    {
        int lebIndex;

        for( lebIndex = 0; (lebIndex < infoPtr->nbBlk); lebIndex++ )
        {
            if( descPtr->ubiLebToPeb[lebIndex] == ieb )
            {
                lebIndex = INVALID_PEB;
                break;
            }
        }

        if( (INVALID_PEB == lebIndex) ||
            (ieb == descPtr->vtblPeb[0]) ||
            (ieb == descPtr->vtblPeb[1]) )
        {
            // Skip this block because it is already used in the volume block list
            // or is used to store the VTBL
            continue;
        }
        res = pa_flash_CheckBadBlock( desc, ieb, &isBad );
        if (LE_OK != res)
        {
            return res;
        }
        if (isBad)
        {
            LE_WARN("Skipping bad block %d", ieb);
            badBlkCnt++;
            continue;
        }

        blkOff = ieb * infoPtr->eraseSize;
        res = FlashSeekAtOffset( desc, blkOff );
        if (LE_OK != res)
        {
            return res;
        }
        res = FlashRead( desc, blockPtr, (infoPtr->writeSize * 2) );
        if (LE_OK != res)
        {
            return res;
        }
        ecHdrPtr = (struct ubi_ec_hdr *)blockPtr;
        ec = be64toh(ecHdrPtr->ec);
        if( ERASED_VALUE_32 == ecHdrPtr->magic )
        {
            peb = ieb;
            pec = 0;
            break;
        }
        vidHdrPtr = (struct ubi_vid_hdr *)(blockPtr + be32toh(ecHdrPtr->vid_hdr_offset));
        if( ERASED_VALUE_32 != vidHdrPtr->magic )
        {
            continue;
        }
        ec = be64toh(ecHdrPtr->ec);
        if( INVALID_PEB == peb )
        {
            peb = ieb;
            pec = ec;
            LE_INFO("New block at %u: ec %"PRIu64, peb, pec);
        }
        else
        {
            if( ec < pec )
            {
                peb = ieb;
                pec = ec;
                LE_INFO("Register block at %u: ec %"PRIu64, peb, pec);
            }
        }
    }
    if( (INVALID_PEB == peb) )
    {
        LE_CRIT("No block to add one on volume %d", descPtr->ubiVolumeId);
        return LE_OUT_OF_RANGE;
    }
    *pebPtr = peb;
    *ecPtr = pec;
    badBlkDiff = badBlkCnt > descPtr->ubiBadBlkCnt;
    if (badBlkDiff > 0)
    {
        infoPtr->ubiPebFreeCount -= badBlkDiff;
        descPtr->ubiBadBlkCnt = badBlkCnt;
    }
    infoPtr->ubiPebFreeCount--;
    UpdateVolFreeSize(infoPtr);
    LE_INFO("Get block at %u: ec %"PRIu64, peb, pec);
    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Increment the Erase Counter. If a pointer to mean of Erase Count is filled, add the current value
 * to the pointed mean count.
 */
//--------------------------------------------------------------------------------------------------
static void UpdateEraseCounter
(
    pa_flash_MtdDesc_t *descPtr,          ///< [IN] Private flash descriptor
    struct ubi_ec_hdr* ecHdrPtr           ///< [IN] Pointer to a UBI EC header
)
{
    uint64_t ec;
    uint32_t crc;

    if( !descPtr->ubiAbsOffset )
    {
        ec = be64toh(ecHdrPtr->ec) + 1;
        if( ec > UBI_MAX_ERASECOUNTER )
        {
            ec = UBI_MAX_ERASECOUNTER;
            LE_WARN("MTD%d UBI volume ID %u: Max erase counter value reached",
                    descPtr->mtdNum, descPtr->ubiVolumeId);
        }
        ecHdrPtr->ec = htobe64(ec);
        crc = le_crc_Crc32( (uint8_t *)ecHdrPtr, UBI_EC_HDR_SIZE_CRC, LE_CRC_START_CRC32 );
        ecHdrPtr->hdr_crc = htobe32(crc);
    }
}

//--------------------------------------------------------------------------------------------------
/**
 * Update the Volume ID header of all blocks belonging to an UBI volume.
 *
 * @return
 *      - LE_OK            On success
 *      - LE_FAULT         On failure
 *      - LE_OUT_OF_RANGE  If blockIndex is outside the volume
 *      - others           Depending of the flash operations
 */
//--------------------------------------------------------------------------------------------------
static le_result_t UpdateVidBlock
(
    pa_flash_Desc_t desc,              ///< [IN] File descriptor to the flash device
    uint32_t        blockIndex,        ///< [IN] LEB in volume to update
    uint8_t*        blockPtr,          ///< [IN] Temporary block buffer to use for reading
    uint32_t        reservedPebs,      ///< [IN] Number of reserved PEBs to set
    uint32_t        newSize            ///< [IN] Data size for the this LEB
)
{
    pa_flash_MtdDesc_t *descPtr = (pa_flash_MtdDesc_t *)desc;
    struct ubi_ec_hdr *ecHdrPtr;
    struct ubi_vid_hdr *vidHdrPtr;
    off_t blkOff;
    uint32_t crc;
    le_result_t res = LE_OK;

    if( descPtr->vtblPtr->vol_type == UBI_VID_STATIC )
    {
        if (INVALID_PEB == descPtr->ubiLebToPeb[blockIndex])
        {
            return LE_OUT_OF_RANGE;
        }
        blkOff = descPtr->ubiLebToPeb[blockIndex] * descPtr->mtdInfo.eraseSize;
        res = FlashSeekAtOffset( desc, blkOff );
        if (LE_OK != res)
        {
            return res;
        }
        res = FlashRead( desc, blockPtr, descPtr->mtdInfo.eraseSize );
        if (LE_OK != res)
        {
            return res;
        }
        res = FlashEraseBlock( desc, blkOff / descPtr->mtdInfo.eraseSize );
        if (LE_OK != res)
        {
            return res;
        }
        res = FlashSeekAtOffset( desc, blkOff );
        if (LE_OK != res)
        {
             return res;
        }

        ecHdrPtr = (struct ubi_ec_hdr *)blockPtr;
        UpdateEraseCounter( descPtr, ecHdrPtr );
        vidHdrPtr = (struct ubi_vid_hdr *)(blockPtr + be32toh(ecHdrPtr->vid_hdr_offset));
        if ((UBI_NO_SIZE != newSize))
        {
            vidHdrPtr->data_size = htobe32(newSize);
            crc = le_crc_Crc32(blockPtr + be32toh(ecHdrPtr->data_offset),
                               newSize, LE_CRC_START_CRC32);
            vidHdrPtr->data_crc = htobe32(crc);
            LE_DEBUG("Update VID Header at %lx: DSZ %u (newSize %u)",
                     blkOff, be32toh(vidHdrPtr->data_size), newSize);
        }
        vidHdrPtr->used_ebs = htobe32(reservedPebs);
        crc = le_crc_Crc32( (uint8_t *)vidHdrPtr, UBI_VID_HDR_SIZE_CRC, LE_CRC_START_CRC32 );
        vidHdrPtr->hdr_crc = htobe32(crc);
        LE_DEBUG("Update VID Header at %lx: used_ebs %x, hdr_crc %x",
                 blkOff, be32toh(vidHdrPtr->used_ebs), be32toh(vidHdrPtr->hdr_crc));

        LE_DEBUG("Write EC+VID at %lx: size %x", blkOff, descPtr->mtdInfo.eraseSize);
        res = FlashWrite( desc, blockPtr, descPtr->mtdInfo.eraseSize );
    }
    return res;
}

//--------------------------------------------------------------------------------------------------
/**
 * Update the Volume ID header of all blocks belonging to an UBI volume.
 *
 * @return
 *      - LE_OK            On success
 *      - LE_FAULT         On failure
 *      - others           Depending of the flash operations
 */
//--------------------------------------------------------------------------------------------------
static le_result_t UpdateAllVidBlock
(
    pa_flash_Desc_t desc,              ///< [IN] File descriptor to the flash device
    uint8_t*        blockPtr,          ///< [IN] Temporary block buffer to use for reading
    uint32_t        reservedPebs,      ///< [IN] Number of reserved PEBs to set
    uint32_t        newSize            ///< [IN] New size for the whole volume
)
{
    pa_flash_MtdDesc_t *descPtr = (pa_flash_MtdDesc_t *)desc;
    off_t blkOff;
    uint32_t blk;
    uint32_t dataSize = descPtr->mtdInfo.eraseSize - (2 * descPtr->mtdInfo.writeSize);
    le_result_t res;

    if( descPtr->vtblPtr->vol_type == UBI_VID_STATIC )
    {
        for( blk = 0;
             (reservedPebs) && (blk < (reservedPebs - 1)) &&
             (INVALID_PEB != descPtr->ubiLebToPeb[blk]);
             blk++ )
        {
            res = UpdateVidBlock(desc, blk, blockPtr, reservedPebs, UBI_NO_SIZE);
            if (LE_OK != res)
            {
                return res;
            }
        }

        res = UpdateVidBlock(desc, blk, blockPtr, reservedPebs, newSize % dataSize);
        if ((LE_OK != res) && (LE_OUT_OF_RANGE != res))
        {
            return res;
        }
        descPtr->ubiVolumeSize = newSize;
    }
    for( blk = reservedPebs;
         (blk < be32toh(descPtr->vtblPtr->reserved_pebs))
             && (INVALID_PEB != descPtr->ubiLebToPeb[blk]);
         blk++ )
    {
        blkOff = descPtr->ubiLebToPeb[blk] * descPtr->mtdInfo.eraseSize;
        LE_DEBUG("Erasing block and updating EC in %u [peb %u]",
                 blk, descPtr->ubiLebToPeb[blk]);
        res = FlashSeekAtOffset( desc, blkOff );
        if (LE_OK != res)
        {
            return res;
        }
        res = FlashRead( desc, blockPtr, descPtr->mtdInfo.writeSize);
        if (LE_OK != res)
        {
            return res;
        }
        UpdateEraseCounter( descPtr, (struct ubi_ec_hdr *)blockPtr );
        res = FlashEraseBlock( desc, blkOff / descPtr->mtdInfo.eraseSize );
        if (LE_OK != res)
        {
            return res;
        }
        res = FlashSeekAtOffset( desc, blkOff );
        if (LE_OK != res)
        {
            return res;
        }

        res = FlashWrite( desc, blockPtr, descPtr->mtdInfo.writeSize );
        if (LE_OK != res)
        {
            return res;
        }
        descPtr->ubiLebToPeb[blk] = INVALID_PEB;
    }
    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Update the Volume Table of the UBI. This is needed when the number of reserved PEBs for a volume
 * ID change
 *
 * @return
 *      - LE_OK            On success
 *      - LE_FAULT         On failure
 *      - others           Depending of the flash operations
 */
//--------------------------------------------------------------------------------------------------
static le_result_t UpdateVtbl
(
    pa_flash_Desc_t desc,          ///< [IN] File descriptor to the flash device
    uint8_t*        blockPtr,      ///< [IN] Temporary block buffer to use for reading
    uint32_t        reservedPebs   ///< [IN] Number of reserved PEBs to set
)
{
    pa_flash_MtdDesc_t *descPtr = (pa_flash_MtdDesc_t *)desc;
    uint32_t blk;
    uint32_t crc;
    struct ubi_ec_hdr *ecHdrPtr;
    off_t blkOff;
    le_result_t res;

    descPtr->vtblPtr->reserved_pebs = htobe32(reservedPebs);
    for( blk = 0; blk < 2; blk++ )
    {
        struct ubi_vtbl_record *vtblPtr;
        blkOff = descPtr->vtblPeb[blk] * descPtr->mtdInfo.eraseSize;
        LE_DEBUG("Updating reserved_peb in VTBL %u [peb %u]",
                 blk, descPtr->vtblPeb[blk]);
        res = FlashSeekAtOffset( desc, blkOff );
        if (LE_OK != res)
        {
            return res;
        }
        res = FlashRead( desc, blockPtr, descPtr->mtdInfo.eraseSize );
        if (LE_OK != res)
        {
            return res;
        }
        ecHdrPtr = (struct ubi_ec_hdr *)blockPtr;
        UpdateEraseCounter( descPtr, ecHdrPtr );
        vtblPtr = (struct ubi_vtbl_record *)(blockPtr + be32toh(ecHdrPtr->data_offset));
        vtblPtr[descPtr->ubiVolumeId].reserved_pebs = htobe32(reservedPebs);
        crc = le_crc_Crc32( (uint8_t *)&vtblPtr[descPtr->ubiVolumeId],
                            UBI_VTBL_RECORD_SIZE_CRC,
                            LE_CRC_START_CRC32 );
        vtblPtr[descPtr->ubiVolumeId].crc = htobe32(crc);
        res = FlashEraseBlock( desc, blkOff / descPtr->mtdInfo.eraseSize );
        if (LE_OK != res)
        {
            return res;
        }
        res = FlashSeekAtOffset( desc, blkOff );
        if (LE_OK != res)
        {
            return res;
        }
        LE_DEBUG("Write VTBL at %lx: size %x", blkOff, descPtr->mtdInfo.eraseSize);
        res = FlashWrite( desc, blockPtr, descPtr->mtdInfo.eraseSize );
        if (LE_OK != res)
        {
            return res;
        }
    }
    if( descPtr->vtblPtr->vol_type == UBI_VID_DYNAMIC )
    {
        descPtr->ubiVolumeSize = reservedPebs * descPtr->mtdInfo.eraseSize;
    }
    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Read the UBI EC (Erase Count) header at the given block, check for validity and store it into
 * the buffer pointer.
 *
 * @return
 *      - LE_OK            On success
 *      - LE_FAULT         On failure
 *      - LE_FORMAT_ERROR  The block is erased
 *      - LE_UNSUPPORTED   UBI magic not correct, this is not a UBI EC block
 *      - others           Depending of the flash operations
 */
//--------------------------------------------------------------------------------------------------
static le_result_t ReadEcHeader
(
    pa_flash_Desc_t    desc,            ///< [IN] File descriptor to the flash device
    off_t              physEraseBlock,  ///< [IN] Physical erase block (PEB) to read
    struct ubi_ec_hdr* ecHeaderPtr,     ///< [IN] Buffer to store read data
    bool               isNoWarn         ///< [IN] true is no warning are requested
)
{
    le_result_t res;
    uint32_t crc;
    int i;

    res = FlashSeekAtOffset( desc, physEraseBlock );
    if( LE_OK != res )
    {
        return res;
    }
    if (LE_OK != FlashRead( desc, (uint8_t*)ecHeaderPtr, UBI_EC_HDR_SIZE ) )
    {
        return res;
    }

    for( i = 0; (i < UBI_EC_HDR_SIZE) && (((uint8_t*)ecHeaderPtr)[i] == 0xFF); i++ )
    {
    }
    if (UBI_EC_HDR_SIZE == i)
    {
        LE_DEBUG("Block %lx is erased", physEraseBlock );
        return LE_FORMAT_ERROR;
    }

    if ((uint32_t)UBI_EC_HDR_MAGIC != be32toh(ecHeaderPtr->magic))
    {
        if (!isNoWarn)
        {
            LE_ERROR( "Bad magic at %lx: Expected %x, received %x",
                      physEraseBlock, UBI_EC_HDR_MAGIC, be32toh(ecHeaderPtr->magic));
        }
        return LE_UNSUPPORTED;
    }

    if (UBI_VERSION != ecHeaderPtr->version)
    {
        LE_ERROR( "Bad version at %lx: Expected %d, received %d",
                  physEraseBlock, UBI_VERSION, ecHeaderPtr->version);
        return LE_FAULT;
    }

    crc = le_crc_Crc32((uint8_t*)ecHeaderPtr, UBI_EC_HDR_SIZE_CRC, LE_CRC_START_CRC32);
    if (be32toh(ecHeaderPtr->hdr_crc) != crc)
    {
        LE_ERROR( "Bad CRC at %lx: Calculated %x, received %x",
                  physEraseBlock, crc, be32toh(ecHeaderPtr->hdr_crc));
        return LE_FAULT;
    }

    LE_DEBUG("PEB %lx : MAGIC %c%c%c%c, EC %"PRIu64", VID %x DATA %x CRC %x",
             physEraseBlock,
             ((char *)&(ecHeaderPtr->magic))[0],
             ((char *)&(ecHeaderPtr->magic))[1],
             ((char *)&(ecHeaderPtr->magic))[2],
             ((char *)&(ecHeaderPtr->magic))[3],
             be64toh(ecHeaderPtr->ec),
             be32toh(ecHeaderPtr->vid_hdr_offset),
             be32toh(ecHeaderPtr->data_offset),
             be32toh(ecHeaderPtr->hdr_crc));

    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Read the UBI Volume ID header at the given block + offset, check for validity and store it into
 * the buffer pointer.
 *
 * @return
 *      - LE_OK            On success
 *      - LE_FORMAT_ERROR  The block is erased
 *      - LE_FAULT         On failure
 *      - others           Depending of the flash operations
 */
//--------------------------------------------------------------------------------------------------
static le_result_t ReadVidHeader
(
    pa_flash_Desc_t     desc,            ///< [IN] File descriptor to the flash device
    off_t               physEraseBlock,  ///< [IN] Physcal erase block (PEB) to read
    struct ubi_vid_hdr* vidHeaderPtr,    ///< [IN] Pointer to the VID header
    off_t               vidOffset        ///< [IN] Offset of VID header in physical block
)
{
    le_result_t res;
    uint32_t crc;
    int i;

    res = FlashSeekAtOffset( desc, physEraseBlock + vidOffset );
    if( LE_OK != res )
    {
        return res;
    }
    if (LE_OK != FlashRead( desc, (uint8_t*)vidHeaderPtr, UBI_VID_HDR_SIZE ) )
    {
        return res;
    }

    for( i = 0; (i < UBI_VID_HDR_SIZE) && (((uint8_t*)vidHeaderPtr)[i] == 0xFF); i++ )
    {
    }
    if (UBI_VID_HDR_SIZE == i)
    {
        LE_DEBUG("Block %lx is erased", physEraseBlock );
        return LE_FORMAT_ERROR;
    }

    if ((uint32_t)UBI_VID_HDR_MAGIC != be32toh(vidHeaderPtr->magic))
    {
        LE_ERROR( "Bad magic at %lx: Expected %x, received %x",
            physEraseBlock, UBI_VID_HDR_MAGIC, be32toh(vidHeaderPtr->magic));
        return LE_FAULT;
    }

    if (UBI_VERSION != vidHeaderPtr->version)
    {
        LE_ERROR( "Bad version at %lx: Expected %d, received %d",
            physEraseBlock, UBI_VERSION, vidHeaderPtr->version);
        return LE_FAULT;
    }

    crc = LE_CRC_START_CRC32;
    crc = le_crc_Crc32((uint8_t*)vidHeaderPtr, UBI_VID_HDR_SIZE_CRC, crc);
    if (be32toh(vidHeaderPtr->hdr_crc) != crc)
    {
        LE_ERROR( "Bad CRC at %lx: Calculated %x, received %x",
            physEraseBlock, crc, be32toh(vidHeaderPtr->hdr_crc));
        return LE_FAULT;
    }

    if( be32toh(vidHeaderPtr->vol_id) < PA_FLASH_UBI_MAX_VOLUMES )
    {
        LE_DEBUG("PEB : %lx, MAGIC %c%c%c%c, VER %hhd, VT %hhd CP %hhd CT %hhd VID "
                 "%x LNUM %x DSZ %x EBS %x DPD %x DCRC %x CRC %x", physEraseBlock,
                 ((char *)&(vidHeaderPtr->magic))[0],
                 ((char *)&(vidHeaderPtr->magic))[1],
                 ((char *)&(vidHeaderPtr->magic))[2],
                 ((char *)&(vidHeaderPtr->magic))[3],
                 (vidHeaderPtr->version),
                 (vidHeaderPtr->vol_type),
                 (vidHeaderPtr->copy_flag),
                 (vidHeaderPtr->compat),
                 be32toh(vidHeaderPtr->vol_id),
                 be32toh(vidHeaderPtr->lnum),
                 be32toh(vidHeaderPtr->data_size),
                 be32toh(vidHeaderPtr->used_ebs),
                 be32toh(vidHeaderPtr->data_pad),
                 be32toh(vidHeaderPtr->data_crc),
                 be32toh(vidHeaderPtr->hdr_crc));
    }
    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Read the UBI Volume Table at the given block + offset, check for validity and store it into the
 * buffer pointer.
 *
 * @return
 *      - LE_OK            On success
 *      - LE_FAULT         On failure
 *      - others           Depending of the flash operations
 */
//--------------------------------------------------------------------------------------------------
static le_result_t ReadVtbl
(
    pa_flash_Desc_t         desc,            ///< [IN] File descriptor to the flash device
    off_t                   physEraseBlock,  ///< [IN] Physcal erase block (PEB) to read
    struct ubi_vtbl_record* vtblPtr,         ///< [IN] Pointer to the VTBL
    off_t                   vtblOffset       ///< [IN] Offset of VTBL in physical block
)
{
    le_result_t res;
    uint32_t crc;
    int i;

    res = FlashSeekAtOffset( desc, physEraseBlock + vtblOffset );
    if( LE_OK != res )
    {
        return res;
    }
    if (LE_OK != FlashRead( desc, (uint8_t*)vtblPtr,
                            PA_FLASH_UBI_MAX_VOLUMES * UBI_VTBL_RECORD_HDR_SIZE ) )
    {
        return res;
    }

    for( i = 0; i < PA_FLASH_UBI_MAX_VOLUMES; i++ )
    {
        if( (INVALID_PEB) == be32toh(vtblPtr[i].reserved_pebs))
        {
            continue;
        }
        crc = le_crc_Crc32((uint8_t*)&vtblPtr[i], UBI_VTBL_RECORD_SIZE_CRC, LE_CRC_START_CRC32);
        if( be32toh(vtblPtr[i].crc) != crc )
        {
            LE_ERROR("VID %d : Bad CRC %x expected %x", i, crc, be32toh(vtblPtr[i].crc));
            return LE_FAULT;
        }
        if( vtblPtr[i].vol_type )
        {
            LE_DEBUG("VID %d RPEBS %u AL %X RPD %X VT %X UPDM %X NL %X \"%s\" FL %X CRC %X",
                     i,
                     be32toh(vtblPtr[i].reserved_pebs),
                     be32toh(vtblPtr[i].alignment),
                     be32toh(vtblPtr[i].data_pad),
                     vtblPtr[i].vol_type,
                     vtblPtr[i].upd_marker,
                     be16toh(vtblPtr[i].name_len),
                     vtblPtr[i].name,
                     vtblPtr[i].flags,
                     be32toh(vtblPtr[i].crc));
        }
    }
    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Check if the partition is an UBI container and all blocks belonging to this partition are valid.
 *
 * @return
 *      - LE_OK            On success
 *      - LE_BAD_PARAMETER If desc is NULL or is not a valid descriptor
 *      - LE_OUT_OF_RANGE  If UBI abs offset is below the number of LEBs
 *      - LE_FAULT         On failure
 *      - LE_IO_ERROR      If a flash IO error occurs
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_flash_CheckUbiAtOffset
(
    pa_flash_Desc_t desc,    ///< [IN]  Private flash descriptor
    off_t offset,            ///< [IN]  Base offset for the UBI
    bool* isUbiPtr           ///< [OUT] true if the partition is an UBI container, false otherwise
)
{
    pa_flash_MtdDesc_t* descPtr = (pa_flash_MtdDesc_t *)desc;
    uint32_t peb;
    struct ubi_ec_hdr ecHeader;
    off_t pebOffset;
    bool isBad, isUbi = false;
    pa_flash_Info_t* infoPtr;
    le_result_t res;

    if( (!descPtr) || (descPtr->magic != desc) || (!isUbiPtr) )
    {
        return LE_BAD_PARAMETER;
    }

    if( !descPtr->scanDone )
    {
        (void)pa_flash_Scan(desc, NULL);
    }

    infoPtr = &(descPtr->mtdInfo);
    if( infoPtr->nbLeb <= descPtr->ubiBasePeb )
    {
        return LE_OUT_OF_RANGE;
    }

    *isUbiPtr = false;
    for( peb = descPtr->ubiBasePeb; peb < infoPtr->nbLeb; peb++ )
    {
        LE_DEBUG("Check if bad block at peb %u", peb);
        res = pa_flash_CheckBadBlock( descPtr, peb, &isBad );
        if( LE_OK != res )
        {
            goto error;
        }
        if (isBad)
        {
            LE_WARN("Skipping bad block %d", peb);
            continue;
        }

        pebOffset = peb * infoPtr->eraseSize;
        res = ReadEcHeader( descPtr, pebOffset, &ecHeader, true );
        if (LE_FORMAT_ERROR == res)
        {
            if( descPtr->ubiAbsOffset )
            {
                break;
            }
            // If the block is erased, continue the scan
            continue;
        }
        else if (LE_UNSUPPORTED == res)
        {
            // If the block has a bad magic, it does not belong to an UBI
            LE_DEBUG("MTD %d is NOT an UBI container", descPtr->mtdNum);
            // Not an UBI container.
            return LE_OK;
        }
        else if (LE_OK != res)
        {
            goto error;
        }
        isUbi = true;
    }

    *isUbiPtr = isUbi;
    return LE_OK;

error:
    return (LE_IO_ERROR == res ? LE_IO_ERROR : LE_FAULT);
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
    bool* isUbiPtr           ///< [OUT] true if the partition is an UBI container, false otherwise
)
{
    return pa_flash_CheckUbiAtOffset( desc, 0, isUbiPtr );
}

//--------------------------------------------------------------------------------------------------
/**
 * Scan an UBI partition for the volumes number and volumes name
 * volume ID.
 *
 * @return
 *      - LE_OK            On success
 *      - LE_BAD_PARAMETER If desc is NULL or is not a valid descriptor
 *      - LE_FAULT         On failure
 *      - LE_BUSY          If a scan was already run on an UBI volume
 *      - LE_IO_ERROR      If a flash IO error occurs
 *      - LE_FORMAT_ERROR  If the flash is not in UBI format
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_flash_ScanUbiForVolumesAtOffset
(
    pa_flash_Desc_t desc,            ///< [IN]  Private flash descriptor
    off_t           offset,          ///< [IN]  Base offset for the UBI
    uint32_t*       ubiVolNumberPtr, ///< [OUT] UBI volume number found
    char            ubiVolName[PA_FLASH_UBI_MAX_VOLUMES][PA_FLASH_UBI_MAX_VOLUMES]
                                     ///< [OUT] UBI volume name array
)
{
    pa_flash_MtdDesc_t *descPtr = (pa_flash_MtdDesc_t *)desc;
    uint32_t peb;
    struct ubi_ec_hdr ecHeader;
    struct ubi_vid_hdr vidHeader;
    off_t pebOffset;
    bool isBad;
    uint32_t iVtblPeb = 0;
    le_result_t res;
    pa_flash_Info_t *infoPtr = &descPtr->mtdInfo;

    if( (!descPtr) || (descPtr->magic != desc))
    {
        return LE_BAD_PARAMETER;
    }

    if (descPtr->vtblPtr)
    {
        memset(descPtr->ubiLebToPeb, -1, sizeof(descPtr->ubiLebToPeb));
        goto scanDone;
    }

    if( !descPtr->scanDone )
    {
        (void)pa_flash_Scan(desc, NULL);
    }

    if( -1 == UpdateUbiAbsOffset( descPtr, offset ) )
    {
        return LE_OUT_OF_RANGE;
    }

    memset(descPtr->vtbl, 0, sizeof(struct ubi_vtbl_record) * PA_FLASH_UBI_MAX_VOLUMES);
    memset(descPtr->vtblPeb, -1, sizeof(descPtr->vtblPeb));
    memset(descPtr->ubiLebToPeb, -1, sizeof(descPtr->ubiLebToPeb));
    for( peb = descPtr->ubiBasePeb; peb < infoPtr->nbLeb; peb++ )
    {
        LE_DEBUG("Check if bad block at peb %u", peb);
        res = pa_flash_CheckBadBlock( desc, peb, &isBad );
        if( LE_OK != res )
        {
            goto error;
        }
        if (isBad)
        {
            LE_WARN("Skipping bad block %d", peb);
            continue;
        }

        pebOffset = peb * infoPtr->eraseSize;
        res = ReadEcHeader( descPtr, pebOffset, &ecHeader, false );
        if (LE_FORMAT_ERROR == res)
        {
            continue;
        }
        else if (LE_OK != res)
        {
            goto error;
        }
        res = ReadVidHeader( descPtr, pebOffset, &vidHeader, be32toh(ecHeader.vid_hdr_offset) );
        if (LE_FORMAT_ERROR == res)
        {
            continue;
        }
        if (LE_OK != res)
        {
            LE_CRIT("Error when reading VID Header at %d", peb);
            goto error;
        }

        if (UBI_LAYOUT_VOLUME_ID == be32toh(vidHeader.vol_id))
        {
            descPtr->ubiDataOffset = be32toh(ecHeader.data_offset);
            res = ReadVtbl( descPtr, pebOffset, descPtr->vtbl, be32toh(ecHeader.data_offset) );
            if (LE_OK != res)
            {
                LE_CRIT("Error when reading Vtbl at %d", peb);
                goto error;
            }
            if( iVtblPeb < 2 )
            {
                descPtr->vtblPeb[iVtblPeb++] = peb;
            }
        }
        else
        {
            // nothing to do
        }
    }

scanDone:
    if( (INVALID_PEB == descPtr->vtblPeb[0]) ||
        (INVALID_PEB == descPtr->vtblPeb[1]) )
    {
        LE_ERROR("No volume present on MTD %d or NOT an UBI", descPtr->mtdNum);
        res = LE_FORMAT_ERROR;
        goto error;
    }

    if ((ubiVolNumberPtr) && (ubiVolName))
    {
        int i;
        *ubiVolNumberPtr = 0;
        for( i = 0; i < PA_FLASH_UBI_MAX_VOLUMES; i++ )
        {
            if( descPtr->vtbl[i].vol_type )
            {
                LE_DEBUG("VOL %i \"%s\" VT %u RPEBS %u", i,
                         descPtr->vtbl[i].name,
                         descPtr->vtbl[i].vol_type,
                         be32toh(descPtr->vtbl[i].reserved_pebs));
                memcpy(ubiVolName[i], descPtr->vtbl[i].name, PA_FLASH_UBI_MAX_VOLUMES);
                (*ubiVolNumberPtr)++;
            }
        }
        LE_INFO("MTD%d: %u UBI volumes founds", descPtr->mtdNum, *ubiVolNumberPtr);
    }
    return LE_OK;

error:
    descPtr->ubiAbsOffset = 0;
    descPtr->ubiOffsetInPeb = 0;
    descPtr->ubiBasePeb = 0;
    return (LE_IO_ERROR == res || LE_FORMAT_ERROR == res ? res : LE_FAULT);
}

//--------------------------------------------------------------------------------------------------
/**
 * Scan an UBI partition for the volumes number and volumes name
 * volume ID.
 *
 * @return
 *      - LE_OK            On success
 *      - LE_BAD_PARAMETER If desc is NULL or is not a valid descriptor
 *      - LE_FAULT         On failure
 *      - LE_BUSY          If a scan was already run on an UBI volume
 *      - LE_IO_ERROR      If a flash IO error occurs
 *      - LE_FORMAT_ERROR  If the flash is not in UBI format
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_flash_ScanUbiForVolumes
(
    pa_flash_Desc_t desc,            ///< [IN]  Private flash descriptor
    uint32_t*       ubiVolNumberPtr, ///< [OUT] UBI volume number found
    char            ubiVolName[PA_FLASH_UBI_MAX_VOLUMES][PA_FLASH_UBI_MAX_VOLUMES]
                                     ///< [OUT] UBI volume name array
)
{
    return pa_flash_ScanUbiForVolumesAtOffset( desc, 0, ubiVolNumberPtr, ubiVolName );
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
    pa_flash_MtdDesc_t* descPtr = (pa_flash_MtdDesc_t *)desc;
    uint32_t peb;
    struct ubi_ec_hdr ecHeader;
    struct ubi_vid_hdr vidHeader;
    off_t pebOffset;
    bool isBad;
    uint32_t iVtblPeb = 0, ubiVolSize = 0;
    le_result_t res;
    pa_flash_Info_t* infoPtr;

    if( (!descPtr) || (descPtr->magic != desc) || (ubiVolId >= PA_FLASH_UBI_MAX_VOLUMES) )
    {
        return LE_BAD_PARAMETER;
    }

    if( !descPtr->scanDone )
    {
        (void)pa_flash_Scan(desc, NULL);
    }

    infoPtr = &descPtr->mtdInfo;
    descPtr->ubiBadBlkCnt = 0;
    infoPtr->ubi = false;
    infoPtr->ubiPebFreeCount = 0;
    infoPtr->ubiVolFreeSize = 0;
    descPtr->ubiVolumeId = INVALID_UBI_VOLUME;
    descPtr->ubiVolumeSize = UBI_NO_SIZE;
    descPtr->vtblPtr = NULL;
    memset(descPtr->vtbl, 0, sizeof(struct ubi_vtbl_record) * PA_FLASH_UBI_MAX_VOLUMES);
    memset(descPtr->vtblPeb, -1, sizeof(descPtr->vtblPeb));
    memset(descPtr->ubiLebToPeb, -1, sizeof(descPtr->ubiLebToPeb));

    if( -1 == UpdateUbiAbsOffset( descPtr, offset ) )
    {
        return LE_OUT_OF_RANGE;
    }

    for( peb = descPtr->ubiBasePeb; peb < infoPtr->nbLeb; peb++ )
    {
        LE_DEBUG("Check if bad block at peb %u", peb);
        res = pa_flash_CheckBadBlock( desc, peb, &isBad );
        if( LE_OK != res )
        {
            goto error;
        }
        if (isBad)
        {
            descPtr->ubiBadBlkCnt++;
            LE_WARN("Skipping bad block %d", peb);
            continue;
        }

        pebOffset = peb * infoPtr->eraseSize;
        res = ReadEcHeader( descPtr, pebOffset, &ecHeader, false );
        if (LE_FORMAT_ERROR == res)
        {
            infoPtr->ubiPebFreeCount++;
            continue;
        }
        else if (LE_OK != res)
        {
            goto error;
        }
        res = ReadVidHeader( descPtr, pebOffset, &vidHeader, be32toh(ecHeader.vid_hdr_offset) );
        if (LE_FORMAT_ERROR == res)
        {
            infoPtr->ubiPebFreeCount++;
            continue;
        }
        if (LE_OK != res)
        {
            LE_CRIT("Error when reading VID Header at %d", peb);
            goto error;
        }
        if (UBI_LAYOUT_VOLUME_ID == be32toh(vidHeader.vol_id))
        {
            res = ReadVtbl( descPtr, pebOffset, descPtr->vtbl, be32toh(ecHeader.data_offset) );
            if (LE_OK != res)
            {
                LE_CRIT("Error when reading Vtbl at %d", peb);
                goto error;
            }
            if( iVtblPeb < 2 )
            {
                descPtr->vtblPeb[iVtblPeb++] = peb;
            }
            if( (2 == iVtblPeb) &&
                (be16toh(descPtr->vtbl[ubiVolId].name_len)) &&
                ((UBI_VID_STATIC == descPtr->vtbl[ubiVolId].vol_type) ||
                 (UBI_VID_DYNAMIC == descPtr->vtbl[ubiVolId].vol_type)))
            {
                descPtr->vtblPtr = &(descPtr->vtbl[ubiVolId]);
            }
        }
        else if ((be32toh(vidHeader.vol_id) < PA_FLASH_UBI_MAX_VOLUMES) &&
                 (be32toh(vidHeader.vol_id) == ubiVolId))
        {
            descPtr->ubiDataOffset = be32toh(ecHeader.data_offset);
            descPtr->ubiLebToPeb[be32toh(vidHeader.lnum)] = peb;
            if( UBI_VID_STATIC == vidHeader.vol_type )
            {
                ubiVolSize += be32toh(vidHeader.data_size);
            }
            else
            {
                ubiVolSize += (descPtr->mtdInfo.eraseSize - be32toh(ecHeader.data_offset));
            }
        }
        else if (ERASED_VALUE_32 == be32toh(vidHeader.vol_id))
        {
            infoPtr->ubiPebFreeCount++;
        }
        else
        {
            // nothing to do
        }
    }

    UpdateVolFreeSize(infoPtr);
    LE_DEBUG("mtd %d ubiPebFreeCount %d ubiVolFreeSize %zu", descPtr->mtdNum,
             infoPtr->ubiPebFreeCount, infoPtr->ubiVolFreeSize);

    if( (!descPtr->vtblPtr) ||
        (INVALID_PEB == descPtr->vtblPeb[0]) ||
        (INVALID_PEB == descPtr->vtblPeb[1]) )
    {
        LE_ERROR("Volume ID %d not present on MTD %d or NOT an UBI",
                 ubiVolId, descPtr->mtdNum);
        res = LE_FORMAT_ERROR;
        goto error;
    }

    int i, j;
    for( i = 0; i < PA_FLASH_UBI_MAX_VOLUMES; i++ )
    {
        if( descPtr->vtbl[i].vol_type )
        {
            LE_DEBUG("VOL %i \"%s\" VT %u RPEBS %u", i,
                     descPtr->vtbl[i].name,
                     descPtr->vtbl[i].vol_type,
                     be32toh(descPtr->vtbl[i].reserved_pebs));
            for( j = 0;
                 (i == ubiVolId) && (j < be32toh(descPtr->vtbl[i].reserved_pebs));
                 j++ )
            {
                LE_DEBUG("%u ", descPtr->ubiLebToPeb[j]);
            }
        }
    }
    infoPtr->ubi = true;
    descPtr->ubiVolumeId = ubiVolId;
    descPtr->ubiVolumeSize = ubiVolSize;
    LE_INFO("UBI %u, vol size %u", ubiVolId, ubiVolSize);
    return LE_OK;

error:
    descPtr->ubiAbsOffset = 0;
    descPtr->ubiOffsetInPeb = 0;
    descPtr->ubiBasePeb = 0;
    return res;
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
    return pa_flash_ScanUbiAtOffset( desc, 0, ubiVolId );
}

//--------------------------------------------------------------------------------------------------
/**
 * Clear the scanned list of an UBI volume ID and reset all LEB to PEB
 * After called, the functions "work" with PEB
 *
 * @return
 *      - LE_OK            On success
 *      - LE_BAD_PARAMETER If desc is NULL or is not a valid descriptor
 *      - LE_FORMAT_ERROR  If the flash is not in UBI format
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_flash_UnscanUbi
(
    pa_flash_Desc_t desc      ///< [IN] Private flash descriptor
)
{
    pa_flash_MtdDesc_t* descPtr = (pa_flash_MtdDesc_t *)desc;
    pa_flash_Info_t* infoPtr;

    if( (!descPtr) || (descPtr->magic != desc))
    {
        return LE_BAD_PARAMETER;
    }

    infoPtr = &descPtr->mtdInfo;
    infoPtr->ubi = false;
    descPtr->ubiVolumeId = INVALID_UBI_VOLUME;
    descPtr->vtblPtr = NULL;
    memset(descPtr->vtbl, 0, sizeof(struct ubi_vtbl_record) * PA_FLASH_UBI_MAX_VOLUMES);
    memset(descPtr->vtblPeb, -1, sizeof(descPtr->vtblPeb));
    memset(descPtr->ubiLebToPeb, -1, sizeof(descPtr->ubiLebToPeb));
    infoPtr->ubiPebFreeCount = 0;
    infoPtr->ubiVolFreeSize = 0;
    descPtr->ubiAbsOffset = 0;
    descPtr->ubiOffsetInPeb = 0;
    descPtr->ubiBasePeb = 0;
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
    pa_flash_MtdDesc_t* descPtr = (pa_flash_MtdDesc_t *)desc;
    size_t size;
    uint32_t peb, nbLeb, realSize = 0;
    off_t blkOff;
    bool isBad;
    le_result_t res;

    if( (!descPtr) || (descPtr->magic != desc) || (!dataPtr) || (!dataSizePtr) )
    {
        return LE_BAD_PARAMETER;
    }

    if( (!descPtr->mtdInfo.ubi) || (descPtr->ubiVolumeId >= PA_FLASH_UBI_MAX_VOLUMES ) )
    {
        return LE_FORMAT_ERROR;
    }

    size = *dataSizePtr;
    nbLeb = be32toh(descPtr->vtblPtr->reserved_pebs);
    if( leb >= nbLeb )
    {
        return LE_OUT_OF_RANGE;
    }
    peb = descPtr->ubiLebToPeb[leb];
    if ( peb == -1 )
    {
        return LE_NOT_PERMITTED;
    }

    LE_DEBUG("Check if bad block at peb %u leb %u", peb, leb);
    res = pa_flash_CheckBadBlock( desc, peb, &isBad );
    if( LE_OK != res )
    {
        goto error;
    }
    if (isBad)
    {
        LE_WARN("Skipping bad peb %u, leb %u", peb, leb);
        res = LE_IO_ERROR;
        goto error;
    }

    blkOff = (off_t)peb * descPtr->mtdInfo.eraseSize;
    size = ((*dataSizePtr + descPtr->ubiDataOffset) > descPtr->mtdInfo.eraseSize)
            ? (descPtr->mtdInfo.eraseSize - descPtr->ubiDataOffset)
            : *dataSizePtr;
    realSize = ((nbLeb - 1) == leb)
                  ? descPtr->ubiVolumeSize -
                       ((descPtr->mtdInfo.eraseSize - descPtr->ubiDataOffset) * (nbLeb - 1))
                  : size;
    LE_DEBUG("LEB %u (nbLEB %u) size %zu realSize %u", leb, nbLeb, size, realSize);
    if (realSize > size)
    {
        realSize = size;
    }
    LE_DEBUG("LEB %d/%u PEB %d : Read %zx at block offset %lx",
             leb, nbLeb, peb, size, blkOff);
    res = FlashSeekAtOffset( desc, (off_t)(blkOff) + (off_t)descPtr->ubiDataOffset );
    if( LE_OK != res )
    {
        goto error;
    }
    res = FlashRead( desc, dataPtr, realSize );
    if (LE_OK != res)
    {
        goto error;
    }

    *dataSizePtr = realSize;
    return LE_OK;

error:
    return res;
}

//--------------------------------------------------------------------------------------------------
/**
 * Read data from an UBI volume starting at a given offset and up to a given number of bytes.
 *
 * @return
 *      - LE_OK            On success.
 *      - LE_BAD_PARAMETER If desc is NULL or dataPtr or dataSizePtr is NULL
 *      - LE_FAULT         On failure
 *      - LE_OUT_OF_RANGE  If the offset or length are outside the partition range
 *      - LE_IO_ERROR      If a flash IO error occurs
 *      - LE_FORMAT_ERROR  If the flash is not in UBI format
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_flash_ReadUbiAtOffset
(
    pa_flash_Desc_t desc,        ///< [IN] Private flash descriptor
    off_t           dataOffset,  ///< [IN] Offset from where read should be done
    uint8_t*        dataPtr,     ///< [IN] Pointer to data to be read
    size_t*         dataSizePtr  ///< [IN][OUT] Data size to be read/data size really read
)
{
    pa_flash_MtdDesc_t* descPtr = (pa_flash_MtdDesc_t *)desc;
    size_t totalSize, chunkSize, realChunkSize, dataBlkSize, pos;
    uint32_t peb, leb, nbLeb;
    bool isBad;
    off_t mtdOff, dataBlkOff;
    le_result_t res;

    if((!descPtr) || (descPtr->magic != desc) || (!dataPtr) || (!dataSizePtr))
    {
        return LE_BAD_PARAMETER;
    }

    if((!descPtr->mtdInfo.ubi) || (descPtr->ubiVolumeId >= PA_FLASH_UBI_MAX_VOLUMES))
    {
        return LE_FORMAT_ERROR;
    }

    totalSize = *dataSizePtr;
    dataBlkSize = descPtr->mtdInfo.eraseSize - descPtr->ubiDataOffset;
    nbLeb = be32toh(descPtr->vtblPtr->reserved_pebs);
    pos = 0;

    while (pos < totalSize)
    {
        // Get the logical erase block given a logical offset
        leb = dataOffset / dataBlkSize;
        if(leb >= nbLeb)
        {
            res = LE_OUT_OF_RANGE;
            goto error;
        }

        // Get the physical erase block given a logical erase block
        peb = descPtr->ubiLebToPeb[leb];
        if (peb == -1)
        {
            res = LE_NOT_PERMITTED;
            goto error;
        }

        // Check that the physical block is not marked bad
        res = pa_flash_CheckBadBlock(desc, peb, &isBad);
        if (( LE_OK != res) || (isBad))
        {
            LE_WARN("Bad block detected at peb: %u", peb);
            res = LE_IO_ERROR;
            goto error;
        }

        // Compute the physical offset
        dataBlkOff = (dataOffset % dataBlkSize);
        mtdOff = (descPtr->mtdInfo.eraseSize * peb) + dataBlkOff + descPtr->ubiDataOffset;

        // Compute the size of the chunk to be read in this iteration
        chunkSize = ((dataBlkOff + (totalSize - pos)) > dataBlkSize)
                        ? (dataBlkSize - dataBlkOff)
                        : (totalSize - pos);
        realChunkSize = ((nbLeb - 1) == leb)
                       ? descPtr->ubiVolumeSize -
                           ((descPtr->mtdInfo.eraseSize - descPtr->ubiDataOffset) * (nbLeb - 1))
                       : chunkSize;
        if( realChunkSize > chunkSize )
        {
            realChunkSize = chunkSize;
        }

        LE_DEBUG("dataOffset: %ld, peb: %u, dataBlkOff: %ld, mtdOff: %ld, "
                 "chunkSize: %zu, realChunkSize: %zu pos:%zu",
                 dataOffset, peb, dataBlkOff, mtdOff, chunkSize, realChunkSize, pos);

        // Seek and read from flash
        res = FlashSeekAtOffset(desc, mtdOff);
        if( LE_OK != res )
        {
            goto error;
        }

        res = FlashRead( desc, dataPtr + pos, realChunkSize);
        if (LE_OK != res)
        {
            goto error;
        }

        pos += realChunkSize;
        dataOffset += realChunkSize;

        // Update the amount of data read so far
        *dataSizePtr = pos;

        // No more data to read
        if( realChunkSize != chunkSize )
        {
            break;
        }
    }
    return LE_OK;

error:

    // Even if an error occured, some data was successfully read from flash. In this case,
    // return the size of the data
    if (pos)
    {
        LE_WARN("Error occured (%d) but some data was successfully read from flash", res);
        return LE_OK;
    }

    // Return the error code in case of failure
    *dataSizePtr = 0;
    return res;

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
    pa_flash_Desc_t desc,              ///< [IN] Private flash descriptor
    uint32_t        leb,               ///< [IN] LEB to write
    uint8_t*        dataPtr,           ///< [IN] Pointer to data to be written
    size_t          dataSize,          ///< [IN][OUT] Size to be written
    bool            isExtendUbiVolume  ///< [IN] True if the volume may be extended by one block if
                                       ///<      write is the leb is outside the current volume
)
{
    pa_flash_MtdDesc_t* descPtr = (pa_flash_MtdDesc_t *)desc;
    uint32_t nbLeb, blk, reservedPebs, pebErase = INVALID_PEB;
    uint32_t crc;
    off_t blkOff;
    uint64_t eraseCount;
    struct ubi_ec_hdr* ecHdrPtr;
    struct ubi_vid_hdr* vidHdrPtr;
    uint8_t* blockPtr = NULL;
    off_t dataOffset;
    pa_flash_Info_t* infoPtr;
    le_result_t res;

    if( (!descPtr) || (descPtr->magic != desc) || (!dataPtr) )
    {
        return LE_BAD_PARAMETER;
    }

    infoPtr = &descPtr->mtdInfo;
    if( (!infoPtr->ubi) || (descPtr->ubiVolumeId >= PA_FLASH_UBI_MAX_VOLUMES) )
    {
        return LE_FORMAT_ERROR;
    }

    reservedPebs = nbLeb = be32toh(descPtr->vtblPtr->reserved_pebs);
    if( (leb > nbLeb) || ((leb == nbLeb) && (!isExtendUbiVolume)) )
    {
        return LE_OUT_OF_RANGE;
    }

    dataOffset = (infoPtr->writeSize * 2);
    if( (!UbiBlockPool) )
    {
        UbiBlockPool = le_mem_CreatePool("UBI Block Pool", infoPtr->eraseSize);
        le_mem_ExpandPool( UbiBlockPool, 1 );
    }
    blockPtr = le_mem_ForceAlloc(UbiBlockPool);

    blk = leb;
    if( (blk == reservedPebs) && isExtendUbiVolume )
    {
        uint32_t ieb;

        LE_DEBUG("Create new LEB %d in VolID %d \"%s\"",
                 blk, descPtr->ubiVolumeId, descPtr->vtblPtr->name);
        reservedPebs++;

        if( descPtr->vtblPtr->vol_type == UBI_VID_STATIC )
        {
            res = UpdateAllVidBlock( desc, blockPtr, reservedPebs, UBI_NO_SIZE );
            if (LE_OK != res)
            {
                goto error;
            }
        }
        res = UpdateVtbl( desc, blockPtr, reservedPebs );
        if (LE_OK != res)
        {
            goto error;
        }

        res = GetNewBlock( desc, blockPtr, &eraseCount, &ieb );
        if( LE_OK != res )
        {
            LE_CRIT("Failed to add one block on volume %d", descPtr->ubiVolumeId);
            goto error;
        }
        LE_DEBUG3(blockPtr);

        ecHdrPtr = (struct ubi_ec_hdr *)blockPtr;
        if( INVALID_ERASECOUNTER == eraseCount || ERASED_VALUE_32 == ecHdrPtr->magic )
        {
            CreateEcHeader(descPtr, ecHdrPtr);
        }
        LE_DEBUG3(blockPtr);

        vidHdrPtr = (struct ubi_vid_hdr *)(blockPtr + be32toh(ecHdrPtr->vid_hdr_offset));
        CreateVidHeader(descPtr, vidHdrPtr, blk, reservedPebs);
        descPtr->vtblPtr->reserved_pebs = htobe32(reservedPebs);
        descPtr->ubiLebToPeb[blk] = ieb;
        LE_DEBUG3(blockPtr);
        blkOff = descPtr->ubiLebToPeb[blk] * infoPtr->eraseSize;
        res = FlashSeekAtOffset( desc, blkOff );
        if (LE_OK != res)
        {
            goto error;
        }
    }
    else
    {
        uint32_t newBlk;

        eraseCount = INT_MAX;
        res = -1;
        if (!descPtr->ubiAbsOffset)
        {
            res = GetNewBlock( desc, blockPtr, &eraseCount, &newBlk );
        }
        else if( INVALID_PEB == descPtr->ubiLebToPeb[blk] )
        {
            res = GetNewBlock( desc, blockPtr, &eraseCount, &newBlk );
            if( LE_OK != res )
            {
                LE_CRIT("Failed to add one block on volume %d", descPtr->ubiVolumeId);
                goto error;
            }
            LE_DEBUG3(blockPtr);

            ecHdrPtr = (struct ubi_ec_hdr *)blockPtr;
        }
        if( LE_OK != res )
        {
            blkOff = descPtr->ubiLebToPeb[blk] * infoPtr->eraseSize;
            LE_DEBUG("read UBI block : LEB %d PEB %d (at %lx)",
                     blk, descPtr->ubiLebToPeb[blk], blkOff);
            LE_DEBUG("Read blk %d, size %lx at %lx",
                    blk, dataOffset, blkOff );
            res = FlashSeekAtOffset( desc, blkOff );
            if (LE_OK != res)
            {
                goto error;
            }
            res = FlashRead( desc, blockPtr, dataOffset );
            if (LE_OK != res)
            {
                goto error;
            }
        }
        else
        {
            ecHdrPtr = (struct ubi_ec_hdr *)blockPtr;
            if( INVALID_ERASECOUNTER == eraseCount || ERASED_VALUE_32 == ecHdrPtr->magic )
            {
                CreateEcHeader(descPtr, ecHdrPtr);

                vidHdrPtr = (struct ubi_vid_hdr*)(blockPtr + be32toh(ecHdrPtr->vid_hdr_offset));
                CreateVidHeader(descPtr, vidHdrPtr, blk, be32toh(descPtr->vtblPtr->reserved_pebs));
            }
            else
            {
                if( INVALID_PEB != descPtr->ubiLebToPeb[blk] )
                {
                    blkOff = descPtr->ubiLebToPeb[blk] * infoPtr->eraseSize;
                    blkOff += infoPtr->writeSize;
                    LE_DEBUG("read UBI block : LEB %d PEB %d (at %lx)",
                             blk, descPtr->ubiLebToPeb[blk], blkOff);
                    LE_DEBUG("Read blk %d, size %lx at %lx",
                            blk, dataOffset, blkOff );
                    res = FlashSeekAtOffset( desc, blkOff );
                    if (LE_OK != res)
                    {
                        goto error;
                    }
                    res = FlashRead( desc, blockPtr + infoPtr->writeSize,
                                     dataOffset - infoPtr->writeSize );
                    if (LE_OK != res)
                    {
                        goto error;
                    }
                    pebErase = descPtr->ubiLebToPeb[blk];
                }
                else
                {
                    // Create a VID header with the volume ID
                    vidHdrPtr = (struct ubi_vid_hdr*)(blockPtr + be32toh(ecHdrPtr->vid_hdr_offset));
                    CreateVidHeader(descPtr, vidHdrPtr, blk, be32toh(descPtr->vtblPtr->reserved_pebs));
                }
            }
            descPtr->ubiLebToPeb[blk] = newBlk;
            blkOff = descPtr->ubiLebToPeb[blk] * infoPtr->eraseSize;
        }
    }
    ecHdrPtr = (struct ubi_ec_hdr *)blockPtr;
    LE_INFO("LEB %u, PEB %lu OFFSET %lx, EC %"PRIu64,
            blk, blkOff / infoPtr->eraseSize, blkOff, ecHdrPtr->ec);
    UpdateEraseCounter( descPtr, ecHdrPtr );
    vidHdrPtr = (struct ubi_vid_hdr *)(blockPtr + be32toh(ecHdrPtr->vid_hdr_offset));
    if( descPtr->vtblPtr->vol_type == UBI_VID_STATIC )
    {
        vidHdrPtr->data_size = htobe32(dataSize);
        crc = le_crc_Crc32( dataPtr, dataSize, LE_CRC_START_CRC32 );
        vidHdrPtr->data_crc = htobe32(crc);
        crc = le_crc_Crc32( (uint8_t *)vidHdrPtr, UBI_VID_HDR_SIZE_CRC, LE_CRC_START_CRC32 );
        vidHdrPtr->hdr_crc = htobe32(crc);
    }
    LE_DEBUG("Erase and write blk %d, size %lx at %lx",
             blk, dataOffset, blkOff);
    res = FlashEraseBlock( desc, blkOff / infoPtr->eraseSize );
    if (LE_OK != res)
    {
        goto error;
    }

    LE_DEBUG("Write DATA at %lx: size %zx", blkOff + dataOffset, dataSize);
    LE_DEBUG3(dataPtr);
    memcpy(blockPtr + dataOffset, dataPtr, dataSize);

    res = FlashSeekAtOffset( desc, blkOff );
    if (LE_OK != res)
    {
        goto error;
    }

    LE_DEBUG("Update VID Header at %lx: oldsize %x newsize %zx, data_crc %x, hdr_crc %x",
             blkOff, be32toh(vidHdrPtr->data_size), dataSize,
             be32toh(vidHdrPtr->data_crc), be32toh(vidHdrPtr->hdr_crc));

    LE_DEBUG("Write EC+VID at %lx: size %lx", blkOff, dataOffset);
    res = FlashWrite( desc, blockPtr, dataOffset + dataSize );
    LE_DEBUG3(blockPtr);
    if (LE_OK != res)
    {
        goto error;
    }

    if( INVALID_PEB != pebErase )
    {
        blkOff = pebErase * infoPtr->eraseSize;
        LE_DEBUG("read UBI block : LEB %d PEB %d (at %lx)",
                 pebErase, pebErase, blkOff);
        LE_DEBUG("Read blk %d, size %lx at %lx",
                pebErase, dataOffset, blkOff );
        res = FlashSeekAtOffset( desc, blkOff );
        if (LE_OK != res)
        {
            goto error;
        }
        res = FlashRead( desc, blockPtr, infoPtr->writeSize );
        if (LE_OK != res)
        {
            goto error;
        }
        res = FlashEraseBlock( desc, pebErase );
        if( LE_OK != res )
        {
            LE_CRIT("Failed to erase old PEB %u", pebErase);
        }
        ecHdrPtr = (struct ubi_ec_hdr *)blockPtr;
        UpdateEraseCounter( descPtr, ecHdrPtr );
        res = FlashWriteAtBlock( desc, blkOff / infoPtr->eraseSize, blockPtr, infoPtr->writeSize );
    }

error:
    if( blockPtr )
    {
        le_mem_Release(blockPtr);
    }
    return res;
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
    pa_flash_MtdDesc_t* descPtr = (pa_flash_MtdDesc_t *)desc;
    uint32_t reservedPebs;
    uint8_t* blockPtr = NULL;
    off_t dataOffset, dataSize;
    pa_flash_Info_t* infoPtr;
    le_result_t res;

    if( (!descPtr) || (descPtr->magic != desc) )
    {
        return LE_BAD_PARAMETER;
    }

    infoPtr = &descPtr->mtdInfo;
    if( (!infoPtr->ubi) || (descPtr->ubiVolumeId >= PA_FLASH_UBI_MAX_VOLUMES) )
    {
        return LE_UNSUPPORTED;
    }

    dataOffset = (2 *infoPtr->writeSize);
    dataSize = infoPtr->eraseSize - dataOffset;
    reservedPebs = (newSize + (dataSize - 1)) / dataSize;
    LE_DEBUG("Reducing UBI vol %u from %u to %u blocks[last %u] with newSize %zu",
             descPtr->ubiVolumeId, be32toh(descPtr->vtblPtr->reserved_pebs),
             reservedPebs, descPtr->ubiLebToPeb[reservedPebs - 1], newSize);
    if( reservedPebs <= be32toh(descPtr->vtblPtr->reserved_pebs) )
    {
        uint32_t lastSize = newSize % dataSize;
        if( (!UbiBlockPool) )
        {
            UbiBlockPool = le_mem_CreatePool("UBI Block Pool", infoPtr->eraseSize);
            le_mem_ExpandPool( UbiBlockPool, 1 );
        }
        blockPtr = le_mem_ForceAlloc(UbiBlockPool);

        if( reservedPebs == be32toh(descPtr->vtblPtr->reserved_pebs) )
        {
            res = LE_OK;
            if (lastSize)
            {
                LE_DEBUG("Setting size %u for last peb on VolId %d", lastSize, descPtr->ubiVolumeId);
                res = UpdateVidBlock( desc, reservedPebs - 1, blockPtr, reservedPebs, lastSize );
            }
        }
        else
        {
            LE_DEBUG("Starting to reduce reserved_pebs for VolId %d", descPtr->ubiVolumeId);
            res = UpdateAllVidBlock( desc, blockPtr, reservedPebs, newSize );
        }
        if( LE_OK != res )
        {
            goto error;
        }
        res = UpdateVtbl( desc, blockPtr, reservedPebs );
        if( LE_OK != res )
        {
            goto error;
        }
        le_mem_Release(blockPtr);
    }
    return LE_OK;

error:
    if( blockPtr )
    {
        le_mem_Release(blockPtr);
    }
    return res;
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
    pa_flash_MtdDesc_t *descPtr = (pa_flash_MtdDesc_t *)desc;

    if( (!descPtr) || (descPtr->magic != desc) )
    {
        return LE_BAD_PARAMETER;
    }

    if( (descPtr->ubiVolumeId >= PA_FLASH_UBI_MAX_VOLUMES) || \
        (!descPtr->vtblPtr))
    {
        return LE_FORMAT_ERROR;
    }

    if (freeBlockPtr)
    {
        *freeBlockPtr = descPtr->mtdInfo.ubiPebFreeCount;
    }
    if (volBlockPtr)
    {
        *volBlockPtr = be32toh(descPtr->vtblPtr->reserved_pebs);
    }
    if (volSizePtr)
    {
        *volSizePtr = descPtr->ubiVolumeSize;
    }
    return LE_OK;
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
    char            volName[PA_FLASH_UBI_MAX_VOLUMES],
                                  ///< [OUT] Name of the volume
    uint32_t*       volFlagsPtr   ///< [OUT] Flags set to the volume
)
{
    pa_flash_MtdDesc_t *descPtr = (pa_flash_MtdDesc_t *)desc;

    if( (!descPtr) || (descPtr->magic != desc) )
    {
        return LE_BAD_PARAMETER;
    }

    if( (descPtr->ubiVolumeId >= PA_FLASH_UBI_MAX_VOLUMES) || \
        (!descPtr->vtblPtr))
    {
        return LE_FORMAT_ERROR;
    }

    if (volName)
    {
        strncpy(volName, (char *)descPtr->vtblPtr->name, PA_FLASH_UBI_MAX_VOLUMES);
    }
    if (volTypePtr)
    {
        *volTypePtr = descPtr->vtblPtr->vol_type;
    }
    if (volFlagsPtr)
    {
        *volFlagsPtr = descPtr->vtblPtr->flags;
    }
    return LE_OK;
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
    pa_flash_MtdDesc_t *descPtr = (pa_flash_MtdDesc_t *)desc;

    if( (!descPtr) || (descPtr->magic != desc) )
    {
        return LE_BAD_PARAMETER;
    }

    if (ubiOffsetPtr)
    {
        *ubiOffsetPtr = descPtr->ubiAbsOffset;
    }
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
    struct ubi_vid_hdr *vidHdrPtr;

    if( (!pattern)|| (!data) )
    {
        return LE_BAD_PARAMETER;
    }

    vidHdrPtr = (struct ubi_vid_hdr *)data;
    if (pattern != be32toh(vidHdrPtr->magic))
    {
        return LE_NOT_FOUND;
    }
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
    int i, size;

    if( (!pageSize) || (!dataSize) || (!data) )
    {
        return LE_BAD_PARAMETER;
    }

    for (i = *dataSize - 1; i >= 0; i--)
    {
        if (((const uint8_t *)data)[i] != 0xFF)
        {
            break;
        }
    }

    /* The resulting length must be aligned to the minimum flash I/O size */
    size = i + 1;
    *dataSize = ((size + pageSize - 1) / pageSize) * pageSize;
    return LE_OK;
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
le_result_t pa_flash_CreateUbi
(
    pa_flash_Desc_t desc,           ///< [IN] Private flash descriptor
    bool            isForcedCreate  ///< [IN] If set to true the UBI partition is overwriten and the
                                    ///<      previous content is lost
)
{
    pa_flash_MtdDesc_t *descPtr = (pa_flash_MtdDesc_t *)desc;
    bool isUbi, isBad;
    uint32_t peb;
    off_t pebOffset;
    struct ubi_ec_hdr* ecHeaderPtr;
    struct ubi_vid_hdr vidHeader;
    uint8_t* blockPtr = NULL;
    pa_flash_Info_t* infoPtr;
    le_result_t res;
    int nbVtblPeb = 0;

    res = pa_flash_UnscanUbi(desc);
    if (LE_OK != res)
    {
        return res;
    }

    res = pa_flash_CheckUbi(desc, &isUbi);
    if ((LE_OK == res) && (isUbi))
    {
        if (!isForcedCreate)
        {
            res = LE_BUSY;
        }
    }
    if (LE_OK != res)
    {
        return res;
    }

    infoPtr = &descPtr->mtdInfo;

    if ((!UbiBlockPool))
    {
        UbiBlockPool = le_mem_CreatePool("UBI Block Pool", infoPtr->eraseSize);
        le_mem_ExpandPool( UbiBlockPool, 1 );
    }
    blockPtr = le_mem_ForceAlloc(UbiBlockPool);
    memset(blockPtr, 0xFF, infoPtr->eraseSize);
    ecHeaderPtr = (struct ubi_ec_hdr*)blockPtr;

    for( peb = 0; peb < infoPtr->nbLeb; peb++ )
    {
        LE_DEBUG("Check if bad block at peb %u", peb);
        res = pa_flash_CheckBadBlock( descPtr, peb, &isBad );
        if (LE_OK != res)
        {
            goto error;
        }
        if (isBad)
        {
            LE_WARN("Skipping bad block %d", peb);
            continue;
        }

        pebOffset = peb * infoPtr->eraseSize;
        res = ReadEcHeader( descPtr, pebOffset, ecHeaderPtr, false );
        if ((LE_FORMAT_ERROR == res) || (LE_UNSUPPORTED == res))
        {
            // Create a new EC header
            CreateEcHeader(descPtr, ecHeaderPtr);
        }
        else if (LE_OK == res)
        {
            res = ReadVidHeader( descPtr, pebOffset,
                                 &vidHeader, be32toh(ecHeaderPtr->vid_hdr_offset) );
            // The two first blocks are used to handle the Volume Label Table (vtbl)
            // So, until the two blocks are filled, we need to create an empty vtbl
            if ((LE_FORMAT_ERROR == res) && (nbVtblPeb == 2))
            {
                // This is a free UBI block containing only the EC header. Do nothing
                LE_INFO("PEB %u: EC header is up to date", peb);
                continue;
            }

            // Update the EC, erase the block and write the EC header
            UpdateEraseCounter(descPtr, ecHeaderPtr);
        }
        else
        {
            goto error;
        }
        // Erase the current block
        res = FlashEraseBlock( desc, peb );
        if (LE_OK != res)
        {
            // Need to mark the block bad !
            continue;
        }
        res = FlashSeekAtOffset( desc, pebOffset );
        if (LE_OK != res)
        {
            goto error;
        }
        // Write the EC header
        res = FlashWrite( desc, blockPtr, infoPtr->writeSize );
        if (LE_OK != res)
        {
            goto error;
        }
        LE_INFO("PEB %u: Write UBI EC header, MAGIC %c%c%c%c, EC %"PRIu64", VID %x DATA %x CRC %x",
                 peb,
                 ((char *)&(ecHeaderPtr->magic))[0],
                 ((char *)&(ecHeaderPtr->magic))[1],
                 ((char *)&(ecHeaderPtr->magic))[2],
                 ((char *)&(ecHeaderPtr->magic))[3],
                 be64toh(ecHeaderPtr->ec),
                 be32toh(ecHeaderPtr->vid_hdr_offset),
                 be32toh(ecHeaderPtr->data_offset),
                 be32toh(ecHeaderPtr->hdr_crc));

        if (2 > nbVtblPeb)
        {
            // The VTBL should stand into 2 blocks. We use the 2 first block (0 and 1) to
            // store an empty VTBL
            uint32_t crc;
            uint32_t vol;
            struct ubi_vid_hdr* vidHeaderPtr = (struct ubi_vid_hdr*)
                                                   (blockPtr +
                                                    be32toh(ecHeaderPtr->vid_hdr_offset));
            struct ubi_vtbl_record* vtblPtr = (struct ubi_vtbl_record*)
                                                  (blockPtr +
                                                   be32toh(ecHeaderPtr->data_offset));

            // Create a VID header with the VTBL marker: VTBL layout volume
            memset(vidHeaderPtr, 0, sizeof(struct ubi_vid_hdr));
            vidHeaderPtr->magic = htobe32(UBI_VID_HDR_MAGIC);
            vidHeaderPtr->version = UBI_VERSION;
            vidHeaderPtr->vol_type = UBI_VID_DYNAMIC;
            vidHeaderPtr->compat = 5;
            vidHeaderPtr->vol_id = htobe32(UBI_LAYOUT_VOLUME_ID);
            vidHeaderPtr->lnum = htobe32(nbVtblPeb);
            crc = le_crc_Crc32( (uint8_t *)vidHeaderPtr,
                                UBI_VID_HDR_SIZE_CRC, LE_CRC_START_CRC32 );
            vidHeaderPtr->hdr_crc = htobe32(crc);
            res = FlashSeekAtOffset( desc, peb * infoPtr->eraseSize
                                     + be32toh(ecHeaderPtr->vid_hdr_offset) );
            if (LE_OK != res)
            {
                goto error;
            }
            // Write the VID header for VTBL layout volume
            res = FlashWrite( desc, (uint8_t *)vidHeaderPtr, infoPtr->writeSize );
            if (LE_OK != res)
            {
                goto error;
            }
            LE_INFO("PEB %u: Write VID header, MAGIC %c%c%c%c, VER %hhd, VT %hhd CP %hhd CT %hhd"
                    " VID %x LNUM %x DSZ %x EBS %x DPD %x DCRC %x CRC %x",
                    peb,
                    ((char *)&(vidHeaderPtr->magic))[0],
                    ((char *)&(vidHeaderPtr->magic))[1],
                    ((char *)&(vidHeaderPtr->magic))[2],
                    ((char *)&(vidHeaderPtr->magic))[3],
                    (vidHeaderPtr->version),
                    (vidHeaderPtr->vol_type),
                    (vidHeaderPtr->copy_flag),
                    (vidHeaderPtr->compat),
                    be32toh(vidHeaderPtr->vol_id),
                    be32toh(vidHeaderPtr->lnum),
                    be32toh(vidHeaderPtr->data_size),
                    be32toh(vidHeaderPtr->used_ebs),
                    be32toh(vidHeaderPtr->data_pad),
                    be32toh(vidHeaderPtr->data_crc),
                    be32toh(vidHeaderPtr->hdr_crc));

            // Create an empty VTBL and update the CRCs for all records
            memset(vtblPtr, 0, sizeof(struct ubi_vtbl_record) * UBI_MAX_VOLUMES);
            for( vol = 0; vol < UBI_MAX_VOLUMES; vol++ )
            {
                crc = le_crc_Crc32( (uint8_t *)&vtblPtr[vol],
                                    UBI_VTBL_RECORD_SIZE_CRC, LE_CRC_START_CRC32 );
                vtblPtr[vol].crc = htobe32(crc);
            }
            res = FlashSeekAtOffset( desc, peb * infoPtr->eraseSize
                                               + be32toh(ecHeaderPtr->data_offset) );
            if (LE_OK != res)
            {
                goto error;
            }
            // Write the VTBL. Align the size to write the write size multiple
            res = FlashWrite( desc, (uint8_t *)vtblPtr,
                              (((sizeof(struct ubi_vtbl_record) * UBI_MAX_VOLUMES)
                                  + infoPtr->writeSize - 1)
                                  / infoPtr->writeSize)
                                  * infoPtr->writeSize );
            if (LE_OK != res)
            {
                goto error;
            }
            LE_INFO("PEB %u: Write VTBL, LNUM %u", peb, nbVtblPeb);
            nbVtblPeb++;
        }
    }
    le_mem_Release(blockPtr);
    return LE_OK;

error:
    if (blockPtr)
    {
        le_mem_Release(blockPtr);
    }
    return res;
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
    pa_flash_MtdDesc_t *descPtr = (pa_flash_MtdDesc_t *)desc;
    bool isUbi;
    uint32_t peb;
    struct ubi_ec_hdr* ecHeaderPtr;
    uint8_t* blockPtr = NULL;
    pa_flash_Info_t* infoPtr;
    le_result_t res;
    int nbVtblPeb = 0;

    if( !offset )
    {
        return pa_flash_CreateUbi(desc, isForcedCreate);
    }

    res = pa_flash_UnscanUbi(desc);
    if (LE_OK != res)
    {
        return res;
    }

    res = pa_flash_CheckUbiAtOffset(desc, offset, &isUbi);
    if ((LE_OK == res) && (isUbi))
    {
        if (!isForcedCreate)
        {
            res = LE_BUSY;
        }
    }
    if (LE_OK != res)
    {
        goto error;
    }

    infoPtr = &descPtr->mtdInfo;
    if( -1 == UpdateUbiAbsOffset( descPtr, offset ) )
    {
        return LE_OUT_OF_RANGE;
    }

    if ((!UbiBlockPool))
    {
        UbiBlockPool = le_mem_CreatePool("UBI Block Pool", infoPtr->eraseSize);
        le_mem_ExpandPool( UbiBlockPool, 1 );
    }
    blockPtr = le_mem_ForceAlloc(UbiBlockPool);
    memset(blockPtr, 0xFF, infoPtr->eraseSize);
    ecHeaderPtr = (struct ubi_ec_hdr*)blockPtr;

    for( nbVtblPeb = 0; nbVtblPeb < 2; nbVtblPeb++ )
    {
        peb = descPtr->ubiBasePeb + nbVtblPeb;
        // Create a new EC header
        CreateEcHeader(descPtr, ecHeaderPtr);
        // Erase the current block
        LE_INFO("PEB %u: Write UBI EC header, MAGIC %c%c%c%c, EC %"PRIu64", VID %x DATA %x CRC %x",
                 peb,
                 ((char *)&(ecHeaderPtr->magic))[0],
                 ((char *)&(ecHeaderPtr->magic))[1],
                 ((char *)&(ecHeaderPtr->magic))[2],
                 ((char *)&(ecHeaderPtr->magic))[3],
                 be64toh(ecHeaderPtr->ec),
                 be32toh(ecHeaderPtr->vid_hdr_offset),
                 be32toh(ecHeaderPtr->data_offset),
                 be32toh(ecHeaderPtr->hdr_crc));

        // The VTBL should stand into 2 blocks. We use the 2 first block (0 and 1) to
        // store an empty VTBL
        uint32_t crc;
        uint32_t vol;
        struct ubi_vid_hdr* vidHeaderPtr = (struct ubi_vid_hdr*)
                                            (blockPtr +
                                             be32toh(ecHeaderPtr->vid_hdr_offset));
        struct ubi_vtbl_record* vtblPtr = (struct ubi_vtbl_record*)
                                           (blockPtr +
                                            be32toh(ecHeaderPtr->data_offset));

        // Create a VID header with the VTBL marker: VTBL layout volume
        memset(vidHeaderPtr, 0, sizeof(struct ubi_vid_hdr));
        vidHeaderPtr->magic = htobe32(UBI_VID_HDR_MAGIC);
        vidHeaderPtr->version = UBI_VERSION;
        vidHeaderPtr->vol_type = UBI_VID_DYNAMIC;
        vidHeaderPtr->compat = 5;
        vidHeaderPtr->vol_id = htobe32(UBI_LAYOUT_VOLUME_ID);
        vidHeaderPtr->lnum = htobe32(nbVtblPeb);
        crc = le_crc_Crc32( (uint8_t *)vidHeaderPtr,
                            UBI_VID_HDR_SIZE_CRC, LE_CRC_START_CRC32 );
        vidHeaderPtr->hdr_crc = htobe32(crc);
        LE_INFO("PEB %u: Write VID header, MAGIC %c%c%c%c, VER %hhd, VT %hhd CP %hhd CT %hhd"
                " VID %x LNUM %x DSZ %x EBS %x DPD %x DCRC %x CRC %x",
                peb,
                ((char *)&(vidHeaderPtr->magic))[0],
                ((char *)&(vidHeaderPtr->magic))[1],
                ((char *)&(vidHeaderPtr->magic))[2],
                ((char *)&(vidHeaderPtr->magic))[3],
                (vidHeaderPtr->version),
                (vidHeaderPtr->vol_type),
                (vidHeaderPtr->copy_flag),
                (vidHeaderPtr->compat),
                be32toh(vidHeaderPtr->vol_id),
                be32toh(vidHeaderPtr->lnum),
                be32toh(vidHeaderPtr->data_size),
                be32toh(vidHeaderPtr->used_ebs),
                be32toh(vidHeaderPtr->data_pad),
                be32toh(vidHeaderPtr->data_crc),
                be32toh(vidHeaderPtr->hdr_crc));

        // Create an empty VTBL and update the CRCs for all records
        memset(vtblPtr, 0, sizeof(struct ubi_vtbl_record) * UBI_MAX_VOLUMES);
        for( vol = 0; vol < UBI_MAX_VOLUMES; vol++ )
        {
            crc = le_crc_Crc32( (uint8_t *)&vtblPtr[vol],
                                UBI_VTBL_RECORD_SIZE_CRC, LE_CRC_START_CRC32 );
            vtblPtr[vol].crc = htobe32(crc);
        }
        res = FlashSeekAtBlock( desc, peb );
        if (LE_OK != res)
        {
            goto error;
        }
        // Write the VTBL. Align the size to write the write size multiple
        res = FlashWrite( desc, blockPtr, infoPtr->eraseSize );
        if (LE_OK != res)
        {
            goto error;
        }
        descPtr->vtblPeb[nbVtblPeb] = peb;
        LE_INFO("PEB %u: Write VTBL, LNUM %u", peb, nbVtblPeb);
    }
    le_mem_Release(blockPtr);
    return LE_OK;

error:
    if (blockPtr)
    {
        le_mem_Release(blockPtr);
    }
    descPtr->ubiAbsOffset = 0;
    descPtr->ubiOffsetInPeb = 0;
    descPtr->ubiBasePeb = 0;
    descPtr->vtblPeb[0] = -1;
    descPtr->vtblPeb[1] = -1;
    return res;
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
le_result_t pa_flash_CreateUbiVolumeWithFlags
(
    pa_flash_Desc_t desc,      ///< [IN] Private flash descriptor
    uint32_t ubiVolId,         ///< [IN] UBI volume ID
    const char* ubiVolNamePtr, ///< [IN] UBI volume name
    uint32_t ubiVolType,       ///< [IN] UBI volume type: dynamic or static
    uint32_t ubiVolSize,       ///< [IN] UBI volume size (for dynamic volumes only)
    uint32_t ubiVolFlags       ///< [IN] UBI volume flags (for dynamic volumes only)
)
{
    pa_flash_MtdDesc_t *descPtr = (pa_flash_MtdDesc_t *)desc;
    struct ubi_ec_hdr* ecHeaderPtr;
    struct ubi_vid_hdr* vidHeaderPtr;
    struct ubi_vtbl_record* vtblPtr;
    uint8_t* blockPtr = NULL;
    pa_flash_Info_t* infoPtr;
    le_result_t res;
    uint32_t vol, peb, leb, volPeb = (uint32_t)-1;
    uint32_t crc, volType, volPebs, usedPebs = 0;
    uint64_t ec;

    if ((!descPtr) || (descPtr->magic != desc) || (ubiVolId >= PA_FLASH_UBI_MAX_VOLUMES) ||
        (NULL == ubiVolNamePtr))
    {
        return LE_BAD_PARAMETER;
    }
    switch (ubiVolType)
    {
        case PA_FLASH_VOLUME_DYNAMIC:
            volPebs = (ubiVolSize +
                         (descPtr->mtdInfo.eraseSize - (2 * descPtr->mtdInfo.writeSize)) - 1) /
                      (descPtr->mtdInfo.eraseSize - (2 * descPtr->mtdInfo.writeSize));
            volType = UBI_VID_DYNAMIC;
            break;
        case PA_FLASH_VOLUME_STATIC:
            volPebs = descPtr->ubiAbsOffset
                         ? (ubiVolSize +
                               (descPtr->mtdInfo.eraseSize - (2 * descPtr->mtdInfo.writeSize)) - 1) /
                           (descPtr->mtdInfo.eraseSize - (2 * descPtr->mtdInfo.writeSize))
                         : 1;
            volType = UBI_VID_STATIC;
            break;
        default:
            return LE_BAD_PARAMETER;
    }
    LE_INFO("UbiOffset: %ld", descPtr->ubiAbsOffset);
    if( !descPtr->scanDone || ((-1 == descPtr->vtblPeb[0]) || (-1 == descPtr->vtblPeb[1])) )
    {
        res = pa_flash_ScanUbiForVolumesAtOffset(desc, descPtr->ubiAbsOffset, NULL, NULL);
        if (LE_OK != res)
        {
            goto error_unscan;
        }
    }
    for (vol = 0; vol < PA_FLASH_UBI_MAX_VOLUMES; vol++ )
    {
        if ((descPtr->vtbl[vol].name[0]) &&
            ((vol == ubiVolId) ||
             (0 == strcmp((const char *)descPtr->vtbl[vol].name, ubiVolNamePtr))))
        {
            LE_ERROR("MTD%u: UBI volume %u name '%s' already exits",
                     descPtr->mtdNum, ubiVolId, descPtr->vtbl[vol].name);
            res = LE_DUPLICATE;
            goto error_unscan;
        }
        if ((UBI_VID_STATIC == descPtr->vtbl[vol].vol_type) ||
            (UBI_VID_DYNAMIC == descPtr->vtbl[vol].vol_type))
        {
            usedPebs += be32toh(descPtr->vtbl[vol].reserved_pebs);
        }
    }

    // The number of PEBs to reserve is 2 * UBI_BEB_LIMIT, 2 PEBs for the VTBL, 1 PEB for
    // wear-leveling and 1 PEB for the atomic LEB change operation
    usedPebs += (2 * UBI_BEB_LIMIT + 4);
    if ((descPtr->mtdInfo.nbLeb - usedPebs) < volPebs)
    {
        LE_ERROR("MTD%u: UBI volume %u requires too many PEBs %u, only %u free PEBs",
                 descPtr->mtdNum, ubiVolId, volPebs, (descPtr->mtdInfo.nbLeb - usedPebs));
        res = LE_NO_MEMORY;
        goto error_unscan;
    }

    infoPtr = &descPtr->mtdInfo;
    descPtr->ubiVolumeId = INVALID_UBI_VOLUME;
    descPtr->vtblPtr = NULL;
    memset(descPtr->ubiLebToPeb, -1, sizeof(descPtr->ubiLebToPeb));
    infoPtr->ubiVolFreeSize = 0;
    infoPtr->ubi = false;

    if ((!UbiBlockPool))
    {
        UbiBlockPool = le_mem_CreatePool("UBI Block Pool", infoPtr->eraseSize);
        le_mem_ExpandPool( UbiBlockPool, 1 );
    }
    blockPtr = le_mem_ForceAlloc(UbiBlockPool);
    memset(blockPtr, 0xFF, infoPtr->eraseSize);
    ecHeaderPtr = (struct ubi_ec_hdr*)blockPtr;

    if (!descPtr->ubiAbsOffset || (UBI_VID_STATIC == volType))
    {
        // We need at least one block free to create the volume
        // except if we have an UBI starting at an offset and the volume is dynamic
        res = GetNewBlock(descPtr, blockPtr, &ec, &volPeb);
        if (LE_OK != res)
        {
            LE_ERROR("Failed to get a PEB free");
            goto error;
        }
        // Do not need to erase the block like the new block is already free
        // It may be a fully erased block or a block with only an EC header
        if (INVALID_ERASECOUNTER == be64toh(ecHeaderPtr->ec))
        {
            // This is an erased block
            CreateEcHeader(descPtr, ecHeaderPtr);
            res = FlashSeekAtBlock( desc, volPeb );
            if (LE_OK != res)
            {
                volPeb = (uint32_t)-1;
                goto error;
            }
            LE_DEBUG2("Flash EC header, peb %x", volPeb);
            res = FlashWrite( desc, (uint8_t*)ecHeaderPtr, infoPtr->writeSize );
            if (LE_OK != res)
            {
                goto error;
            }
        }
        infoPtr->ubiPebFreeCount--;
    }

    if (UBI_VID_STATIC == volType)
    {
        // Create a VID header with the volume ID if the volume is static
        vidHeaderPtr = (struct ubi_vid_hdr*)(blockPtr + be32toh(ecHeaderPtr->vid_hdr_offset));
        memset(vidHeaderPtr, 0, sizeof(struct ubi_vid_hdr));
        vidHeaderPtr->magic = htobe32(UBI_VID_HDR_MAGIC);
        vidHeaderPtr->version = UBI_VERSION;
        vidHeaderPtr->vol_type = volType;
        vidHeaderPtr->vol_id = htobe32(ubiVolId);
        vidHeaderPtr->lnum = htobe32(0);
        // If volume is static, the number of PEBs used for this volume must be set
        // It needs always one PEB, even if no data are in written in the volume
        vidHeaderPtr->used_ebs = htobe32(volPebs);
        crc = le_crc_Crc32( (uint8_t *)vidHeaderPtr,
                            UBI_VID_HDR_SIZE_CRC, LE_CRC_START_CRC32 );
        vidHeaderPtr->hdr_crc = htobe32(crc);
        res = FlashSeekAtOffset( desc, volPeb * infoPtr->eraseSize
                                          + htobe32(ecHeaderPtr->vid_hdr_offset) );
        if (LE_OK != res)
        {
            goto error;
        }
        LE_DEBUG2("Flash VID header, peb %x", volPeb);
        res = FlashWrite( desc, (uint8_t*)vidHeaderPtr, infoPtr->writeSize );
        if (LE_OK != res)
        {
            goto error;
        }
        descPtr->ubiLebToPeb[0] = volPeb;
    }

    // Update the VTBL to register the new volume name at volume ID position
    memset(blockPtr, 0xFF, infoPtr->eraseSize);
    for( leb = 0; leb < 2; leb++ )
    {
        // Read the VTBL block
        peb = descPtr->vtblPeb[leb];
        LE_DEBUG("Updating reserved_peb in VTBL %u [peb %u]",
                 leb, peb);
        res = FlashSeekAtBlock( desc, peb );
        if (LE_OK != res)
        {
            goto error;
        }
        res = FlashRead( desc, blockPtr, descPtr->mtdInfo.eraseSize);
        if (LE_OK != res)
        {
            goto error;
        }
        // Update the EC header
        LE_DEBUG3(blockPtr);
        ecHeaderPtr = (struct ubi_ec_hdr *)blockPtr;
        UpdateEraseCounter( descPtr, ecHeaderPtr );
        vtblPtr = (struct ubi_vtbl_record *)(blockPtr + be32toh(ecHeaderPtr->data_offset));
        memset(&vtblPtr[ubiVolId], 0, sizeof(struct ubi_vtbl_record));
        // Copy the volume name into the record, the name length, the number of PEBs and the
        // volume type
        strncpy((char *)vtblPtr[ubiVolId].name, ubiVolNamePtr, UBI_MAX_VOLUMES);
        vtblPtr[ubiVolId].name_len = htobe16(strlen(ubiVolNamePtr));
        vtblPtr[ubiVolId].reserved_pebs = htobe32(volPebs);
        vtblPtr[ubiVolId].alignment = htobe32(1);
        vtblPtr[ubiVolId].vol_type = ubiVolType;
        vtblPtr[ubiVolId].flags = (uint8_t)(ubiVolFlags & 0xFF);

        crc = le_crc_Crc32( (uint8_t *)&vtblPtr[ubiVolId],
                            UBI_VTBL_RECORD_SIZE_CRC,
                            LE_CRC_START_CRC32 );
        vtblPtr[ubiVolId].crc = htobe32(crc);
        // Erase the VTBL block
        res = FlashEraseBlock( desc, peb );
        if (LE_OK != res)
        {
            goto error;
        }
        res = FlashSeekAtBlock( desc, peb );
        if (LE_OK != res)
        {
            goto error;
        }
        // Update the whole VTBL block
        LE_INFO("PEB %u: Write VTBL, LNUM %u", peb, leb);
        res = FlashWrite( desc, blockPtr, descPtr->mtdInfo.eraseSize);
        if (LE_OK != res)
        {
            goto error;
        }
    }

    memcpy(descPtr->vtbl, vtblPtr, sizeof(descPtr->vtbl));
    descPtr->ubiVolumeId = ubiVolId;
    descPtr->vtblPtr = &(descPtr->vtbl[descPtr->ubiVolumeId]);
    infoPtr->ubi = true;
    le_mem_Release(blockPtr);

    return LE_OK;

error:
    if ((uint32_t)-1 != volPeb)
    {
        FlashEraseBlock( desc, volPeb );
    }
    if (blockPtr)
    {
        le_mem_Release(blockPtr);
    }
error_unscan:
    (void)pa_flash_UnscanUbi(desc);
    return res;
}

//--------------------------------------------------------------------------------------------------
/**
 * Delete UBI volume
 *
 * @return
 *      - LE_OK            On success
 *      - LE_BAD_PARAMETER If desc is NULL or is not a valid descriptor
 *      - LE_FORMAT_ERROR  If the flash is not in UBI format
 *      - LE_NOT_FOUND     If the volume name does not exist
 *      - LE_IO_ERROR      If a flash IO error occurs
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_flash_DeleteUbiVolume
(
    pa_flash_Desc_t desc,     ///< [IN] Private flash descriptor
    uint32_t ubiVolId         ///< [IN] UBI volume ID
)
{
    pa_flash_MtdDesc_t *descPtr = (pa_flash_MtdDesc_t *)desc;
    struct ubi_ec_hdr* ecHeaderPtr;
    struct ubi_vtbl_record* vtblPtr;
    uint8_t* blockPtr = NULL;
    pa_flash_Info_t* infoPtr;
    le_result_t res;
    uint32_t peb, leb, reservedPebs;
    uint32_t crc;

    if ((!descPtr) || (descPtr->magic != desc) || (ubiVolId >= PA_FLASH_UBI_MAX_VOLUMES))
    {
        return LE_BAD_PARAMETER;
    }

    res = pa_flash_UnscanUbi(desc);
    if (LE_OK != res)
    {
        return res;
    }

    res = pa_flash_ScanUbi(desc, ubiVolId);
    if (LE_OK != res)
    {
        return res;
    }

    infoPtr = &descPtr->mtdInfo;
    // Number of LEB allocated to this volume.
    reservedPebs = be32toh(descPtr->vtbl[ubiVolId].reserved_pebs);

    if ((!UbiBlockPool))
    {
        UbiBlockPool = le_mem_CreatePool("UBI Block Pool", infoPtr->eraseSize);
        le_mem_ExpandPool( UbiBlockPool, 1 );
    }
    blockPtr = le_mem_ForceAlloc(UbiBlockPool);
    memset(blockPtr, 0xFF, infoPtr->eraseSize);
    ecHeaderPtr = (struct ubi_ec_hdr*)blockPtr;

    // Erase all LEB belonging to the volume to delete. Only write an updated
    // EC header to mark them free
    for (leb = 0; leb < reservedPebs; leb++)
    {
        // Fetch the PEB corresponding to the LEB
        peb = descPtr->ubiLebToPeb[leb];
        if (-1 == peb)
        {
            LE_ERROR("LEB %u: Invalid PEB for volume %u", leb, ubiVolId);
            continue;
        }
        res = FlashSeekAtBlock( desc, peb );
        if (LE_OK != res)
        {
            goto error;
        }
        // Read the EC header from the block
        res = FlashRead( desc, blockPtr, infoPtr->writeSize );
        if (LE_OK != res)
        {
            goto error;
        }
        // Erase the block
        res = FlashEraseBlock( desc, peb );
        if (LE_OK != res)
        {
            if (LE_IO_ERROR == res)
            {
                (void)pa_flash_MarkBadBlock( desc, peb );
                LE_ERROR("PEB %u is BAD", peb);
            }
            goto error;
        }
        // Update the EC, erase the block and write the EC header
        UpdateEraseCounter(descPtr, ecHeaderPtr);
        res = FlashSeekAtBlock( desc, peb );
        if (LE_OK != res)
        {
            goto error;
        }
        res = FlashWrite( desc, blockPtr, infoPtr->writeSize );
        if (LE_OK != res)
        {
            goto error;
        }
        LE_INFO("PEB %u, LEB %u: Write EC header", peb, leb);
    }

    // Update the VTBL to unregister the volume. We just need to set the whole record
    // to 0x0 and update the CRC. The record is at position volume ID.
    for( leb = 0; leb < 2; leb++ )
    {
        // Read the VTBL block
        peb = descPtr->vtblPeb[leb];
        LE_DEBUG("Updating reserved_peb in VTBL %u [peb %u]",
                 leb, peb);
        res = FlashSeekAtBlock( desc, peb );
        if (LE_OK != res)
        {
            goto error;
        }
        res = FlashRead( desc, blockPtr, descPtr->mtdInfo.eraseSize);
        if (LE_OK != res)
        {
            goto error;
        }
        // Update the EC header
        ecHeaderPtr = (struct ubi_ec_hdr *)blockPtr;
        UpdateEraseCounter( descPtr, ecHeaderPtr );
        vtblPtr = (struct ubi_vtbl_record *)(blockPtr + be32toh(ecHeaderPtr->data_offset));
        // Set all the record bytes to 0 and update the CRC of this record
        memset(&vtblPtr[descPtr->ubiVolumeId], 0, sizeof(struct ubi_vtbl_record));
        crc = le_crc_Crc32( (uint8_t *)&vtblPtr[descPtr->ubiVolumeId],
                            UBI_VTBL_RECORD_SIZE_CRC,
                            LE_CRC_START_CRC32 );
        vtblPtr[descPtr->ubiVolumeId].crc = htobe32(crc);
        // Erase the VTBL block
        res = FlashEraseBlock( desc, peb );
        if (LE_OK != res)
        {
            goto error;
        }
        res = FlashSeekAtBlock( desc, peb );
        if (LE_OK != res)
        {
            goto error;
        }
        // Write the VTBL block
        LE_INFO("PEB %u: Write VTBL, LNUM %u", peb, leb);
        res = FlashWrite( desc, blockPtr, descPtr->mtdInfo.eraseSize );
        if (LE_OK != res)
        {
            goto error;
        }
    }

    le_mem_Release(blockPtr);
    return pa_flash_UnscanUbi(desc);

error:
    if (blockPtr)
    {
        le_mem_Release(blockPtr);
    }
    (void)pa_flash_UnscanUbi(desc);
    return res;
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
    pa_flash_MtdDesc_t *descPtr = (pa_flash_MtdDesc_t *)desc;
    uint32_t peb, blockIndex;
    off_t offset;

    if( (!descPtr) || (descPtr->magic != desc) )
    {
        return LE_BAD_PARAMETER;
    }

    // Get current offset inside the flash
    offset = lseek(descPtr->fd, 0, SEEK_CUR);
    if( -1 == offset )
    {
        LE_ERROR("MTD %d: lseek fails to return current offset: %m", descPtr->mtdNum);
        return (EIO == errno) ? LE_IO_ERROR : LE_FAULT;
    }
    // Compute the LEB related to the given ofsfet
    peb = (offset / descPtr->mtdInfo.eraseSize );
    blockIndex = peb;
    if( descPtr->scanDone )
    {
        // Fetch the LEB linked to the PEB.
        for( blockIndex = 0; blockIndex < descPtr->mtdInfo.nbLeb; blockIndex++ )
        {
            if( peb == descPtr->lebToPeb[blockIndex] )
            {
                break;
            }
        }
        // No LEB linked. Offset is invalid
        if( blockIndex == descPtr->mtdInfo.nbLeb )
        {
            return LE_NOT_PERMITTED;
        }
    }

    if( offsetPtr )
    {
        *offsetPtr = (blockIndex * descPtr->mtdInfo.eraseSize)
                         + (offset & (descPtr->mtdInfo.eraseSize - 1));
    }
    if( blockIndexPtr )
    {
        *blockIndexPtr = blockIndex;
    }
    if( absOffsetPtr )
    {
        *absOffsetPtr = offset;
    }
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
le_result_t pa_flash_SeekAtAbsOffset
(
    pa_flash_Desc_t desc,
    off_t offset
)
{
    pa_flash_MtdDesc_t *descPtr = (pa_flash_MtdDesc_t *)desc;
    int rc;

    if( (!descPtr) || (descPtr->magic != desc) )
    {
        return LE_BAD_PARAMETER;
    }

    if( offset > descPtr->mtdInfo.size )
    {
        return LE_OUT_OF_RANGE;
    }

    rc = lseek(descPtr->fd, offset, SEEK_SET);
    if( -1 == rc )
    {
        LE_ERROR("MTD %d: lseek fails at peb %lu offset %lx: %m",
                 descPtr->mtdNum, offset / descPtr->mtdInfo.eraseSize, offset);
        return (EIO == errno) ? LE_IO_ERROR : LE_FAULT;
    }
    return LE_OK;
}
