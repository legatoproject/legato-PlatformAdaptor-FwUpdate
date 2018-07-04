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
#include <linux/../../src/kernel/include/generated/autoconf.h>

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

    memset(ecHdrPtr, 0, sizeof(struct ubi_ec_hdr));
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

    for( ieb = 0; ieb < infoPtr->nbBlk; ieb++ )
    {
        int lebIndex;

        for( lebIndex = 0; (lebIndex < infoPtr->nbBlk); lebIndex++ )
        {
            if( descPtr->lebToPeb[lebIndex] == ieb )
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
        res = pa_flash_SeekAtOffset( desc, blkOff );
        if (LE_OK != res)
        {
            return res;
        }
        res = pa_flash_Read( desc,
                             blockPtr,
                             (infoPtr->writeSize * 2));
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
            LE_INFO("New block at %u: ec %llu", peb, pec);
        }
        else
        {
            if( ec < pec )
            {
                peb = ieb;
                pec = ec;
                LE_INFO("Register block at %u: ec %llu", peb, pec);
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
    LE_INFO("Get block at %u: ec %llu", peb, pec);
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
        if (INVALID_PEB == descPtr->lebToPeb[blockIndex])
        {
            return LE_OUT_OF_RANGE;
        }
        blkOff = descPtr->lebToPeb[blockIndex] * descPtr->mtdInfo.eraseSize;
        res = pa_flash_SeekAtOffset( desc, blkOff );
        if (LE_OK != res)
        {
            return res;
        }
        res = pa_flash_Read( desc,
                             blockPtr,
                             descPtr->mtdInfo.eraseSize );
        if (LE_OK != res)
        {
            return res;
        }
        res = pa_flash_EraseBlock( desc, blkOff / descPtr->mtdInfo.eraseSize );
        if (LE_OK != res)
        {
            return res;
        }
        res = pa_flash_SeekAtOffset( desc, blkOff );
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
        res = pa_flash_Write( desc,
                              blockPtr,
                              descPtr->mtdInfo.eraseSize );
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
             (INVALID_PEB != descPtr->lebToPeb[blk]);
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
    }
    for( blk = reservedPebs;
         (blk < be32toh(descPtr->vtblPtr->reserved_pebs))
             && (INVALID_PEB != descPtr->lebToPeb[blk]);
         blk++ )
    {
        blkOff = descPtr->lebToPeb[blk] * descPtr->mtdInfo.eraseSize;
        LE_DEBUG("Erasing block and updating EC in %u [peb %u]",
                 blk, descPtr->lebToPeb[blk]);
        res = pa_flash_SeekAtOffset( desc, blkOff );
        if (LE_OK != res)
        {
            return res;
        }
        res = pa_flash_Read( desc,
                             blockPtr,
                             descPtr->mtdInfo.writeSize);
        if (LE_OK != res)
        {
            return res;
        }
        UpdateEraseCounter( descPtr, (struct ubi_ec_hdr *)blockPtr );
        res = pa_flash_EraseBlock( desc, blkOff / descPtr->mtdInfo.eraseSize );
        if (LE_OK != res)
        {
            return res;
        }
        res = pa_flash_SeekAtOffset( desc, blkOff );
        if (LE_OK != res)
        {
            return res;
        }

        res = pa_flash_Write( desc,
                              blockPtr,
                              descPtr->mtdInfo.writeSize);
        if (LE_OK != res)
        {
            return res;
        }
        descPtr->lebToPeb[blk] = INVALID_PEB;
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
        res = pa_flash_SeekAtOffset( desc, blkOff );
        if (LE_OK != res)
        {
            return res;
        }
        res = pa_flash_Read( desc,
                             blockPtr,
                             descPtr->mtdInfo.eraseSize);
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
        res = pa_flash_EraseBlock( desc, blkOff / descPtr->mtdInfo.eraseSize );
        if (LE_OK != res)
        {
            return res;
        }
        res = pa_flash_SeekAtOffset( desc, blkOff );
        if (LE_OK != res)
        {
            return res;
        }
        LE_DEBUG("Write VTBL at %lx: size %x", blkOff, descPtr->mtdInfo.eraseSize);
        res = pa_flash_Write( desc,
                              blockPtr,
                              descPtr->mtdInfo.eraseSize);
        if (LE_OK != res)
        {
            return res;
        }
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

    res = pa_flash_SeekAtOffset( desc, physEraseBlock );
    if( LE_OK != res )
    {
        return res;
    }
    if (LE_OK != pa_flash_Read( desc, (uint8_t*)ecHeaderPtr, UBI_EC_HDR_SIZE ) )
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

    LE_DEBUG("PEB %lx : MAGIC %c%c%c%c, EC %lld, VID %x DATA %x CRC %x",
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

    res = pa_flash_SeekAtOffset( desc, physEraseBlock + vidOffset );
    if( LE_OK != res )
    {
        return res;
    }
    if (LE_OK != pa_flash_Read( desc, (uint8_t*)vidHeaderPtr, UBI_VID_HDR_SIZE ) )
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

    res = pa_flash_SeekAtOffset( desc, physEraseBlock + vtblOffset );
    if( LE_OK != res )
    {
        return res;
    }
    if (LE_OK != pa_flash_Read( desc, (uint8_t*)vtblPtr,
                                PA_FLASH_UBI_MAX_VOLUMES * UBI_VTBL_RECORD_HDR_SIZE ) )
    {
        return res;
    }

    for( i = 0; i < PA_FLASH_UBI_MAX_VOLUMES; i++ )
    {
        if( (INVALID_PEB) == be32toh(vtblPtr[i].reserved_pebs))
            continue;
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
    pa_flash_MtdDesc_t* descPtr = (pa_flash_MtdDesc_t *)desc;
    uint32_t peb;
    struct ubi_ec_hdr ecHeader;
    off_t pebOffset;
    bool isBad;
    pa_flash_Info_t* infoPtr;
    le_result_t res;

    if( (!descPtr) || (descPtr->magic != desc) || (!isUbiPtr) )
    {
        return LE_BAD_PARAMETER;
    }

    infoPtr = &(descPtr->mtdInfo);
    *isUbiPtr = false;
    for( peb = 0; peb < infoPtr->nbBlk; peb++ )
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
    }

    *isUbiPtr = true;
    return LE_OK;

error:
    return (LE_IO_ERROR == res ? LE_IO_ERROR : LE_FAULT);
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
    pa_flash_Desc_t desc,            ///< [IN] Private flash descriptor
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
        return LE_BUSY;
    }
    memset(descPtr->vtbl, 0, sizeof(struct ubi_vtbl_record) * PA_FLASH_UBI_MAX_VOLUMES);
    memset(descPtr->vtblPeb, -1, sizeof(descPtr->vtblPeb));
    memset(descPtr->lebToPeb, -1, sizeof(descPtr->lebToPeb));
    for( peb = 0; (peb < infoPtr->nbBlk); peb++ )
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

    if( (INVALID_PEB == descPtr->vtblPeb[0]) ||
        (INVALID_PEB == descPtr->vtblPeb[1]) )
    {
        LE_ERROR("No volume present on MTD %d or NOT an UBI", descPtr->mtdNum);
        return LE_FORMAT_ERROR;
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
    return (LE_IO_ERROR == res ? LE_IO_ERROR : LE_FAULT);
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

    infoPtr = &descPtr->mtdInfo;
    descPtr->scanDone = false;
    descPtr->ubiBadBlkCnt = 0;
    infoPtr->nbLeb = infoPtr->nbBlk;
    infoPtr->ubi = false;
    infoPtr->ubiPebFreeCount = 0;
    infoPtr->ubiVolFreeSize = 0;
    descPtr->ubiVolumeId = INVALID_UBI_VOLUME;
    descPtr->ubiVolumeSize = UBI_NO_SIZE;
    descPtr->vtblPtr = NULL;
    memset(descPtr->vtbl, 0, sizeof(struct ubi_vtbl_record) * PA_FLASH_UBI_MAX_VOLUMES);
    memset(descPtr->vtblPeb, -1, sizeof(descPtr->vtblPeb));
    memset(descPtr->lebToPeb, -1, sizeof(descPtr->lebToPeb));

    for( peb = 0; peb < infoPtr->nbBlk; peb++ )
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
            descPtr->ubiOffset = be32toh(ecHeader.data_offset);
            descPtr->lebToPeb[be32toh(vidHeader.lnum)] = peb;
            if( UBI_VID_STATIC == vidHeader.vol_type )
            {
                ubiVolSize += be32toh(vidHeader.data_size);
            }
            else
            {
                ubiVolSize += (descPtr->mtdInfo.eraseSize - (2 * descPtr->mtdInfo.writeSize));
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
    LE_DEBUG("mtd %d ubiPebFreeCount %d ubiVolFreeSize %d", descPtr->mtdNum,
             infoPtr->ubiPebFreeCount, infoPtr->ubiVolFreeSize);

    if( (!descPtr->vtblPtr) ||
        (INVALID_PEB == descPtr->vtblPeb[0]) ||
        (INVALID_PEB == descPtr->vtblPeb[1]) )
    {
        LE_ERROR("Volume ID %d not present on MTD %d or NOT an UBI",
                 ubiVolId, descPtr->mtdNum);
        return LE_FORMAT_ERROR;
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
                LE_DEBUG("%u ", descPtr->lebToPeb[j]);
            }
        }
    }
    infoPtr->ubi = true;
    descPtr->ubiVolumeId = ubiVolId;
    descPtr->ubiVolumeSize = ubiVolSize;
    LE_INFO("UBI %u, vol size %u", ubiVolId, ubiVolSize);
    return LE_OK;

error:
    return LE_FAULT;
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
    infoPtr->nbLeb = infoPtr->nbBlk;
    infoPtr->ubi = false;
    descPtr->ubiVolumeId = INVALID_UBI_VOLUME;
    descPtr->vtblPtr = NULL;
    memset(descPtr->vtbl, 0, sizeof(struct ubi_vtbl_record) * PA_FLASH_UBI_MAX_VOLUMES);
    memset(descPtr->vtblPeb, -1, sizeof(descPtr->vtblPeb));
    memset(descPtr->lebToPeb, -1, sizeof(descPtr->lebToPeb));
    infoPtr->ubiPebFreeCount = 0;
    infoPtr->ubiVolFreeSize = 0;
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
    peb = descPtr->lebToPeb[leb];

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
    size = ((*dataSizePtr + descPtr->ubiOffset) > descPtr->mtdInfo.eraseSize)
            ? (descPtr->mtdInfo.eraseSize - descPtr->ubiOffset)
            : *dataSizePtr;
    realSize = ((nbLeb - 1) == leb)
                  ? descPtr->ubiVolumeSize -
                       ((descPtr->mtdInfo.eraseSize - descPtr->ubiOffset) * (nbLeb - 1))
                  : size;
    LE_DEBUG("LEB %u (nbLEB %u) size %u realSize %u", leb, nbLeb, size, realSize);
    if (realSize > size)
    {
        realSize = size;
    }
    LE_DEBUG("LEB %d/%u PEB %d : Read %x at block offset %lx",
             leb, nbLeb, peb, size, blkOff);
    res = pa_flash_SeekAtOffset( desc, (off_t)(blkOff) + (off_t)descPtr->ubiOffset );
    if( LE_OK != res )
    {
        goto error;
    }
    res = pa_flash_Read( desc, dataPtr, realSize);
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
            return res;
        }

        ecHdrPtr = (struct ubi_ec_hdr *)blockPtr;
        if( INVALID_ERASECOUNTER == eraseCount )
        {
            CreateEcHeader(descPtr, ecHdrPtr);
        }

        vidHdrPtr = (struct ubi_vid_hdr *)(blockPtr + be32toh(ecHdrPtr->vid_hdr_offset));
        CreateVidHeader(descPtr, vidHdrPtr, blk, reservedPebs);
        descPtr->vtblPtr->reserved_pebs = htobe32(reservedPebs);
        descPtr->lebToPeb[blk] = ieb;
        blkOff = descPtr->lebToPeb[blk] * infoPtr->eraseSize;
        res = pa_flash_SeekAtOffset( desc, blkOff );
        if (LE_OK != res)
        {
            goto error;
        }
    }
    else
    {
        uint32_t newBlk;

        eraseCount = INT_MAX;
        res = GetNewBlock( desc, blockPtr, &eraseCount, &newBlk );
        if( LE_OK != res )
        {
            blkOff = descPtr->lebToPeb[blk] * infoPtr->eraseSize;
            LE_DEBUG("read UBI block : LEB %d PEB %d (at %lx)",
                     blk, descPtr->lebToPeb[blk], blkOff);
            LE_DEBUG("Read blk %d, size %lx at %lx",
                    blk, dataOffset, blkOff );
            res = pa_flash_SeekAtOffset( desc, blkOff );
            if (LE_OK != res)
            {
                goto error;
            }
            res = pa_flash_Read( desc,
                                 blockPtr,
                                 dataOffset);
            if (LE_OK != res)
            {
                goto error;
            }
        }
        else
        {
            ecHdrPtr = (struct ubi_ec_hdr *)blockPtr;
            if( INVALID_ERASECOUNTER == eraseCount )
            {
                CreateEcHeader(descPtr, ecHdrPtr);

                vidHdrPtr = (struct ubi_vid_hdr*)(blockPtr + be32toh(ecHdrPtr->vid_hdr_offset));
                CreateVidHeader(descPtr, vidHdrPtr, blk, be32toh(descPtr->vtblPtr->reserved_pebs));
            }
            else
            {
                if( INVALID_PEB != descPtr->lebToPeb[blk] )
                {
                    blkOff = descPtr->lebToPeb[blk] * infoPtr->eraseSize;
                    blkOff += infoPtr->writeSize;
                    LE_DEBUG("read UBI block : LEB %d PEB %d (at %lx)",
                             blk, descPtr->lebToPeb[blk], blkOff);
                    LE_DEBUG("Read blk %d, size %lx at %lx",
                            blk, dataOffset, blkOff );
                    res = pa_flash_SeekAtOffset( desc, blkOff );
                    if (LE_OK != res)
                    {
                        goto error;
                    }
                    res = pa_flash_Read(desc,
                                        blockPtr + infoPtr->writeSize,
                                        dataOffset - infoPtr->writeSize);
                    if (LE_OK != res)
                    {
                        goto error;
                    }
                    pebErase = descPtr->lebToPeb[blk];
                }
                else
                {
                    // Create a VID header with the volume ID
                    vidHdrPtr = (struct ubi_vid_hdr*)(blockPtr + be32toh(ecHdrPtr->vid_hdr_offset));
                    CreateVidHeader(descPtr, vidHdrPtr, blk, be32toh(descPtr->vtblPtr->reserved_pebs));
                }
            }
            descPtr->lebToPeb[blk] = newBlk;
            blkOff = descPtr->lebToPeb[blk] * infoPtr->eraseSize;
        }
    }
    ecHdrPtr = (struct ubi_ec_hdr *)blockPtr;
    LE_INFO("LEB %u, PEB %lu OFFSET %lx, EC %llx",
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
    res = pa_flash_EraseBlock( desc, blkOff / infoPtr->eraseSize );
    if (LE_OK != res)
    {
        goto error;
    }

    res = pa_flash_SeekAtOffset(desc, (blkOff + dataOffset));
    if (LE_OK != res)
    {
         goto error;
    }

    LE_DEBUG("Write DATA at %lx: size %x", blkOff + dataOffset, dataSize);
    res = pa_flash_Write(desc, dataPtr, dataSize);
    if (LE_OK != res)
    {
        goto error;
    }

    res = pa_flash_SeekAtOffset( desc, blkOff );
    if (LE_OK != res)
    {
        goto error;
    }

    LE_DEBUG("Update VID Header at %lx: oldsize %x newsize %x, data_crc %x, hdr_crc %x",
             blkOff, be32toh(vidHdrPtr->data_size), dataSize,
             be32toh(vidHdrPtr->data_crc), be32toh(vidHdrPtr->hdr_crc));

    LE_DEBUG("Write EC+VID at %lx: size %lx", blkOff, dataOffset);
    res = pa_flash_Write( desc,
                          blockPtr,
                          dataOffset );
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
        res = pa_flash_SeekAtOffset( desc, blkOff );
        if (LE_OK != res)
        {
            goto error;
        }
        res = pa_flash_Read( desc,
                             blockPtr,
                             infoPtr->writeSize );
        if (LE_OK != res)
        {
            goto error;
        }
        res = pa_flash_EraseBlock( desc, pebErase );
        if( LE_OK != res )
        {
            LE_CRIT("Failed to erase old PEB %u", pebErase);
        }
        ecHdrPtr = (struct ubi_ec_hdr *)blockPtr;
        UpdateEraseCounter( descPtr, ecHdrPtr );
        res = pa_flash_WriteAtBlock( desc,
                                     blkOff / infoPtr->eraseSize,
                                     blockPtr,
                                     infoPtr->writeSize );
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
    LE_DEBUG("Reducing UBI vol %u from %u to %u blocks[last %u] with newSize %u",
             descPtr->ubiVolumeId, be32toh(descPtr->vtblPtr->reserved_pebs),
             reservedPebs, descPtr->lebToPeb[reservedPebs - 1], newSize);
    if( reservedPebs <= be32toh(descPtr->vtblPtr->reserved_pebs) )
    {
        uint32_t lastSize = newSize % dataSize;
        if( (!UbiBlockPool) )
        {
            UbiBlockPool = le_mem_CreatePool("UBI Block Pool", infoPtr->eraseSize);
            le_mem_ExpandPool( UbiBlockPool, 1 );
        }
        blockPtr = le_mem_ForceAlloc(UbiBlockPool);

        if( (reservedPebs == be32toh(descPtr->vtblPtr->reserved_pebs)) )
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

    if( (descPtr->scanDone) || (descPtr->ubiVolumeId >= PA_FLASH_UBI_MAX_VOLUMES) || \
        (!descPtr->vtblPtr))
    {
        return LE_FORMAT_ERROR;
    }

    *freeBlockPtr = descPtr->mtdInfo.ubiPebFreeCount;
    *volBlockPtr = be32toh(descPtr->vtblPtr->reserved_pebs);
    *volSizePtr = descPtr->ubiVolumeSize;
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

    for( peb = 0; peb < infoPtr->nbBlk; peb++ )
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
        res = pa_flash_EraseBlock( desc, peb );
        if (LE_OK != res)
        {
            // Need to mark the block bad !
            continue;
        }
        res = pa_flash_SeekAtOffset( desc, pebOffset );
        if (LE_OK != res)
        {
            goto error;
        }
        // Write the EC header
        res = pa_flash_Write( desc, blockPtr, infoPtr->writeSize );
        if (LE_OK != res)
        {
            goto error;
        }
        LE_INFO("PEB %u: Write UBI EC header, MAGIC %c%c%c%c, EC %lld, VID %x DATA %x CRC %x",
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
            res = pa_flash_SeekAtOffset( desc, peb * infoPtr->eraseSize
                                                  + be32toh(ecHeaderPtr->vid_hdr_offset) );
            if (LE_OK != res)
            {
                goto error;
            }
            // Write the VID header for VTBL layout volume
            res = pa_flash_Write( desc, (uint8_t *)vidHeaderPtr, infoPtr->writeSize );
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
            res = pa_flash_SeekAtOffset( desc, peb * infoPtr->eraseSize
                                                  + be32toh(ecHeaderPtr->data_offset) );
            if (LE_OK != res)
            {
                goto error;
            }
            // Write the VTBL. Align the size to write the write size multiple
            res = pa_flash_Write( desc, (uint8_t *)vtblPtr,
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
            volPebs = 1;
            volType = UBI_VID_STATIC;
            break;
        default:
            return LE_BAD_PARAMETER;
    }

    if (descPtr->scanDone)
    {
        return LE_FORMAT_ERROR;
    }

    res = pa_flash_Unscan(desc);
    if (LE_OK != res)
    {
        return res;
    }
    res = pa_flash_ScanUbiForVolumes(desc, NULL, NULL);
    if (LE_OK != res)
    {
        goto error_unscan;
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
    if ((descPtr->mtdInfo.nbBlk - usedPebs) < volPebs)
    {
        LE_ERROR("MTD%u: UBI volume %u requires too many PEBs %u, only %u free PEBs",
                 descPtr->mtdNum, ubiVolId, volPebs, (descPtr->mtdInfo.nbBlk - usedPebs));
        res = LE_NO_MEMORY;
        goto error_unscan;
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

    // We need at least one block free to create the volume
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
        res = pa_flash_SeekAtBlock( desc, volPeb );
        if (LE_OK != res)
        {
            volPeb = (uint32_t)-1;
            goto error;
        }
        res = pa_flash_Write( desc, (uint8_t*)ecHeaderPtr, infoPtr->writeSize );
        if (LE_OK != res)
        {
            goto error;
        }
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
      vidHeaderPtr->used_ebs = htobe32(1);
      crc = le_crc_Crc32( (uint8_t *)vidHeaderPtr,
                          UBI_VID_HDR_SIZE_CRC, LE_CRC_START_CRC32 );
      vidHeaderPtr->hdr_crc = htobe32(crc);
      res = pa_flash_SeekAtOffset( desc,
                                   volPeb * infoPtr->eraseSize
                                       + htobe32(ecHeaderPtr->vid_hdr_offset) );
      if (LE_OK != res)
      {
          goto error;
      }
      res = pa_flash_Write( desc, (uint8_t*)vidHeaderPtr, infoPtr->writeSize );
      if (LE_OK != res)
      {
          goto error;
      }
    }

    // Update the VTBL to register the new volume name at volume ID position
    memset(blockPtr, 0xFF, infoPtr->eraseSize);
    for( leb = 0; leb < 2; leb++ )
    {
        // Read the VTBL block
        peb = descPtr->vtblPeb[leb];
        LE_DEBUG("Updating reserved_peb in VTBL %u [peb %u]",
                 leb, peb);
        res = pa_flash_SeekAtBlock( desc, peb );
        if (LE_OK != res)
        {
            goto error;
        }
        res = pa_flash_Read( desc,
                             blockPtr,
                             descPtr->mtdInfo.eraseSize);
        if (LE_OK != res)
        {
            goto error;
        }
        // Update the EC header
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
        crc = le_crc_Crc32( (uint8_t *)&vtblPtr[ubiVolId],
                            UBI_VTBL_RECORD_SIZE_CRC,
                            LE_CRC_START_CRC32 );
        vtblPtr[ubiVolId].crc = htobe32(crc);
        // Erase the VTBL block
        res = pa_flash_EraseBlock( desc, peb );
        if (LE_OK != res)
        {
            goto error;
        }
        res = pa_flash_SeekAtBlock( desc, peb );
        if (LE_OK != res)
        {
            goto error;
        }
        // Update the whole VTBL block
        LE_INFO("PEB %u: Write VTBL, LNUM %u", peb, leb);
        res = pa_flash_Write( desc,
                              blockPtr,
                              descPtr->mtdInfo.eraseSize);
        if (LE_OK != res)
        {
            goto error;
        }
    }

    le_mem_Release(blockPtr);
    return pa_flash_UnscanUbi(desc);

    return LE_OK;

error:
    if ((uint32_t)-1 != volPeb)
    {
        pa_flash_EraseBlock( desc, volPeb );
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

    if (descPtr->scanDone)
    {
        return LE_FORMAT_ERROR;
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
        peb = descPtr->lebToPeb[leb];
        if (-1 == peb)
        {
            LE_ERROR("LEB %u: Invalid PEB for volume %u", leb, ubiVolId);
            continue;
        }
        res = pa_flash_SeekAtBlock( desc, peb );
        if (LE_OK != res)
        {
            goto error;
        }
        // Read the EC header from the block
        res = pa_flash_Read( desc, blockPtr, infoPtr->writeSize );
        if (LE_OK != res)
        {
            goto error;
        }
        // Erase the block
        res = pa_flash_EraseBlock( desc, peb );
        if (LE_OK != res)
        {
            // Do markBad ?
        }
        // Update the EC, erase the block and write the EC header
        UpdateEraseCounter(descPtr, ecHeaderPtr);
        res = pa_flash_SeekAtBlock( desc, peb );
        if (LE_OK != res)
        {
            goto error;
        }
        res = pa_flash_Write( desc, blockPtr, infoPtr->writeSize );
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
        res = pa_flash_SeekAtBlock( desc, peb );
        if (LE_OK != res)
        {
            goto error;
        }
        res = pa_flash_Read( desc,
                             blockPtr,
                             descPtr->mtdInfo.eraseSize);
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
        res = pa_flash_EraseBlock( desc, peb );
        if (LE_OK != res)
        {
            goto error;
        }
        res = pa_flash_SeekAtBlock( desc, peb );
        if (LE_OK != res)
        {
            goto error;
        }
        // Write the VTBL block
        LE_INFO("PEB %u: Write VTBL, LNUM %u", peb, leb);
        res = pa_flash_Write( desc,
                              blockPtr,
                              descPtr->mtdInfo.eraseSize);
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
