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
 * Wear-Leveling threshold: when (max - min) erase counter is greater than this threshold, UBI will
 * perform wear-leveling on the block.
 */
//--------------------------------------------------------------------------------------------------
#ifdef CONFIG_MTD_UBI_WL_THRESHOLD
#define WL_THRESHOLD CONFIG_MTD_UBI_WL_THRESHOLD
#else
#define WL_THRESHOLD UINT_MAX
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
    pa_flash_Info_t *infoPtr  ///< pointer to flash informations
)
{
    infoPtr->ubiVolFreeSize = infoPtr->ubiPebFreeCount * (infoPtr->eraseSize -
                                                          (PEB_HDR_NB_BLOCKS * infoPtr->writeSize));
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
    pa_flash_MtdDesc_t *descPtr = (pa_flash_MtdDesc_t *)desc;
    pa_flash_Info_t *infoPtr = &descPtr->mtdInfo;
    uint64_t ec, pec = INVALID_ERASECOUNTER;
    struct ubi_ec_hdr *ecHdrPtr;
    struct ubi_vid_hdr *vidHdrPtr;
    off_t blkOff;
    int ieb, peb = - 1;
    bool isBad;
    uint32_t badBlkCnt = 0;
    int32_t badBlkDiff;
    le_result_t res;

    for( ieb = 0; ieb < infoPtr->nbBlk; ieb++ )
    {
        if( (INVALID_PEB != descPtr->lebToPeb[ieb]) ||
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
        if (LE_OK != res )
        {
            return res;
        }
        res = pa_flash_Read( desc,
                             blockPtr,
                             (infoPtr->writeSize * 2));
        if (LE_OK != res )
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
            if( (ec < *ecPtr) && (ec < pec) )
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
    struct ubi_ec_hdr* ecHdrPtr,          ///< [IN] Pointer to a UBI EC header
    uint64_t*          meanEraseCountPtr  ///< [IN][OUT] Pointer the mean of EC count
)
{
    uint64_t ec;
    uint32_t crc;

    ec = be64toh(ecHdrPtr->ec) + 1;
    if( ec > UBI_MAX_ERASECOUNTER )
    {
        ec = ((meanEraseCountPtr) ? *meanEraseCountPtr : UBI_MAX_ERASECOUNTER);
    }
    if( meanEraseCountPtr )
    {
        (*meanEraseCountPtr) = (*meanEraseCountPtr + ec) / 2;
    }
    if( descPtr->mtdInfo.ubiMinEraseCount > ec )
    {
        descPtr->mtdInfo.ubiMinEraseCount = ec;
    }
    if( descPtr->mtdInfo.ubiMaxEraseCount < ec )
    {
        descPtr->mtdInfo.ubiMaxEraseCount = ec;
    }
    ecHdrPtr->ec = htobe64(ec);
    crc = le_crc_Crc32( (uint8_t *)ecHdrPtr, UBI_EC_HDR_SIZE_CRC, LE_CRC_START_CRC32 );
    ecHdrPtr->hdr_crc = htobe32(crc);
}

//--------------------------------------------------------------------------------------------------
/**
 * Update the reserved_pebs field from a Volume ID header to the new given value
 */
//--------------------------------------------------------------------------------------------------
static void UpdateReservedPebs
(
    struct ubi_vid_hdr* vidHdrPtr,    ///< [IN] Pointer to a UBI VID header
    uint32_t            reservedPebs  ///< [IN] New reserved PEBs value
)
{
    uint32_t crc;

    vidHdrPtr->used_ebs = htobe32(reservedPebs);
    crc = le_crc_Crc32( (uint8_t *)vidHdrPtr, UBI_VID_HDR_SIZE_CRC, LE_CRC_START_CRC32 );
    vidHdrPtr->hdr_crc = htobe32(crc);
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
    uint64_t*       meanEraseCountPtr  ///< [IN][OUT] Pointer the mean of EC count
)
{
    pa_flash_MtdDesc_t *descPtr = (pa_flash_MtdDesc_t *)desc;
    uint32_t blk;
    struct ubi_ec_hdr *ecHdrPtr;
    struct ubi_vid_hdr *vidHdrPtr;
    off_t blkOff;
    le_result_t res;

    if( descPtr->vtblPtr->vol_type == UBI_VID_STATIC )
    {
        for( blk = 0;
             (blk < reservedPebs) && (INVALID_PEB != descPtr->lebToPeb[blk]);
             blk++ )
        {
            blkOff = descPtr->lebToPeb[blk] * descPtr->mtdInfo.eraseSize;
            res = pa_flash_SeekAtOffset( desc, blkOff );
            if (LE_OK != res )
            {
                return res;
            }
            res = pa_flash_Read( desc,
                                 blockPtr,
                                 descPtr->mtdInfo.eraseSize );
            if (LE_OK != res )
            {
                return res;
            }
            res = pa_flash_EraseBlock( desc, blkOff / descPtr->mtdInfo.eraseSize );
            if (LE_OK != res)
            {
                return res;
            }
            res = pa_flash_SeekAtOffset( desc, blkOff );
            if (LE_OK != res )
            {
                 return res;
            }

            ecHdrPtr = (struct ubi_ec_hdr *)blockPtr;
            UpdateEraseCounter( descPtr, ecHdrPtr, meanEraseCountPtr );
            vidHdrPtr = (struct ubi_vid_hdr *)(blockPtr + be32toh(ecHdrPtr->vid_hdr_offset));
            UpdateReservedPebs( vidHdrPtr, reservedPebs );
            LE_DEBUG("Update VID Header at %lx: used_ebs %x, hdr_crc %x",
                     blkOff, be32toh(vidHdrPtr->used_ebs), be32toh(vidHdrPtr->hdr_crc));

            LE_DEBUG("Write EC+VID at %lx: size %x", blkOff, descPtr->mtdInfo.eraseSize);
            res = pa_flash_Write( desc,
                                  blockPtr,
                                  descPtr->mtdInfo.eraseSize );
            if (LE_OK != res)
            {
                return res;
            }
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
        if (LE_OK != res )
        {
            return res;
        }
        res = pa_flash_Read( desc,
                             blockPtr,
                             descPtr->mtdInfo.writeSize);
        if (LE_OK != res )
        {
            return res;
        }
        UpdateEraseCounter( descPtr, (struct ubi_ec_hdr *)blockPtr, NULL );
        res = pa_flash_EraseBlock( desc, blkOff / descPtr->mtdInfo.eraseSize );
        if (LE_OK != res)
        {
            return res;
        }
        res = pa_flash_SeekAtOffset( desc, blkOff );
        if (LE_OK != res )
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
        if (LE_OK != res )
        {
            return res;
        }
        res = pa_flash_Read( desc,
                             blockPtr,
                             descPtr->mtdInfo.eraseSize);
        if (LE_OK != res )
        {
            return res;
        }
        ecHdrPtr = (struct ubi_ec_hdr *)blockPtr;
        UpdateEraseCounter( descPtr, ecHdrPtr, NULL );
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
        if (LE_OK != res )
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
    pa_flash_MtdDesc_t *descPtr = (pa_flash_MtdDesc_t *)desc;
    le_result_t res;
    uint32_t crc;
    int i;
    uint64_t ec;

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

    ec = be64toh(ecHeaderPtr->ec);
    if( descPtr->mtdInfo.ubiMinEraseCount > ec )
    {
        descPtr->mtdInfo.ubiMinEraseCount = ec;
    }
    if( descPtr->mtdInfo.ubiMaxEraseCount < ec )
    {
        descPtr->mtdInfo.ubiMaxEraseCount = ec;
    }
    LE_DEBUG("PEB %lx : MAGIC %c%c%c%c, EC %lld (min %lld max %lld), VID %x DATA %x CRC %x",
             physEraseBlock,
             ((char *)&(ecHeaderPtr->magic))[0],
             ((char *)&(ecHeaderPtr->magic))[1],
             ((char *)&(ecHeaderPtr->magic))[2],
             ((char *)&(ecHeaderPtr->magic))[3],
             be64toh(ecHeaderPtr->ec),
             descPtr->mtdInfo.ubiMinEraseCount,
             descPtr->mtdInfo.ubiMaxEraseCount,
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
 * Check if the UBI partition was externally modified since it was opened. At the first call, update
 * the Erase Counter (EC) min and max values. This may be also done by calling pa_flash_ScanUbi().
 * At the next calls, verify that the EC values are these expected: return true into the isGoodPtr
 * if the integrity of the UBI partition is good. Else, this parameter is returned to false.
 *
 * The integrity is controlled by comparing the previous and current max and min EC values. If they
 * differ, it is that an external update of EC was done outside the PA, because the PA will update
 * these values.
 * In a same way, if the wear-leveling threshold is greater than max EC - min EC, we considere that
 * potentially the wear-leveling will be triggered by UBI layers.
 *
 * @return
 *      - LE_OK            On success
 *      - LE_BAD_PARAMETER If desc is NULL or is not a valid descriptor
 *      - LE_FAULT         On failure
 *      - LE_IO_ERROR      If a flash IO error occurs
 *      - LE_FORMAT_ERROR  If the flash is not in UBI format
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_flash_CheckUbiIntegrity
(
    pa_flash_Desc_t desc,        ///< [IN]  Private flash descriptor
    bool *isGoodPtr              ///< [OUT] true if integrity is good, false otherwise
)
{
    pa_flash_MtdDesc_t *descPtr = (pa_flash_MtdDesc_t *)desc;
    pa_flash_MtdDesc_t descTemp;
    pa_flash_Desc_t descTempPtr = (pa_flash_Desc_t)&descTemp;
    uint32_t peb;
    struct ubi_ec_hdr ecHeader;
    off_t pebOffset;
    bool isBad;
    le_result_t res;
    pa_flash_Info_t *infoPtr = &(descPtr->mtdInfo);
    pa_flash_Info_t *infoTempPtr = &(descTemp.mtdInfo);

    if( (!descPtr) || (descPtr->magic != desc) || (!isGoodPtr) )
    {
        return LE_BAD_PARAMETER;
    }

    *isGoodPtr = false;
    memcpy(&descTemp, descPtr, sizeof(descTemp));
    descTemp.magic = &descTemp;
    for( peb = 0; peb < infoPtr->nbBlk; peb++ )
    {
        LE_DEBUG("Check if bad block at peb %u", peb);
        res = pa_flash_CheckBadBlock( descTempPtr, peb, &isBad );
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
        res = ReadEcHeader( descTempPtr, pebOffset, &ecHeader, true );
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
            return LE_FORMAT_ERROR;
        }
        else if (LE_OK != res )
        {
            goto error;
        }
    }

    *isGoodPtr = true;
    if( !infoPtr->ubi )
    {
        // First call of this service for a partition. Just update the min and max EC
        // This is also filled when pa_flash_ScanUbi() is called.
        infoPtr->ubiMinEraseCount = infoTempPtr->ubiMinEraseCount;
        infoPtr->ubiMaxEraseCount = infoTempPtr->ubiMaxEraseCount;
        infoPtr->ubiWlThreshold = WL_THRESHOLD;
        infoPtr->ubi = true;
        // No check to do for the first call.
        return LE_OK;
    }

    // If wear-leveling threshold is over EC (max - min), the UBI layer may have start
    // the wear-leveling mechanism on this partition.
    // If the EC max or EC min have changed during the copy, the UBI layer may have
    // performed a scrubbing on this partition.
    // If a case above is true, we recompute the checksum to ensure that the source
    // was not modified by the UBI layer during the copy.
    if( ((infoTempPtr->ubiMaxEraseCount - infoTempPtr->ubiMinEraseCount) >= WL_THRESHOLD) ||
        ((infoTempPtr->ubiMaxEraseCount != infoPtr->ubiMaxEraseCount) ||
         (infoTempPtr->ubiMinEraseCount != infoPtr->ubiMinEraseCount)) )
    {
        LE_ERROR("MTD %d was modified outside PA UBI", descPtr->mtdNum);
        LE_ERROR("Open   : Min EC %lld Max EC %lld WL threshold %u",
                 infoPtr->ubiMinEraseCount, infoPtr->ubiMaxEraseCount, WL_THRESHOLD);
        LE_ERROR("Checked: Min EC %lld Max EC %lld WL threshold %u",
                 infoTempPtr->ubiMinEraseCount, infoTempPtr->ubiMaxEraseCount, WL_THRESHOLD);
        *isGoodPtr = false;
    }
    return LE_OK;

error:
    return LE_FAULT;
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
    pa_flash_MtdDesc_t *descPtr = (pa_flash_MtdDesc_t *)desc;
    uint32_t peb;
    struct ubi_ec_hdr ecHeader;
    struct ubi_vid_hdr vidHeader;
    off_t pebOffset;
    bool isBad;
    uint32_t iVtblPeb = 0;
    le_result_t res;
    pa_flash_Info_t *infoPtr = &descPtr->mtdInfo;

    if( (!descPtr) || (descPtr->magic != desc) || (ubiVolId >= PA_FLASH_UBI_MAX_VOLUMES) )
    {
        return LE_BAD_PARAMETER;
    }

    descPtr->scanDone = false;
    descPtr->ubiBadBlkCnt = 0;
    infoPtr->nbLeb = infoPtr->nbBlk;
    infoPtr->ubi = false;
    infoPtr->ubiPebFreeCount = 0;
    infoPtr->ubiVolFreeSize = 0;
    infoPtr->ubiMinEraseCount = 0;
    infoPtr->ubiMaxEraseCount = 0;
    infoPtr->ubiWlThreshold = 0;
    descPtr->ubiVolumeId = INVALID_UBI_VOLUME;
    memset( descPtr->vtbl, 0, sizeof(struct ubi_vtbl_record) * PA_FLASH_UBI_MAX_VOLUMES);
    memset( descPtr->vtblPeb, -1, sizeof(descPtr->vtblPeb));
    memset( descPtr->lebToPeb, -1, sizeof(descPtr->lebToPeb));

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
        if (LE_FORMAT_ERROR == res )
        {
            infoPtr->ubiPebFreeCount++;
            continue;
        }
        else if (LE_OK != res )
        {
            goto error;
        }
        res = ReadVidHeader( descPtr, pebOffset, &vidHeader, be32toh(ecHeader.vid_hdr_offset) );
        if (LE_FORMAT_ERROR == res )
        {
            infoPtr->ubiPebFreeCount++;
            continue;
        }
        if (LE_OK != res )
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
        else if ((be32toh(vidHeader.vol_id) < PA_FLASH_UBI_MAX_VOLUMES) &&
                 (be32toh(vidHeader.vol_id) == ubiVolId))
        {
            descPtr->ubiOffset = be32toh(ecHeader.data_offset);
            descPtr->lebToPeb[be32toh(vidHeader.lnum)] = peb;
            descPtr->vtblPtr = &(descPtr->vtbl[ubiVolId]);
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
    descPtr->mtdInfo.ubiWlThreshold = WL_THRESHOLD;
    descPtr->ubiVolumeId = ubiVolId;
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
    pa_flash_MtdDesc_t *descPtr = (pa_flash_MtdDesc_t *)desc;
    pa_flash_Info_t *infoPtr = &descPtr->mtdInfo;

    if( (!descPtr) || (descPtr->magic != desc))
    {
        return LE_BAD_PARAMETER;
    }

    infoPtr->nbLeb = infoPtr->nbBlk;
    infoPtr->ubi = false;
    descPtr->ubiVolumeId = INVALID_UBI_VOLUME;
    memset( descPtr->vtbl, 0, sizeof(struct ubi_vtbl_record) * PA_FLASH_UBI_MAX_VOLUMES);
    memset( descPtr->vtblPeb, -1, sizeof(descPtr->vtblPeb));
    memset( descPtr->lebToPeb, -1, sizeof(descPtr->lebToPeb));
    infoPtr->ubiPebFreeCount = 0;
    infoPtr->ubiVolFreeSize = 0;
    infoPtr->ubiMinEraseCount = 0;
    infoPtr->ubiMaxEraseCount = 0;
    infoPtr->ubiWlThreshold = 0;
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
    size_t size = *dataSizePtr;
    uint32_t peb, nbLeb;
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
    LE_DEBUG("LEB %d/%u PEB %d : Read %x at block offset %lx",
             leb, nbLeb, peb, size, blkOff);
    res = pa_flash_SeekAtOffset( desc, (off_t)(blkOff) + (off_t)descPtr->ubiOffset );
    if( LE_OK != res )
    {
        goto error;
    }
    res = pa_flash_Read( desc, dataPtr, size);
    if (LE_OK != res )
    {
        goto error;
    }

    *dataSizePtr = size;
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
    uint64_t eraseCount, meanEraseCount;
    struct ubi_ec_hdr* ecHdrPtr;
    struct ubi_vid_hdr* vidHdrPtr;
    uint8_t* blockPtr = NULL;
    off_t dataOffset;
    le_result_t res;

    if( (!descPtr) || (descPtr->magic != desc) || (!dataPtr) )
    {
        return LE_BAD_PARAMETER;
    }

    if( (!descPtr->mtdInfo.ubi) || (descPtr->ubiVolumeId >= PA_FLASH_UBI_MAX_VOLUMES ) )
    {
        return LE_FORMAT_ERROR;
    }

    reservedPebs = nbLeb = be32toh(descPtr->vtblPtr->reserved_pebs);
    if( (leb > nbLeb) || ((leb == nbLeb) && (!isExtendUbiVolume)) )
    {
        return LE_OUT_OF_RANGE;
    }

    dataOffset = (descPtr->mtdInfo.writeSize * 2);
    if( (!UbiBlockPool) )
    {
        UbiBlockPool = le_mem_CreatePool("UBI Block Pool", descPtr->mtdInfo.eraseSize);
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

        meanEraseCount = blk;
        if( descPtr->vtblPtr->vol_type == UBI_VID_STATIC )
        {
            meanEraseCount = 0;
            res = UpdateAllVidBlock( desc,
                                     blockPtr,
                                     reservedPebs,
                                     &meanEraseCount );
            if (LE_OK != res)
            {
                goto error;
            }
            meanEraseCount /= blk;
        }
        res = UpdateVtbl( desc, blockPtr, reservedPebs );
        if (LE_OK != res)
        {
            goto error;
        }

        eraseCount = meanEraseCount;
        res = GetNewBlock( desc, blockPtr, &eraseCount, &ieb );
        if( LE_OK != res )
        {
            LE_CRIT("Failed to add one block on volume %d", descPtr->ubiVolumeId);
            return res;
        }

        ecHdrPtr = (struct ubi_ec_hdr *)blockPtr;
        if( INVALID_ERASECOUNTER == eraseCount )
        {
            blkOff = descPtr->lebToPeb[0] * descPtr->mtdInfo.eraseSize;
            LE_DEBUG("read UBI block : LEB %d PEB %d (at %lx)",
                    0, descPtr->lebToPeb[0], blkOff);
            LE_DEBUG("Read blk %d, size %lx at %lx",
                    0, dataOffset, blkOff );
            res = pa_flash_SeekAtOffset( desc, blkOff );
            if (LE_OK != res )
            {
                goto error;
            }
            res = pa_flash_Read( desc,
                                 blockPtr,
                                 dataOffset);
            if (LE_OK != res )
            {
                goto error;
            }
        }
        vidHdrPtr = (struct ubi_vid_hdr *)(blockPtr + be32toh(ecHdrPtr->vid_hdr_offset));
        if( ERASED_VALUE_32 == vidHdrPtr->magic )
        {
            blkOff = descPtr->lebToPeb[0] * descPtr->mtdInfo.eraseSize;
            blkOff += be32toh(ecHdrPtr->vid_hdr_offset);
            LE_DEBUG("read UBI block : LEB %d PEB %d (at %lx)",
                    0, descPtr->lebToPeb[0], blkOff);
            LE_DEBUG("Read blk %d, size %lx at %lx",
                    0, dataOffset, blkOff );
            res = pa_flash_SeekAtOffset( desc, blkOff );
            if (LE_OK != res )
            {
                goto error;
            }
            res = pa_flash_Read( desc,
                                 (uint8_t*)vidHdrPtr,
                                 descPtr->mtdInfo.writeSize);
            if (LE_OK != res )
            {
                goto error;
            }
        }
        vidHdrPtr->lnum = htobe32(blk);
        if( descPtr->vtblPtr->vol_type == UBI_VID_STATIC )
        {
            vidHdrPtr->used_ebs = htobe32(reservedPebs);
        }
        crc = le_crc_Crc32( (uint8_t *)vidHdrPtr, UBI_VID_HDR_SIZE_CRC, LE_CRC_START_CRC32 );
        vidHdrPtr->hdr_crc = htobe32(crc);
        descPtr->vtblPtr->reserved_pebs = htobe32(reservedPebs);
        descPtr->lebToPeb[blk] = ieb;
        blkOff = descPtr->lebToPeb[blk] * descPtr->mtdInfo.eraseSize;
        res = pa_flash_SeekAtOffset( desc, blkOff );
        if (LE_OK != res )
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
            blkOff = descPtr->lebToPeb[blk] * descPtr->mtdInfo.eraseSize;
            LE_DEBUG("read UBI block : LEB %d PEB %d (at %lx)",
                     blk, descPtr->lebToPeb[blk], blkOff);
            LE_DEBUG("Read blk %d, size %lx at %lx",
                    blk, dataOffset, blkOff );
            res = pa_flash_SeekAtOffset( desc, blkOff );
            if (LE_OK != res )
            {
                goto error;
            }
            res = pa_flash_Read( desc,
                                 blockPtr,
                                 dataOffset);
            if (LE_OK != res )
            {
                goto error;
            }
        }
        else
        {
            ecHdrPtr = (struct ubi_ec_hdr *)blockPtr;
            if( INVALID_ERASECOUNTER == eraseCount )
            {
                blkOff = descPtr->lebToPeb[0] * descPtr->mtdInfo.eraseSize;
                LE_DEBUG("read UBI block : LEB %d PEB %d (at %lx)",
                        0, descPtr->lebToPeb[0], blkOff);
                LE_DEBUG("Read blk %d, size %lx at %lx",
                        0, dataOffset, blkOff );
                res = pa_flash_SeekAtOffset( desc, blkOff );
                if (LE_OK != res )
                {
                    goto error;
                }
                res = pa_flash_Read( desc,
                                     blockPtr,
                                     dataOffset);
                if (LE_OK != res )
                {
                    goto error;
                }
                ecHdrPtr = (struct ubi_ec_hdr *)blockPtr;
                ecHdrPtr->ec = 0;
            }
            else
            {
                blkOff = descPtr->lebToPeb[blk] * descPtr->mtdInfo.eraseSize;
                blkOff += descPtr->mtdInfo.writeSize;
                LE_DEBUG("read UBI block : LEB %d PEB %d (at %lx)",
                         blk, descPtr->lebToPeb[blk], blkOff);
                LE_DEBUG("Read blk %d, size %lx at %lx",
                        blk, dataOffset, blkOff );
                res = pa_flash_SeekAtOffset( desc, blkOff );
                if (LE_OK != res )
                {
                    goto error;
                }
                res = pa_flash_Read( desc,
                                     blockPtr + descPtr->mtdInfo.writeSize,
                                     dataOffset - descPtr->mtdInfo.writeSize);
                if (LE_OK != res )
                {
                    goto error;
                }
            }
            pebErase = descPtr->lebToPeb[blk];
            descPtr->lebToPeb[blk] = newBlk;
            blkOff = descPtr->lebToPeb[blk] * descPtr->mtdInfo.eraseSize;
        }
    }
    ecHdrPtr = (struct ubi_ec_hdr *)blockPtr;
    LE_INFO("LEB %u, PEB %lu OFFSET %lx, EC %llx",
            blk, blkOff / descPtr->mtdInfo.eraseSize, blkOff, ecHdrPtr->ec);
    UpdateEraseCounter( descPtr, ecHdrPtr, NULL );
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
             blk, dataOffset, blkOff );
    res = pa_flash_EraseBlock( desc, blkOff / descPtr->mtdInfo.eraseSize );
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
    if (LE_OK != res )
    {
        goto error;
    }

    res = pa_flash_SeekAtOffset( desc, blkOff );
    if (LE_OK != res )
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
        blkOff = pebErase * descPtr->mtdInfo.eraseSize;
        LE_DEBUG("read UBI block : LEB %d PEB %d (at %lx)",
                 pebErase, pebErase, blkOff);
        LE_DEBUG("Read blk %d, size %lx at %lx",
                pebErase, dataOffset, blkOff );
        res = pa_flash_SeekAtOffset( desc, blkOff );
        if (LE_OK != res )
        {
            goto error;
        }
        res = pa_flash_Read( desc,
                             blockPtr,
                             descPtr->mtdInfo.writeSize );
        if (LE_OK != res )
        {
            goto error;
        }
        res = pa_flash_EraseBlock( desc, pebErase );
        if( LE_OK != res )
        {
            LE_CRIT("Failed to erase old PEB %u", pebErase);
        }
        ecHdrPtr = (struct ubi_ec_hdr *)blockPtr;
        UpdateEraseCounter( descPtr, ecHdrPtr, NULL );
        res = pa_flash_WriteAtBlock( desc,
                                     blkOff / descPtr->mtdInfo.eraseSize,
                                     blockPtr,
                                     descPtr->mtdInfo.writeSize );
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
    le_result_t res;

    if( (!descPtr) || (descPtr->magic != desc) )
    {
        return LE_BAD_PARAMETER;
    }

    if( (!descPtr->mtdInfo.ubi) || (descPtr->ubiVolumeId >= PA_FLASH_UBI_MAX_VOLUMES ) )
    {
        return LE_UNSUPPORTED;
    }

    dataOffset = (2 *descPtr->mtdInfo.writeSize);
    dataSize = descPtr->mtdInfo.eraseSize - dataOffset;
    reservedPebs = (newSize + (dataSize - 1)) / dataSize;
    LE_DEBUG("Reducing UBI vol %u from %u to %u blocks[last %u]",
             descPtr->ubiVolumeId, be32toh(descPtr->vtblPtr->reserved_pebs),
             reservedPebs, descPtr->lebToPeb[reservedPebs - 1] );
    if( reservedPebs < be32toh(descPtr->vtblPtr->reserved_pebs) )
    {
        if( (!UbiBlockPool) )
        {
            UbiBlockPool = le_mem_CreatePool("UBI Block Pool", descPtr->mtdInfo.eraseSize);
            le_mem_ExpandPool( UbiBlockPool, 1 );
        }
        blockPtr = le_mem_ForceAlloc(UbiBlockPool);

        LE_DEBUG("Starting to reduce reserved_pebs for VolId %d", descPtr->ubiVolumeId);
        res = UpdateAllVidBlock( desc, blockPtr, reservedPebs, NULL );
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
