/**
 * @file pa_flash_ubi.c
 *
 * Implementation of UBI low level flash access
 *
 * Copyright (C) Sierra Wireless Inc.
 *
 */

#include <netinet/in.h>
#include "legato.h"
#include "flash-ubi.h"
#include "pa_flash.h"
#include "pa_flash_local.h"

//--------------------------------------------------------------------------------------------------
/**
 * Pool for the blocks required for UBI low level fucntions
 */
//--------------------------------------------------------------------------------------------------
static le_mem_PoolRef_t UbiBlockPool = NULL;

//--------------------------------------------------------------------------------------------------
/**
 * Read the UBI EC (Erase Count) header at the given block, check for validity and store it into
 * the buffer pointer.
 *
 * @return
 *      - LE_OK            On success
 *      - LE_FAULT         On failure
 *      - others           Depending of the flash operations
 */
//--------------------------------------------------------------------------------------------------
static le_result_t ReadEcHeader
(
    pa_flash_Desc_t desc,          ///< [IN] File descriptor to the flash device
    off_t physEraseBlock,          ///< [IN] Physcal erase block (PEB) to read
    struct ubi_ec_hdr *ecHeaderPtr ///< [IN] Buffer to store read data
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
        LE_DEBUG("Block %lx is erased\n", physEraseBlock );
        return LE_FORMAT_ERROR;
    }

    if ((uint32_t)UBI_EC_HDR_MAGIC != ntohl(ecHeaderPtr->magic))
    {
        LE_ERROR( "Bad magic at %lx: Expected %x, received %x\n",
                  physEraseBlock, UBI_EC_HDR_MAGIC, ntohl(ecHeaderPtr->magic));
        return LE_FAULT;
    }

    if (UBI_VERSION != ecHeaderPtr->version)
    {
        LE_ERROR( "Bad version at %lx: Expected %d, received %d\n",
                  physEraseBlock, UBI_VERSION, ecHeaderPtr->version);
        return LE_FAULT;
    }

    crc = le_crc_Crc32((uint8_t*)ecHeaderPtr, UBI_EC_HDR_SIZE_CRC, LE_CRC_START_CRC32);
    if (ntohl(ecHeaderPtr->hdr_crc) != crc)
    {
        LE_ERROR( "Bad CRC at %lx: Calculated %x, received %x\n",
                  physEraseBlock, crc, ntohl(ecHeaderPtr->hdr_crc));
        return LE_FAULT;
    }

    LE_DEBUG( "PEB %lx : MAGIC %c%c%c%c, EC %lld, VID %x DATA %x CRC %x\n",
              physEraseBlock,
              ((char *)&(ecHeaderPtr->magic))[0],
              ((char *)&(ecHeaderPtr->magic))[1],
              ((char *)&(ecHeaderPtr->magic))[2],
              ((char *)&(ecHeaderPtr->magic))[3],
              ecHeaderPtr->ec,
              ntohl(ecHeaderPtr->vid_hdr_offset),
              ntohl(ecHeaderPtr->data_offset),
              ntohl(ecHeaderPtr->hdr_crc) );

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
    pa_flash_Desc_t desc,          ///< [IN] File descriptor to the flash device
    off_t physEraseBlock,          ///< [IN] Physcal erase block (PEB) to read
    struct ubi_vid_hdr *vidHeaderPtr,  ///< [IN] Pointer to the VID header
    off_t vidOffset                ///< [IN] Offset of VID header in physical block
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
        LE_DEBUG("Block %lx is erased\n", physEraseBlock );
        return LE_FORMAT_ERROR;
    }

    if ((uint32_t)UBI_VID_HDR_MAGIC != ntohl(vidHeaderPtr->magic))
    {
        LE_ERROR( "Bad magic at %lx: Expected %x, received %x\n",
            physEraseBlock, UBI_VID_HDR_MAGIC, ntohl(vidHeaderPtr->magic));
        return LE_FAULT;
    }

    if (UBI_VERSION != vidHeaderPtr->version)
    {
        LE_ERROR( "Bad version at %lx: Expected %d, received %d\n",
            physEraseBlock, UBI_VERSION, vidHeaderPtr->version);
        return LE_FAULT;
    }

    crc = LE_CRC_START_CRC32;
    crc = le_crc_Crc32((uint8_t*)vidHeaderPtr, UBI_VID_HDR_SIZE_CRC, crc);
    if (ntohl(vidHeaderPtr->hdr_crc) != crc)
    {
        LE_ERROR( "Bad CRC at %lx: Calculated %x, received %x\n",
            physEraseBlock, crc, ntohl(vidHeaderPtr->hdr_crc));
        return LE_FAULT;
    }

    if( ntohl(vidHeaderPtr->vol_id) < PA_FLASH_UBI_MAX_VOLUMES )
    {
        LE_DEBUG("PEB : %lx, MAGIC %c%c%c%c, VER %hhd, VT %hhd CP %hhd CT %hhd VID "
                 "%x LNUM %x DSZ %x EBS %x DPD %x DCRC %x CRC %x\n", physEraseBlock,
                 ((char *)&(vidHeaderPtr->magic))[0],
                 ((char *)&(vidHeaderPtr->magic))[1],
                 ((char *)&(vidHeaderPtr->magic))[2],
                 ((char *)&(vidHeaderPtr->magic))[3],
                 (vidHeaderPtr->version),
                 (vidHeaderPtr->vol_type),
                 (vidHeaderPtr->copy_flag),
                 (vidHeaderPtr->compat),
                 ntohl(vidHeaderPtr->vol_id),
                 ntohl(vidHeaderPtr->lnum),
                 ntohl(vidHeaderPtr->data_size),
                 ntohl(vidHeaderPtr->used_ebs),
                 ntohl(vidHeaderPtr->data_pad),
                 ntohl(vidHeaderPtr->data_crc),
                 ntohl(vidHeaderPtr->hdr_crc) );
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
    pa_flash_Desc_t desc,          ///< [IN] File descriptor to the flash device
    off_t physEraseBlock,          ///< [IN] Physcal erase block (PEB) to read
    struct ubi_vtbl_record *vtblPtr,  ///< [IN] Pointer to the VTBL
    off_t vtblOffset               ///< [IN] Offset of VTBL in physical block
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
        if( ((uint32_t)-1) == ntohl(vtblPtr[i].reserved_pebs))
            continue;
        crc = le_crc_Crc32((uint8_t*)&vtblPtr[i], UBI_VTBL_RECORD_SIZE_CRC, LE_CRC_START_CRC32);
        if( ntohl(vtblPtr[i].crc) != crc )
        {
            LE_ERROR("VID %d : Bad CRC %x expected %x\n", i, crc, ntohl(vtblPtr[i].crc));
            return LE_FAULT;
        }
        if( vtblPtr[i].vol_type )
        {
            LE_DEBUG( "VID %d RPEBS %u AL %X RPD %X VT %X UPDM %X NL %X \"%s\" FL %X CRC %X\n",
                      i,
                      ntohl(vtblPtr[i].reserved_pebs),
                      ntohl(vtblPtr[i].alignment),
                      ntohl(vtblPtr[i].data_pad),
                      vtblPtr[i].vol_type,
                      vtblPtr[i].upd_marker,
                      ntohs(vtblPtr[i].name_len),
                      vtblPtr[i].name,
                      vtblPtr[i].flags,
                      ntohl(vtblPtr[i].crc));
        }
    }
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
    uint32_t ubiVolId         ///< [IN] UBI volume ID
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

    if( (!descPtr) || (descPtr->magic != desc) || (ubiVolId >= PA_FLASH_UBI_MAX_VOLUMES) )
    {
        return LE_BAD_PARAMETER;
    }

    descPtr->scanDone = false;
    descPtr->mtdInfo.nbLeb = descPtr->mtdInfo.nbBlk;
    descPtr->mtdInfo.ubi = false;
    descPtr->ubiVolumeId = (uint32_t)-1;
    memset( descPtr->vtbl, 0, sizeof(struct ubi_vtbl_record) * PA_FLASH_UBI_MAX_VOLUMES);
    memset( descPtr->vtblPeb, -1, sizeof(descPtr->vtblPeb));
    memset( descPtr->lebToPeb, -1, sizeof(descPtr->lebToPeb));

    for( peb = 0; peb < descPtr->mtdInfo.nbBlk; peb++ )
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

        pebOffset = peb * descPtr->mtdInfo.eraseSize;
        res = ReadEcHeader( descPtr, pebOffset, &ecHeader );
        if (LE_FORMAT_ERROR == res )
        {
            continue;
        }
        else if (LE_OK != res )
        {
            goto error;
        }
        res = ReadVidHeader( descPtr, pebOffset, &vidHeader, ntohl(ecHeader.vid_hdr_offset) );
        if (LE_FORMAT_ERROR == res )
        {
            continue;
        }
        if (LE_OK != res )
        {
            LE_CRIT("Error when reading VID Header at %d\n", peb);
            goto error;
        }
        if (UBI_LAYOUT_VOLUME_ID == ntohl(vidHeader.vol_id))
        {
            res = ReadVtbl( descPtr, pebOffset, descPtr->vtbl, ntohl(ecHeader.data_offset) );
            if (LE_OK != res)
            {
                LE_CRIT("Error when reading Vtbl at %d\n", peb);
                goto error;
            }
            if( iVtblPeb < 2 )
            {
                descPtr->vtblPeb[iVtblPeb++] = peb;
            }
        }
        else if ((ntohl(vidHeader.vol_id) < PA_FLASH_UBI_MAX_VOLUMES) &&
                 (ntohl(vidHeader.vol_id) == ubiVolId))
        {
            descPtr->ubiOffset = ntohl(ecHeader.data_offset);
            descPtr->lebToPeb[ntohl(vidHeader.lnum)] = peb;
            descPtr->vtblPtr = &(descPtr->vtbl[ubiVolId]);
        }
    }

    if( (!descPtr->vtblPtr) ||
        (-1 == (int)descPtr->vtblPeb[0]) ||
        (-1 == (int)descPtr->vtblPeb[1]) )
    {
        LE_ERROR("Volume ID %d not present on MTD %d or NOT an UBI\n",
                 ubiVolId, descPtr->mtdNum);
        return LE_FORMAT_ERROR;
    }

    int i, j;
    for( i = 0; i < PA_FLASH_UBI_MAX_VOLUMES; i++ )
    {
        if( descPtr->vtbl[i].vol_type )
        {
            LE_DEBUG("VOL %i \"%s\" VT %u RPEBS %u\n", i,
                     descPtr->vtbl[i].name,
                     descPtr->vtbl[i].vol_type,
                     ntohl(descPtr->vtbl[i].reserved_pebs));
            for( j = 0;
                 (i == ubiVolId) && (j < ntohl(descPtr->vtbl[i].reserved_pebs));
                 j++ )
            {
                LE_DEBUG( "%u ", descPtr->lebToPeb[j] );
            }
        }
    }
    descPtr->mtdInfo.ubi = true;
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

    if( (!descPtr) || (descPtr->magic != desc))
    {
        return LE_BAD_PARAMETER;
    }

    descPtr->mtdInfo.nbLeb = descPtr->mtdInfo.nbBlk;
    descPtr->mtdInfo.ubi = false;
    descPtr->ubiVolumeId = (uint32_t)-1;
    memset( descPtr->vtbl, 0, sizeof(struct ubi_vtbl_record) * PA_FLASH_UBI_MAX_VOLUMES);
    memset( descPtr->vtblPeb, -1, sizeof(descPtr->vtblPeb));
    memset( descPtr->lebToPeb, -1, sizeof(descPtr->lebToPeb));
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
    pa_flash_Desc_t desc,     ///< [IN] Private flash descriptor
    uint32_t leb,             ///< [IN] LEB to read
    uint8_t *dataPtr,         ///< [IN] Pointer to data to be read
    size_t *dataSizePtr       ///< [IN][OUT] Pointer to size to read
)
{
    pa_flash_MtdDesc_t *descPtr = (pa_flash_MtdDesc_t *)desc;
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

    nbLeb = ntohl(descPtr->vtblPtr->reserved_pebs);
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
    pa_flash_Desc_t desc,     ///< [IN] Private flash descriptor
    uint32_t leb,             ///< [IN] LEB to write
    uint8_t *dataPtr,         ///< [IN] Pointer to data to be written
    size_t dataSize,          ///< [IN][OUT] Size to be written
    bool extendUbiVolume      ///< [IN] True if the volume may be extended by one block if write
                              ///<      is the leb is outside the current volume
)
{
    pa_flash_MtdDesc_t *descPtr = (pa_flash_MtdDesc_t *)desc;
    uint32_t nbLeb, blk, reserved_pebs;
    uint32_t crc;
    off_t blkOff;
    struct ubi_ec_hdr *ecHdrPtr;
    struct ubi_vid_hdr *vidHdrPtr;
    uint8_t *blockPtr = NULL;
    off_t dataOffset;
    bool isBad;
    le_result_t res;

    if( (!descPtr) || (descPtr->magic != desc) || (!dataPtr) )
    {
        return LE_BAD_PARAMETER;
    }

    if( (!descPtr->mtdInfo.ubi) || (descPtr->ubiVolumeId >= PA_FLASH_UBI_MAX_VOLUMES ) )
    {
        return LE_FORMAT_ERROR;
    }

    reserved_pebs = nbLeb = ntohl(descPtr->vtblPtr->reserved_pebs);
    if( (leb > nbLeb) || ((leb == nbLeb) && (!extendUbiVolume)) )
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
    if( (blk == reserved_pebs) && extendUbiVolume )
    {
        uint32_t ieb;

        LE_DEBUG("Create new LEB %d in VolID %d \"%s\"\n",
                 blk, descPtr->ubiVolumeId, descPtr->vtblPtr->name);
        reserved_pebs++;

        if( descPtr->vtblPtr->vol_type == UBI_VID_STATIC )
        {
            for( ieb = 0; ieb < blk; ieb++ )
            {
                blkOff = descPtr->lebToPeb[ieb] * descPtr->mtdInfo.eraseSize;
                res = pa_flash_SeekAtOffset( desc, blkOff );
                if (LE_OK != res )
                {
                    goto error;
                }
                res = pa_flash_Read( desc,
                                     blockPtr,
                                     descPtr->mtdInfo.eraseSize );
                if (LE_OK != res )
                {
                    goto error;
                }
                res = pa_flash_EraseBlock( desc, blkOff / descPtr->mtdInfo.eraseSize );
                if (LE_OK != res)
                {
                    goto error;
                }
                res = pa_flash_SeekAtOffset( desc, blkOff );
                if (LE_OK != res )
                {
                     goto error;
                }

                ecHdrPtr = (struct ubi_ec_hdr *)blockPtr;
                vidHdrPtr = (struct ubi_vid_hdr *)(blockPtr + ntohl(ecHdrPtr->vid_hdr_offset));
                vidHdrPtr->used_ebs = htonl(reserved_pebs);
                crc = le_crc_Crc32( (uint8_t *)vidHdrPtr,
                                    UBI_VID_HDR_SIZE_CRC, LE_CRC_START_CRC32 );
                vidHdrPtr->hdr_crc = htonl(crc);
                LE_DEBUG("Update VID Header at %lx: used_ebs %x, hdr_crc %x\n",
                         blkOff, ntohl(vidHdrPtr->used_ebs), ntohl(vidHdrPtr->hdr_crc));

                LE_DEBUG("Write EC+VID at %lx: size %lx\n", blkOff, dataOffset);
                res = pa_flash_Write( desc,
                                      blockPtr,
                                      descPtr->mtdInfo.eraseSize);
                if (LE_OK != res)
                {
                    goto error;
                }
            }
        }
        for( ieb = 0; ieb < 2; ieb++ )
        {
            struct ubi_vtbl_record *vtblPtr;
            blkOff = descPtr->vtblPeb[ieb] * descPtr->mtdInfo.eraseSize;
            res = pa_flash_SeekAtOffset( desc, blkOff );
            if (LE_OK != res )
            {
                goto error;
            }
            res = pa_flash_Read( desc,
                                 blockPtr,
                                 descPtr->mtdInfo.eraseSize);
            if (LE_OK != res )
            {
                goto error;
            }
            ecHdrPtr = (struct ubi_ec_hdr *)blockPtr;
            vidHdrPtr = (struct ubi_vid_hdr *)(blockPtr + ntohl(ecHdrPtr->vid_hdr_offset));
            vtblPtr = (struct ubi_vtbl_record *)(blockPtr + ntohl(ecHdrPtr->data_offset));
            vtblPtr[descPtr->ubiVolumeId].reserved_pebs = htonl(reserved_pebs);
            crc = le_crc_Crc32( (uint8_t *)&vtblPtr[descPtr->ubiVolumeId],
                                UBI_VTBL_RECORD_SIZE_CRC,
                                LE_CRC_START_CRC32 );
            vtblPtr[descPtr->ubiVolumeId].crc = htonl(crc);
            res = pa_flash_EraseBlock( desc, blkOff / descPtr->mtdInfo.eraseSize );
            if (LE_OK != res)
            {
                LE_ERROR("Erase of VTBL peb %ld fails\n",
                         blkOff / descPtr->mtdInfo.eraseSize);
                goto error;
            }
            res = pa_flash_SeekAtOffset( desc, blkOff );
            if (LE_OK != res )
            {
                LE_ERROR("Seek to VTBL peb %ld fails\n",
                         blkOff / descPtr->mtdInfo.eraseSize);
                goto error;
            }
            LE_DEBUG("Write VTBL at %lx\n", blkOff);
            res = pa_flash_Write( desc,
                                  blockPtr,
                                  descPtr->mtdInfo.eraseSize);
            if (LE_OK != res)
            {
                LE_ERROR("Write of VTBL peb %ld fails\n",
                         blkOff / descPtr->mtdInfo.eraseSize);
                goto error;
            }
        }

        for( ieb = 0; ieb < descPtr->mtdInfo.nbBlk; ieb++ )
        {
             res = pa_flash_CheckBadBlock( desc, ieb, &isBad );
             if (LE_OK != res)
             {
                 goto error;
             }
             if (isBad)
             {
                 LE_WARN("Skipping bad block %d", ieb);
                 continue;
             }

             blkOff = ieb * descPtr->mtdInfo.eraseSize;
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
             if( ecHdrPtr->magic == (uint32_t)-1 )
                 break;
             vidHdrPtr = (struct ubi_vid_hdr *)(blockPtr + ntohl(ecHdrPtr->vid_hdr_offset));
             if( vidHdrPtr->magic == (uint32_t)-1 )
                 break;
        }
        if( ieb == descPtr->mtdInfo.nbBlk )
        {
            LE_CRIT("No block to add one on volume %d\n", descPtr->ubiVolumeId);
            return LE_OUT_OF_RANGE;
        }
        blkOff = descPtr->lebToPeb[0] * descPtr->mtdInfo.eraseSize;
        LE_DEBUG("read UBI block : LEB %d PEB %d (at %lx)\n",
                0, descPtr->lebToPeb[0], blkOff);
        LE_DEBUG("Read blk %d, size %lx at %lx\n",
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
        vidHdrPtr = (struct ubi_vid_hdr *)(blockPtr + ntohl(ecHdrPtr->vid_hdr_offset));
        vidHdrPtr->lnum = htonl(blk);
        if( descPtr->vtblPtr->vol_type == UBI_VID_STATIC )
        {
            vidHdrPtr->used_ebs = htonl(reserved_pebs);
        }
        crc = le_crc_Crc32( (uint8_t *)vidHdrPtr, UBI_VID_HDR_SIZE_CRC, LE_CRC_START_CRC32 );
        vidHdrPtr->hdr_crc = htonl(crc);
        descPtr->vtblPtr->reserved_pebs = htonl(reserved_pebs);
        descPtr->lebToPeb[ blk ] = ieb;
        blkOff = descPtr->lebToPeb[blk] * descPtr->mtdInfo.eraseSize;
        res = pa_flash_SeekAtOffset( desc, blkOff );
        if (LE_OK != res )
        {
            goto error;
        }
    }
    else
    {
        blkOff = descPtr->lebToPeb[blk] * descPtr->mtdInfo.eraseSize;
        LE_DEBUG("read UBI block : LEB %d PEB %d (at %lx)\n",
                 blk, descPtr->lebToPeb[blk], blkOff);
        LE_DEBUG("Read blk %d, size %lx at %lx\n",
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
    ecHdrPtr = (struct ubi_ec_hdr *)blockPtr;
    vidHdrPtr = (struct ubi_vid_hdr *)(blockPtr + ntohl(ecHdrPtr->vid_hdr_offset));
    if( descPtr->vtblPtr->vol_type == UBI_VID_STATIC )
    {
        vidHdrPtr->data_size = htonl(dataSize);
        crc = le_crc_Crc32( dataPtr, dataSize, LE_CRC_START_CRC32 );
        vidHdrPtr->data_crc = htonl(crc);
        crc = le_crc_Crc32( (uint8_t *)vidHdrPtr, UBI_VID_HDR_SIZE_CRC, LE_CRC_START_CRC32 );
        vidHdrPtr->hdr_crc = htonl(crc);
    }
    LE_DEBUG("Erase and write blk %d, size %lx at %lx\n",
             blk, dataOffset, blkOff );
    res = pa_flash_EraseBlock( desc, blkOff / descPtr->mtdInfo.eraseSize );
    if (LE_OK != res)
    {
        goto error;
    }
    res = pa_flash_SeekAtOffset( desc, blkOff );
    if (LE_OK != res )
    {
        goto error;
    }

    LE_DEBUG("Update VID Header at %lx: oldsize %x newsize %x, data_crc %x, hdr_crc %x\n",
             blkOff, ntohl(vidHdrPtr->data_size), dataSize,
             ntohl(vidHdrPtr->data_crc), ntohl(vidHdrPtr->hdr_crc));

    LE_DEBUG("Write EC+VID at %lx: size %lx\n", blkOff, dataOffset);
    res = pa_flash_Write( desc,
                          blockPtr,
                          dataOffset);
    if (LE_OK != res)
    {
        goto error;
    }

    blkOff += dataOffset;
    res = pa_flash_SeekAtOffset(desc, blkOff);
    if (LE_OK != res)
    {
         goto error;
    }

    LE_DEBUG("Write DATA at %lx: size %x\n", blkOff, dataSize);
    res = pa_flash_Write(desc, dataPtr, dataSize);
    if (LE_OK != res )
    {
        goto error;
    }

    le_mem_Release(blockPtr);
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
    pa_flash_MtdDesc_t *descPtr = (pa_flash_MtdDesc_t *)desc;
    uint32_t nbLeb, blk, reserved_pebs;
    uint32_t crc;
    off_t blkOff;
    struct ubi_ec_hdr *ecHdrPtr;
    struct ubi_vid_hdr *vidHdrPtr;
    uint8_t *blockPtr = NULL;
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
    reserved_pebs = nbLeb = (newSize + (dataSize - 1)) / dataSize;
    LE_DEBUG("Reducing UBI vol %u from %u to %u blocks[last %u]\n",
             descPtr->ubiVolumeId, ntohl(descPtr->vtblPtr->reserved_pebs),
    reserved_pebs, descPtr->lebToPeb[reserved_pebs-1] );
    if( reserved_pebs < ntohl(descPtr->vtblPtr->reserved_pebs) )
    {
        if( (!UbiBlockPool) )
        {
            UbiBlockPool = le_mem_CreatePool("UBI Block Pool", descPtr->mtdInfo.eraseSize);
            le_mem_ExpandPool( UbiBlockPool, 1 );
        }
        blockPtr = le_mem_ForceAlloc(UbiBlockPool);

        LE_DEBUG("Starting to reduce reserved_pebs for VolId %d", descPtr->ubiVolumeId);
        for( blk = reserved_pebs; blk < ntohl(descPtr->vtblPtr->reserved_pebs); blk++ )
        {
            blkOff = descPtr->lebToPeb[blk] * descPtr->mtdInfo.eraseSize;
            LE_DEBUG("Erasing block and updating EC in %u [peb %u]\n",
                     blk, descPtr->lebToPeb[blk]);
            res = pa_flash_SeekAtOffset( desc, blkOff );
            if (LE_OK != res )
            {
                goto error;
            }
            res = pa_flash_Read( desc,
                                 blockPtr,
                                 descPtr->mtdInfo.writeSize);
            if (LE_OK != res )
            {
                goto error;
            }
            res = pa_flash_EraseBlock( desc, blkOff / descPtr->mtdInfo.eraseSize );
            if (LE_OK != res)
            {
                goto error;
            }
            res = pa_flash_SeekAtOffset( desc, blkOff );
            if (LE_OK != res )
            {
                goto error;
            }

            res = pa_flash_Write( desc,
                                  blockPtr,
                                  descPtr->mtdInfo.writeSize);
            if (LE_OK != res)
            {
                goto error;
            }
        }
        if( descPtr->vtblPtr->vol_type == UBI_VID_STATIC )
        {
            for( blk = 0; blk < reserved_pebs; blk++ )
            {
                blkOff = descPtr->lebToPeb[blk] * descPtr->mtdInfo.eraseSize;
                res = pa_flash_SeekAtOffset( desc, blkOff );
                if (LE_OK != res )
                {
                    goto error;
                }
                res = pa_flash_Read( desc,
                                     blockPtr,
                                     descPtr->mtdInfo.eraseSize);
                if (LE_OK != res )
                {
                    goto error;
                }
                res = pa_flash_EraseBlock( desc, blkOff / descPtr->mtdInfo.eraseSize );
                if (LE_OK != res)
                {
                    goto error;
                }
                res = pa_flash_SeekAtOffset( desc, blkOff );
                if (LE_OK != res )
                {
                     goto error;
                }

                ecHdrPtr = (struct ubi_ec_hdr *)blockPtr;
                vidHdrPtr = (struct ubi_vid_hdr *)(blockPtr + ntohl(ecHdrPtr->vid_hdr_offset));
                vidHdrPtr->used_ebs = htonl(reserved_pebs);
                crc = le_crc_Crc32( (uint8_t *)vidHdrPtr, UBI_VID_HDR_SIZE_CRC, LE_CRC_START_CRC32 );
                vidHdrPtr->hdr_crc = htonl(crc);
                LE_DEBUG("Update VID Header at %lx: used_ebs %x, hdr_crc %x\n",
                         blkOff, ntohl(vidHdrPtr->used_ebs), ntohl(vidHdrPtr->hdr_crc));

                LE_DEBUG("Write EC+VID at %lx: size %x\n", blkOff, descPtr->mtdInfo.eraseSize);
                res = pa_flash_Write( desc,
                                      blockPtr,
                                      descPtr->mtdInfo.eraseSize);
                if (LE_OK != res)
                {
                    goto error;
                }
            }
        }
        descPtr->vtblPtr->reserved_pebs = htonl(reserved_pebs);
        for( blk = 0; blk < 2; blk++ )
        {
            struct ubi_vtbl_record *vtblPtr;
            blkOff = descPtr->vtblPeb[blk] * descPtr->mtdInfo.eraseSize;
            LE_DEBUG("Updating reserved_peb in VTBL %u [peb %u]\n",
                     blk, descPtr->vtblPeb[blk]);
            res = pa_flash_SeekAtOffset( desc, blkOff );
            if (LE_OK != res )
            {
                goto error;
            }
            res = pa_flash_Read( desc,
                                 blockPtr,
                                 descPtr->mtdInfo.eraseSize);
            if (LE_OK != res )
            {
                goto error;
            }
            ecHdrPtr = (struct ubi_ec_hdr *)blockPtr;
            vidHdrPtr = (struct ubi_vid_hdr *)(blockPtr + ntohl(ecHdrPtr->vid_hdr_offset));
            vtblPtr = (struct ubi_vtbl_record *)(blockPtr + ntohl(ecHdrPtr->data_offset));
            vtblPtr[descPtr->ubiVolumeId].reserved_pebs = htonl(reserved_pebs);
            crc = le_crc_Crc32( (uint8_t *)&vtblPtr[descPtr->ubiVolumeId],
                         UBI_VTBL_RECORD_SIZE_CRC, LE_CRC_START_CRC32 );
            vtblPtr[descPtr->ubiVolumeId].crc = htonl(crc);
            res = pa_flash_EraseBlock( desc, blkOff / descPtr->mtdInfo.eraseSize );
            if (LE_OK != res)
            {
                goto error;
            }
            res = pa_flash_SeekAtOffset( desc, blkOff );
            if (LE_OK != res )
            {
                goto error;
            }
            LE_DEBUG("Write VTBL at %lx: size %x\n", blkOff, descPtr->mtdInfo.eraseSize);
            res = pa_flash_Write( desc,
                                  blockPtr,
                                  descPtr->mtdInfo.eraseSize);
            if (LE_OK != res)
            {
                goto error;
            }
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
