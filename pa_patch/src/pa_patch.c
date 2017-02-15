/**
 * @file pa_patch.c
 *
 * Copyright (C) Sierra Wireless Inc.
 *
 */

#include "legato.h"
#include "pa_patch.h"
#include "pa_flash.h"

//--------------------------------------------------------------------------------------------------
/**
 * Internal descriptor type for patch access
 */
//--------------------------------------------------------------------------------------------------
typedef struct
{
    pa_patch_Desc_t *magic;
    pa_patch_Context_t context;
    pa_flash_Desc_t flashOrigDesc;
    pa_flash_Info_t *flashOrigInfo;
    pa_flash_LebToPeb_t *flashOrigLebToPeb;
    pa_flash_Desc_t flashDestDesc;
    pa_flash_Info_t *flashDestInfo;
    pa_flash_LebToPeb_t *flashDestLebToPeb;
    uint8_t *origDataPtr;
    uint8_t *destDataPtr;
}
pa_patch_InternalDesc_t;

//--------------------------------------------------------------------------------------------------
/**
 * Pool for the internal descriptor
 */
//--------------------------------------------------------------------------------------------------
static le_mem_PoolRef_t PatchDescPool = NULL;

//--------------------------------------------------------------------------------------------------
/**
 * Pool for the patch segment buffer
 */
//--------------------------------------------------------------------------------------------------
le_mem_PoolRef_t PatchSegmentPool = NULL;

//--------------------------------------------------------------------------------------------------
/**
 * Open a patch context and return a patch descriptor
 *
 * @return
 *      - LE_OK            On success
 *      - LE_BAD_PAREMETER If desc is NULL or if mode is not correct
 *      - LE_OUT_OF_RANGE  The segment size is not compatible with the flash
 *      - LE_FAULT         On failure
 *      - LE_UNSUPPORTED   If the flash device cannot be opened
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_patch_Open
(
    pa_patch_Context_t *ctx,  ///< [IN] Context of the patch to be open
    pa_patch_Desc_t *desc,    ///< [OUT] Private flash descriptor
    uint8_t **origDataPtr,    ///< [OUT] Pointer to the orig data buffer
    uint8_t **destDataPtr     ///< [OUT] Pointer to the dest data buffer
)
{
    pa_patch_InternalDesc_t *descPtr = NULL;
    pa_flash_OpenMode_t origMode = 0;
    pa_flash_OpenMode_t destMode = 0;
    le_result_t res;

    if( (!ctx) || (!desc) || (!origDataPtr) || (!destDataPtr) )
    {
        return LE_BAD_PARAMETER;
    }

    if( (ctx->origImage != ctx->destImage) || (!ctx->segmentSize) ||
        (PA_PATCH_MAX_SEGMENTSIZE < ctx->segmentSize) )
    {
        return LE_UNSUPPORTED;
    }
    switch( ctx->origImage )
    {
        case PA_PATCH_IMAGE_UBIFLASH:
        case PA_PATCH_IMAGE_RAWFLASH:
             break;
        default:
             return LE_UNSUPPORTED;
    }

    if( (!PatchDescPool) )
    {
        PatchDescPool = le_mem_CreatePool("Patch Desc Pool", sizeof(pa_patch_InternalDesc_t) );
        le_mem_ExpandPool( PatchDescPool, 1 );
    }
    if( (!PatchSegmentPool) )
    {
        PatchSegmentPool = le_mem_CreatePool("Patch Segment Pool", PA_PATCH_MAX_SEGMENTSIZE );
        le_mem_ExpandPool( PatchSegmentPool, 2 );
    }
    descPtr = le_mem_ForceAlloc(PatchDescPool);
    memset( descPtr, 0, sizeof(pa_patch_InternalDesc_t) );
    memcpy( &(descPtr->context), ctx, sizeof(pa_patch_Context_t) );

    switch( descPtr->context.origImage )
    {
        case PA_PATCH_IMAGE_RAWFLASH:
             origMode |= (PA_FLASH_OPENMODE_READONLY|PA_FLASH_OPENMODE_MARKBAD);
             if( descPtr->context.origImageDesc.flash.isLogical )
             {
                 origMode |= PA_FLASH_OPENMODE_LOGICAL;
                 if( descPtr->context.origImageDesc.flash.isDual )
                 {
                     origMode |= PA_FLASH_OPENMODE_LOGICAL_DUAL;
                 }
             }
             destMode |= (PA_FLASH_OPENMODE_READWRITE|PA_FLASH_OPENMODE_MARKBAD);
             if( descPtr->context.destImageDesc.flash.isLogical )
             {
                 destMode |= PA_FLASH_OPENMODE_LOGICAL;
                 if( descPtr->context.destImageDesc.flash.isDual )
                 {
                     destMode |= PA_FLASH_OPENMODE_LOGICAL_DUAL;
                 }
             }
             res = pa_flash_Open( descPtr->context.origImageDesc.flash.mtdNum,
                                         origMode,
                                         &(descPtr->flashOrigDesc),
                                         &(descPtr->flashOrigInfo) );
             if( LE_OK != res )
             {
                 LE_ERROR("Failed to open origin flash device %d: %d\n",
                          descPtr->context.origImageDesc.flash.mtdNum,
                          res);
                 goto erroropen;
             }
             res = pa_flash_Open( descPtr->context.destImageDesc.flash.mtdNum,
                                         destMode,
                                         &(descPtr->flashDestDesc),
                                         &(descPtr->flashDestInfo) );
             if( LE_OK != res )
             {
                 LE_ERROR("Failed to open destination flash device %d: %d\n",
                          descPtr->context.destImageDesc.flash.mtdNum,
                          res);
                 goto erroropen;
             }

             if( descPtr->context.segmentSize !=
                 ((descPtr->context.segmentSize / descPtr->flashOrigInfo->eraseSize) *
                  descPtr->flashOrigInfo->eraseSize) )
             {
                 LE_ERROR("Segment size %x is not a multiple of flash erase blocks %x:\n",
                          descPtr->context.segmentSize, (descPtr->flashOrigInfo)->eraseSize);
                 res = LE_OUT_OF_RANGE;
                 goto erroropen;
             }

             res = pa_flash_Scan( descPtr->flashOrigDesc, &(descPtr->flashOrigLebToPeb) );
             if( LE_OK != res )
             {
                 LE_ERROR("Failed to scan origin flash device %d: %d\n",
                          descPtr->context.origImageDesc.flash.mtdNum,
                          res);
                 goto erroropen;
             }
             res = pa_flash_Scan( descPtr->flashDestDesc, &(descPtr->flashDestLebToPeb) );
             if( LE_OK != res )
             {
                 LE_ERROR("Failed to scan destination flash device %d: %d\n",
                          descPtr->context.destImageDesc.flash.mtdNum,
                          res);
                 goto erroropen;
             }
             break;
        case PA_PATCH_IMAGE_UBIFLASH:
             origMode |= PA_FLASH_OPENMODE_UBI;
             destMode |= PA_FLASH_OPENMODE_UBI;
             origMode |= (PA_FLASH_OPENMODE_READONLY|PA_FLASH_OPENMODE_MARKBAD);
             destMode |= (PA_FLASH_OPENMODE_READWRITE|PA_FLASH_OPENMODE_MARKBAD);
             if( (descPtr->context.origImageDesc.flash.isLogical) ||
                 (descPtr->context.destImageDesc.flash.isLogical) )
             {
                 LE_ERROR("Logical partitions not supported for UBI images");
                 res = LE_UNSUPPORTED;
                 goto erroropen;
             }
             res = pa_flash_Open( descPtr->context.origImageDesc.flash.mtdNum,
                                         origMode,
                                         &(descPtr->flashOrigDesc),
                                         &(descPtr->flashOrigInfo) );
             if( LE_OK != res )
             {
                 LE_ERROR("Failed to open origin flash device %d: %d\n",
                          descPtr->context.origImageDesc.flash.mtdNum,
                          res);
                 goto erroropen;
             }
             res = pa_flash_Open( descPtr->context.destImageDesc.flash.mtdNum,
                                         destMode,
                                         &(descPtr->flashDestDesc),
                                         &(descPtr->flashDestInfo) );
             if( LE_OK != res )
             {
                 LE_ERROR("Failed to open destination flash device %d: %d\n",
                          descPtr->context.destImageDesc.flash.mtdNum,
                          res);
                 goto erroropen;
             }

             if( (descPtr->context.segmentSize != (descPtr->flashOrigInfo->eraseSize -
                                                   (2 * descPtr->flashOrigInfo->writeSize))) )
             {
                 LE_ERROR("Segment size %x is not compatible with UBI structure %x:\n",
                          descPtr->context.segmentSize, descPtr->flashOrigInfo->writeSize);
                 res = LE_OUT_OF_RANGE;
                 goto erroropen;
             }
             res = pa_flash_ScanUbi( descPtr->flashOrigDesc,
                                     descPtr->context.origImageDesc.flash.ubiVolId );
             if( LE_OK != res )
             {
                 LE_ERROR("Failed to scan UBI origin flash device %d, UBI volume %d: %d\n",
                          descPtr->context.origImageDesc.flash.mtdNum,
                          descPtr->context.origImageDesc.flash.ubiVolId,
                          res);
                 goto erroropen;
             }
             res = pa_flash_ScanUbi( descPtr->flashDestDesc,
                                     descPtr->context.destImageDesc.flash.ubiVolId );
             if( LE_OK != res )
             {
                 LE_ERROR("Failed to scan UBI origin flash device %d, UBI volume %d: %d\n",
                          descPtr->context.destImageDesc.flash.mtdNum,
                          descPtr->context.origImageDesc.flash.ubiVolId,
                          res);
                 goto erroropen;
             }
             break;
        default:
             LE_ERROR("Unsupported Image %d\n", descPtr->context.origImage);
             goto erroropen;
    }
    descPtr->origDataPtr = le_mem_ForceAlloc(PatchSegmentPool);
    descPtr->destDataPtr = le_mem_ForceAlloc(PatchSegmentPool);
    *origDataPtr = descPtr->origDataPtr;
    *destDataPtr = descPtr->destDataPtr;
    descPtr->magic = (pa_patch_Desc_t *)descPtr;
    *desc = (pa_patch_Desc_t*)descPtr;
    return LE_OK;

erroropen:
    if( descPtr->flashDestDesc )
    {
        pa_flash_Close( descPtr->flashDestDesc );
    }
    if( descPtr->flashOrigDesc )
    {
        pa_flash_Close( descPtr->flashDestDesc );
    }
    if( descPtr->destDataPtr )
    {
        le_mem_Release(descPtr->destDataPtr);
    }
    if( descPtr->origDataPtr )
    {
        le_mem_Release(descPtr->origDataPtr);
    }
    if( descPtr )
    {
        le_mem_Release(descPtr);
    }
    return res;
}

//--------------------------------------------------------------------------------------------------
/**
 * Close a patch descriptor
 *
 * @return
 *      - LE_OK            On success
 *      - LE_BAD_PAREMETER If desc is NULL or not a valid flash descriptor
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_patch_Close
(
    pa_patch_Desc_t desc,     ///< [IN] Private flash descriptor
    bool            update,   ///< [IN] Update the destination size
    size_t          destSize  ///< [IN] Final size of the destination
)
{
    pa_patch_InternalDesc_t *descPtr = (pa_patch_InternalDesc_t *)desc;
    uint32_t blk;
    le_result_t res = LE_OK;;

    if( (!desc) || (descPtr->magic != desc) )
    {
        return LE_BAD_PARAMETER;
    }

    descPtr->magic = NULL;

    if( update )
    {
        LE_DEBUG("update %d, destSize = %x\n", update, destSize );
        switch( descPtr->context.destImage )
        {
            case PA_PATCH_IMAGE_RAWFLASH:
                 blk = (destSize + (descPtr->flashDestInfo->eraseSize - 1))
                        / descPtr->flashDestInfo->eraseSize;
                 LE_DEBUG("Last block %u used by patch\n", blk );
                 for( ; blk < descPtr->flashDestInfo->nbLeb; blk++ )
                 {
                     LE_DEBUG("Erasing remaing block %u\n", blk);
                     pa_flash_EraseBlock( descPtr->flashDestDesc, blk );
                 }
                 break;
            case PA_PATCH_IMAGE_UBIFLASH:
                 res = pa_flash_AdjustUbiSize( descPtr->flashDestDesc, destSize );
                 break;
            default:
                 break;
        }
    }

    if( descPtr->flashDestDesc )
    {
        pa_flash_Close( descPtr->flashDestDesc );
    }
    if( descPtr->flashOrigDesc )
    {
        pa_flash_Close( descPtr->flashOrigDesc );
    }
    if( descPtr->destDataPtr )
    {
        le_mem_Release(descPtr->destDataPtr);
    }
    if( descPtr->origDataPtr )
    {
        le_mem_Release(descPtr->origDataPtr);
    }
    if( descPtr )
    {
        le_mem_Release(descPtr);
    }
    return res;
}

//--------------------------------------------------------------------------------------------------
/**
 * Read data starting the given block. If a Bad block is detected,
 * the error LE_IO_ERROR is returned and operation is aborted.
 * Note that the length should not be greater than eraseSize
 *
 * @return
 *      - LE_OK            On success
 *      - LE_BAD_PARAMETER If desc is NULL or dataPtr is NULL or dataSizePtr is NULL
 *      - LE_FAULT         On failure
 *      - LE_OUT_OF_RANGE  If the block is outside the partition
 *      - others           Depending of the image type and PA device used
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_patch_ReadSegment
(
    pa_patch_Desc_t desc,
    off_t offset,
    uint8_t *dataPtr,
    size_t  *dataSizePtr
)
{
    pa_patch_InternalDesc_t *descPtr = (pa_patch_InternalDesc_t *)desc;
    size_t size, chunckSize;
    int blk;
    le_result_t res;

    if( (!desc) || (descPtr->magic != desc) || (!dataSizePtr) )
    {
        return LE_BAD_PARAMETER;
    }

    *dataSizePtr = 0;
    size = descPtr->context.segmentSize;
    switch( descPtr->context.origImage )
    {
        case PA_PATCH_IMAGE_RAWFLASH:
             if( ((off_t)size + offset) > (off_t)(descPtr->flashOrigInfo->nbLeb *
                                                  descPtr->flashOrigInfo->eraseSize) )
             {
                 size = (size_t)(descPtr->flashOrigInfo->nbLeb *
                                 descPtr->flashOrigInfo->eraseSize) -
                        (size_t)offset;
             }
             res = pa_flash_SeekAtOffset( descPtr->flashOrigDesc, offset );
             if( LE_OK != res )
             {
                 return res;
             }
             *dataSizePtr = size;
             chunckSize = descPtr->context.origImage == PA_PATCH_IMAGE_RAWFLASH
                             ? descPtr->flashOrigInfo->eraseSize
                             : descPtr->context.segmentSize;
             for( blk = 0; blk < (size / chunckSize); blk++ )
             {
                 res = pa_flash_Read( descPtr->flashOrigDesc,
                                      (descPtr->origDataPtr + (blk * chunckSize)),
                                      chunckSize );
                 if( LE_OK != res )
                 {
                     return res;
                 }
             }
             return res;
        case PA_PATCH_IMAGE_UBIFLASH:
             blk = offset / descPtr->context.segmentSize;
             res = pa_flash_ReadUbiAtBlock( descPtr->flashOrigDesc,
                                            blk, descPtr->origDataPtr, &size);
             *dataSizePtr = size;
             return res;
    }
    return LE_UNSUPPORTED;
}

//--------------------------------------------------------------------------------------------------
/**
 * Write data starting the given block. If a Bad block is detected,
 * the error LE_IO_ERROR is returned and operation is aborted.
 * Note that the block should be erased before the first write (pa_patch_EraseAtBlock)
 * Note that the length should be a multiple of writeSize and should not be greater than eraseSize
 *
 * @return
 *      - LE_OK            On success
 *      - LE_BAD_PARAMETER If desc is NULL or dataPtr is NULL
 *      - LE_FAULT         On failure
 *      - LE_OUT_OF_RANGE  If the block is outside the partition
 *      - others           Depending of the image type and PA device used
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_patch_WriteSegment
(
    pa_patch_Desc_t desc,
    off_t offset,
    uint8_t *dataPtr,
    uint32_t newSize
)
{
    pa_patch_InternalDesc_t *descPtr = (pa_patch_InternalDesc_t *)desc;
    int blk, maxblk;
    off_t blkOff;
    le_result_t res;

    if( (!desc) || (descPtr->magic != desc) )
    {
        return LE_BAD_PARAMETER;
    }

    switch( descPtr->context.destImage )
    {
        case PA_PATCH_IMAGE_RAWFLASH:
            maxblk = (newSize + (descPtr->flashDestInfo->eraseSize - 1))
                     / descPtr->flashDestInfo->eraseSize;
            for( blk = 0; blk < maxblk; blk++ )
            {
                blkOff = (blk * descPtr->flashDestInfo->eraseSize) + offset;

                LE_DEBUG("Erase and write blk %d, size %d at %lx to %x\n",
                         blk, descPtr->flashDestInfo->eraseSize, blkOff,
                         blk * descPtr->flashDestInfo->eraseSize );
                LE_DEBUG("Erase and write blk %d, blkOff=%lx, _ph_offset=%lx\n",
                         blk, blkOff, offset);
                res = pa_flash_EraseBlock( descPtr->flashDestDesc,
                                           blkOff / descPtr->flashDestInfo->eraseSize );
                if (LE_OK != res)
                {
                    return res;
                }
                res = pa_flash_SeekAtOffset( descPtr->flashDestDesc, blkOff );
                if (LE_OK != res)
                {
                    return res;
                }
                res = pa_flash_Write( descPtr->flashDestDesc,
                                      &dataPtr[blk * descPtr->flashDestInfo->eraseSize],
                                      descPtr->flashDestInfo->eraseSize);
                if (LE_OK != res)
                {
                    return res;
                }
            }
            break;
        case PA_PATCH_IMAGE_UBIFLASH:
             blk = offset / descPtr->context.segmentSize;
             res = pa_flash_WriteUbiAtBlock( descPtr->flashDestDesc,
                                             blk,
                                             descPtr->destDataPtr,
                                             (newSize + (descPtr->flashDestInfo->writeSize - 1)) &
                                             ~(descPtr->flashDestInfo->writeSize - 1),
                                             true);
             return res;
        default:
            return LE_UNSUPPORTED;
    }
    return LE_OK;
}

