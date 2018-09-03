/**
 * @file deltaUpdate.c
 *
 * implementation of the delta update process.
 *
 * Copyright (C) Sierra Wireless Inc.
 *
 */

#include "legato.h"
#include "pa_flash.h"
#include "pa_patch.h"
#include "bspatch.h"
#include "deltaUpdate_local.h"
#include "cwe_local.h"
#include "utils_local.h"
#include "partition_local.h"

//--------------------------------------------------------------------------------------------------
/**
 * Delta patch DIFF magic signature
 */
//--------------------------------------------------------------------------------------------------
#define DIFF_MAGIC   "BSDIFF40\0\0\0\0\0\0\0\0"

//--------------------------------------------------------------------------------------------------
/**
 * Define the temporary patch path
 */
//--------------------------------------------------------------------------------------------------
#define TMP_PATCH_PATH "/tmp/.tmp.patch"

//==================================================================================================
//                                       Private Functions
//==================================================================================================

//--------------------------------------------------------------------------------------------------
/**
 * Check if data flashed into a an UBI volume ID is correct
 *
 * @return
 *      - LE_OK        on success
 *      - LE_FAULT     if checksum is not correct
 *      - others       depending of the UBI functions return
 */
//--------------------------------------------------------------------------------------------------
static le_result_t CheckUbiData
(
    int mtdNum,                        ///< [IN] Minor of the MTD device to check
    uint32_t ubiVolId,                 ///< [IN] UBI Volume ID to check
    size_t sizeToCheck,                ///< [IN] Size to be used to compute the CRC
    uint32_t crc32ToCheck,             ///< [IN] Expected CRC 32
    le_mem_PoolRef_t flashImgPool      ///< [IN] memory pool
)
{
    pa_flash_Desc_t desc = NULL;
    uint8_t* checkBlockPtr = NULL;

    size_t size, imageSize = 0;
    uint32_t blk, crc32 = LE_CRC_START_CRC32;
    pa_flash_Info_t *mtdInfoPtr;
    le_result_t res = LE_FAULT;

    LE_INFO( "MTD %d VolId %"PRIu32" Size=%zu, Crc32=0x%08x",
             mtdNum, ubiVolId, sizeToCheck, crc32ToCheck );

    res = pa_flash_Open( mtdNum, PA_FLASH_OPENMODE_READONLY, &desc, &mtdInfoPtr );
    if (LE_OK != res)
    {
        LE_ERROR("Open of MTD %d fails: %d\n", mtdNum, res );
        goto error;
    }

    res = pa_flash_ScanUbi( desc, ubiVolId );
    if (LE_OK != res)
    {
        LE_ERROR("Scan of MTD %d UBI volId %u fails: %d\n", mtdNum, ubiVolId, res );
        goto error;
    }

    checkBlockPtr = le_mem_ForceAlloc(flashImgPool);
    for (blk = 0; imageSize < sizeToCheck; blk++)
    {
        size = (sizeToCheck - imageSize);
        LE_DEBUG("LEB %d : Read 0x%zx", blk, size);
        res = pa_flash_ReadUbiAtBlock( desc, blk, checkBlockPtr, &size);
        if (LE_OK != res )
        {
            goto error;
        }

        crc32 = le_crc_Crc32( checkBlockPtr, size, crc32);
        imageSize += size;
    }
    if (crc32 != crc32ToCheck)
    {
        LE_CRIT( "Bad CRC32 calculated on mtd%d: read 0x%08x != expected 0x%08x",
                 mtdNum, crc32, crc32ToCheck );
        res = LE_FAULT;
        goto error;
    }

    if (!sizeToCheck)
    {
        LE_INFO("CRC32 OK for MTD %d VolId %d, crc 0x%X\n", mtdNum, ubiVolId, crc32 );
    }

    pa_flash_Close( desc );
    le_mem_Release(checkBlockPtr);
    return LE_OK;

error:
    if (desc)
    {
        pa_flash_Close( desc );
    }
    if (checkBlockPtr)
    {
        le_mem_Release(checkBlockPtr);
    }
    return res;
}

//--------------------------------------------------------------------------------------------------
/**
 * Check if there is enough space on a destination partition
 *
 * @return
 *      - LE_OK        on success
 *      - LE_FAULT     on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t IsFreeSpace
(
    deltaUpdate_Ctx_t *ctxPtr,  ///< [IN] Delta update context
    int  mtdNum,                ///< [IN] mtd partition number
    bool isLogical,             ///< [IN] Logical partition
    bool isDual,                ///< [IN] Dual of a logical partition
    bool *isFreePtr             ///< [OUT] flag set to true if there is enough space on the
                                ///<       destination
)
{
    const cwe_Header_t *cweHdrPtr = ctxPtr->cweHdrPtr;
    const deltaUpdate_PatchMetaHdr_t *patchMetaHdrPtr = ctxPtr->metaHdrPtr;
    pa_flash_Desc_t desc = NULL;

    if (patchMetaHdrPtr->ubiVolId == PA_PATCH_INVALID_UBI_VOL_ID)
    {
        // RAW partition

        pa_flash_Info_t flashInfo;
        if (LE_OK != pa_flash_GetInfo(mtdNum, &flashInfo, isLogical, isDual))
        {
            LE_ERROR("Failed to get flash info.");
            goto error;
        }
        *isFreePtr = !(cweHdrPtr->imageSize > flashInfo.size);
    }
    else
    {
        // UBI volume

        le_result_t res;
        pa_flash_Info_t *mtdInfoPtr;

        res = pa_flash_Open( mtdNum, PA_FLASH_OPENMODE_READONLY, &desc, &mtdInfoPtr );
        if (LE_OK != res)
        {
            LE_ERROR("Open of MTD %d fails: %d\n", mtdNum, res );
            goto error;
        }

        res = pa_flash_ScanUbi( desc, patchMetaHdrPtr->ubiVolId );
        if (LE_OK != res)
        {
            LE_ERROR("Scan of MTD %d UBI volId %u fails: %d\n", mtdNum, patchMetaHdrPtr->ubiVolId,
                     res );
            goto error;
        }

        *isFreePtr = !(patchMetaHdrPtr->ubiVolId > mtdInfoPtr->ubiVolFreeSize);

        pa_flash_Close( desc );
    }

    return LE_OK;
error:
    if (desc)
    {
        pa_flash_Close( desc );
    }
    return LE_FAULT;
}

//==================================================================================================
//  PUBLIC API FUNCTIONS
//==================================================================================================

//--------------------------------------------------------------------------------------------------
/**
 * This function is used by the Legato SW Update component to read a Patch Meta header
 *
 * @return
 *      - LE_OK            The request was accepted
 *      - LE_BAD_PARAMETER The parameter is invalid
 *      - LE_FAULT         If an error occurs
 */
//--------------------------------------------------------------------------------------------------
le_result_t deltaUpdate_LoadPatchMetaHeader
(
    const uint8_t* startPtr,             ///< [IN] start address of the Patch Meta header to be read
    deltaUpdate_PatchMetaHdr_t* hdpPtr   ///< [OUT] pointer to a Patch Meta header structure
)
{
    if ((NULL == startPtr) || (NULL == hdpPtr))
    {
        LE_ERROR("Bad parameters");
        return LE_BAD_PARAMETER;
    }
    else
    {
        uint8_t *dataToHdrPtr;

        // Check patch magic
        if (memcmp( ((deltaUpdate_PatchMetaHdr_t*)startPtr)->diffType, DIFF_MAGIC,
                    sizeof(hdpPtr->diffType)))
        {
            LE_ERROR("Patch type is not correct: %s",
                     ((deltaUpdate_PatchMetaHdr_t*)startPtr)->diffType);
            memset(hdpPtr->diffType, 0, sizeof(hdpPtr->diffType));
            return LE_FAULT;
        }
        // Copy patch meta header and take care of byte order BIG endian vs LITTLE endian
        memcpy( &hdpPtr->diffType, startPtr, sizeof(hdpPtr->diffType) );
        dataToHdrPtr = (uint8_t*)&(((deltaUpdate_PatchMetaHdr_t*)startPtr)->segmentSize);
        hdpPtr->segmentSize = utils_TranslateNetworkByteOrder( &dataToHdrPtr );
        hdpPtr->numPatches = utils_TranslateNetworkByteOrder( &dataToHdrPtr );
        hdpPtr->ubiVolId = utils_TranslateNetworkByteOrder( &dataToHdrPtr );
        hdpPtr->origSize = utils_TranslateNetworkByteOrder( &dataToHdrPtr );
        hdpPtr->origCrc32 = utils_TranslateNetworkByteOrder( &dataToHdrPtr );
        hdpPtr->destSize = utils_TranslateNetworkByteOrder( &dataToHdrPtr );
        hdpPtr->destCrc32 = utils_TranslateNetworkByteOrder( &dataToHdrPtr );

        LE_INFO("Meta Header: SegSz 0x%X NumPtch 0x%X UbiVolId 0x%X "
                "OrigSz 0x%X OrigCrc 0x%X DestSz 0x%X DestCrc 0x%X",
                hdpPtr->segmentSize, hdpPtr->numPatches, hdpPtr->ubiVolId, hdpPtr->origSize,
                hdpPtr->origCrc32, hdpPtr->destSize, hdpPtr->destCrc32);
    }
    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * This function is used by the Legato SW Update component to read a Patch header
 *
 * @return
 *      - LE_OK            The request was accepted
 *      - LE_BAD_PARAMETER The parameter is invalid
 *      - LE_FAULT         If an error occurs
 */
//--------------------------------------------------------------------------------------------------
le_result_t deltaUpdate_LoadPatchHeader
(
    const uint8_t* startPtr,             ///< [IN] start address of the Patch header to be read
    deltaUpdate_Ctx_t *ctxPtr            ///< [IN] Delta update context
)
{
    if ((NULL == startPtr) || (NULL == ctxPtr))
    {
        LE_ERROR("Bad parameters");
        return LE_BAD_PARAMETER;
    }
    else
    {
        uint8_t *dataPtr = (uint8_t *)startPtr;
        deltaUpdate_PatchHdr_t *hdpPtr = ctxPtr->hdrPtr;

        hdpPtr->offset = utils_TranslateNetworkByteOrder( &dataPtr );
        hdpPtr->number = utils_TranslateNetworkByteOrder( &dataPtr );
        hdpPtr->size = utils_TranslateNetworkByteOrder( &dataPtr );
        LE_DEBUG("Patch %d: At offset 0x%x size 0x%x\n",
                 hdpPtr->number, hdpPtr->offset, hdpPtr->size);
        ctxPtr->patchRemLen = hdpPtr->size;
    }
    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Apply patch to a partition
 *
 * @return
 *      - LE_OK            on success
 *      - LE_FAULT         on failure
 *      - LE_NOT_PERMITTED if the patch is applied to the SBL
 *      - others           depending of the UBI or flash functions return
 */
//--------------------------------------------------------------------------------------------------
le_result_t deltaUpdate_ApplyPatch
(
    deltaUpdate_Ctx_t *ctxPtr,          ///< [IN] Delta update context
    size_t length,                      ///< [IN] Input data length
    size_t offset,                      ///< [IN] Data offset in the package
    const uint8_t* dataPtr,             ///< [IN] input data
    bool forceClose,                    ///< [IN] Force close of device and resources
    bool *isFlashedPtr                  ///< [OUT] true if flash write was done
)
{
    static int MtdDestNum = -1, MtdOrigNum = -1;
    static bool InPatch = false;
    static bool IsOrigLogical, IsOrigDual, IsDestLogical, IsDestDual;
    static char *MtdNamePtr = NULL;
    static int PatchFd = -1;
    static uint32_t PatchCrc32;

    const cwe_Header_t *cweHdrPtr = ctxPtr->cweHdrPtr;
    const deltaUpdate_PatchHdr_t *patchHdrPtr = ctxPtr->hdrPtr;
    deltaUpdate_PatchMetaHdr_t *patchMetaHdrPtr = ctxPtr->metaHdrPtr;

    size_t wrLen;
    le_result_t res;

    if (forceClose)
    {
        // If forceClose set, close descriptor and release all resources
        LE_CRIT( "Closing and releasing MTD due to forceClose\n" );
        goto error;
    }

    if ((!dataPtr) || (!length) || (!ctxPtr))
    {
        goto error;
    }

    LE_INFO("Image type %"PRIu32" len %zu offset %zu (%"PRIu32")",
            cweHdrPtr->imageType, length, offset, cweHdrPtr->imageSize);

    if (CWE_IMAGE_TYPE_SBL1 == cweHdrPtr->imageType)
    {
        LE_ERROR("SBL could not be flashed as a patch");
        return LE_NOT_PERMITTED;
    }

    LE_DEBUG( "InPatch %d, len %zu, offset %zu\n", InPatch, length, offset );
    if (!InPatch)
    {
        MtdOrigNum = partition_GetMtdFromImageType( cweHdrPtr->imageType, false,
                                                    &MtdNamePtr, &IsOrigLogical, &IsOrigDual );
        MtdDestNum = partition_GetMtdFromImageType( cweHdrPtr->imageType, true,
                                                    &MtdNamePtr, &IsDestLogical, &IsDestDual );

        if ((-1 == MtdDestNum) || (-1 == MtdOrigNum))
        {
            LE_ERROR( "Unable to find a valid mtd for image type %d\n", cweHdrPtr->imageType );
            goto error;
        }

        if (LE_OK != partition_CheckIfMounted( MtdDestNum ))
        {
            LE_ERROR("MTD %d is mounted", MtdDestNum);
            goto error;
        }

        // check if image size is compliant with partition size
        bool isFree;

        if (LE_OK != IsFreeSpace(ctxPtr, MtdDestNum, IsDestLogical, IsDestDual, &isFree))
        {
            LE_ERROR("Unable to get free space");
            goto error;
        }
        if (!isFree)
        {
            LE_ERROR("Destination is too small");
            goto error;
        }

        // set bad image flag before applying patch
        res = partition_SetBadImage(cweHdrPtr->imageType, true);
        if (LE_OK != res)
        {
            LE_ERROR("Failed to set bad image flag for CWE imageType %d", cweHdrPtr->imageType);
            goto error;
        }

        // No patch in progress. This is a new patch
        PatchCrc32 = LE_CRC_START_CRC32;

        if (PA_PATCH_INVALID_UBI_VOL_ID != patchMetaHdrPtr->ubiVolId)
        {
            // Patch is related to an UBI volume
            // Check if the image inside the original UBI container has to right CRC
            if (LE_OK != CheckUbiData( MtdOrigNum,
                                       patchMetaHdrPtr->ubiVolId,
                                       patchMetaHdrPtr->origSize,
                                       patchMetaHdrPtr->origCrc32,
                                       *ctxPtr->poolPtr ))
            {
                LE_CRIT("Cannot apply patch. Partition \%s\" is not conform", MtdNamePtr);
                goto error;
            }
            // Check if the image inside the destination is a UBI container and the volume
            // ID exists
            if (LE_OK != CheckUbiData( MtdDestNum,
                                       patchMetaHdrPtr->ubiVolId,
                                       0,
                                       LE_CRC_START_CRC32,
                                       *ctxPtr->poolPtr ))
            {
                LE_CRIT("Cannot apply patch. Partition \%s\" is not UBI", MtdNamePtr);
                goto error;
            }
        }
        else if (LE_OK != partition_CheckData( MtdOrigNum,
                                               IsOrigLogical,
                                               IsOrigDual,
                                               patchMetaHdrPtr->origSize,
                                               0,
                                               patchMetaHdrPtr->origCrc32,
                                               *ctxPtr->poolPtr,
                                               true))
        {
            LE_CRIT("Cannot apply patch. Partition \"%s\" CRC32 does not match",
                    MtdNamePtr);
            goto error;
        }
        else
        {
            // Do nothing... CRC match
        }

        InPatch = true;
    }

    if (-1 == PatchFd)
    {
        // Create a new file containing the patch body
        PatchFd = open( TMP_PATCH_PATH, O_TRUNC | O_CREAT | O_WRONLY, S_IRUSR|S_IWUSR );
        if (-1 == PatchFd)
        {
            LE_CRIT("Failed to create patch file: %m");
            goto error;
        }
    }

    size_t *patchRemLenPtr = &ctxPtr->patchRemLen;
    size_t patchRemLen = *patchRemLenPtr;
    wrLen = (length > patchRemLen) ? patchRemLen : length;

    LE_DEBUG("Patch %u: Writing to patch file %d: wrLen = %zu, "
             "Patch.size %u, PatchRemLen %zu\n",
             patchHdrPtr->number, PatchFd, wrLen,
             patchHdrPtr->size, patchRemLen);
    if (wrLen != write( PatchFd, dataPtr, wrLen ))
    {
        LE_ERROR("Write to patch fails: %m");
        goto error;
    }

    *patchRemLenPtr -= wrLen;

    // Patch is complete. So apply it using bspatch
    if (0 == *patchRemLenPtr)
    {
        pa_flash_Desc_t desc;
        pa_patch_Context_t ctx;
        le_result_t res;
        bool isUbiPatch = false, isUbiPartition;

        close(PatchFd);
        PatchFd = -1;
        if (isFlashedPtr)
        {
            *isFlashedPtr = true;
        }
        LE_INFO("Applying patch %d, size %d at 0x%x\n",
                patchHdrPtr->number, patchHdrPtr->size, patchHdrPtr->offset);

        // Fill the patch context for origin and destination images
        ctx.segmentSize = patchMetaHdrPtr->segmentSize;
        ctx.patchOffset = patchHdrPtr->offset;
        if( PA_PATCH_INVALID_UBI_VOL_ID == patchMetaHdrPtr->ubiVolId )
        {
            ctx.origImage = PA_PATCH_IMAGE_RAWFLASH;
            ctx.destImage = PA_PATCH_IMAGE_RAWFLASH;
        }
        else
        {
            ctx.origImage = PA_PATCH_IMAGE_UBIFLASH;
            ctx.destImage = PA_PATCH_IMAGE_UBIFLASH;
            isUbiPatch = true;
        }
        ctx.origImageSize = patchMetaHdrPtr->origSize;
        ctx.origImageCrc32 = patchMetaHdrPtr->origCrc32;
        ctx.origImageDesc.flash.mtdNum = MtdOrigNum;
        ctx.origImageDesc.flash.ubiVolId = patchMetaHdrPtr->ubiVolId;
        ctx.origImageDesc.flash.isLogical = IsOrigLogical;
        ctx.origImageDesc.flash.isDual = IsOrigDual;
        ctx.destImageSize = patchMetaHdrPtr->destSize;
        ctx.destImageCrc32 = patchMetaHdrPtr->destCrc32;
        ctx.destImageDesc.flash.mtdNum = MtdDestNum;
        ctx.destImageDesc.flash.ubiVolId = patchMetaHdrPtr->ubiVolId;
        ctx.destImageDesc.flash.isLogical = IsDestLogical;
        ctx.destImageDesc.flash.isDual = IsDestDual;

        if (isUbiPatch)
        {
             if (LE_OK != pa_flash_Open( MtdOrigNum,
                                         PA_FLASH_OPENMODE_READONLY |
                                         (IsOrigLogical
                                          ? (IsOrigDual ? PA_FLASH_OPENMODE_LOGICAL_DUAL
                                             : PA_FLASH_OPENMODE_LOGICAL)
                                          : 0),
                                         &desc,
                                         NULL ))
             {
                 goto error;
             }
             // Check for UBI validity of the active partition.
             res = pa_flash_CheckUbi( desc, &isUbiPartition );
             if ((LE_OK != res) || (!isUbiPartition))
             {
                 pa_flash_Close(desc);
                 LE_ERROR("Check of UBI on MTD %d failed: %d, Validity %d",
                          MtdOrigNum, res, isUbiPartition);
                 goto error;
             }
        }
        res = bsPatch( &ctx,
                       TMP_PATCH_PATH,
                       &PatchCrc32,
                       patchMetaHdrPtr->numPatches == patchHdrPtr->number,
                       false);
        unlink(TMP_PATCH_PATH);
        if (LE_OK == res)
        {
            if (isUbiPatch)
            {
                // In this case, we need to recompute the checksum of the MTD to ensure that
                // it is conform to what we read during the patch.
                res = CheckUbiData( MtdOrigNum,
                                    patchMetaHdrPtr->ubiVolId,
                                    patchMetaHdrPtr->origSize,
                                    patchMetaHdrPtr->origCrc32,
                                   *ctxPtr->poolPtr );
                if (LE_OK != res)
                {
                    LE_CRIT("Cannot apply patch. MTD %d is not conform", MtdOrigNum);
                }
            }
        }
        if (isUbiPatch)
        {
            pa_flash_Close(desc);
        }
        if (LE_OK != res)
        {
            goto error;
        }
    }

    res = LE_OK;

    if ((offset + length) >= cweHdrPtr->imageSize )
    {
        // The whole patch segments were applied to destination image
        InPatch = false;
        LE_INFO( "Patch applied\n");
        close(PatchFd);
        PatchFd = -1;

        // Check if destination CRC is the expected one
        if (PA_PATCH_INVALID_UBI_VOL_ID != patchMetaHdrPtr->ubiVolId)
        {
            if (LE_OK != CheckUbiData( MtdDestNum,
                                       patchMetaHdrPtr->ubiVolId,
                                       patchMetaHdrPtr->destSize,
                                       patchMetaHdrPtr->destCrc32,
                                       *ctxPtr->poolPtr ))
            {
                LE_CRIT("UBI Patch failed Partition %d (\"%s\") CRC32 does not match",
                        MtdDestNum, MtdNamePtr);
                goto error;
            }
        }
        else
        {
            if (LE_OK != partition_CheckData( MtdDestNum,
                                              IsDestLogical,
                                              IsDestDual,
                                              patchMetaHdrPtr->destSize,
                                              0,
                                              patchMetaHdrPtr->destCrc32,
                                              *ctxPtr->poolPtr,
                                              true))
            {
                LE_CRIT("Patch failed Partition %d (\"%s\") CRC32 does not match",
                        MtdDestNum, MtdNamePtr);
                goto error;
            }
        }

        // clear bad image flag
        res = partition_SetBadImage(cweHdrPtr->imageType, false);
        if (LE_OK != res)
        {
            LE_ERROR("Failed to clear bad image flag for CWE imageType %d", cweHdrPtr->imageType);
        }

        LE_DEBUG( "CRC32: Expected 0x%X Patched 0x%X", patchMetaHdrPtr->destCrc32, PatchCrc32 );
        MtdDestNum = -1;
        MtdOrigNum = -1;
        // erase the diffType to allow to detect a new Patch Meta header
        memset(patchMetaHdrPtr->diffType, 0, sizeof(patchMetaHdrPtr->diffType));
    }

    return res;

error:
    InPatch = false;
    MtdDestNum = -1;
    MtdOrigNum = -1;
    if (-1 != PatchFd)
    {
        close(PatchFd);
        PatchFd = -1;
    }
    unlink(TMP_PATCH_PATH);
    res = bsPatch( NULL, NULL, NULL, true, true );
    return (forceClose ? res : LE_FAULT);
}

//--------------------------------------------------------------------------------------------------
/**
 * This function returns the expected length of to read according to the patch progress
 *
 * @return
 *      - the length to read
 *      - -1 on error
 */
//--------------------------------------------------------------------------------------------------
ssize_t deltaUpdate_GetPatchLengthToRead
(
    const deltaUpdate_Ctx_t *ctxPtr,    ///< [IN] Delta update context
    size_t chunkLength,                 ///< [IN] chunk length
    bool isImageToBeRead                ///< [IN] Boolean to know if data concerns header or
                                        ///<      component image
)
{
    ssize_t readCount = 0;

    if (!ctxPtr)
    {
        return -1;
    }

    if (false == isImageToBeRead)
    {
        // we are dealing with a patch
        // if Patch Meta Header has been successfully decoded then diffType[0] will be
        // non null
        if (ctxPtr->metaHdrPtr->diffType[0])
        {
            // we're already in a patch treatment so read a patch header
            readCount = PATCH_HEADER_SIZE;
        }
        else
        {
            // we're not already in a patch treatment so read a patch meta header
            readCount = PATCH_META_HEADER_SIZE;
        }
    }
    else
    {
        readCount = (ctxPtr->patchRemLen > chunkLength) ? chunkLength : ctxPtr->patchRemLen;
    }

    return readCount;
}

