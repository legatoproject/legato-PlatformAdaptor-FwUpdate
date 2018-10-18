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
#include "pa_flash_local.h"
#include "imgpatch.h"

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
    le_result_t res;

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
 * Open a UBI volume in target partition.
 *
 * @return
 *      - LE_OK        on success
 *      - LE_FAULT     on failure
 */
//--------------------------------------------------------------------------------------------------
static le_result_t OpenUbiVolume
(
    partition_Ctx_t* partCtxPtr,
    deltaUpdate_Ctx_t* ctxPtr,
    pa_flash_Desc_t desc
)
{
    deltaUpdate_PatchMetaHdr_t* metaHdrPtr = ctxPtr->metaHdrPtr;
    uint32_t volType;
    uint32_t volFlags;
    bool createVolumeReq = *(ctxPtr->ubiVolumeCreatedPtr) ? false : true;


    char volName[PA_FLASH_UBI_MAX_VOLUMES]= "";
    LE_INFO("createVolumeReq: %d, desc: %p", createVolumeReq, desc);
    // Get ubi volume and type
    le_result_t result = pa_flash_GetUbiTypeAndName(desc, &volType, volName, &volFlags);

    if (LE_OK != result)
    {
        LE_ERROR("Failed to get ubi volume type and name. desc: %p, result: %d, volName: %s",
                 desc, (int)(result), volName);
        return LE_FAULT;
    }
    if (metaHdrPtr->ubiVolType != (uint8_t)-1)
    {
        volType = metaHdrPtr->ubiVolType;
        volFlags = metaHdrPtr->ubiVolFlags;
    }

    if (LE_OK != partition_OpenUbiVolumeSwifotaPartition(partCtxPtr,
                                                         metaHdrPtr->ubiVolId,
                                                         volType,
                                                         PA_FLASH_VOLUME_STATIC == volType
                                                             ? metaHdrPtr->destSize
                                                             : -1,
                                                         volFlags,
                                                         volName,
                                                         createVolumeReq))

    {
        LE_ERROR("Failed to create ubi volume inside swifota");
        return LE_FAULT;
    }

    // The volume is sucessfully created. Set this boolean to be able to re-open the volume later
    // without recreate it
    *(ctxPtr->ubiVolumeCreatedPtr) = true;

    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Close a UBI volume in target partition.
 *
 * @return
 *      - LE_OK        on success
 *      - LE_FAULT     on failure
 */
//--------------------------------------------------------------------------------------------------
static le_result_t CloseAndVerifyUbiVolume
(
    partition_Ctx_t* partCtxPtr,
    deltaUpdate_Ctx_t* ctxPtr
)
{
    deltaUpdate_PatchMetaHdr_t* metaHdrPtr = ctxPtr->metaHdrPtr;

    if (LE_OK != partition_CloseUbiVolumeSwifotaPartition(partCtxPtr,
                                                           metaHdrPtr->destSize, false, NULL))
    {
        LE_ERROR("Failed to close ubi volume inside swifota partition");
        return LE_FAULT;
    }

    // The volume is sucessfully closed. Clear this boolean to be able to create other volumes later
    *(ctxPtr->ubiVolumeCreatedPtr) = false;

    uint32_t crc = 0, fullCrc = 0;
    size_t volSize = 0, fullSize = 0;
    LE_INFO("Requesting UBI volume size %u CRC32 0x%08x",
            metaHdrPtr->destSize, metaHdrPtr->destCrc32);
    if (LE_OK != partition_ComputeUbiVolumeCrc32SwifotaPartition(partCtxPtr,
                                                     metaHdrPtr->ubiVolId,
                                                     &volSize, &crc,
                                                     &fullSize, &fullCrc))
    {
        LE_ERROR("Failed to compute crc32 ubi volume in swifota partition");
        return LE_FAULT;
    }
    // Check crc32 of the ubi volume
    if (((fullSize != metaHdrPtr->destSize) || (fullCrc != metaHdrPtr->destCrc32)) &&
        ((volSize != metaHdrPtr->destSize) || (crc != metaHdrPtr->destCrc32)))
    {
        LE_ERROR("UBI volume size or crc32 mismatch. "
                 "Expected CRC32 = 0x%x size = %u",
                 metaHdrPtr->destCrc32, metaHdrPtr->destSize);
        LE_ERROR("Computed full CRC32= 0x%x size %zu", fullCrc, fullSize);
        LE_ERROR("Computed CRC32 = 0x%x size = %zu", crc, volSize);
        return LE_FAULT;
    }
    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Apply a patch in ubi partition.
 *
 * @return
 *      - LE_OK        on success
 *      - LE_FAULT     on failure
 */
//--------------------------------------------------------------------------------------------------
static le_result_t  ApplyUbiPatch
(
    int mtdOrigNum,                   ///< [IN] MTD number of the source partition
    deltaUpdate_Ctx_t* ctxPtr,        ///< [IN] Delta update context
    const char* patchFilePtr,         ///< [IN] File containing patch data
    pa_flash_Desc_t desc,             ///< [IN] Source flash read source chunk
    partition_Ctx_t* partCtxPtr,      ///< [IN] Target flash to write the patched file
    size_t* wrLenToFlash              ///< [OUT] Amount of data written to target flash
)
{
    if (!ctxPtr || !patchFilePtr || !partCtxPtr)
    {
        LE_ERROR("Bad input parameter. ctxPtr: %p, patchFilePtr: %p, partCtxPtr: %p",
                 ctxPtr,
                 patchFilePtr,
                 partCtxPtr);
        return LE_FAULT;
    }

    // If it is ubi volume
    // 1. Check volume crc32 with meta crc32
    // 2. Create ubi partition and volume if it is not created  yet
    // 3. If NODIFF then copy ubi volume
    // 4. If imgdiff specified then,call applyPatch_ApplyImgPatch()
    le_result_t result;
    if (0 == memcmp(ctxPtr->metaHdrPtr->diffType, NODIFF_MAGIC, strlen(NODIFF_MAGIC)))
    {
        // Must have opened a ubi volume before, no need to create ubi
        if (LE_OK != OpenUbiVolume(partCtxPtr, ctxPtr, desc))
        {
            LE_ERROR("Failed to create ubi volume inside swifota");
            return LE_FAULT;
        }
        // No chunk here, just copy what is inside patch file
        if (LE_OK !=imgpatch_WriteChunk(patchFilePtr, 0, ctxPtr->metaHdrPtr->destSize, partCtxPtr))
        {
            LE_ERROR("Failed to write small volume");
            return LE_FAULT;
        }
        *wrLenToFlash = ctxPtr->metaHdrPtr->destSize;
        // Close ubi volume partition
        if (LE_OK != CloseAndVerifyUbiVolume(partCtxPtr, ctxPtr))
        {
            LE_ERROR("Failed to close ubi volume inside swifota partition");
            return LE_FAULT;
        }
        // Now clear patch meta and other related info
        memset(ctxPtr->metaHdrPtr, 0 , sizeof(deltaUpdate_PatchMetaHdr_t));
        LE_INFO("Build UBI volume successful");
    }
    else if (0 == memcmp(ctxPtr->metaHdrPtr->diffType, IMGDIFF_MAGIC, strlen(IMGDIFF_MAGIC)))
    {
        bool value = false;
        if(LE_OK != applyPatch_IsFirstPatch(ctxPtr->imgCtxPtr, &value))
        {
            LE_ERROR("Bad imgpatch context: %p", ctxPtr->imgCtxPtr);
            return LE_FAULT;
        }

        if ((value) || (ctxPtr->reopenUbiVolume))
        {
            // Patch is related to an UBI volume
            // Check if the image inside the original UBI container has the right CRC
            if (LE_OK != CheckUbiData( mtdOrigNum,
                                       ctxPtr->metaHdrPtr->ubiVolId,
                                       ctxPtr->metaHdrPtr->origSize,
                                       ctxPtr->metaHdrPtr->origCrc32,
                                       *ctxPtr->poolPtr ))
            {
                LE_CRIT("Cannot apply patch. Partition not conform");
                return LE_FAULT;
            }

            if (LE_OK != OpenUbiVolume(partCtxPtr, ctxPtr, desc))
            {
                LE_ERROR("Failed to create ubi volume inside swifota");
                return LE_FAULT;
            }
            ctxPtr->reopenUbiVolume = false;
        }

        result = applyPatch_ApplyImgPatch(ctxPtr->imgCtxPtr, patchFilePtr, desc,
                                          partCtxPtr, wrLenToFlash);

        if (LE_OK != result)
        {
            LE_ERROR("Failed to apply patch inside swifota");
            return LE_FAULT;
        }

        value = false;
        if (LE_OK != applyPatch_IsLastPatch(ctxPtr->imgCtxPtr, &value))
        {
            LE_ERROR("Bad imgpatch context: %p", ctxPtr->imgCtxPtr);
            return LE_FAULT;
        }

        if (value)
        {
            // Close ubi volume partition
            if (LE_OK != CloseAndVerifyUbiVolume(partCtxPtr, ctxPtr))
            {
                LE_ERROR("Failed to close ubi volume inside swifota partition");
                return LE_FAULT;
            }
            if (LE_OK != CheckUbiData( mtdOrigNum,
                                       ctxPtr->metaHdrPtr->ubiVolId,
                                       ctxPtr->metaHdrPtr->origSize,
                                       ctxPtr->metaHdrPtr->origCrc32,
                                       *ctxPtr->poolPtr ))
            {
                LE_CRIT("Failed in applying patch. Partition not conform");
                return LE_FAULT;
            }

            LE_INFO("Build UBI volume successful");
        }
    }
    else
    {
        LE_ERROR("Unsupported diff type for ubi partition");
        return LE_FAULT;
    }

    return LE_OK;
}

//==================================================================================================
//  PUBLIC API FUNCTIONS
//==================================================================================================

//--------------------------------------------------------------------------------------------------
/**
 * This function is used to resume delta update
 *
 */
//--------------------------------------------------------------------------------------------------
void deltaUpdate_ResumeCtx
(
    partition_Ctx_t* partCtxPtr,     ///< [IN] Partition context
    deltaUpdate_Ctx_t* ctxPtr        ///< [IN] Delta update context
)
{
    if (!ctxPtr || !partCtxPtr)
    {
        LE_ERROR("Bad input parameter. ctxPtr: %p, partCtxPtr: %p", ctxPtr, partCtxPtr);
        return;
    }

    if (0 == memcmp(ctxPtr->metaHdrPtr->diffType, IMGDIFF_MAGIC, strlen(IMGDIFF_MAGIC)))
    {
        bool value = false;
        if(LE_OK != applyPatch_IsFirstPatch(ctxPtr->imgCtxPtr, &value))
        {
            LE_ERROR("Bad imgpatch context: %p", ctxPtr->imgCtxPtr);
            return;
        }

        if (!value)
        {
            // We are not in the first patch. UBI volume has already been created and data has
            // already been written. We need to reopen the volume later without erasing its content.
            ctxPtr->reopenUbiVolume = true;
        }
    }
    else
    {
        ctxPtr->reopenUbiVolume = false;
    }
}

//--------------------------------------------------------------------------------------------------
/**
 * This function is used by the Legato FW Update component to check whether current one is imgpatch
 * or not
 *
 * @return
 *      - True            If it is img patch
 *      - False           Otherwise
 */
//--------------------------------------------------------------------------------------------------
bool deltaUpdate_IsImgPatch
(
    uint32_t imgType             ///< [IN] cwe Header type
)
{

    if ((CWE_IMAGE_TYPE_USER == imgType) ||
        (CWE_IMAGE_TYPE_DSP2 == imgType) ||
        (CWE_IMAGE_TYPE_SYST == imgType))
    {
        return true;
    }
    return false;
}
//--------------------------------------------------------------------------------------------------
/**
 * This function is used by the Legato FW Update component to read a Patch Meta header
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
        LE_INFO("Patch type: %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX",
                     ((deltaUpdate_PatchMetaHdr_t*)startPtr)->diffType[0],
                     ((deltaUpdate_PatchMetaHdr_t*)startPtr)->diffType[1],
                     ((deltaUpdate_PatchMetaHdr_t*)startPtr)->diffType[2],
                     ((deltaUpdate_PatchMetaHdr_t*)startPtr)->diffType[3],
                     ((deltaUpdate_PatchMetaHdr_t*)startPtr)->diffType[4],
                     ((deltaUpdate_PatchMetaHdr_t*)startPtr)->diffType[5],
                     ((deltaUpdate_PatchMetaHdr_t*)startPtr)->diffType[6],
                     ((deltaUpdate_PatchMetaHdr_t*)startPtr)->diffType[7]);
        // Check patch magic

        if ((memcmp( ((deltaUpdate_PatchMetaHdr_t*)startPtr)->diffType, BSDIFF_MAGIC,
                     strlen(BSDIFF_MAGIC))) &&
            (memcmp( ((deltaUpdate_PatchMetaHdr_t*)startPtr)->diffType, IMGDIFF_MAGIC,
                     strlen(IMGDIFF_MAGIC))) &&
            (memcmp( ((deltaUpdate_PatchMetaHdr_t*)startPtr)->diffType, NODIFF_MAGIC,
                     strlen(NODIFF_MAGIC))))
        {
            LE_ERROR("Patch type is not correct: %s",
                     ((deltaUpdate_PatchMetaHdr_t*)startPtr)->diffType);
            memset(hdpPtr->diffType, 0, sizeof(hdpPtr->diffType));
            return LE_FAULT;
        }
        // Copy patch meta header and take care of byte order BIG endian vs LITTLE endian
        memcpy( &hdpPtr->diffType, startPtr, sizeof(hdpPtr->diffType) );
        deltaUpdate_PatchMetaHdr_t* tmpPtr = (deltaUpdate_PatchMetaHdr_t*)startPtr;
        hdpPtr->segmentSize = be32toh(tmpPtr->segmentSize);
        hdpPtr->numPatches = be32toh(tmpPtr->numPatches);
        hdpPtr->ubiVolId = be16toh(tmpPtr->ubiVolId);
        hdpPtr->ubiVolType = tmpPtr->ubiVolType;
        hdpPtr->ubiVolFlags = tmpPtr->ubiVolFlags;
        hdpPtr->origSize = be32toh(tmpPtr->origSize);
        hdpPtr->origCrc32 = be32toh(tmpPtr->origCrc32);
        hdpPtr->destSize = be32toh(tmpPtr->destSize);
        hdpPtr->destCrc32 = be32toh(tmpPtr->destCrc32);

        LE_INFO("Meta Header: SegSz 0x%X NumPtch %u UbiVolId %hu Type %hhu Flags %hhX",
                hdpPtr->segmentSize, hdpPtr->numPatches, hdpPtr->ubiVolId,
                hdpPtr->ubiVolType, hdpPtr->ubiVolFlags);
        LE_INFO("OrigSz %u OrigCrc 0x%X DestSz %u DestCrc 0x%X",
                hdpPtr->origSize, hdpPtr->origCrc32, hdpPtr->destSize, hdpPtr->destCrc32);
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
        LE_INFO("Patch %d: At offset 0x%x size 0x%x\n",
                hdpPtr->number, hdpPtr->offset, hdpPtr->size);
        ctxPtr->patchRemLen = hdpPtr->size;
    }
    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Apply imgpatch to a partition. This must be applied to UBI partition, caller should confirm that
 * it is applying patch to ubi partition.
 *
 * @return
 *      - LE_OK            on success
 *      - LE_FAULT         on failure
 *      - LE_NOT_PERMITTED if the patch is applied to the SBL
 *      - others           depending on the flash functions return
 */
//--------------------------------------------------------------------------------------------------
le_result_t deltaUpdate_ApplyUbiImgPatch
(
    deltaUpdate_Ctx_t *ctxPtr,          ///< [IN] Delta update context
    size_t length,                      ///< [IN] Input data length
    size_t offset,                      ///< [IN] Data offset in the package
    const uint8_t* dataPtr,             ///< [IN] Input data
    partition_Ctx_t* partitionCtxPtr,   ///< [IN] Context of the source partition
    size_t* lengthPtr,                  ///< [IN][OUT] Length to write and length written
    size_t* wrLenPtr,                   ///< [OUT] Length really written to flash
    bool forceClose,                    ///< [IN] Force close of device and resources
    bool *isFlashedPtr                  ///< [OUT] true if flash write was done
)
{
    static int MtdOrigNum = -1;
    static bool InPatch = false;
    static char *MtdNamePtr;
    static int PatchFd = -1;
    static pa_flash_Desc_t desc;

    size_t wrLen;
    le_result_t res;

    if (forceClose)
    {
        // If forceClose set, close descriptor and release all resources
        LE_CRIT( "Closing and releasing MTD due to forceClose\n" );
        goto ubierror;
    }

    if ((!dataPtr) || (!ctxPtr) || (!partitionCtxPtr))
    {
        goto ubierror;
    }

    const cwe_Header_t *cweHdrPtr = ctxPtr->cweHdrPtr;
    deltaUpdate_PatchMetaHdr_t *patchMetaHdrPtr = ctxPtr->metaHdrPtr;

    LE_INFO("Image type %"PRIu32" len %zu offset %zu (%"PRIu32")",
            cweHdrPtr->imageType, length, offset, cweHdrPtr->imageSize);

    if (CWE_IMAGE_TYPE_SBL1 == cweHdrPtr->imageType)
    {
        LE_ERROR("SBL could not be flashed as a patch");
        return LE_NOT_PERMITTED;
    }

    *wrLenPtr = 0;
    LE_DEBUG( "InPatch %d, len %zu, offset %zu\n", InPatch, length, offset );

    if (!InPatch)
    {
        bool isUbiPartition =false;
        MtdOrigNum = partition_GetMtdFromImageTypeOrName( cweHdrPtr->imageType, NULL, &MtdNamePtr );

        if (-1 == MtdOrigNum)
        {
            LE_ERROR( "Unable to find a valid mtd for image type %d\n", cweHdrPtr->imageType );
            goto ubierror;
        }

        if (PA_PATCH_INVALID_UBI_VOL_ID == patchMetaHdrPtr->ubiVolId)
        {
            LE_ERROR("Target isn't an UBI partition");
            goto ubierror;
        }


        if (LE_OK != pa_flash_Open( MtdOrigNum,
                                    PA_FLASH_OPENMODE_READONLY,
                                    &desc,
                                    NULL ))
        {
            goto ubierror;
        }
        // Check for UBI validity of the active partition.
        res = pa_flash_CheckUbi( desc, &isUbiPartition );
        if ((LE_OK != res) || (!isUbiPartition))
        {
            LE_ERROR("Check of UBI on MTD %d failed: %d, Validity %d",
                     MtdOrigNum, res, isUbiPartition);
            goto ubierror;
        }

        res = pa_flash_ScanUbi(desc, patchMetaHdrPtr->ubiVolId);
        if (LE_OK != res)
        {
            LE_ERROR("Scan of MTD %d UBI volId %u fails: %d",
                     MtdOrigNum, patchMetaHdrPtr->ubiVolId, res );
            goto ubierror;
        }
        LE_INFO("desc: %p, ubivol: %u", desc, patchMetaHdrPtr->ubiVolId);
        InPatch = true;
    }

    size_t *patchRemLenPtr = &ctxPtr->patchRemLen;
    if (0 == length)   // This is copy case for imgdiff, must be handled properly
    {
        *patchRemLenPtr = 0;
    }
    else
    {
        if (-1 == PatchFd)
        {
            // Create a new file containing the patch body
            PatchFd = open( TMP_PATCH_PATH, O_TRUNC|O_CREAT|O_WRONLY, S_IRUSR|S_IWUSR );
            if (-1 == PatchFd)
            {
                LE_CRIT("Failed to create patch file: %m");
                goto ubierror;
            }
        }


        size_t patchRemLen = *patchRemLenPtr;
        wrLen = (length > patchRemLen) ? patchRemLen : length;

        size_t nLen = 0;
        int rc;

        while( nLen < wrLen )
        {
            rc = write( PatchFd, dataPtr, wrLen );
            if( rc < 0 )
            {
                LE_ERROR("Write to patch fails: %m");
                goto ubierror;
            }
            nLen += rc;
        }

        *patchRemLenPtr -= wrLen;
    }
    // Patch is complete. So apply it using bspatch
    if (0 == *patchRemLenPtr)
    {

        if (PatchFd > 0)
        {
            close(PatchFd);
            PatchFd = -1;
        }


        // Check the delta image type and apply patch depending on patch type
        // Only two types of image will be handled here NODIFF and IMGDIFF2
        // BSDIFF40 will be handled by bspatch section.
        if (LE_OK != ApplyUbiPatch(MtdOrigNum, ctxPtr, TMP_PATCH_PATH,
                                   desc, partitionCtxPtr, wrLenPtr))
        {
            LE_ERROR("Failed to apply ubi patch");
            goto ubierror;
        }

        if (isFlashedPtr)
        {
            *isFlashedPtr = true;
        }

        if (lengthPtr)
        {
            *lengthPtr = length;
        }

        bool value = false;
        if (LE_OK != applyPatch_IsLastPatch(ctxPtr->imgCtxPtr, &value))
        {
            LE_ERROR("Bad imgpatch context: %p", ctxPtr->imgCtxPtr);;
            goto ubierror;
        }

        if (value)
        {
            pa_flash_Close(desc);
            InPatch = false;
            MtdOrigNum = -1;
            // Now clear patch meta and other related info
            memset(ctxPtr->metaHdrPtr, 0 , sizeof(deltaUpdate_PatchMetaHdr_t));
            applyPatch_Init(ctxPtr->imgCtxPtr);
        }
    }
    else
    {
        if (lengthPtr)
        {
            *lengthPtr = length;
        }

        return LE_OK;
    }

    return LE_OK;

ubierror:
    InPatch = false;
    MtdOrigNum = -1;
    if (-1 != PatchFd)
    {
        close(PatchFd);
        PatchFd = -1;
    }
    pa_flash_Close(desc);
    unlink(TMP_PATCH_PATH);

    return LE_FAULT;
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
    deltaUpdate_Ctx_t* ctxPtr,          ///< [IN] Delta update context
    size_t length,                      ///< [IN] Input data length
    size_t offset,                      ///< [IN] Data offset in the package
    const uint8_t* dataPtr,             ///< [IN] input data
    partition_Ctx_t* partitionCtxPtr,   ///< [IN] Context of the source partition
    size_t* lengthPtr,                  ///< [IN][OUT] Length to write and length written
    size_t* wrLenPtr,                   ///< [OUT] Length really written to flash
    bool forceClose,                    ///< [IN] Force close of device and resources
    bool *isFlashedPtr                  ///< [OUT] true if flash write was done
)
{
    static int MtdOrigNum = -1;
    static bool InPatch = false;
    static char *MtdNamePtr;
    static int PatchFd = -1;
    static uint32_t PatchCrc32;

    size_t wrLen;
    le_result_t res;

    if (forceClose)
    {
        // If forceClose set, close descriptor and release all resources
        LE_CRIT( "Closing and releasing MTD due to forceClose\n" );
        goto error;
    }

    if ((!dataPtr) || (!length) || (!ctxPtr) || (!partitionCtxPtr))
    {
        goto error;
    }

    const cwe_Header_t *cweHdrPtr = ctxPtr->cweHdrPtr;
    const deltaUpdate_PatchHdr_t *patchHdrPtr = ctxPtr->hdrPtr;
    deltaUpdate_PatchMetaHdr_t *patchMetaHdrPtr = ctxPtr->metaHdrPtr;

    LE_INFO("Image type %"PRIu32" len %zu offset %zu (%"PRIu32")",
            cweHdrPtr->imageType, length, offset, cweHdrPtr->imageSize);

    if (CWE_IMAGE_TYPE_SBL1 == cweHdrPtr->imageType)
    {
        LE_ERROR("SBL could not be flashed as a patch");
        return LE_NOT_PERMITTED;
    }

    if( PA_PATCH_INVALID_UBI_VOL_ID != patchMetaHdrPtr->ubiVolId )
    {
        LE_ERROR("bspatch only applied to non-ubi volume. Expected (volId): %u, Read (volId): %u",
                 PA_PATCH_INVALID_UBI_VOL_ID, patchMetaHdrPtr->ubiVolId);
        goto error;
    }

    if (wrLenPtr)
    {
        *wrLenPtr = 0;
    }

    LE_DEBUG( "InPatch %d, len %zu, offset %zu\n", InPatch, length, offset );
    if (!InPatch)
    {
        MtdOrigNum = partition_GetMtdFromImageTypeOrName( cweHdrPtr->imageType, NULL, &MtdNamePtr );

        if (-1 == MtdOrigNum)
        {
            LE_ERROR( "Unable to find a valid mtd for image type %d\n", cweHdrPtr->imageType );
            goto error;
        }

        // No patch in progress. This is a new patch
        PatchCrc32 = LE_CRC_START_CRC32;

        if (LE_OK != partition_CheckData( MtdOrigNum,
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

    size_t nLen = 0;
    int rc;

    while( nLen < wrLen )
    {
        rc = write( PatchFd, dataPtr, wrLen );
        if( rc < 0 )
        {
            LE_ERROR("Write to patch fails: %m");
            goto error;
        }
        nLen += rc;
    }

    *patchRemLenPtr -= wrLen;

    // Patch is complete. So apply it using bspatch
    if (0 == *patchRemLenPtr)
    {
        pa_patch_Context_t ctx;
        le_result_t res;

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

        ctx.origImage = PA_PATCH_IMAGE_RAWFLASH;
        ctx.destImage = PA_PATCH_IMAGE_RAWFLASH;

        ctx.origImageSize = patchMetaHdrPtr->origSize;
        ctx.origImageCrc32 = patchMetaHdrPtr->origCrc32;
        ctx.origImageDesc.flash.mtdNum = MtdOrigNum;
        ctx.origImageDesc.flash.ubiVolId = (uint32_t)patchMetaHdrPtr->ubiVolId;
        ctx.origImageDesc.flash.isLogical = false;
        ctx.origImageDesc.flash.isDual = false;
        ctx.destImageSize = patchMetaHdrPtr->destSize;
        ctx.destImageCrc32 = patchMetaHdrPtr->destCrc32;
        ctx.destImageDesc.flash.mtdNum = -1;
        ctx.destImageDesc.flash.ubiVolId = patchMetaHdrPtr->ubiVolId;
        ctx.destImageDesc.flash.isLogical = false;
        ctx.destImageDesc.flash.isDual = false;
        ctx.destArg1 = (void*)partitionCtxPtr;
        ctx.destArg2 = (void*)wrLenPtr;

        res = bsPatch( &ctx,
                       TMP_PATCH_PATH,
                       &PatchCrc32,
                       patchMetaHdrPtr->numPatches == patchHdrPtr->number,
                       false);
        unlink(TMP_PATCH_PATH);

        if (patchMetaHdrPtr->numPatches == patchHdrPtr->number)
        {
            LE_INFO("Last patch applied");
            // erase the diffType to allow to detect a new Patch Meta header
            memset(patchMetaHdrPtr->diffType, 0, sizeof(patchMetaHdrPtr->diffType));
            InPatch = false;
            MtdOrigNum = -1;
        }

        if (lengthPtr)
        {
            *lengthPtr = length;
        }

        if (LE_OK != res)
        {
            goto error;
        }
    }

    LE_INFO("CurrentPatch: %d Patch count: %u", patchHdrPtr->number, patchMetaHdrPtr->numPatches);
    return LE_OK;

error:
    InPatch = false;
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
            deltaUpdate_PatchMetaHdr_t* hdpPtr = ctxPtr->metaHdrPtr;

            if (0 == memcmp(hdpPtr->diffType, BSDIFF_MAGIC, strlen(BSDIFF_MAGIC)))
            {
                LE_DEBUG("Read bsdiff patch meta");
                readCount = PATCH_HEADER_SIZE;
            }
            else if (0 == memcmp(hdpPtr->diffType, IMGDIFF_MAGIC, strlen(IMGDIFF_MAGIC)))
            {
                LE_DEBUG("Read imgdiff patch meta");
                readCount = applyPatch_GetPatchLengthToRead(ctxPtr->imgCtxPtr,
                                                            chunkLength,
                                                            isImageToBeRead);
            }
            else
            {
                LE_CRIT("Bad diffType: %s", hdpPtr->diffType);
                readCount = -1;
            }
        }
        else
        {
            LE_DEBUG("Read meta header");
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

