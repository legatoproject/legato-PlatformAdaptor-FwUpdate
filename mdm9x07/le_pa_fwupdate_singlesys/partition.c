/**
 * @file partition.c
 *
 * Partition management functions
 *
 *
 * Copyright (C) Sierra Wireless Inc.
 *
 */

#include <sys/time.h>
#include "legato.h"
#include "cwe_local.h"
#include "partition_local.h"
#include "pa_flash.h"

//--------------------------------------------------------------------------------------------------
/**
 * "ubi" string length
 */
//--------------------------------------------------------------------------------------------------
#define UBI_STRING_LENGTH      3

//--------------------------------------------------------------------------------------------------
/**
 * "/sys/class/ubi" access path
 */
//--------------------------------------------------------------------------------------------------
#ifdef LEGATO_EMBEDDED
#define SYS_CLASS_UBI_PATH     "/sys/class/ubi"
#else
#define SYS_CLASS_UBI_PATH     "/tmp"
#endif

//--------------------------------------------------------------------------------------------------
/**
 * "/sys/class/mtd" access path
 */
//--------------------------------------------------------------------------------------------------
#ifdef LEGATO_EMBEDDED
#define PROC_MTD_PATH          "/proc/mtd"
#else
#define PROC_MTD_PATH          "/tmp/mtd"
#endif

//--------------------------------------------------------------------------------------------------
/**
 * Full image start block offset
 */
//--------------------------------------------------------------------------------------------------
#define IMG_BLOCK_OFFSET      2

//--------------------------------------------------------------------------------------------------
/**
 * Delay to wait before running the CRC computation on a erase block. This is to prevent lack
 * of CPU resources and hardware watchdog elapses.
 * This 1 milli-second in nano-seconds.
 */
//--------------------------------------------------------------------------------------------------
#define SUSPEND_DELAY (1000000)

//==================================================================================================
//                                       Static variables
//==================================================================================================

//--------------------------------------------------------------------------------------------------
/**
 * Partition Name, Sub System ID and Image Type matrix
 */
//--------------------------------------------------------------------------------------------------
partition_Identifier_t Partition_Identifier[ CWE_IMAGE_TYPE_COUNT ] = {
    { NULL,     },
    { "sbl",    },
    { NULL,     },
    { NULL,     },
    { "modem",  },
    { NULL,     },
    { "rpm",    },
    { NULL,     },
    { NULL,     },
    { NULL,     },
    { NULL,     },
    { "boot",   },
    { "aboot",  },
    { NULL,     },
    { NULL,     },
    { NULL,     },
    { NULL,     },
    { NULL,     },
    { NULL,     },
    { NULL,     },
    { NULL,     },
    { NULL,     },
    { "system", },
    { "lefwkro" },
    { NULL,     },
    { NULL,     },
    { NULL,     },
    { NULL,     },
    { NULL,     },
    { "tz",     },
    { NULL,     },
    { NULL,     },
    { "userapp" },
    { NULL,     },
    { NULL,     },
    { NULL,     },
    { NULL,     },
};

//--------------------------------------------------------------------------------------------------
/**
 * Pointer to the MTD name
 */
//--------------------------------------------------------------------------------------------------
static char* MtdNamePtr = NULL;

//--------------------------------------------------------------------------------------------------
/**
 * Image size
 */
//--------------------------------------------------------------------------------------------------
static size_t  ImageSize = 0;

//==================================================================================================
//  PUBLIC API FUNCTIONS
//==================================================================================================

//--------------------------------------------------------------------------------------------------
/**
 * Gets the MTD number and partition name belonging to an image type or a real name (if not NULL).
 * The MTD name and the write size of the partition are also returned as output parameters.
 *
 * @return
 *      - The MTD number belonging the image type for the boot system (dual or initial)
 *      -  1 if initial boot system is 2,
 *      - -1 in case of failure
 */
//--------------------------------------------------------------------------------------------------
int partition_GetMtdFromImageTypeOrName
(
    cwe_ImageType_t partName,         ///< [IN] Partition enumerate to get
    char*  partNamePtr,               ///< [IN] Partition name to get or NULL
    char** mtdNamePtr                 ///< [OUT] Pointer to the real MTD partition name
                                      ///<       RPM2), false in case of lower partition
)
{
    FILE* flashFdPtr;
    char mtdBuf[100], mtdFetchName[16];
    int mtdNum = -1, l;

    char* mtdPartNamePtr;

    if (mtdNamePtr)
    {
        *mtdNamePtr = NULL;
    }
    // Valid image type
    if (partName > CWE_IMAGE_TYPE_MAX)
    {
        LE_ERROR("partName > CWE_IMAGE_TYPE_MAX");
        return -1;
    }

    if( partNamePtr )
    {
        mtdPartNamePtr = partNamePtr;
    }
    else
    {
        mtdPartNamePtr = Partition_Identifier[partName].namePtr;
        // If NULL, the partition (even if it exists) is not managed by fwupdate component
        if (!mtdPartNamePtr)
        {
            LE_ERROR("Partition not managed by fwupdate");
            return -1;
        }
    }

    // Build the partition name to fetch into the /proc/mtd
    snprintf( mtdFetchName, sizeof(mtdFetchName), "\"%s\"", mtdPartNamePtr );
    l = strlen( mtdFetchName );

    // Open the /proc/mtd partition
    if (NULL == (flashFdPtr = fopen(PROC_MTD_PATH, "r")))
    {
        LE_ERROR( "fopen on /proc/mtd failed: %m" );
        return -1;
    }

    // Read all entries until the partition names match
    while (fgets(mtdBuf, sizeof(mtdBuf), flashFdPtr ))
    {
        // This is the fetched partition
        if (0 == strncmp( mtdBuf + strlen( mtdBuf ) - l - 1, mtdFetchName, l ))
        {
            // Get the MTD number
            if (1 != sscanf( mtdBuf, "mtd%d", &mtdNum ))
            {
                LE_ERROR( "Unable to scan the mtd number in %s", mtdBuf );
            }
            else
            {
                // Output MTD partition name and MTD number
                if (mtdNamePtr)
                {
                    *mtdNamePtr = mtdPartNamePtr;
                    LE_DEBUG( "Partition %s is mtd%d", *mtdNamePtr, mtdNum );
                }
            }
            break;
        }
    }
    fclose( flashFdPtr );

    // Return the MTD number
    return mtdNum;
}

//--------------------------------------------------------------------------------------------------
/**
 * This function checks if the partition related to the given MTD is currently mounted or is
 * attached to an UBI.
 *
 * @return
 *      - LE_OK            The partition is not mounted and not attached to an UBI
 *      - LE_BAD_PARAMETER The MTD number is negative
 *      - LE_BUSY          The partition is currently mounted or attached
 *      - LE_FAULT         If an error occurs
 */
//--------------------------------------------------------------------------------------------------
le_result_t partition_CheckIfMounted
(
    int mtdNum
)
{
    DIR* dirPtr;
    struct dirent *direntPtr;
    FILE* fdPtr;
    int  ubiMtdNum = - 1;
    char ubiMtdNumStr[PATH_MAX];
    char mountStr[PATH_MAX];
    le_result_t res = LE_OK;

    if (0 > mtdNum)
    {
        return LE_BAD_PARAMETER;
    }

    // Check if the MTD is attached as UBI
    dirPtr = opendir( SYS_CLASS_UBI_PATH );
    if (dirPtr)
    {
        // Read all entries in the directory
        while ((NULL != (direntPtr = readdir( dirPtr ))))
        {
           if ((0 == strncmp( "ubi", direntPtr->d_name, UBI_STRING_LENGTH )) &&
               (isdigit( direntPtr->d_name[UBI_STRING_LENGTH] )) &&
               (!strchr( direntPtr->d_name, '_')) )
           {
               snprintf( ubiMtdNumStr, sizeof(ubiMtdNumStr), SYS_CLASS_UBI_PATH "/%s/mtd_num",
                         direntPtr->d_name );
               ubiMtdNum = - 1;
               // Try to read the MTD number attached to this UBI
               fdPtr = fopen( ubiMtdNumStr, "r" );
               if (fdPtr)
               {
                   if (EOF == fscanf(fdPtr, "%d", &ubiMtdNum))
                   {
                       LE_ERROR("error while reading the MTD number %m");
                   }

                   fclose( fdPtr );
               }
               else
               {
                   // Skip if the open fails
                   continue;
               }
               if (ubiMtdNum == mtdNum)
               {
                   // When the MTD is attached, we consider it is busy and reject it
                   LE_ERROR("MTD %d is attached to UBI %s. Device is busy",
                            mtdNum, direntPtr->d_name);
                   res = LE_BUSY;
                   break;
               }
           }
        }
        closedir( dirPtr );
    }
    // Not attached to UBI, look into the /proc/mounts
    if (ubiMtdNum != mtdNum)
    {
        snprintf( ubiMtdNumStr, sizeof(ubiMtdNumStr), "/dev/mtdblock%d ", mtdNum );
        fdPtr = fopen( "/proc/mounts", "r" );
        if (fdPtr)
        {
            while (fgets( mountStr, sizeof(mountStr), fdPtr ))
            {
                if (0 == strncmp( mountStr, ubiMtdNumStr, strlen(ubiMtdNumStr) ) )
                {
                    LE_ERROR("MTD %d s mounted. Device is busy", mtdNum);
                    res = LE_BUSY;
                    break;
                }
            }
            fclose(fdPtr);
        }
        else
        {
            res = LE_FAULT;
        }
    }

    return res;
}

//--------------------------------------------------------------------------------------------------
/**
 * This function checks if the partition related to the given MTD is currently an UBI container. If
 * yes, returns the UBI Identifier and the number of volumes detected.
 *
 * @return
 *      - LE_OK            The partition is an UBI container
 *      - LE_BAD_PARAMETER The MTD number is negative, or the other parameters are NULL
 *      - LE_FORMAT_ERROR  The partition is not an UBI container
 *      - LE_FAULT         If an error occurs
 */
//--------------------------------------------------------------------------------------------------
le_result_t partition_CheckIfUbiAndGetUbiVolumes
(
    int mtdNum,             ///< [IN]  MTD to check as UBI container
    int* ubiIdPtr,          ///< [OUT] UBI identifier in case of UBI container
    int* nbUbiVolumesPtr    ///< [OUT] Number of UBI volumes detected
)
{
    DIR* dirPtr;
    struct dirent *direntPtr;
    FILE* fdPtr;
    int  ubiMtdNum = - 1;
    char ubiTmpStr[PATH_MAX];
    le_result_t res = LE_FORMAT_ERROR;

    if ((0 > mtdNum) || (!ubiIdPtr) || (!nbUbiVolumesPtr))
    {
        LE_ERROR("Bad parameters");
        return LE_BAD_PARAMETER;
    }

    *ubiIdPtr = -1;        // Not a valid UBI identifier
    *nbUbiVolumesPtr = -1; // Not a valid number of UBI volumes

    // Check if the MTD is attached as UBI
    dirPtr = opendir( SYS_CLASS_UBI_PATH );
    if (dirPtr)
    {
        // Read all entries in the directory
        while ((NULL != (direntPtr = readdir( dirPtr ))))
        {
           if ((0 == strncmp( "ubi", direntPtr->d_name, UBI_STRING_LENGTH )) &&
               (isdigit( direntPtr->d_name[UBI_STRING_LENGTH] )) &&
               (!strchr( direntPtr->d_name, '_')) )
           {
               snprintf( ubiTmpStr, sizeof(ubiTmpStr), SYS_CLASS_UBI_PATH "/%s/mtd_num",
                         direntPtr->d_name );
               ubiMtdNum = - 1;
               // Try to read the MTD number attached to this UBI
               fdPtr = fopen( ubiTmpStr, "r" );
               if (fdPtr)
               {
                   if (EOF == fscanf(fdPtr, "%d", &ubiMtdNum))
                   {
                       LE_ERROR("error while reading the MTD number %m");
                   }

                   fclose( fdPtr );
               }
               else
               {
                   // Skip if the open fails
                   continue;
               }
               if (ubiMtdNum == mtdNum)
               {
                   if (1 == sscanf(direntPtr->d_name, "ubi%d", &ubiMtdNum))
                   {
                       res = LE_OK;
                   }
                   break;
               }
           }
        }
        closedir( dirPtr );
    }
    else
    {
        res = LE_FAULT;
    }

    if (LE_OK == res)
    {
        int nbUbiVol;

        // The current MTD is an UBI container. Read the number of UBI volumes supported
        snprintf( ubiTmpStr, sizeof(ubiTmpStr), SYS_CLASS_UBI_PATH "/ubi%d/volumes_count",
                  ubiMtdNum);
        fdPtr = fopen( ubiTmpStr, "r" );
        if (fdPtr)
        {
            if (1 == fscanf( fdPtr, "%d", &nbUbiVol ))
            {
                *ubiIdPtr = ubiMtdNum;
                *nbUbiVolumesPtr = nbUbiVol;
                LE_INFO("MTD %d UBI %d Nb Volumes %d", mtdNum, ubiMtdNum, nbUbiVol);
            }
            else
            {
                LE_ERROR("Unable to read the number of UBI volumes. MTD %d UBI %d",
                         mtdNum, ubiMtdNum);
                res = LE_FAULT;
            }
            fclose( fdPtr );
        }
        else
        {
            LE_ERROR("Unable to open entry '%s'. MTD %d UBI %d: %m",
                     ubiTmpStr, mtdNum, ubiMtdNum);
            res = LE_FAULT;
        }
    }

    return res;
}

//--------------------------------------------------------------------------------------------------
/**
 * Check if data flashed into a partition are correctly written
 *
 * @return
 *      - LE_OK       on success
 *      - LE_FAULT    on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t partition_CheckData
(
    int mtdNum,                        ///< [IN] Minor of the MTD device to check
    size_t sizeToCheck,                ///< [IN] Size to be used to compute the CRC
    off_t atOffset,                    ///< [IN] Force offset to start from
    uint32_t crc32ToCheck,             ///< [IN] Expected CRC 32
    le_mem_PoolRef_t flashImgPool,     ///< [IN] Memory pool
    bool isEccChecked                  ///< [IN] Whether need to check ecc status in the partition
)
{
    pa_flash_Desc_t flashFd = NULL;
    uint8_t* checkBlockPtr = NULL;

    size_t size, imageSize = 0;
    off_t offset = atOffset;
    uint32_t crc32 = LE_CRC_START_CRC32;
    pa_flash_Info_t* flashInfoPtr;
    pa_flash_EccStats_t flashEccStats;
    pa_flash_OpenMode_t mode = PA_FLASH_OPENMODE_READONLY;
    struct timespec suspendDelay = { 0, SUSPEND_DELAY }; // 1 ms.
    le_result_t res;

    LE_DEBUG("Size=%zu, Crc32=0x%08X", sizeToCheck, crc32ToCheck);

    checkBlockPtr = (uint8_t *) le_mem_ForceAlloc(flashImgPool);

    if (LE_OK != pa_flash_Open( mtdNum, mode, &flashFd, &flashInfoPtr ))
    {
        LE_ERROR("Open of MTD %d fails: %m", mtdNum );
        goto error;
    }
    if (LE_OK != pa_flash_Scan( flashFd, NULL ))
    {
        LE_ERROR("Scan of MTD %d fails: %m", mtdNum );
        goto error;
    }

    while ((imageSize < sizeToCheck) && (offset < (flashInfoPtr->nbLeb * flashInfoPtr->eraseSize)))
    {
        loff_t blkOff = (loff_t)offset;
        uint32_t iBlk, nBlk;

        size = (((imageSize + flashInfoPtr->eraseSize) < sizeToCheck)
                   ? flashInfoPtr->eraseSize
                   : (sizeToCheck - imageSize));

        // As we will compute a CRC for a big amount of memory, we need to give time for others
        // processes to schedule and also to prevent the hardware watchdog to elapse.
        if ((-1 == nanosleep(&suspendDelay, NULL)) && (EINTR != errno))
        {
            LE_ERROR("nanosleep(%ld.%ld) fails: %m", suspendDelay.tv_sec, suspendDelay.tv_nsec);
        }

        LE_DEBUG("Read %d at offset 0x%lx, block offset 0x%llx", size, offset, blkOff);
        if (LE_OK != pa_flash_SeekAtBlock( flashFd,
                                           ((off_t)blkOff / flashInfoPtr->eraseSize) ))
        {
            LE_ERROR("Seek fails for offset 0x%llx: %m", blkOff);
            goto error;
        }
        nBlk = (size + (flashInfoPtr->writeSize - 1)) / flashInfoPtr->writeSize;
        for (iBlk = 0; iBlk < nBlk; iBlk++)
        {
            if (LE_OK != pa_flash_Read( flashFd,
                                        (checkBlockPtr + (iBlk * flashInfoPtr->writeSize)),
                                        flashInfoPtr->writeSize ))
            {
                LE_ERROR("Read fails for offset 0x%llx: %m", blkOff);
                goto error;
            }
        }

        crc32 = le_crc_Crc32( checkBlockPtr, size, crc32);
        offset += size;
        imageSize += size;
    }

    // Check for unrecoverable ECC errors on active partition and abort if some.
    res = pa_flash_GetEccStats( flashFd, &flashEccStats );
    if (LE_OK != res)
    {
        LE_ERROR("Getting ECC statistics fails on mtd%d: %d", mtdNum, res);
        goto error;
    }
    // Corrected ECC errors are ignored, because normally the data are valid.
    // Abort in case of unrecoverable ECC errors.
    if (flashEccStats.failed)
    {
        LE_CRIT("Unrecoverable ECC errors detected on mtd%d: %u %u %u",
                 mtdNum, flashEccStats.corrected, flashEccStats.failed, flashEccStats.badBlocks);
        // ECCGETSTATS only record the number of ECC errors happened from power in this partition.
        // In case the dest partition is erased after sync/update, there should be no more ECC
        // errors. So remove the check for the dest partition. For the src partition, there is a
        // bug in driver that ECC can't be detected, so keep the ecc check for src partition.
        if (true == isEccChecked)
        {
          goto error;
        }
    }

    if (crc32 != crc32ToCheck)
    {
        LE_CRIT( "Bad CRC32 calculated on mtd%d: read 0x%08x != expected 0x%08x",
                 mtdNum, crc32, crc32ToCheck );
        goto error;
    }

    LE_INFO("CRC32 OK for mtd%d", mtdNum );

    pa_flash_Close( flashFd );
    le_mem_Release(checkBlockPtr);
    return LE_OK;

error:
    pa_flash_Close( flashFd );
    le_mem_Release(checkBlockPtr);
    return LE_FAULT;
}

//--------------------------------------------------------------------------------------------------
/**
 * Write data in SWIFOTA partition
 *
 * @return
 *      - LE_OK on success
 *      - LE_FAULT on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t partition_WriteSwifotaPartition
(
    partition_Ctx_t *ctxPtr,          ///< [INOUT] Context
    size_t* lengthPtr,                ///< [INOUT] Data length pointer
    size_t offset,                    ///< [IN] Data offset in the partition
    const uint8_t* dataPtr,           ///< [IN] Input data
    bool forceClose,                  ///< [IN] Force close of device and resources
    bool *isFlashedPtr                ///< [OUT] True if flash write was done
)
{
    if (forceClose)
    {
        // If forceClose set, close descriptor and release all resources
        LE_CRIT( "Closing and releasing MTD due to forceClose" );
        goto error;
    }

    // Check input parameters
    if (!ctxPtr || !dataPtr)
    {
        LE_ERROR("NULL pointer");
        return LE_FAULT;
    }

    int mtdNum;
    le_result_t ret = LE_OK;
    uint32_t* fullImageCrc32 = &ctxPtr->fullImageCrc;

    // Static variables for WriteData
    static size_t InOffset               = 0;      // Current offset in erase block
    static uint8_t* DataPtr              = NULL;   // Buffer to copy data (size of an erase block)
    static pa_flash_Info_t* FlashInfoPtr = NULL;   // MTD information of the current MTD
    static pa_flash_Desc_t MtdFd         = NULL;   // File descriptor for MTD operations
    const cwe_Header_t *hdrPtr           = ctxPtr->cweHdrPtr;

    LE_INFO("Image type %"PRIu32" len %zu offset 0x%zx", hdrPtr->imageType, *lengthPtr, offset);

    // Open the partition if not already done and perform some checks before writing into it.
    if ((NULL == MtdFd) && (0 == ImageSize))
    {
        int iblk = 0;
        le_result_t res;

        mtdNum = partition_GetMtdFromImageTypeOrName(0, "swifota", &MtdNamePtr);
        if (-1 == mtdNum)
        {
            LE_ERROR( "Unable to find a valid mtd for image type \"swifota\"" );
            return LE_FAULT;
        }

        if (LE_OK != partition_CheckIfMounted(mtdNum))
        {
            LE_ERROR("MTD %d is mounted", mtdNum);
            return LE_FAULT;
        }

        if (LE_OK != pa_flash_Open(mtdNum,
                                   PA_FLASH_OPENMODE_READWRITE | PA_FLASH_OPENMODE_MARKBAD,
                                   &MtdFd,
                                   &FlashInfoPtr))
        {
            LE_ERROR("Fails to open MTD %d", mtdNum );
            return LE_FAULT;
        }

        if (LE_OK != pa_flash_Scan( MtdFd, NULL ))
        {
            LE_ERROR("Fails to scan MTD");
            goto error;
        }

        // Check if the image size is compliant with partition size. For SWIFOTA, the first two
        // blocks are reserved for Meta data.
        if (hdrPtr->imageSize > (FlashInfoPtr->size - (IMG_BLOCK_OFFSET * FlashInfoPtr->eraseSize)))
        {
            LE_ERROR("Image size overlaps with the Meta data reserved blocks. Image size: %d,"
                      "partition size: %d", hdrPtr->imageSize, FlashInfoPtr->size);
            goto error;
        }

        DataPtr = le_mem_ForceAlloc(*ctxPtr->flashPoolPtr);
        ImageSize = ctxPtr->fullImageSize;
        InOffset = offset % FlashInfoPtr->eraseSize;

        // If the data offset is not aligned on an erase block start address, we need to move back
        // the already written data from flash to memory along with the new data.
        if (InOffset)
        {
            InOffset = offset % FlashInfoPtr->eraseSize;
            offset -= InOffset;

            if (LE_OK != pa_flash_SeekAtOffset(MtdFd,
                                               offset +
                                               (IMG_BLOCK_OFFSET * FlashInfoPtr->eraseSize)))
            {
                LE_ERROR("Failed to seek block at offset: %d", offset);
                goto error;
            }

            if (LE_OK != pa_flash_Read(MtdFd, DataPtr, InOffset))
            {
                LE_ERROR( "Fread to nandwrite fails: %m" );
                goto error;
            }
        }

        // When offset is 0. It means that we are about to write the first chunk of data in the
        // current partition.
        if (offset == 0)
        {
            ctxPtr->logicalBlock = IMG_BLOCK_OFFSET;
            ctxPtr->phyBlock = 0;
            *fullImageCrc32 = LE_CRC_START_CRC32;
            iblk = 0;
        }
        else
        {
            iblk = offset / FlashInfoPtr->eraseSize + IMG_BLOCK_OFFSET;
        }

        // Erase blocks
        for (; iblk < FlashInfoPtr->nbLeb; iblk++)
        {
            bool isBad;

            if ((LE_OK != (res = pa_flash_CheckBadBlock(MtdFd, iblk, &isBad)))
                && (res != LE_NOT_PERMITTED))
            {
                LE_ERROR("Fails to check bad block %d", iblk);
                goto error;
            }
            if (isBad)
            {
                LE_WARN("Skipping bad block %d", iblk);
            }
            else
            {
                res = pa_flash_EraseBlock(MtdFd, iblk);
                if ((LE_OK != res) && (res != LE_NOT_PERMITTED))
                {
                    LE_ERROR("Fails to erase block %d: res=%d", iblk, res);
                    goto error;
                }
                if ((!ctxPtr->phyBlock) && (iblk >= ctxPtr->logicalBlock))
                {
                    ctxPtr->phyBlock = iblk;
                }
            }
        }

        if (LE_OK != pa_flash_SeekAtOffset(MtdFd,
                                           offset + (IMG_BLOCK_OFFSET * FlashInfoPtr->eraseSize)))
        {
            LE_ERROR("Fails to seek block at %d", iblk);
            goto error;
        }
    }

    if ((NULL == FlashInfoPtr) || (NULL == DataPtr))
    {
        LE_ERROR("Bad behavior !!!");
        goto error;
    }

    if (((uint32_t)(*lengthPtr + InOffset)) >= FlashInfoPtr->eraseSize)
    {
        size_t inOffsetSave = FlashInfoPtr->eraseSize - InOffset;
        memcpy(DataPtr + InOffset, dataPtr, inOffsetSave);
        // set isFlashed before the write because even if the write returns an error
        // some data could have been written in the flash
        if (isFlashedPtr)
        {
            *isFlashedPtr = true;
        }

        if (LE_OK != pa_flash_Write(MtdFd, DataPtr, FlashInfoPtr->eraseSize))
        {
            LE_ERROR( "fwrite to nandwrite fails: %m" );
            goto error;
        }
        *fullImageCrc32 = le_crc_Crc32(DataPtr, FlashInfoPtr->eraseSize, *fullImageCrc32);
        InOffset = 0;
        *lengthPtr = inOffsetSave;
    }
    else
    {
        memcpy( DataPtr + InOffset, dataPtr, *lengthPtr );
        InOffset += *lengthPtr;
    }

    if ((*lengthPtr + offset) >= ImageSize)
    {
        uint32_t reservedOffset = FlashInfoPtr->eraseSize * 2;
        if (InOffset)
        {
            if (InOffset <= FlashInfoPtr->eraseSize)
            {
                memset(DataPtr + InOffset,
                       PA_FLASH_ERASED_VALUE,
                       FlashInfoPtr->eraseSize - InOffset);
            }
            // set isFlashed before the write because even if the write returns an error
            // some data could have been written in the flash
            if (isFlashedPtr)
            {
                *isFlashedPtr = true;
            }

            if (LE_OK != pa_flash_Write(MtdFd, DataPtr, FlashInfoPtr->eraseSize))
            {
                LE_ERROR("fwrite to nandwrite fails: %m" );
                goto error;
            }
            *fullImageCrc32 = le_crc_Crc32(DataPtr, InOffset, *fullImageCrc32);
        }

        le_mem_Release(DataPtr);
        pa_flash_Close(MtdFd);
        MtdFd = NULL;
        LE_INFO("Update for partiton %s done with return %d", MtdNamePtr, ret);
        MtdNamePtr = NULL;

        mtdNum = partition_GetMtdFromImageTypeOrName( 0, "swifota", &MtdNamePtr);
        if (-1 == mtdNum)
        {
            LE_ERROR("Unable to find a valid mtd for \"swifota\"" );
            return LE_FAULT;
        }
        ret = partition_CheckData(mtdNum, ImageSize, reservedOffset,
                                  *fullImageCrc32, *ctxPtr->flashPoolPtr, false);
        DataPtr = NULL;
        ImageSize = 0;
        InOffset = 0;
    }
    return ret;

error:
    InOffset = 0;
    ret = LE_OK;
    if (MtdFd)
    {
        ret = pa_flash_Close( MtdFd );
        MtdFd = NULL;
    }
    ImageSize = 0;
    MtdNamePtr = NULL;
    if (DataPtr)
    {
        le_mem_Release(DataPtr);
        DataPtr = NULL;
    }
    return (forceClose ? ret : LE_FAULT);
}

//--------------------------------------------------------------------------------------------------
/**
 * Write meta data in the beginning of SWIFOTA partition
 *
 * @return
 *      - LE_OK on success
 *      - LE_FAULT on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t partition_WriteMetaData
(
    const partition_Ctx_t *ctxPtr,    ///< [IN] Context
    size_t length,                    ///< [IN] Input data length
    size_t offset,                    ///< [IN] Data offset in the package
    const uint8_t* dataPtr,           ///< [IN] Input data
    bool forceClose                  ///< [IN] Force close of device and resources
)
{
    int mtdNum;
    le_result_t ret = LE_OK;

    if (forceClose)
    {
        // If forceClose set, close descriptor and release all resources
        LE_CRIT( "Closing and releasing MTD due to forceClose" );
        goto error;
    }

    // Check input parameters
    if (!ctxPtr || !dataPtr)
    {
        LE_ERROR("NULL pointer");
        return LE_FAULT;
    }

    // Static variables definition
    static uint8_t *DataPtr = NULL;      // Buffer to copy data (size of an erase block)
    static pa_flash_Info_t *FlashInfoPtr;  // MTD information of the current MTD
    static pa_flash_Desc_t MtdFd = NULL; // File descriptor for MTD operations
    const cwe_Header_t *hdrPtr = ctxPtr->cweHdrPtr;

    LE_INFO ("Image type %"PRIu32" len %zu offset 0x%zx", hdrPtr->imageType, length, offset);

    if ((NULL == MtdFd) && (0 == ImageSize))
    {
        int iblk = 0;
        le_result_t res;

        mtdNum = partition_GetMtdFromImageTypeOrName(0, "swifota", &MtdNamePtr);

        if (-1 == mtdNum)
        {
            LE_ERROR( "Unable to find a valid mtd for image type \"swifota\"" );
            return LE_FAULT;
        }
        LE_INFO ("Writing \"%s\" (mtd%d) from CWE image %d",
                 MtdNamePtr, mtdNum, hdrPtr->imageType );

        if (LE_OK != partition_CheckIfMounted( mtdNum ))
        {
            LE_ERROR("MTD %d is mounted", mtdNum);
            return LE_FAULT;
        }

        if (LE_OK != pa_flash_Open( mtdNum,
                                    PA_FLASH_OPENMODE_WRITEONLY | PA_FLASH_OPENMODE_MARKBAD,
                                    &MtdFd,
                                    &FlashInfoPtr ))
        {
            LE_ERROR("Fails to open MTD %d", mtdNum );
            return LE_FAULT;
        }

        res = pa_flash_EraseBlock( MtdFd, 0);
        if ((LE_OK != res) && (res != LE_NOT_PERMITTED))
        {
            LE_ERROR("Fails to erase block %d: res=%d", iblk, res);
            goto error;
        }

        res = pa_flash_EraseBlock( MtdFd, 1);
        if ((LE_OK != res) && (res != LE_NOT_PERMITTED))
        {
            LE_ERROR("Fails to erase block %d: res=%d", iblk, res);
            goto error;
        }

        if (LE_OK != pa_flash_SeekAtOffset(MtdFd, 0))
        {
            LE_ERROR("Fails to seek block at %d", iblk);
            goto error;
        }
        uint8_t Data[FlashInfoPtr->eraseSize];
        memset(Data, 0x00, FlashInfoPtr->eraseSize);
        memcpy(Data, dataPtr, length);

        if (LE_OK != pa_flash_Write( MtdFd, Data, FlashInfoPtr->eraseSize))
        {
            LE_ERROR( "fwrite to nandwrite fails: %m" );
            goto error;
        }
    }

error:
    if (DataPtr)
    {
        le_mem_Release(DataPtr);
        DataPtr = NULL;
    }

    return ret;
}
