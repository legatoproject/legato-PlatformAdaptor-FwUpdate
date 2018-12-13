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
#include "pa_flash_local.h"

#define LE_DEBUG3 LE_DEBUG

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
#define SYS_CLASS_UBI_PATH     "/sys/class/ubi"

//--------------------------------------------------------------------------------------------------
/**
 * "/sys/class/mtd" access path
 */
//--------------------------------------------------------------------------------------------------
#define PROC_MTD_PATH          "/proc/mtd"

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
 * Memory Pool for flash temporary image blocks
 */
//--------------------------------------------------------------------------------------------------
static le_mem_PoolRef_t   PartitionPool = NULL;

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
 * MTD number for SWIFOTA partition
 */
//--------------------------------------------------------------------------------------------------
static uint32_t MtdNumSwifota = (uint32_t)-1;

//--------------------------------------------------------------------------------------------------
/**
 * Size of the erase block
 */
//--------------------------------------------------------------------------------------------------
static uint32_t MtdEraseSize = 0;

//--------------------------------------------------------------------------------------------------
/**
 * File descriptor for MTD operations
 */
//--------------------------------------------------------------------------------------------------
static pa_flash_Desc_t MtdFd = NULL;

//--------------------------------------------------------------------------------------------------
/**
 * MTD information of the current MTD
 */
//--------------------------------------------------------------------------------------------------
static pa_flash_Info_t* FlashInfoPtr = NULL;

//--------------------------------------------------------------------------------------------------
/**
 * Partition internal variables exported for Suspend/Resume
 */
//--------------------------------------------------------------------------------------------------
#define PARTITION_MAGIC     0x50615254
typedef struct
{
    uint32_t magic;          ///< Magic signature to check the validity
    size_t mySize;           ///< Size of my self to check the validity
    size_t imageSize;        ///< Current image size
    size_t inOffset;         ///< Current offset in erase block
    off_t ubiOffset;         ///< Start UBI offset in SWIFOTA (-1 if no UBI)
    uint32_t ubiVolId;       ///< UBI volume Id in progress (-1 if no volume)
    uint32_t ubiVolType;     ///< UBI volume Type in progress
    uint32_t ubiVolSize;     ///< UBI volume Size in progress
    char ubiVolName[128];    ///< UBI volume name in progress
    uint32_t ubiWriteLeb;    ///< Number of LEB written in the current UBI volume
    uint32_t ubiNbPeb;       ///< Total number of PEB belonging to the UBI partition
    uint32_t ubiImageSeq;    ///< UBI image sequence number
    bool isUbiImageSeq;      ///< true is UBI image sequence number is meaningfull
    uint8_t dataPtr[0];      ///< Buffer to copy data (size of an erase block)
}
Partition_t;

Partition_t* PartitionPtr = NULL;

//==================================================================================================
//  PRIVATE API FUNCTIONS
//==================================================================================================

//--------------------------------------------------------------------------------------------------
/**
 * Reset all internal counters, offset and variables to default values. If the PartitionPtr does not
 * exist (NULL), it is allocated before its values are reset.
 */
//--------------------------------------------------------------------------------------------------
static void partition_Reset
(
    void
)
{
    if( (0 == MtdEraseSize) || ((uint32_t)-1 == MtdNumSwifota) || (NULL == PartitionPool))
    {
        partition_Initialize();
    }
    if( NULL == PartitionPtr)
    {
        PartitionPtr = le_mem_AssertAlloc(PartitionPool);
        PartitionPtr->magic = PARTITION_MAGIC;
        PartitionPtr->mySize = sizeof(Partition_t) + MtdEraseSize;
    }
    PartitionPtr->imageSize = 0;
    PartitionPtr->ubiOffset = -1;
    PartitionPtr->ubiVolId = (uint32_t)-1;
    PartitionPtr->ubiVolType = 0;
    PartitionPtr->ubiWriteLeb = 0;
    PartitionPtr->ubiNbPeb = 0;
    PartitionPtr->ubiImageSeq = 0;
    PartitionPtr->isUbiImageSeq = false;
    memset(PartitionPtr->ubiVolName, 0, sizeof(PartitionPtr->ubiVolName));
}

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
 * Calculate how much real data is stored in the buffer
 *
 * This function calculates how much "real data" is stored in a buffer and returns the "real data"
 * length. Continuous 0xFF bytes at the end of the buffer are not considered as "real data".
 *
 * @return
 *      - LE_OK            If success and the "real data" length is valid
 *      - LE_BAD_PARAMETER If dataPtr is NULL or dataSize is 0
 */
//--------------------------------------------------------------------------------------------------
le_result_t partition_CalculateDataLength
(
    uint8_t* dataPtr,
    size_t *dataSize
)
{
    size_t ibyte;

    if( !dataPtr || !*dataSize )
    {
        return LE_BAD_PARAMETER;
    }
    for( ibyte = *dataSize - 1; (ibyte > 0) && (dataPtr[ibyte] == 0xFF); ibyte-- )
    {
        // Do nothing
    }
    *dataSize = ibyte + 1;
    return LE_OK;
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
        off_t blkOff = offset;
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

        LE_DEBUG("Read %zu at offset 0x%lx, block offset 0x%lx", size, offset, blkOff);
        if (LE_OK != pa_flash_SeekAtBlock( flashFd,
                                           (blkOff / flashInfoPtr->eraseSize) ))
        {
            LE_ERROR("Seek fails for offset 0x%lx: %m", blkOff);
            goto error;
        }
        nBlk = (size + (flashInfoPtr->writeSize - 1)) / flashInfoPtr->writeSize;
        for (iBlk = 0; iBlk < nBlk; iBlk++)
        {
            if (LE_OK != pa_flash_Read( flashFd,
                                        (checkBlockPtr + (iBlk * flashInfoPtr->writeSize)),
                                        flashInfoPtr->writeSize ))
            {
                LE_ERROR("Read fails for offset 0x%lx: %m", blkOff);
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
 * Check if data flashed into a partition are correctly written
 *
 * @return
 *      - LE_OK       on success
 *      - LE_FAULT    on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t partition_CheckUbiVolumeData
(
    int mtdNum,                        ///< [IN] Minor of the MTD device to check
    size_t sizeToCheck,                ///< [IN] Size to be used to compute the CRC
    uint32_t ubiVolId,                 ///< [IN] UBI volume ID to be checked
    uint32_t crc32ToCheck,             ///< [IN] Expected CRC 32
    le_mem_PoolRef_t flashImgPool,     ///< [IN] Memory pool
    bool isEccChecked                  ///< [IN] Whether need to check ecc status in the partition
)
{
    pa_flash_Desc_t flashFd = NULL;
    uint8_t* checkBlockPtr = NULL;

    size_t size, imageSize = 0, ubiDataSize;
    uint32_t crc32 = LE_CRC_START_CRC32;
    uint32_t ubiVolLeb, iVolLeb = 0, ubiVolType;
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
    if (LE_OK != pa_flash_ScanUbi( flashFd, ubiVolId ))
    {
        LE_ERROR("Scan of MTD %d for UBI vol Id %u fails: %m", mtdNum, ubiVolId );
        goto error;
    }
    if (LE_OK != pa_flash_GetUbiInfo( flashFd, NULL, &ubiVolLeb, NULL ))
    {
        LE_ERROR("Scan of MTD %d for UBI vol Id %u fails: %m", mtdNum, ubiVolId );
        goto error;
    }
    if (LE_OK != pa_flash_GetUbiTypeAndName( flashFd,  &ubiVolType, NULL, NULL ))
    {
        LE_ERROR("Scan of MTD %d for UBI vol Id %u fails: %m", mtdNum, ubiVolId );
        goto error;
    }

    ubiDataSize = flashInfoPtr->eraseSize - (2 * flashInfoPtr->writeSize);
    while ((imageSize < sizeToCheck) && (iVolLeb < ubiVolLeb))
    {
        size = (((imageSize + ubiDataSize) < sizeToCheck)
                   ? ubiDataSize
                   : (sizeToCheck - imageSize));

        // As we will compute a CRC for a big amount of memory, we need to give time for others
        // processes to schedule and also to prevent the hardware watchdog to elapse.
        if ((-1 == nanosleep(&suspendDelay, NULL)) && (EINTR != errno))
        {
            LE_ERROR("nanosleep(%ld.%ld) fails: %m", suspendDelay.tv_sec, suspendDelay.tv_nsec);
        }

        if (LE_OK != pa_flash_ReadUbiAtBlock( flashFd, iVolLeb, checkBlockPtr, &size ))
        {
            LE_ERROR("Read fails for UBI vol Id %u, LEB %u: %m", ubiVolId, iVolLeb);
            goto error;
        }

        LE_DEBUG("pa_flash_ReadUbiAtBlock( %u, %zu )", iVolLeb, size);
        iVolLeb++;
        imageSize += size;
        if( (iVolLeb == ubiVolLeb) && (ubiVolType == PA_FLASH_VOLUME_DYNAMIC) )
        {
            (void)partition_CalculateDataLength(checkBlockPtr, &size);
            LE_DEBUG("pa_flash_CalculateDataLength -> %zu", size);
        }
        crc32 = le_crc_Crc32( checkBlockPtr, size, crc32);
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
        LE_CRIT( "Bad CRC32 calculated on mtd%d UBI vol Id %u: read 0x%08x != expected 0x%08x",
                 mtdNum, ubiVolId, crc32, crc32ToCheck );
        goto error;
    }

    LE_INFO("CRC32 OK for mtd%d, UBI vol Id %u", mtdNum, ubiVolId );

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
 * Get the partition internals to be save for Suspend/Resume. If the partition internals does not
 * exist, it is created.
 *
 * @return
 *      - LE_OK on success
 *      - LE_BAD_PARAMETER if one parameter is NULL
 */
//--------------------------------------------------------------------------------------------------
le_result_t partition_GetPartitionInternals
(
    void** partitionPtr,                ///< [OUT] Pointer to the partition internals
    size_t* partitionSizePtr            ///< [OUT] Pointer to the partition internals size
)
{
    if( NULL == PartitionPtr )
    {
        partition_Reset();
    }
    if( (NULL == partitionPtr) || (NULL == partitionSizePtr) )
    {
        return LE_BAD_PARAMETER;
    }
    *partitionPtr = (void*)PartitionPtr;
    *partitionSizePtr = PartitionPtr->mySize;
    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Set the partition internals to be restored for Suspend/Resume. If the partition internals does
 * not exist, it is created.
 *
 * @return
 *      - LE_OK on success
 *      - LE_BAD_PARAMETER if one parameter is invalid or if the magic check fails
 */
//--------------------------------------------------------------------------------------------------
le_result_t partition_SetPartitionInternals
(
    void* partitionPtr                  ///< [IN] Pointer to the partition internals
)
{
    Partition_t* ptr = (Partition_t*)partitionPtr;
    le_result_t res = LE_OK;

    if( NULL == PartitionPtr )
    {
        partition_Reset();
    }
    if( (NULL == partitionPtr) || (PARTITION_MAGIC != ptr->magic) ||
        (PartitionPtr->mySize != ptr->mySize) )
    {
        return LE_BAD_PARAMETER;
    }
    // Do not copy if pointers are same
    if( ptr != PartitionPtr )
    {
        memmove(PartitionPtr, ptr, PartitionPtr->mySize);
    }

    LE_INFO("imageSize: %zu, inOffset: %zx, ubiOffset: %lx,"
            " ubiVolId: %u, ubiWriteLeb: %u, ubiNbPeb: %u",
            PartitionPtr->imageSize, PartitionPtr->inOffset, PartitionPtr->ubiOffset,
            PartitionPtr->ubiVolId, PartitionPtr->ubiWriteLeb, PartitionPtr->ubiNbPeb );
    if( -1 != PartitionPtr->ubiOffset )
    {
        Partition_t pTmp;
        memcpy(&pTmp, PartitionPtr, sizeof(pTmp));
        res = partition_OpenUbiSwifotaPartition( NULL,
                                                 PartitionPtr->ubiImageSeq,
                                                 PartitionPtr->isUbiImageSeq,
                                                 false, NULL );
        memcpy(PartitionPtr, &pTmp, sizeof(Partition_t));
    }
    return res;
}

//--------------------------------------------------------------------------------------------------
/**
 * Get absolute current data offset in SWIFOTA partition
 *
 * @return
 *      - LE_OK on success
 *      - LE_BAD_PARAMETER if offsetPtr is NULL
 *      - LE_FORMAT_ERROR if the SWIFOTA partition is not currently opened
 *      - LE_FAULT on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t partition_GetSwifotaOffsetPartition
(
    off_t* offsetPtr                  ///< [OUT] Data offset in the partition
)
{
    le_result_t res;

    if( offsetPtr == NULL )
    {
        return LE_BAD_PARAMETER;
    }
    if( MtdFd == NULL )
    {
        return LE_FORMAT_ERROR;
    }
    res = pa_flash_Tell(MtdFd, NULL, offsetPtr);
    LE_DEBUG("offsetPtr 0x%lx InOffset 0x%zx", *offsetPtr, PartitionPtr->inOffset);
    if( LE_OK == res )
    {
        *offsetPtr -= (IMG_BLOCK_OFFSET * FlashInfoPtr->eraseSize);
    }
    return res;
}

//--------------------------------------------------------------------------------------------------
/**
 * Set absolute current data offset in SWIFOTA partition
 *
 * @return
 *      - LE_OK on success
 *      - LE_FORMAT_ERROR if the SWIFOTA partition is not currently opened
 *      - LE_FAULT on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t partition_SetSwifotaOffsetPartition
(
    off_t offset                      ///< [IN] Data offset in the partition
)
{
    if( MtdFd == NULL )
    {
        return LE_FORMAT_ERROR;
    }
    offset += (IMG_BLOCK_OFFSET * FlashInfoPtr->eraseSize);
    return pa_flash_SeekAtOffset(MtdFd, offset);
}

//--------------------------------------------------------------------------------------------------
/**
 * Open the SWIFOTA partition for writing
 *
 * @return
 *      - LE_OK on success
 *      - LE_BUSY if the partition is already opened
 *      - LE_OUT_OF_RANGE if the image size is greater than the partition size
 *      - LE_FAULT on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t partition_OpenSwifotaPartition
(
    partition_Ctx_t *ctxPtr,          ///< [INOUT] Context
    size_t offset                     ///< [IN] Data offset in the package
)
{
    int mtdNum;
    le_result_t res = LE_FAULT;
    uint32_t* fullImageCrc32Ptr = &ctxPtr->fullImageCrc;
    const cwe_Header_t *hdrPtr = ctxPtr->cweHdrPtr;

    // Open the partition if not already done and perform some checks before writing into it.
    if (NULL == MtdFd)
    {
        int iblk = 0;

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
            res = LE_OUT_OF_RANGE;
            goto error;
        }

        PartitionPtr->imageSize = ctxPtr->fullImageSize;
        PartitionPtr->inOffset = offset % FlashInfoPtr->eraseSize;

        LE_DEBUG("ImageSize %zu (0x%08zx), InOffset %08zx",
                 PartitionPtr->imageSize, PartitionPtr->imageSize, PartitionPtr->inOffset);

        // If the data offset is not aligned on an erase block start address, we need to move back
        // the already written data from flash to memory along with the new data.
        if (PartitionPtr->inOffset)
        {
            PartitionPtr->inOffset = offset % FlashInfoPtr->eraseSize;
            offset -= PartitionPtr->inOffset;

            if (LE_OK != pa_flash_SeekAtOffset(MtdFd,
                                               offset +
                                               (IMG_BLOCK_OFFSET * FlashInfoPtr->eraseSize)))
            {
                LE_ERROR("Failed to seek block at offset: %zu", offset);
                goto error;
            }

            if (LE_OK != pa_flash_Read(MtdFd, PartitionPtr->dataPtr, PartitionPtr->inOffset))
            {
                LE_ERROR( "Fread to nandwrite fails: %m" );
                goto error;
            }
        }

        // When offset is 0. It means that we are able to write the first chunk of data in the
        // current partition.
        if (offset == 0)
        {
            int nbPebMetaData = 0;

            ctxPtr->logicalBlock = 0;
            ctxPtr->phyBlock = 0;
            *fullImageCrc32Ptr = LE_CRC_START_CRC32;
            iblk = 0;

            // Go back physical access as we really need to deal with "real" PEB
            (void)pa_flash_Unscan(MtdFd);

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
                    else if( nbPebMetaData < IMG_BLOCK_OFFSET )
                    {
                        nbPebMetaData++;
                    }
                    else if ((!ctxPtr->phyBlock) && (iblk >= ctxPtr->logicalBlock))
                    {
                        ctxPtr->phyBlock = iblk;
                        ctxPtr->logicalBlock = iblk;
                    }
                }
            }
            LE_INFO("phyBlock = %u, logicalBlock = %u", ctxPtr->phyBlock, ctxPtr->logicalBlock);

            // Go to logical mode, as we no more require to deal with real PEB.
            (void)pa_flash_Scan(MtdFd, NULL);
        }
        else
        {
            iblk = offset / FlashInfoPtr->eraseSize + IMG_BLOCK_OFFSET;
        }

        if (LE_OK != pa_flash_SeekAtOffset(MtdFd,
                                           offset + (IMG_BLOCK_OFFSET * FlashInfoPtr->eraseSize)))
        {
            LE_ERROR("Fails to seek block at %d", iblk);
            goto error;
        }
    }
    else
    {
        LE_CRIT("Partition \"%s\" is already opened", MtdNamePtr);
        return LE_BUSY;
    }
    return LE_OK;

error:
    if (MtdFd)
    {
        (void)pa_flash_Close( MtdFd );
        MtdFd = NULL;
    }
    MtdNamePtr = NULL;
    partition_Reset();
    return res;
}

//--------------------------------------------------------------------------------------------------
/**
 * Close the SWIFOTA partition. When closed, the flush of remaining data is forced.
 *
 * @return
 *      - LE_OK on success
 *      - LE_FAULT on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t partition_CloseSwifotaPartition
(
    partition_Ctx_t *ctxPtr,          ///< [INOUT] Context
    size_t offset,                    ///< [IN] Data offset in the package
    bool forceClose,                  ///< [IN] Force close of device and resources
    bool *isFlashedPtr                ///< [OUT] True if flash write was done
)
{
    le_result_t ret = LE_OK;

    if (forceClose)
    {
        // If forceClose set, close descriptor and release all resources
        LE_CRIT( "Closing and releasing MTD due to forceClose" );
        goto error;
    }

    uint32_t* fullImageCrc32Ptr = &ctxPtr->fullImageCrc;

    if (PartitionPtr->inOffset)
    {
        if (PartitionPtr->inOffset <= FlashInfoPtr->eraseSize)
        {
            memset(PartitionPtr->dataPtr + PartitionPtr->inOffset,
                   PA_FLASH_ERASED_VALUE,
                   FlashInfoPtr->eraseSize - PartitionPtr->inOffset);
        }
        // set isFlashed before the write because even if the write returns an error
        // some data could have been written in the flash
        if (isFlashedPtr)
        {
            *isFlashedPtr = true;
        }

        if (LE_OK != pa_flash_Write(MtdFd, PartitionPtr->dataPtr, FlashInfoPtr->eraseSize))
        {
            LE_ERROR("fwrite to nandwrite fails: %m" );
            goto error;
        }
        *fullImageCrc32Ptr = le_crc_Crc32(PartitionPtr->dataPtr,
                                          PartitionPtr->inOffset,
                                          *fullImageCrc32Ptr);
    }

    pa_flash_Close(MtdFd);
    MtdFd = NULL;
    LE_INFO("Update for partiton %s done with return %d", MtdNamePtr, ret);
    MtdNamePtr = NULL;
    partition_Reset();

    return LE_OK;

error:
    ret = LE_OK;
    if (MtdFd)
    {
        ret = pa_flash_Close( MtdFd );
        MtdFd = NULL;
    }
    MtdNamePtr = NULL;
    partition_Reset();
    return (forceClose ? ret : LE_FAULT);
}

//--------------------------------------------------------------------------------------------------
/**
 * Compute the CRC32 of the DATA in UPDATE partitions
 *
 * @return
 *      - LE_OK on success
 *      - LE_FAULT on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t partition_ComputeDataCrc32SwifotaPartition
(
    partition_Ctx_t *ctxPtr,          ///< [INOUT] Context
    off_t inOffset,                   ///< [IN] Current offset in SWIFOTA to start CRC32 computation
    uint32_t size,                    ///< [IN] Size of the data
    uint32_t* crc32Ptr                ///< [OUT] CRC32 computed on the data
)
{
    off_t atOffset, rdoffset;
    size_t rdsize = 0, crcsize = 0, baseSize;
    uint32_t crc32 = LE_CRC_START_CRC32;
    uint8_t* blockPtr = NULL;
    le_result_t res, crcRes = LE_OK;
    pa_flash_Desc_t mtdFd = MtdFd;
    pa_flash_Info_t* flashInfoPtr = FlashInfoPtr;

    if( NULL == mtdFd )
    {
        int mtdNum = partition_GetMtdFromImageTypeOrName(0, "swifota", NULL);
        if (-1 == mtdNum)
        {
            LE_ERROR( "Unable to find a valid mtd for image type \"swifota\"" );
            return LE_FAULT;
        }

        if (LE_OK != pa_flash_Open(mtdNum,
                                   PA_FLASH_OPENMODE_READONLY,
                                   &mtdFd,
                                   &flashInfoPtr))
        {
            LE_ERROR("Fails to open MTD %d", mtdNum );
            return LE_FAULT;
        }

        if (LE_OK != pa_flash_Scan( mtdFd, NULL ))
        {
            LE_ERROR("Fails to scan MTD");
            goto out;
        }
        atOffset = (IMG_BLOCK_OFFSET * flashInfoPtr->eraseSize) + size;
    }
    else
    {
        res = pa_flash_Tell(mtdFd, NULL, &atOffset);
        if( LE_OK != res )
        {
            LE_ERROR("pa_flash_Tell fails: %d", res);
            return res;
        }
    }

    rdoffset = inOffset + (IMG_BLOCK_OFFSET * flashInfoPtr->eraseSize);
    res = pa_flash_SeekAtOffset(mtdFd, rdoffset);
    LE_DEBUG("Seek at 0x%lx", rdoffset);
    if( LE_OK != res )
    {
        LE_ERROR("pa_flash_SeekAtOffset fails: %d", res);
        return res;
    }
    res = pa_flash_Tell(mtdFd, NULL, &rdoffset);
    if( LE_OK != res )
    {
        LE_ERROR("pa_flash_Tell fails: %d", res);
        return res;
    }
    LE_DEBUG("Tell at 0x%lx", rdoffset);
    blockPtr = (uint8_t*)le_mem_ForceAlloc(*ctxPtr->flashPoolPtr);
    baseSize = flashInfoPtr->eraseSize - (inOffset & (flashInfoPtr->eraseSize - 1));
    for( rdsize = 0; rdsize < size; rdsize += crcsize, rdoffset += crcsize )
    {
        crcsize = ((size - rdsize) >= baseSize ? baseSize : size - rdsize);
        if( crcsize > flashInfoPtr->eraseSize )
        {
            crcsize = flashInfoPtr->eraseSize;
        }
        LE_DEBUG("size %u rdsize %zu crcsize %zu baseSize %zu rdoffset 0x%lx atOffset 0x%lx",
                 size, rdsize, crcsize, baseSize, rdoffset, atOffset);
        if( rdoffset < atOffset )
        {
            res = pa_flash_SeekAtOffset(mtdFd, rdoffset);
            if( LE_OK != res )
            {
                LE_ERROR("pa_flash_SeekAtOffset fails: %d", res);
                return res;
            }
            crcRes = pa_flash_Read(mtdFd, blockPtr, baseSize);
            if( LE_OK != crcRes )
            {
                LE_ERROR("pa_flash_Read fails: %d", res);
                break;
            }
            baseSize = flashInfoPtr->eraseSize;
        }
        else
        {
            if( PartitionPtr->inOffset && MtdFd )
            {
                LE_DEBUG("rdoffset 0x%lx atOffset 0x%lx Copy PartitionPtr->dataPtr at 0x%zx",
                         rdoffset, atOffset, PartitionPtr->inOffset);
                memcpy(blockPtr, PartitionPtr->dataPtr, PartitionPtr->inOffset);
                crcRes = LE_OK;
            }
            else
            {
                crcRes = LE_OUT_OF_RANGE;
                break;
            }
        }

        LE_DEBUG3("%hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX",
                  blockPtr[0], blockPtr[1], blockPtr[2], blockPtr[3],
                  blockPtr[4], blockPtr[5], blockPtr[6], blockPtr[7]);
        LE_DEBUG3("%hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX",
                  blockPtr[0x1000+0], blockPtr[0x1000+1], blockPtr[0x1000+2], blockPtr[0x1000+3],
                  blockPtr[0x1000+4], blockPtr[0x1000+5], blockPtr[0x1000+6], blockPtr[0x1000+7]);
        LE_DEBUG3("%hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX",
                  blockPtr[0x2000+0], blockPtr[0x2000+1], blockPtr[0x2000+2], blockPtr[0x2000+3],
                  blockPtr[0x2000+4], blockPtr[0x2000+5], blockPtr[0x2000+6], blockPtr[0x2000+7]);
        crc32 = le_crc_Crc32( blockPtr, crcsize, crc32 );
    }

out:
    if( blockPtr )
    {
        le_mem_Release( blockPtr );
    }

    if( NULL == MtdFd )
    {
        (void)pa_flash_Close(mtdFd);
    }
    else
    {
        // Restore offset at the last position of the UBI partition
        res = pa_flash_SeekAtOffset(MtdFd, atOffset);
        if( LE_OK != res )
        {
            LE_ERROR("pa_flash_SeekAtOffset fails: %d", res);
            return res;
        }
    }
    LE_INFO("Offset %lx size %zu CRC %08x", inOffset, rdsize, crc32);
    if( crc32Ptr )
    {
        *crc32Ptr = crc32;
    }

    return crcRes;
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

    le_result_t ret = LE_OK;
    uint32_t* fullImageCrc32Ptr = &ctxPtr->fullImageCrc;
    const cwe_Header_t *hdrPtr  = ctxPtr->cweHdrPtr;

    LE_INFO("Image type %"PRIu32" len %zu", hdrPtr->imageType, lengthPtr ? *lengthPtr : 0);

    if ((NULL == FlashInfoPtr) || (NULL == PartitionPtr) || (NULL == lengthPtr))
    {
        LE_ERROR("Bad behavior !!!");
        goto error;
    }

    if (((uint32_t)(*lengthPtr + PartitionPtr->inOffset)) >= FlashInfoPtr->eraseSize)
    {
        size_t inOffsetSave = FlashInfoPtr->eraseSize - PartitionPtr->inOffset;
        memcpy(PartitionPtr->dataPtr + PartitionPtr->inOffset, dataPtr, inOffsetSave);
        // set isFlashed before the write because even if the write returns an error
        // some data could have been written in the flash
        if (isFlashedPtr)
        {
            *isFlashedPtr = true;
        }

        if (LE_OK != pa_flash_Write(MtdFd, PartitionPtr->dataPtr, FlashInfoPtr->eraseSize))
        {
            LE_ERROR( "fwrite to nandwrite fails: %m" );
            goto error;
        }
        *fullImageCrc32Ptr = le_crc_Crc32(PartitionPtr->dataPtr,
                                          FlashInfoPtr->eraseSize,
                                          *fullImageCrc32Ptr);
        PartitionPtr->inOffset = 0;
        *lengthPtr = inOffsetSave;
    }
    else
    {
        memcpy( PartitionPtr->dataPtr + PartitionPtr->inOffset, dataPtr, *lengthPtr );
        PartitionPtr->inOffset += *lengthPtr;
    }

    return ret;

error:
    ret = LE_OK;
    if (MtdFd)
    {
        ret = pa_flash_Close( MtdFd );
        MtdFd = NULL;
    }
    MtdNamePtr = NULL;
    partition_Reset();
    return (forceClose ? ret : LE_FAULT);
}

//--------------------------------------------------------------------------------------------------
/**
 * Open UBI partiton in SWIFOTA partition
 *
 * @return
 *      - LE_OK on success
 *      - LE_FAULT on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t partition_OpenUbiSwifotaPartition
(
    partition_Ctx_t *ctxPtr,          ///< [INOUT] Context
    uint32_t ubiImageSeq,             ///< [IN] UBI image sequence number
    bool isUbiImageSeq,               ///< [IN] true if the UBI image sequence number must be used
    bool forceCreate,                 ///< [IN] Force creation of a new UBI at offset
    bool *isFlashedPtr                ///< [OUT] True if flash write was done
)
{
    off_t mtdOffset;
    le_result_t res;

    res = pa_flash_Tell(MtdFd, NULL, &mtdOffset);
    if( LE_OK != res )
    {
        LE_ERROR("pa_flash_Tell() fails: %d", res);
        return res;
    }
    if (isUbiImageSeq)
    {
        // Clear UBI image sequence number if it is passed as argument
        PartitionPtr->isUbiImageSeq = false;
        res = pa_flash_SetUbiImageSeqNum(MtdFd, ubiImageSeq, true);
        if (LE_OK != res)
        {
            LE_ERROR("Failed to set UBI image sequence number %08x: %d", ubiImageSeq, res);
            return LE_FAULT;
        }
        PartitionPtr->ubiImageSeq = ubiImageSeq;
        PartitionPtr->isUbiImageSeq = true;
    }
    if( !forceCreate )
    {
        res = pa_flash_ScanUbiForVolumesAtOffset(MtdFd, PartitionPtr->ubiOffset, NULL, NULL);
        if( LE_FORMAT_ERROR == res )
        {
            forceCreate = true;
        }
        res = pa_flash_SeekAtOffset(MtdFd, PartitionPtr->ubiOffset);
    }
    if( forceCreate )
    {
        uint32_t* fullImageCrc32Ptr = &ctxPtr->fullImageCrc;

        if( PartitionPtr->inOffset )
        {
            if (PartitionPtr->inOffset <= FlashInfoPtr->eraseSize)
            {
                memset(PartitionPtr->dataPtr + PartitionPtr->inOffset,
                       PA_FLASH_ERASED_VALUE,
                       FlashInfoPtr->eraseSize - PartitionPtr->inOffset);
            }
            // set isFlashed before the write because even if the write returns an error
            // some data could have been written in the flash
            if (isFlashedPtr)
            {
                *isFlashedPtr = true;
            }

            if (LE_OK != pa_flash_Write(MtdFd, PartitionPtr->dataPtr, FlashInfoPtr->eraseSize))
            {
                LE_ERROR("fwrite to nandwrite fails: %m" );
                return res;
            }
            *fullImageCrc32Ptr = le_crc_Crc32(PartitionPtr->dataPtr,
                                              PartitionPtr->inOffset,
                                              *fullImageCrc32Ptr);
        }
        PartitionPtr->ubiOffset = mtdOffset + PartitionPtr->inOffset;
        PartitionPtr->ubiVolId = (uint32_t)-1;
        PartitionPtr->ubiVolSize = 0;
        PartitionPtr->ubiNbPeb = 2;
        memset(PartitionPtr->ubiVolName, 0, sizeof(PartitionPtr->ubiVolName));
        LE_DEBUG("UbiOffset 0x%lx InOffset 0x%zx mtdOffset 0x%lx",
                 PartitionPtr->ubiOffset, PartitionPtr->inOffset, mtdOffset);
        res = pa_flash_CreateUbiAtOffset(MtdFd, PartitionPtr->ubiOffset, forceCreate);
    }
    if( LE_OK != res )
    {
        LE_ERROR("pa_flash_CreateUbiAtOffset fails: %d", res);
        PartitionPtr->ubiOffset = 0;
    }
    else
    {
        LE_INFO("New UBI at 0x%lx", PartitionPtr->ubiOffset);
    }
    PartitionPtr->inOffset = 0;
    return res;
}

//--------------------------------------------------------------------------------------------------
/**
 * Close UBI partition in SWIFOTA partition
 *
 * @return
 *      - LE_OK on success
 *      - LE_BUSY if an UBI volume is already opened
 *      - LE_FORMAT_ERROR if the UBI partition is not opened
 *      - LE_FAULT on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t partition_CloseUbiSwifotaPartition
(
    partition_Ctx_t *ctxPtr,          ///< [INOUT] Context
    bool forceClose,                  ///< [IN] Force close of device and resources
    bool *isFlashedPtr                ///< [OUT] True if flash write was done
)
{
    off_t atOffset = (PartitionPtr->ubiNbPeb * FlashInfoPtr->eraseSize) + PartitionPtr->ubiOffset;
    le_result_t res;

    if( -1 == PartitionPtr->ubiOffset )
    {
        return LE_FORMAT_ERROR;
    }
    if( PartitionPtr->ubiVolId != (uint32_t)-1)
    {
        return LE_BUSY;
    }
    LE_DEBUG("Seek at 0x%lx (Nb PEB %u UBI Offset 0x%lx)",
             atOffset & ~(FlashInfoPtr->eraseSize - 1),
             PartitionPtr->ubiNbPeb, PartitionPtr->ubiOffset);
    PartitionPtr->ubiOffset = -1;
    PartitionPtr->ubiNbPeb = 0;
    PartitionPtr->ubiImageSeq = 0;
    PartitionPtr->isUbiImageSeq = false;
    (void)pa_flash_SetUbiImageSeqNum(MtdFd, 0, false);
    res = pa_flash_Unscan(MtdFd);
    if( LE_OK != res )
    {
        LE_ERROR("pa_flash_Unscan fails: %d", res);
        return res;
    }
    res = pa_flash_Scan(MtdFd, NULL);
    if( LE_OK != res )
    {
        LE_ERROR("pa_flash_Scan fails: %d", res);
        return res;
    }
    res = pa_flash_SeekAtOffset(MtdFd, atOffset & ~(FlashInfoPtr->eraseSize - 1));
    if( LE_OK != res )
    {
        LE_ERROR("pa_flash_SeekAtOffset fails: %d", res);
        return res;
    }
    PartitionPtr->inOffset = atOffset & (FlashInfoPtr->eraseSize - 1);
    LE_DEBUG("Reread block with InOffset %zu", PartitionPtr->inOffset);
    res = pa_flash_Read(MtdFd, PartitionPtr->dataPtr, PartitionPtr->inOffset);
    if( LE_OK != res )
    {
        LE_ERROR("pa_flash_Read fails: %d", res);
        return res;
    }
    res = pa_flash_EraseBlock(MtdFd, atOffset / FlashInfoPtr->eraseSize);
    if( LE_OK != res )
    {
        LE_ERROR("pa_flash_Erase fails: %d", res);
        return res;
    }
    res = pa_flash_SeekAtOffset(MtdFd, atOffset & ~(FlashInfoPtr->eraseSize - 1));
    if( LE_OK != res )
    {
        LE_ERROR("pa_flash_SeekAtOffset fails: %d", res);
        return res;
    }
    res = pa_flash_Tell(MtdFd, NULL, &atOffset);
    if( LE_OK != res )
    {
        LE_ERROR("pa_flash_Tell fails: %d", res);
        return res;
    }
    LE_DEBUG("Tell offset 0x%lx", atOffset);
    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Compute the CRC32 of the UBI partition in SWIFOTA partition
 *
 * @return
 *      - LE_OK on success
 *      - LE_BUSY if an UBI volume is already opened
 *      - LE_FORMAT_ERROR if the UBI partition is not opened
 *      - LE_FAULT on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t partition_ComputeUbiCrc32SwifotaPartition
(
    partition_Ctx_t *ctxPtr,          ///< [INOUT] Context
    uint32_t* sizePtr,                ///< [OUT] Size of the whole UBI partition
    uint32_t* crc32Ptr                ///< [OUT] CRC32 computed on the whole UBI partition
)
{
    off_t atOffset = (PartitionPtr->ubiNbPeb * FlashInfoPtr->eraseSize) + PartitionPtr->ubiOffset;
    size_t size = (PartitionPtr->ubiNbPeb * FlashInfoPtr->eraseSize);
    uint32_t iPeb;
    uint32_t crc32 = LE_CRC_START_CRC32;
    uint8_t* blockPtr = NULL;
    le_result_t res, crcRes = LE_OK;

    if( -1 == PartitionPtr->ubiOffset )
    {
        return LE_FORMAT_ERROR;
    }
    if( PartitionPtr->ubiVolId != (uint32_t)-1 )
    {
        return LE_BUSY;
    }
    LE_DEBUG("Seek at 0x%lx", PartitionPtr->ubiOffset);
    res = pa_flash_SeekAtOffset(MtdFd, PartitionPtr->ubiOffset);
    if( LE_OK != res )
    {
        LE_ERROR("pa_flash_SeekAtOffset fails: %d", res);
        return res;
    }
    blockPtr = (uint8_t*)le_mem_ForceAlloc(*ctxPtr->flashPoolPtr);
    for( iPeb = 0; iPeb < PartitionPtr->ubiNbPeb; iPeb++ )
    {
        crcRes = pa_flash_Read(MtdFd, blockPtr, FlashInfoPtr->eraseSize);
        if( LE_OK != crcRes )
        {
            LE_ERROR("pa_flash_Read fails: %d", res);
            break;
        }
        LE_DEBUG3("%hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX",
                  blockPtr[0], blockPtr[1], blockPtr[2], blockPtr[3],
                  blockPtr[4], blockPtr[5], blockPtr[6], blockPtr[7]);
        LE_DEBUG3("%hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX",
                  blockPtr[0x1000+0], blockPtr[0x1000+1], blockPtr[0x1000+2], blockPtr[0x1000+3],
                  blockPtr[0x1000+4], blockPtr[0x1000+5], blockPtr[0x1000+6], blockPtr[0x1000+7]);
        LE_DEBUG3("%hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX",
                  blockPtr[0x2000+0], blockPtr[0x2000+1], blockPtr[0x2000+2], blockPtr[0x2000+3],
                  blockPtr[0x2000+4], blockPtr[0x2000+5], blockPtr[0x2000+6], blockPtr[0x2000+7]);
        crc32 = le_crc_Crc32( blockPtr, FlashInfoPtr->eraseSize, crc32 );
    }
    le_mem_Release( blockPtr );

    // Restore offset at the last position of the UBI partition
    res = pa_flash_SeekAtOffset(MtdFd, atOffset);
    if( LE_OK != res )
    {
        LE_ERROR("pa_flash_SeekAtOffset fails: %d", res);
        return res;
    }
    LE_INFO("Computed CRC32: 0x%08x Size %zu", crc32, size);
    if( crc32Ptr )
    {
        *crc32Ptr = crc32;
    }
    if( sizePtr )
    {
        *sizePtr = size;
    }
    return crcRes;
}

//--------------------------------------------------------------------------------------------------
/**
 * Open UBI volume in SWIFOTA partition
 *
 * @return
 *      - LE_OK on success
 *      - LE_FAULT on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t partition_OpenUbiVolumeSwifotaPartition
(
    partition_Ctx_t *ctxPtr,          ///< [INOUT] Context
    uint32_t ubiVolId,                ///< [IN] UBI volume ID
    uint32_t ubiVolType,              ///< [IN] UBI volume type
    uint32_t ubiVolSize,              ///< [IN] UBI volume size
    uint32_t ubiVolFlags,             ///< [IN] UBI volume flags
    char* ubiVolName,                 ///< [IN] UBI volume name
    bool createVol                    ///< [IN] true if volume needs to be created
)
{
    le_result_t res;

    off_t ubiOffset;

    res = pa_flash_GetUbiOffset(MtdFd, &ubiOffset);
    if( LE_OK != res)
    {
        LE_ERROR("pa_flash_GetUbiOffset fails : %d", res);
        return res;
    }
    if( !createVol )
    {
        res = pa_flash_ScanUbiAtOffset(MtdFd, ubiOffset, ubiVolId);
        if( LE_FORMAT_ERROR  == res )
        {
            createVol = true;
        }
        else if( LE_OK == res )
        {
            uint32_t volType;
            char     volName[PA_FLASH_UBI_MAX_VOLUMES];
            uint32_t volFlags;

            res = pa_flash_GetUbiTypeAndName(MtdFd, &volType, volName, &volFlags);
            if( LE_OK != res )
            {
                LE_ERROR("Fails to get UBI volume name and type: %d", res);
                return res;
            }
            if( strncmp(volName, ubiVolName, sizeof(volName)) || (volType != ubiVolType) ||
                (volFlags !=  ubiVolFlags) )
            {
                LE_ERROR("Ubi volume %d mismitching parameters: %u %u %s",
                         ubiVolId, volType, volFlags, volName);
                return LE_BAD_PARAMETER;
            }
        }
    }
    if( createVol )
    {
        res = pa_flash_CreateUbiVolumeWithFlags(MtdFd,
                                                ubiVolId, ubiVolName, ubiVolType, ubiVolSize,
                                                ubiVolFlags);
    }
    if( LE_OK != res)
    {
        LE_ERROR("pa_flash_CreateUbiVolumeWithFlags \"%s\" (%u, %u, %u, %u) fails: %d",
                 ubiVolName, ubiVolId, ubiVolType, ubiVolFlags, ubiVolSize, res);
        return res;
    }
    if( createVol )
    {
        PartitionPtr->ubiWriteLeb = 0;
        PartitionPtr->ubiVolId = ubiVolId;
        PartitionPtr->ubiVolType = ubiVolType;
        PartitionPtr->ubiVolSize = ubiVolSize;
        strncpy(PartitionPtr->ubiVolName, ubiVolName, sizeof(PartitionPtr->ubiVolName));
    }
    LE_INFO("Created UBI volume \"%s\" Id %u Size %u Type %u at offset 0x%lx",
            PartitionPtr->ubiVolName, PartitionPtr->ubiVolId, PartitionPtr->ubiVolSize,
            PartitionPtr->ubiVolType, ubiOffset);
    return res;
}

//--------------------------------------------------------------------------------------------------
/**
 * Close UBI volume in SWIFOTA partition
 *
 * @return
 *      - LE_OK on success
 *      - LE_FORMAT_ERROR if the UBI partition is not opened
 *      - LE_FAULT on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t partition_CloseUbiVolumeSwifotaPartition
(
    partition_Ctx_t *ctxPtr,          ///< [INOUT] Context
    uint32_t ubiVolSize,              ///< [IN] UBI volume size
    bool forceClose,                  ///< [IN] Force close of device and resources
    bool *isFlashedPtr                ///< [OUT] True if flash write was done
)
{
    le_result_t res = LE_OK;

    if( PartitionPtr->ubiVolId == (uint32_t)-1 )
    {
        return LE_FORMAT_ERROR;
    }
    LE_INFO("UBI VolSize %u LEB %u InOffset %zx",
            PartitionPtr->ubiVolSize, PartitionPtr->ubiWriteLeb, PartitionPtr->inOffset);
    if (PartitionPtr->inOffset)
    {
        if (isFlashedPtr)
        {
            *isFlashedPtr = true;
        }

        LE_DEBUG("pa_flash_WriteUbiAtBlock(%u %zu)",
                 PartitionPtr->ubiWriteLeb, PartitionPtr->inOffset);
        res = pa_flash_WriteUbiAtBlock(MtdFd,
                                       PartitionPtr->ubiWriteLeb,
                                       PartitionPtr->dataPtr,
                                       PartitionPtr->inOffset,
                                       true);
        if (LE_OK != res)
        {
            LE_ERROR("pa_flash_WriteUbi %u %zu fails: %d",
                     PartitionPtr->ubiWriteLeb, PartitionPtr->inOffset, res);
            return res;
        }
        PartitionPtr->inOffset = 0;
        PartitionPtr->ubiWriteLeb++;
    }

    if( PartitionPtr->ubiVolType == PA_FLASH_VOLUME_STATIC )
    {
        res = pa_flash_AdjustUbiSize(MtdFd, ubiVolSize);
        if (LE_OK != res)
        {
            LE_ERROR("pa_flash_AdjustUbiSize %u fails: %d", ubiVolSize, res);
            return res;
        }
    }
    PartitionPtr->ubiNbPeb += PartitionPtr->ubiWriteLeb;
    LE_INFO("UBI Volume %u Type %u closed: UBI PEB %u",
            PartitionPtr->ubiVolId, PartitionPtr->ubiVolType, PartitionPtr->ubiNbPeb);
    PartitionPtr->ubiVolId = -1;
    PartitionPtr->ubiVolType = 0;
    PartitionPtr->ubiWriteLeb = 0;
    memset(PartitionPtr->ubiVolName, 0, sizeof(PartitionPtr->ubiVolName));
    return res;
}

//--------------------------------------------------------------------------------------------------
/**
 * Write data inside UBI volume in SWIFOTA partition
 *
 * @return
 *      - LE_OK on success
 *      - LE_FORMAT_ERROR if the UBI partition is not opened
 *      - LE_FAULT on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t partition_WriteUbiSwifotaPartition
(
    partition_Ctx_t *ctxPtr,          ///< [INOUT] Context
    size_t* lengthPtr,                ///< [INOUT] Data length pointer
    size_t offset,                    ///< [IN] Data offset in the package
    const uint8_t* dataPtr,           ///< [IN] Input data
    bool forceClose,                  ///< [IN] Force close of device and resources
    bool *isFlashedPtr                ///< [OUT] True if flash write was done
)
{
    le_result_t res = LE_OK;
    size_t ubiDataSize = FlashInfoPtr->eraseSize - (2 * FlashInfoPtr->writeSize);
    uint32_t* fullImageCrc32Ptr = &ctxPtr->fullImageCrc;

    if (forceClose)
    {
        // If forceClose set, close descriptor and release all resources
        LE_CRIT( "Closing and releasing MTD due to forceClose" );
        goto error;
    }

    if( PartitionPtr->ubiVolId == (uint32_t)-1 )
    {
        return LE_FORMAT_ERROR;
    }
    LE_DEBUG("%zu %zu, LEB %u InOffset %zx",
             *lengthPtr, offset, PartitionPtr->ubiWriteLeb, PartitionPtr->inOffset);
    if (((uint32_t)(*lengthPtr + PartitionPtr->inOffset)) >= ubiDataSize)
    {
        size_t inOffsetSave = ubiDataSize - PartitionPtr->inOffset;
        memcpy(PartitionPtr->dataPtr + PartitionPtr->inOffset, dataPtr, inOffsetSave);
        // set isFlashed before the write because even if the write returns an error
        // some data could have been written in the flash
        if (isFlashedPtr)
        {
            *isFlashedPtr = true;
        }

        LE_DEBUG("pa_flash_WriteUbiAtBlock(%u %zu)", PartitionPtr->ubiWriteLeb, ubiDataSize);
        res = pa_flash_WriteUbiAtBlock(MtdFd,
                                       PartitionPtr->ubiWriteLeb,
                                       PartitionPtr->dataPtr,
                                       ubiDataSize,
                                       true);
        if (LE_OK != res)
        {
            LE_ERROR("pa_flash_WriteUbi %u %zu fails: %d",
                     PartitionPtr->ubiWriteLeb, ubiDataSize, res);
            return res;
        }
        *fullImageCrc32Ptr = le_crc_Crc32(PartitionPtr->dataPtr, ubiDataSize, *fullImageCrc32Ptr);
        PartitionPtr->inOffset = 0;
        *lengthPtr = inOffsetSave;
        PartitionPtr->ubiWriteLeb++;
    }
    else
    {
        memcpy( PartitionPtr->dataPtr + PartitionPtr->inOffset, dataPtr, *lengthPtr );
        PartitionPtr->inOffset += *lengthPtr;
    }

    return res;

error:
    return (forceClose ? LE_OK : LE_FAULT);
}

//--------------------------------------------------------------------------------------------------
/**
 * Compute the CRC32 of the UBI volume in SWIFOTA partition
 *
 * @return
 *      - LE_OK on success
 *      - LE_FORMAT_ERROR if the UBI partition is not opened
 *      - LE_BUSY if an UBI volume is already opened
 *      - LE_FAULT on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t partition_ComputeUbiVolumeCrc32SwifotaPartition
(
    partition_Ctx_t *ctxPtr,          ///< [INOUT] Context
    uint32_t ubiVolId,                ///< [IN] UBI volume id
    size_t* sizePtr,                  ///< [OUT] UBI volume size
    uint32_t* crc32Ptr,               ///< [OUT] CRC32 computed on the UBI volume
    size_t* fullSizePtr,              ///< [OUT] UBI volume size with padded data to the end of PEB
    uint32_t* fullCrc32Ptr            ///< [OUT] CRC32 computed on the data padded to the end of PEB
)
{
    off_t atOffset;
    size_t size, volSize = 0, fullSize = 0;
    uint32_t iPeb, volPeb;
    uint32_t crc32 = LE_CRC_START_CRC32, fullCrc32 = LE_CRC_START_CRC32;
    uint8_t* blockPtr = NULL;
    le_result_t res, crcRes = LE_OK;

    if( -1 == PartitionPtr->ubiOffset )
    {
        return LE_FORMAT_ERROR;
    }
    if( PartitionPtr->ubiVolId != (uint32_t)-1 )
    {
        return LE_BUSY;
    }
    res = pa_flash_Tell(MtdFd, NULL, &atOffset);
    if( LE_OK != res )
    {
        LE_ERROR("pa_flash_Tell fails: %d", res);
        return res;
    }
    LE_DEBUG("Tell 0x%lx", atOffset);
    res = pa_flash_ScanUbiAtOffset(MtdFd, PartitionPtr->ubiOffset, ubiVolId);
    if( LE_OK != res )
    {
        LE_ERROR("pa_flash_ScanUbi fails: %d", res);
        return res;
    }
    res = pa_flash_GetUbiInfo(MtdFd, NULL, &volPeb, NULL);
    if( LE_OK != res )
    {
        LE_ERROR("pa_flash_GetUbiInfo fails: %d", res);
        return res;
    }
    blockPtr = (uint8_t*)le_mem_ForceAlloc(*ctxPtr->flashPoolPtr);
    for( iPeb = 0; iPeb < volPeb; iPeb++ )
    {
        size = FlashInfoPtr->eraseSize;
        crcRes = pa_flash_ReadUbiAtBlock(MtdFd, iPeb, blockPtr, &size);
        if( LE_OK != crcRes )
        {
            LE_ERROR("pa_flash_Read fails: %d", res);
            break;
        }
        LE_DEBUG3("%hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX",
                  blockPtr[0], blockPtr[1], blockPtr[2], blockPtr[3],
                  blockPtr[4], blockPtr[5], blockPtr[6], blockPtr[7]);
        LE_DEBUG3("%hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX",
                  blockPtr[0x1000+0], blockPtr[0x1000+1], blockPtr[0x1000+2], blockPtr[0x1000+3],
                  blockPtr[0x1000+4], blockPtr[0x1000+5], blockPtr[0x1000+6], blockPtr[0x1000+7]);
        LE_DEBUG3("%hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX",
                  blockPtr[0x2000+0], blockPtr[0x2000+1], blockPtr[0x2000+2], blockPtr[0x2000+3],
                  blockPtr[0x2000+4], blockPtr[0x2000+5], blockPtr[0x2000+6], blockPtr[0x2000+7]);
        fullSize += size;
        fullCrc32 = le_crc_Crc32( blockPtr, size, fullCrc32 );
        if( (volPeb - 1) == iPeb )
        {
            (void)partition_CalculateDataLength( blockPtr, &size );
        }
        volSize += size;
        crc32 = le_crc_Crc32( blockPtr, size, crc32 );
    }
    le_mem_Release( blockPtr );

    // Restore offset at the last position of the UBI partition
    res = pa_flash_SeekAtOffset(MtdFd, atOffset);
    if( LE_OK != res )
    {
        LE_ERROR("pa_flash_SeekAtOffset fails: %d", res);
        return res;
    }
    LE_INFO("Computed: CRC32 0x%08x Size %zu Full CRC32 0x%08x Full Size %zu",
            crc32, volSize, fullCrc32, fullSize);
    if( crc32Ptr )
    {
        *crc32Ptr = crc32;
    }
    if( sizePtr )
    {
        *sizePtr = volSize;
    }
    if( fullCrc32Ptr )
    {
        *fullCrc32Ptr = fullCrc32;
    }
    if( fullSizePtr )
    {
        *fullSizePtr = fullSize;
    }
    return crcRes;
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
    uint32_t iblk = 0, nblk = 0, mdblk[2] = { 0, 0 };
    bool isBad;
    uint8_t data[MtdEraseSize];
    pa_flash_Info_t *flashInfoPtr;
    pa_flash_Desc_t mtdFd = NULL;
    le_result_t ret;

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

    if( -1 == MtdNumSwifota )
    {
        LE_CRIT("Not initialized");
        return LE_FAULT;
    }

    const cwe_Header_t *hdrPtr = ctxPtr->cweHdrPtr;

    LE_INFO ("MTD %d: Writing from CWE image %d", MtdNumSwifota, hdrPtr->imageType );

    if (LE_OK != partition_CheckIfMounted( MtdNumSwifota ))
    {
        LE_ERROR("MTD %d is mounted", MtdNumSwifota);
        goto error;
    }

    if (LE_OK != pa_flash_Open( MtdNumSwifota,
                                PA_FLASH_OPENMODE_WRITEONLY | PA_FLASH_OPENMODE_MARKBAD,
                                &mtdFd,
                                &flashInfoPtr ))
    {
        LE_ERROR("Fails to open MTD %d", MtdNumSwifota );
        goto error;
    }

    for( iblk = 0, nblk = 0; (nblk < IMG_BLOCK_OFFSET) && (iblk < flashInfoPtr->nbLeb); iblk++ )
    {
        if (LE_OK != pa_flash_CheckBadBlock(mtdFd, iblk, &isBad))
        {
            LE_ERROR("MTD %d: Fails to check bad block at %d", MtdNumSwifota, iblk);
            goto error;
        }

        if( !isBad )
        {
            if (LE_OK != pa_flash_EraseBlock(mtdFd, iblk))
            {
                LE_ERROR( "MTD %d: Failed to erase peb %u", MtdNumSwifota, iblk );
                goto error;
            }
            if (LE_OK != pa_flash_CheckBadBlock(mtdFd, iblk, &isBad))
            {
                LE_ERROR("MTD %d: Fails to check bad block at %d", MtdNumSwifota, iblk);
                goto error;
            }
            if( !isBad )
            {
                mdblk[nblk++] = iblk;
            }
        }
    }

    if( IMG_BLOCK_OFFSET != nblk )
    {
        LE_CRIT("MTD %d: Failed to find to two good blocks for meta-data", MtdNumSwifota);
        goto error;
    }

    memset(data, 0x00, sizeof(data));
    memcpy(data, dataPtr, length);

    LE_INFO("MTD %d: Writing meta data to peb %u", MtdNumSwifota, mdblk[0]);
    if (LE_OK != pa_flash_WriteAtBlock( mtdFd, mdblk[0], data, sizeof(data)))
    {
        LE_ERROR( "MTD %d: Failed to write peb %u", MtdNumSwifota, mdblk[0] );
        goto error;
    }

    if (LE_OK != pa_flash_Close( mtdFd ))
    {
        LE_ERROR( "MTD %d: Failed to close the partition", MtdNumSwifota );
        goto error;
    }

    return LE_OK;

error:
    ret = LE_OK;
    if (mtdFd)
    {
        ret = pa_flash_Close( mtdFd );
    }
    if (MtdFd)
    {
        ret = pa_flash_Close( MtdFd );
        MtdFd = NULL;
        MtdNamePtr = NULL;
    }
    partition_Reset();
    return (forceClose ? ret : LE_FAULT);
}

//--------------------------------------------------------------------------------------------------
/**
 * Initialize partition pool and internal data
 *
 */
//--------------------------------------------------------------------------------------------------
void partition_Initialize
(
    void
)
{
    int mtdNum;
    pa_flash_Info_t flashInfo;

    // Get MTD information from SWIFOTA partition. This is will be used to set the
    // pool object size and compute the max object size
    mtdNum = partition_GetMtdFromImageTypeOrName( 0, "swifota", NULL );
    LE_FATAL_IF(-1 == mtdNum, "Unable to find a valid MTD for \"swifota\"");

    LE_FATAL_IF(LE_OK != pa_flash_GetInfo( mtdNum, &flashInfo, false, false ),
                "Unable to get MTD informations for \"swifota\"");

    MtdNumSwifota = (uint32_t)mtdNum;
    MtdEraseSize = flashInfo.eraseSize;
    PartitionPool = le_mem_CreatePool("PartitionPool", sizeof(Partition_t) + MtdEraseSize);
    le_mem_ExpandPool(PartitionPool, 1);

    partition_Reset();
}
