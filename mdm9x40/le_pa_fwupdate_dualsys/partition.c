/**
 * @file partition.c
 *
 * partition management functions
 *
 *
 * Copyright (C) Sierra Wireless Inc.
 *
 */

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
#define SYS_CLASS_UBI_PATH     "/sys/class/ubi"

//--------------------------------------------------------------------------------------------------
/**
 * "/sys/class/mtd" access path
 */
//--------------------------------------------------------------------------------------------------
#define SYS_CLASS_MTD_PATH     "/sys/class/mtd"

//--------------------------------------------------------------------------------------------------
/**
 * SBL number of passes needed to flash low/high and high/low SBL scrub
 */
//--------------------------------------------------------------------------------------------------
#define SBL_MAX_PASS              2

//--------------------------------------------------------------------------------------------------
/**
 * PBL is looking for SBL signature in the first 2MB of the flash device
 * Should avoid to put SBL outside this
 */
//--------------------------------------------------------------------------------------------------
#define SBL_MAX_BASE_IN_FIRST_2MB  (2*1024*1024)

//==================================================================================================
//                                       Static variables
//==================================================================================================

//--------------------------------------------------------------------------------------------------
/**
 * Partition Name and Image Type matrix
 */
//--------------------------------------------------------------------------------------------------
static char* PartNamePtr[2][ CWE_IMAGE_TYPE_COUNT ] = {
    {
        NULL,
        "sbl",
        NULL,
        NULL,
        "modem",
        NULL,
        "rpm",
        NULL,
        NULL,
        NULL,
        NULL,
        "boot",
        "aboot",
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        "system",
        "lefwkro",
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        "tz",
        NULL,
        NULL,
        "userapp",
        NULL,
        "customer0",
        "customer0",
        "customer2",
    },
    {
        NULL,
        "sbl",
        NULL,
        NULL,
        "modem2",
        NULL,
        "rpm",
        NULL,
        NULL,
        NULL,
        NULL,
        "boot2",
        "aboot2",
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        "system2",
        "lefwkro2",
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        "tz",
        NULL,
        NULL,
        "userapp",
        NULL,
        "customer1",
        "customer1",
        "customer2",
    },
};

//--------------------------------------------------------------------------------------------------
/**
 * Pointer to the MTD name
 */
//--------------------------------------------------------------------------------------------------
static char* MtdNamePtr = NULL;

//--------------------------------------------------------------------------------------------------
/**
 * Pointer to the RAW image space used for SBL scrub
 */
//--------------------------------------------------------------------------------------------------
static uint8_t** RawImagePtr = NULL;

//--------------------------------------------------------------------------------------------------
/**
 * SBL preamble to be found at 0 of any first valid block
 */
//--------------------------------------------------------------------------------------------------
static const unsigned char partition_SBLPreamble[8] = {
    0xd1, 0xdc, 0x4b, 0x84,
    0x34, 0x10, 0xd7, 0x73,
};

//--------------------------------------------------------------------------------------------------
/**
 * Image size
 */
//--------------------------------------------------------------------------------------------------
static size_t  ImageSize = 0;

//==================================================================================================
//                                       Private Functions
//==================================================================================================

//--------------------------------------------------------------------------------------------------
/**
 * Get the initial MTD number used for rootfs (ubi0).
 *
 * @return
 *      - LE_OK on success
 *      - LE_FAULT for any other errors
 */
//--------------------------------------------------------------------------------------------------
static le_result_t GetInitialBootSystemByUbi
(
    int* mtdNumPtr ///< [OUT] the MTD number used for rootfs (ubi0)
)
{
    FILE* flashFdPtr;
    le_result_t le_result = LE_OK;

    // Try to open the MTD belonging to ubi0
    if (NULL == (flashFdPtr = fopen( SYS_CLASS_UBI_PATH "/ubi0/mtd_num", "r" )))
    {
        LE_ERROR( "Unable to determine ubi0 mtd device: %m" );
        le_result = LE_FAULT;
        goto end;
    }
    // Read the MTD number
    if (1 != fscanf( flashFdPtr, "%d", mtdNumPtr ))
    {
        LE_ERROR( "Unable to determine ubi0 mtd device: %m" );
        le_result = LE_FAULT;
    }
    else
    {
        LE_DEBUG( "GetInitialBootSystemByUbi: %d", *mtdNumPtr );
    }
    fclose( flashFdPtr );
end:
    return le_result;
}

//--------------------------------------------------------------------------------------------------
/**
 * Get the image type and the partition name according to its MTD number
 * The partition name (from boot system 1 or 2) is returned as output parameter
 *
 * @return
 *      - LE_OK on success
 *      - LE_FAULT for any other errors
 */
//--------------------------------------------------------------------------------------------------
static le_result_t GetImageTypeFromMtd
(
    int mtdNum,                     ///< [IN] the MTD number
    char** mtdNamePtr,              ///< [OUT] the partition name
    cwe_ImageType_t* imageTypePtr   ///< [OUT] the partition type
)
{
    FILE* flashFdPtr;
    char mtdBuf[100], mtdFetchName[16];
    int partIndex, partSystem;

    // Open the partition name belonging the given MTD number
    snprintf( mtdBuf, sizeof(mtdBuf), SYS_CLASS_MTD_PATH "/mtd%d/name", mtdNum );
    if (NULL == (flashFdPtr = fopen( mtdBuf, "r" )))
    {
        LE_ERROR( "Unable to open %s: %m", mtdBuf );
        return LE_FAULT;
    }
    // Try to read the partition name
    if (1 != fscanf( flashFdPtr, "%15s", mtdFetchName ))
    {
        LE_ERROR( "Unable to read mtd partition name %s: %m", mtdFetchName );
        fclose( flashFdPtr );
        return LE_FAULT;
    }
    fclose( flashFdPtr );
    // Look for the image type into the both system matrix
    mtdFetchName[strlen(mtdFetchName)] = '\0';
    for (partSystem = 0; partSystem < 2; partSystem++)
    {
        for (partIndex = CWE_IMAGE_TYPE_MIN; partIndex < CWE_IMAGE_TYPE_COUNT; partIndex++)
        {
            if (PartNamePtr[ partSystem ][ partIndex ] &&
                (0 == strcmp( mtdFetchName, PartNamePtr[ partSystem ][ partIndex ])))
            {
                // Found: output partition name and return image type
                *mtdNamePtr = PartNamePtr[ partSystem ][ partIndex ];
                *imageTypePtr = partIndex;
                return LE_OK;
            }
        }
    }

    // Not found
    return LE_FAULT;
}

//==================================================================================================
//  PUBLIC API FUNCTIONS
//==================================================================================================

//--------------------------------------------------------------------------------------------------
/**
 * Get the initial boot system using the mtd used for rootfs (ubi0). If the rootfs partition is
 * "system", initial boot system is 1, if it is "system2", initial boot system is 2.
 *
 * @return
 *      - 0 if initial boot system is 1,
 *      - 1 if initial boot system is 2,
 *      - -1 in case of failure
 */
//--------------------------------------------------------------------------------------------------
int partition_GetInitialBootSystem
(
    void
)
{
    static int InitialBootSystem = -1;

    // Check if initial boot system is already known. This is immutable until a reboot is performed
    // and a system swap is requested
    if (-1 == InitialBootSystem)
    {
        // Get the initial MTD number for rootfs
        char *iniMtdNamePtr;
        int iniMtd;
        le_result_t result;
        cwe_ImageType_t imageType;

        result = GetInitialBootSystemByUbi(&iniMtd);

        if ((LE_OK != result) || (-1 == iniMtd))
        {
            LE_ERROR( "Unable to determine initial boot system" );
            return -1;
        }

        // Get the partition name
        if (LE_FAULT == GetImageTypeFromMtd( iniMtd, &iniMtdNamePtr, &imageType ))
        {
            LE_ERROR( "Unable to determine initial boot system" );
            return -1;
        }
        // "system2" : The initial boot system is 2 (return 1)
        if (0 == strcmp( "system2", iniMtdNamePtr ))
        {
            InitialBootSystem = 1;
        }
        // "system" : The initial boot system is 1 (return 0)
        else if (0 == strcmp( "system", iniMtdNamePtr ))
        {
            InitialBootSystem = 0;
        }
        else
        {
            LE_ERROR( "Unable to determine initial boot system" );
        }
    }
    return InitialBootSystem;
}

//--------------------------------------------------------------------------------------------------
/**
 * Get the MTD number and partition name belonging to a image type. If the inDual parameter is true,
 * the MTD is looked into the passive partition matrix. If inDual is false, it is looked into the
 * active (initial boot) partition matrix.
 * The MTD name and the write size of the partition are also returned as output parameters.
 *
 * @return
 *      - The MTD number belonging the image type for the boot system (dual or initial)
 *      - 1 if initial boot system is 2,
 *      - -1 in case of failure
 */
//--------------------------------------------------------------------------------------------------
int partition_GetMtdFromImageType
(
    cwe_ImageType_t partName,         ///< [IN] Partition enumerate to get
    bool inDual,                      ///< [IN] true for the dual partition, false for the active
    char** mtdNamePtr,                ///< [OUT] Pointer to the real MTD partition name
    bool *isLogical,                  ///< [OUT] true if the partition is logical (TZ or RPM)
    bool *isDual                      ///< [OUT] true if the upper partition is concerned (TZ2 or
                                      ///<       RPM2), false in case of lower partition
)
{
    FILE* flashFdPtr;
    char mtdBuf[100], mtdFetchName[16];
    int mtdNum = -1, l, iniBootSystem, dualBootSystem;
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
    // Active system bank
    if (-1 == (iniBootSystem = partition_GetInitialBootSystem()))
    {
        LE_ERROR("bad iniBootSystem");
        return -1;
    }
    // Dual system bank
    dualBootSystem = (iniBootSystem ? 0 : 1);

    mtdPartNamePtr = PartNamePtr[ inDual ? dualBootSystem : iniBootSystem ][ partName ];
    // If NULL, the partition (even if it exists) is not managed by fwupdate component
    if (!mtdPartNamePtr)
    {
        LE_ERROR("partition not managed by fwupdate");
        return -1;
    }

    // Build the partition name to fetch into the /proc/mtd
    snprintf( mtdFetchName, sizeof(mtdFetchName), "\"%s\"", mtdPartNamePtr );
    l = strlen( mtdFetchName );

    // Open the /proc/mtd partition
    if (NULL == (flashFdPtr = fopen( "/proc/mtd", "r" )))
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

    if (isLogical)
    {
        *isLogical = ((CWE_IMAGE_TYPE_QRPM == partName) ||
                      (CWE_IMAGE_TYPE_TZON == partName)) ? true : false;
    }
    if (isDual)
    {
        *isDual = (inDual ? dualBootSystem : iniBootSystem) ? true : false;
    }

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
    DIR *dirPtr;
    struct dirent *direntPtr, *direntResPtr;
    uint8_t direntTab[offsetof(struct dirent, d_name) + PATH_MAX + 1];
    FILE *fd;
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
        direntPtr = (struct dirent *)&direntTab;
        // Read all entries in the directory
        while ((0 == readdir_r( dirPtr, direntPtr, &direntResPtr )) && (direntResPtr))
        {
           if ((0 == strncmp( "ubi", direntPtr->d_name, UBI_STRING_LENGTH )) &&
               (isdigit( direntPtr->d_name[UBI_STRING_LENGTH] )) &&
               (!strchr( direntPtr->d_name, '_')) )
           {
               snprintf( ubiMtdNumStr, sizeof(ubiMtdNumStr), SYS_CLASS_UBI_PATH "/%s/mtd_num",
                         direntPtr->d_name );
               ubiMtdNum = - 1;
               // Try to read the MTD number attached to this UBI
               fd = fopen( ubiMtdNumStr, "r" );
               if (fd)
               {
                   fscanf( fd, "%d", &ubiMtdNum );
                   fclose( fd );
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
        fd = fopen( "/proc/mounts", "r" );
        if (fd)
        {
            while (fgets( mountStr, sizeof(mountStr), fd ))
            {
                if (0 == strncmp( mountStr, ubiMtdNumStr, strlen(ubiMtdNumStr) ) )
                {
                    LE_ERROR("MTD %d s mounted. Device is busy", mtdNum);
                    res = LE_BUSY;
                    break;
                }
            }
            fclose(fd);
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
 * Check if data flashed into a partition are correctly written
 *
 * @return
 *      - LE_OK on success
 *      - LE_FAULT on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t partition_CheckData
(
    int mtdNum,                        ///< [IN] Minor of the MTD device to check
    bool isLogical,                    ///< [IN] true if the partition is logical (TZ or RPM)
    bool isDual,                       ///< [IN] true if the upper partition is concerned (TZ2 or
                                       ///<      RPM2), false in case of lower partition
    size_t sizeToCheck,                ///< [IN] Size to be used to compute the CRC
    off_t atOffset,                    ///< [IN] Force offset to start from
    uint32_t crc32ToCheck,             ///< [IN] Expected CRC 32
    le_mem_PoolRef_t flashImgPool      ///< [IN] memory pool
)
{
    pa_flash_Desc_t flashFd = NULL;
    uint8_t* checkBlockPtr = NULL;

    size_t size, imageSize = 0;
    off_t offset = atOffset;
    uint32_t crc32 = LE_CRC_START_CRC32;
    pa_flash_Info_t* flashInfoPtr;
    pa_flash_OpenMode_t mode = PA_FLASH_OPENMODE_READONLY;

    if (isLogical)
    {
        mode |= ((isDual) ? PA_FLASH_OPENMODE_LOGICAL_DUAL : PA_FLASH_OPENMODE_LOGICAL);
    }

    LE_DEBUG( "Size=%d, Crc32=0x%08x", sizeToCheck, crc32ToCheck);

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

        size = (((imageSize + flashInfoPtr->eraseSize) < sizeToCheck)
                   ? flashInfoPtr->eraseSize
                   : (sizeToCheck - imageSize));
        LE_DEBUG("Read %d at offset 0x%lx, block offset 0x%llx", size, offset, blkOff);
        if (LE_OK != pa_flash_ReadAtBlock( flashFd,
                                           ((off_t)blkOff / flashInfoPtr->eraseSize),
                                           checkBlockPtr,
                                           size))
        {
            LE_ERROR("read fails for offset 0x%llx: %m", blkOff);
            goto error;
        }

        crc32 = le_crc_Crc32( checkBlockPtr, size, crc32);
        offset += size;
        imageSize += size;
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
 * Write data into SBL (SBL scrub)
 *
 * @return
 *      - LE_OK on success
 *      - LE_FAULT on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t partition_WriteDataSBL
(
    const partition_Ctx_t *ctxPtr,    ///< [IN] context
    size_t length,                    ///< [IN] Input data length
    size_t offset,                    ///< [IN] Data offset in the package
    const uint8_t* dataPtr,           ///< [IN] input data
    bool forceClose,                  ///< [IN] Force close of device and resources
    bool *isFlashedPtr                ///< [OUT] true if flash write was done
)
{
    int mtdNum;
    pa_flash_Info_t flashInfo;
    le_result_t res = LE_OK;
    int sblNbBlk = 0, sblMaxBlk, sblIdxBlk;
    pa_flash_Desc_t flashFd = NULL;
    size_t lengthToCopy;
    size_t lengthCopied;
    off_t offsetToCopy;
    const cwe_Header_t* hdrPtr = ctxPtr->cweHdrPtr;

    if (forceClose)
    {
        // If forceClose set, close descriptor and release all resources
        LE_CRIT( "Closing and releasing MTD due to forceClose" );
        goto forceclose;
    }

    mtdNum = partition_GetMtdFromImageType( hdrPtr->imageType, true, &MtdNamePtr, NULL, NULL );

    LE_DEBUG("image type %d len %d offset 0x%x", hdrPtr->imageType, length, offset);

    if (-1 == mtdNum)
    {
        LE_ERROR( "Unable to find a valid mtd for image type %d", hdrPtr->imageType );
        return LE_FAULT;
    }

    if (LE_OK != pa_flash_GetInfo( mtdNum, &flashInfo, false, false ))
    {
        LE_ERROR( "Open MTD fails for MTD %d", mtdNum );
        return LE_FAULT;
    }
    sblNbBlk = (hdrPtr->imageSize + (flashInfo.eraseSize - 1)) / flashInfo.eraseSize;
    sblMaxBlk = flashInfo.nbBlk - sblNbBlk;

    // Check that SBL is not greater than the max block for the partition.
    if (sblNbBlk > (flashInfo.nbBlk / 2))
    {
        LE_ERROR("SBL is too big: %d (nbBlock %d)",
                 ImageSize, (ImageSize / flashInfo.eraseSize));
        goto error;
    }

    if (0 == ImageSize)
    {
        LE_INFO ("Writing \"%s\" (mtd%d) from CWE image %d, size %d",
                 MtdNamePtr, mtdNum, hdrPtr->imageType, hdrPtr->imageSize );

        // Allocate a block to store the SBL temporary image
        ImageSize = hdrPtr->imageSize;
        RawImagePtr = (uint8_t **) le_mem_ForceAlloc(ctxPtr->sblPool);
        memset(RawImagePtr, 0, sizeof(uint8_t*) * (flashInfo.nbBlk / 2));
    }

    // Check that the chunk is inside the SBL temporary image
    if ((offset + length) > ImageSize)
    {
        LE_ERROR("SBL image size and offset/length mismatch: %u < %u+%u",
                 ImageSize, offset, length);
        goto error;
    }

    lengthToCopy = length;
    lengthCopied = 0;
    offsetToCopy = offset;

    do
    {
        // Compute on what block the offsetToCopy belongs
        sblIdxBlk = (offsetToCopy / flashInfo.eraseSize);
        offsetToCopy = (offsetToCopy & (flashInfo.eraseSize - 1));
        if (NULL == RawImagePtr[sblIdxBlk])
        {
            RawImagePtr[sblIdxBlk] = (uint8_t *) le_mem_ForceAlloc(*ctxPtr->flashPoolPtr);
            memset( RawImagePtr[sblIdxBlk], PA_FLASH_ERASED_VALUE, flashInfo.eraseSize );
        }

        if ((lengthToCopy + offsetToCopy - 1) > flashInfo.eraseSize)
        {
            lengthToCopy = flashInfo.eraseSize - offsetToCopy;
        }

        memcpy( RawImagePtr[sblIdxBlk] + offsetToCopy,
                dataPtr,
                lengthToCopy );
        dataPtr += lengthToCopy;
        lengthCopied += lengthToCopy;
        offsetToCopy += ((sblIdxBlk * flashInfo.eraseSize) + lengthCopied);
        lengthToCopy = (length - lengthCopied);
    }
    while (lengthToCopy);

    if ((length + offset) >= ImageSize )
    {
        int sblBlk; // Base of SBL first block
        int nbBadBlk; // Number of BAD blocks inside the half partition
        int sblBaseBlk; // Base block where the SBL will be flashed
        int atBlk = -1;
        int atMaxBlk = -1;
        int atOffset = -1;
        int pass = 0;

        if (LE_OK != pa_flash_Open( mtdNum,
                                    PA_FLASH_OPENMODE_READWRITE | PA_FLASH_OPENMODE_MARKBAD,
                                    &flashFd,
                                    NULL ))
        {
            LE_ERROR( "Open MTD fails for MTD %d", mtdNum );
            return LE_FAULT;
        }

        /* Fetch if a valid SBL exists and get its first block */
        for (sblBlk = 0; sblBlk <= sblMaxBlk; sblBlk++ )
        {
            unsigned char sbl[sizeof(partition_SBLPreamble)];

            if (LE_OK != pa_flash_ReadAtBlock( flashFd, sblBlk, sbl, sizeof(sbl)))
            {
                LE_ERROR("Read of SBL at sector %d fails: %m", sblBlk );
                goto error;
            }
            if (0 == memcmp( sbl, partition_SBLPreamble, sizeof(sbl) ))
            {
                LE_INFO("SBL base found at block %d", sblBlk );
                break;
            }
        }

        if (sblBlk > sblMaxBlk)
        {
            // No valid SBL found in the partition. So we use the base at block 0
            LE_ERROR("No valid SBL signature found. Ignoring and assuming SBL at 0");
            sblBlk = 0;
        }
        else if (sblBlk && (sblBlk < (flashInfo.nbBlk / 2)))
        {
            // If SBL is a lower block, (0..3), SBL is assumed to be in low.
            // Update SBL base according to this.
            sblBlk = 0;
        }
        LE_INFO("Flashing SBL scrub: Size %d, base %d, nbblk %d",
                ImageSize, sblBlk, sblNbBlk );

        // Keep at least one block for spare
        sblMaxBlk--;

        do
        {
            bool isBad;
            uint32_t writeSize;

            // If SBL base is high, erase and flash the low before, and recopy to high
            // If SBL base is low, erase and flash the high before, and recopy to low
            // First block used as base to flash the SBL
            atBlk = (!pass ? (sblBlk ? 0 : flashInfo.nbBlk / 2)
                           : (sblBlk ? flashInfo.nbBlk / 2 : 0));
            atOffset = atBlk * flashInfo.eraseSize;

            // Last block of the SBL half partition
            atMaxBlk = atBlk + (flashInfo.nbBlk / 2);
            nbBadBlk = 0;
            // Check and count bad blocks in half partition to ensure that there is enough
            // good blocks to flash the SBL
            // Erase the half of the partition to be sure that in case of bad blocks, the
            // SBL will be safely written
            for (sblBaseBlk = -1; atBlk < atMaxBlk; atBlk++)
            {
                loff_t blkOff = atBlk * flashInfo.eraseSize;

                if (LE_OK != pa_flash_CheckBadBlock( flashFd, atBlk, &isBad ))
                {
                    LE_ERROR("pa_flash_CheckBadBlock fails for block %d, offset %lld: %m",
                             atBlk, blkOff);
                    goto error;
                }
                if (isBad)
                {
                    LE_WARN("Skipping bad block at %d", atBlk);
                    nbBadBlk++;
                    continue;
                }
                if (-1 == sblBaseBlk)
                {
                    // Block is marked good. Use this block at base for SBL
                    sblBaseBlk = atBlk;
                }
                // Erase this block
                if (LE_OK != pa_flash_EraseBlock( flashFd, atBlk ))
                {
                    LE_ERROR("pa_flash_EraseBlock fails for block %d, offset %lld: %m",
                             atBlk, blkOff);
                    goto error;
                }
            }

            // Not enougth block to flash the SBL
            if ((-1 == sblBaseBlk) ||
                (sblBaseBlk > (atMaxBlk - sblNbBlk)) ||
                (sblBaseBlk >= (SBL_MAX_BASE_IN_FIRST_2MB / flashInfo.eraseSize)) ||
                (nbBadBlk > ((flashInfo.nbBlk / 2) - sblNbBlk)))
            {
                LE_CRIT("(%d)Not enough blocks to update the SBL: Aborting", pass);
                LE_CRIT("(%d)Half nb blk %d, nb bad %d, SBL base %d, SBL nb blk %d",
                        pass, (flashInfo.nbBlk / 2), nbBadBlk, sblBaseBlk, sblNbBlk);
                goto critical;
            }

            // Skip the first page to invalidate the SBL signature
            atOffset = (sblBaseBlk * flashInfo.eraseSize) + flashInfo.writeSize;

            if (LE_OK != pa_flash_SeekAtOffset( flashFd, atOffset ))
            {
                LE_CRIT("pa_flash_SeekAtOffset fails for block %d, offset %d: %m",
                        atBlk, atOffset);
                goto critical;
            }
            writeSize = ((((sblNbBlk > 1) ? flashInfo.eraseSize : ImageSize)
                          - flashInfo.writeSize)
                         + (flashInfo.writeSize - 1)) &
                ~(flashInfo.writeSize - 1);
            if (LE_OK != pa_flash_Write( flashFd,
                                         (RawImagePtr[0] + flashInfo.writeSize),
                                         writeSize ))
            {
                LE_ERROR("(%d)pa_flash_Write fails: %m", pass);
                goto critical;
            }
            for (sblIdxBlk = 1; (sblIdxBlk < sblNbBlk) && RawImagePtr[sblIdxBlk]; sblIdxBlk++)
            {
                writeSize = ((((sblIdxBlk * flashInfo.eraseSize) < ImageSize) ?
                              flashInfo.eraseSize :
                              ImageSize - (sblIdxBlk * flashInfo.eraseSize))
                             + (flashInfo.writeSize - 1)) &
                    ~(flashInfo.writeSize - 1);
                if (LE_OK != pa_flash_Write(flashFd, RawImagePtr[sblIdxBlk], writeSize))
                {
                    LE_ERROR("(%d)pa_flash_Write: %m", pass);
                    goto critical;
                }
            }

            atOffset = sblBaseBlk * flashInfo.eraseSize;
            if (LE_OK != pa_flash_SeekAtOffset( flashFd, atOffset ))
            {
                LE_CRIT("pa_flash_SeekAtOffset fails for block %d, offset %d: %m",
                        atBlk, atOffset);
                goto critical;
            }
            // set isFlashed before the write because even if the write returns an error
            // some data could have been written in the flash
            if (isFlashedPtr)
            {
                *isFlashedPtr = true;
            }
            if (LE_OK != pa_flash_Write( flashFd, RawImagePtr[0], flashInfo.writeSize))
            {
                LE_ERROR("(%d)pa_flash_Write fails: %m", pass);
                goto critical;
            }

            if (LE_OK != partition_CheckData( mtdNum,
                                              0,
                                              0,
                                              ImageSize,
                                              (atOffset < (flashInfo.nbBlk / 2)
                                               ? 0
                                               : (flashInfo.nbBlk / 2)) * flashInfo.eraseSize,
                                              hdrPtr->crc32,
                                              *ctxPtr->flashPoolPtr))
            {
                LE_CRIT("SBL flash failed at block %d. Erasing...", sblBaseBlk);
                for (atBlk = 0; atBlk < (flashInfo.nbBlk / 2); atBlk++)
                {
                    pa_flash_EraseBlock( flashFd, atBlk + (atOffset / flashInfo.eraseSize) );
                }
                goto critical;
            }

            // Do low and high or high and low: 2 passes
        } while (++pass < SBL_MAX_PASS);

        atOffset = (sblBlk ? 0 : flashInfo.nbBlk / 2) * flashInfo.eraseSize;
        for (atBlk = 0; atBlk < flashInfo.nbBlk / 2; atBlk++)
        {
            pa_flash_EraseBlock( flashFd, atBlk + (sblBlk ? 0 : flashInfo.nbBlk / 2) );
        }

        pa_flash_Close(flashFd);

        for (sblIdxBlk = 0; (sblIdxBlk < sblNbBlk) && RawImagePtr[sblIdxBlk]; sblIdxBlk++)
        {
            le_mem_Release(RawImagePtr[sblIdxBlk]);
        }
        le_mem_Release(RawImagePtr);
        RawImagePtr = NULL;
        ImageSize = 0;
        LE_INFO("Update for partiton %s done with return %d",
                MtdNamePtr, res);
        MtdNamePtr = NULL;
    }

    return res;

critical:
    // The SBL may be partially updated or corrupted
    LE_CRIT("SBL is not updated correctly");
error:
    LE_ERROR("Update for partiton %s failed with return %d", MtdNamePtr, res);
forceclose:
    res = LE_OK;
    if (flashFd)
    {
        res = pa_flash_Close(flashFd);
    }
    if (RawImagePtr)
    {
        for (sblIdxBlk = 0; (sblIdxBlk < sblNbBlk) && RawImagePtr[sblIdxBlk]; sblIdxBlk++)
        {
            le_mem_Release(RawImagePtr[sblIdxBlk]);
        }
        le_mem_Release(RawImagePtr);
    }
    RawImagePtr = NULL;
    ImageSize = 0;
    MtdNamePtr = NULL;
    return (forceClose ? res : LE_FAULT);
}

//--------------------------------------------------------------------------------------------------
/**
 * Write data in UPDATE partitions
 *
 * @return
 *      - LE_OK on success
 *      - LE_FAULT on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t partition_WriteUpdatePartition
(
    const partition_Ctx_t *ctxPtr,    ///< [IN] context
    size_t length,                    ///< [IN] Input data length
    size_t offset,                    ///< [IN] Data offset in the package
    const uint8_t* dataPtr,           ///< [IN] input data
    bool forceClose,                  ///< [IN] Force close of device and resources
    bool *isFlashedPtr                ///< [OUT] true if flash write was done
)
{
    int mtdNum;
    le_result_t ret = LE_OK;
    bool isLogical = false, isDual = false;

    // Static variables for WriteData
    static size_t InOffset = 0;          // Current offset in erase block
    static uint8_t *DataPtr = NULL;      // Buffer to copy data (size of an erase block)
    static pa_flash_Info_t *FlashInfoPtr;  // MTD information of the current MTD
    static pa_flash_Desc_t MtdFd = NULL; // File descriptor for MTD operations
    const cwe_Header_t *hdrPtr = ctxPtr->cweHdrPtr;

    if (forceClose)
    {
        // If forceClose set, close descriptor and release all resources
        LE_CRIT( "Closing and releasing MTD due to forceClose" );
        goto error;
    }

    LE_DEBUG ("image type %d len %d offset 0x%x", hdrPtr->imageType, length, offset);

    if ((NULL == MtdFd) && (0 == ImageSize) )
    {
        int iblk;
        le_result_t res;

        mtdNum = partition_GetMtdFromImageType(hdrPtr->imageType, true, &MtdNamePtr, &isLogical,
                                               &isDual);

        if (-1 == mtdNum)
        {
            LE_ERROR( "Unable to find a valid mtd for image type %d", hdrPtr->imageType );
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
                                    PA_FLASH_OPENMODE_WRITEONLY | PA_FLASH_OPENMODE_MARKBAD |
                                    (isLogical
                                     ? (isDual ? PA_FLASH_OPENMODE_LOGICAL_DUAL
                                               : PA_FLASH_OPENMODE_LOGICAL)
                                     : 0),
                                     &MtdFd,
                                     &FlashInfoPtr ))
        {
            LE_ERROR("Fails to open MTD %d", mtdNum );
            return LE_FAULT;
        }
        // check if the image size is compliant with partition size
        if (hdrPtr->imageSize > FlashInfoPtr->size)
        {
            LE_ERROR("Image size (%d) > partition size (%d)", hdrPtr->imageSize, FlashInfoPtr->size);
            goto error;
        }
        if (LE_OK != pa_flash_Scan( MtdFd, NULL ))
        {
            LE_ERROR("Fails to scan MTD");
            goto error;
        }
        for (iblk = offset / FlashInfoPtr->eraseSize; iblk < FlashInfoPtr->nbLeb; iblk++)
        {
            bool isBad;

            if ((LE_OK != (res = pa_flash_CheckBadBlock( MtdFd, iblk, &isBad )))
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
                res = pa_flash_EraseBlock( MtdFd, iblk );
                if ((LE_OK != res) && (res != LE_NOT_PERMITTED))
                {
                    LE_ERROR("Fails to erase block %d: res=%d", iblk, res);
                    goto error;
                }
            }
        }
        if (LE_OK != pa_flash_SeekAtOffset( MtdFd, offset ))
        {
            LE_ERROR("Fails to seek block at %d", iblk);
            goto error;
        }
        DataPtr = le_mem_ForceAlloc(*ctxPtr->flashPoolPtr);
        InOffset = 0;
        ImageSize = hdrPtr->imageSize;
    }

    if ((NULL == FlashInfoPtr) || (NULL == DataPtr))
    {
        LE_ERROR("Bad behavior !!!");
        goto error;
    }

    if (((uint32_t)(length + InOffset)) >= FlashInfoPtr->eraseSize)
    {
        memcpy( DataPtr + InOffset, dataPtr, FlashInfoPtr->eraseSize - InOffset );
        // set isFlashed before the write because even if the write returns an error
        // some data could have been written in the flash
        if (isFlashedPtr)
        {
            *isFlashedPtr = true;
        }
        if (LE_OK != pa_flash_Write( MtdFd, DataPtr, FlashInfoPtr->eraseSize ))
        {
            LE_ERROR( "fwrite to nandwrite fails: %m" );
            goto error;
        }
        InOffset = length - (FlashInfoPtr->eraseSize - InOffset);
        memcpy( DataPtr, dataPtr, InOffset );
    }
    else
    {
        memcpy( DataPtr + InOffset, dataPtr, length );
        InOffset += length;
    }

    if ((length + offset) >= ImageSize )
    {
        if (InOffset)
        {
            if (InOffset <= FlashInfoPtr->eraseSize)
            {
                memset( DataPtr + InOffset,
                        PA_FLASH_ERASED_VALUE,
                        FlashInfoPtr->eraseSize - InOffset );
            }
            // set isFlashed before the write because even if the write returns an error
            // some data could have been written in the flash
            if (isFlashedPtr)
            {
                *isFlashedPtr = true;
            }
            if (LE_OK != pa_flash_Write( MtdFd, DataPtr, FlashInfoPtr->eraseSize))
            {
                LE_ERROR( "fwrite to nandwrite fails: %m" );
                goto error;
            }
        }
        le_mem_Release(DataPtr);
        DataPtr = NULL;
        InOffset = 0;
        pa_flash_Close( MtdFd );
        MtdFd = NULL;
        ImageSize = 0;
        LE_INFO( "Update for partiton %s done with return %d", MtdNamePtr, ret );
        MtdNamePtr = NULL;

        mtdNum = partition_GetMtdFromImageType( hdrPtr->imageType, true, &MtdNamePtr, &isLogical,
                                                &isDual );
        if (-1 == mtdNum)
        {
            LE_ERROR( "Unable to find a valid mtd for image type %d", hdrPtr->imageType );
            return LE_FAULT;
        }

        ret = partition_CheckData( mtdNum, isLogical, isDual, hdrPtr->imageSize, 0, hdrPtr->crc32,
                                   *ctxPtr->flashPoolPtr );
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


