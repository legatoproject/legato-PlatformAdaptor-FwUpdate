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
#include "pa_fwupdate_dualsys.h"
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

//--------------------------------------------------------------------------------------------------
/**
 * Bit mask for undefined or not applicable bad image.
 * This must be set to 0 in order to allow logical OR operations between bad image bit masks.
 */
//--------------------------------------------------------------------------------------------------
#define BADIMG_NDEF 0x0

//==================================================================================================
//                                       Static variables
//==================================================================================================

//--------------------------------------------------------------------------------------------------
/**
 * Partition Name, Sub System ID and Image Type matrix
 */
//--------------------------------------------------------------------------------------------------
partition_Identifier_t Partition_Identifier[ CWE_IMAGE_TYPE_COUNT ] = {
    { { NULL,        NULL,        }, PA_FWUPDATE_SUBSYSID_NONE,  { BADIMG_NDEF, BADIMG_NDEF } },
    { { "sbl",       "sbl",       }, PA_FWUPDATE_SUBSYSID_MODEM, { BADIMG_NDEF, BADIMG_NDEF } },
    { { NULL,        NULL,        }, PA_FWUPDATE_SUBSYSID_NONE,  { BADIMG_NDEF, BADIMG_NDEF } },
    { { NULL,        NULL,        }, PA_FWUPDATE_SUBSYSID_NONE,  { BADIMG_NDEF, BADIMG_NDEF } },
    { { "modem",     "modem2",    }, PA_FWUPDATE_SUBSYSID_MODEM, { 0x000000200, 0x000000400 } },
    { { NULL,        NULL,        }, PA_FWUPDATE_SUBSYSID_NONE,  { BADIMG_NDEF, BADIMG_NDEF } },
    { { "rpm",       "rpm",       }, PA_FWUPDATE_SUBSYSID_MODEM, { 0x000000080, 0x000000100 } },
    { { NULL,        NULL,        }, PA_FWUPDATE_SUBSYSID_NONE,  { BADIMG_NDEF, BADIMG_NDEF } },
    { { NULL,        NULL,        }, PA_FWUPDATE_SUBSYSID_NONE,  { BADIMG_NDEF, BADIMG_NDEF } },
    { { NULL,        NULL,        }, PA_FWUPDATE_SUBSYSID_NONE,  { BADIMG_NDEF, BADIMG_NDEF } },
    { { NULL,        NULL,        }, PA_FWUPDATE_SUBSYSID_NONE,  { BADIMG_NDEF, BADIMG_NDEF } },
    { { "boot",      "boot2",     }, PA_FWUPDATE_SUBSYSID_LINUX, { 0x000002000, 0x000004000 } },
    { { "aboot",     "aboot2",    }, PA_FWUPDATE_SUBSYSID_LK,    { 0x000000800, 0x000001000 } },
    { { NULL,        NULL,        }, PA_FWUPDATE_SUBSYSID_NONE,  { BADIMG_NDEF, BADIMG_NDEF } },
    { { NULL,        NULL,        }, PA_FWUPDATE_SUBSYSID_NONE,  { BADIMG_NDEF, BADIMG_NDEF } },
    { { NULL,        NULL,        }, PA_FWUPDATE_SUBSYSID_NONE,  { BADIMG_NDEF, BADIMG_NDEF } },
    { { NULL,        NULL,        }, PA_FWUPDATE_SUBSYSID_NONE,  { BADIMG_NDEF, BADIMG_NDEF } },
    { { NULL,        NULL,        }, PA_FWUPDATE_SUBSYSID_NONE,  { BADIMG_NDEF, BADIMG_NDEF } },
    { { NULL,        NULL,        }, PA_FWUPDATE_SUBSYSID_NONE,  { BADIMG_NDEF, BADIMG_NDEF } },
    { { NULL,        NULL,        }, PA_FWUPDATE_SUBSYSID_NONE,  { BADIMG_NDEF, BADIMG_NDEF } },
    { { NULL,        NULL,        }, PA_FWUPDATE_SUBSYSID_NONE,  { BADIMG_NDEF, BADIMG_NDEF } },
    { { NULL,        NULL,        }, PA_FWUPDATE_SUBSYSID_NONE,  { BADIMG_NDEF, BADIMG_NDEF } },
    { { "system",    "system2",   }, PA_FWUPDATE_SUBSYSID_LINUX, { 0x000008000, 0x000010000 } },
    { { "lefwkro",   "lefwkro2",  }, PA_FWUPDATE_SUBSYSID_LINUX, { 0x000020000, 0x000040000 } },
    { { NULL,        NULL,        }, PA_FWUPDATE_SUBSYSID_NONE,  { BADIMG_NDEF, BADIMG_NDEF } },
    { { NULL,        NULL,        }, PA_FWUPDATE_SUBSYSID_NONE,  { BADIMG_NDEF, BADIMG_NDEF } },
    { { NULL,        NULL,        }, PA_FWUPDATE_SUBSYSID_NONE,  { BADIMG_NDEF, BADIMG_NDEF } },
    { { NULL,        NULL,        }, PA_FWUPDATE_SUBSYSID_NONE,  { BADIMG_NDEF, BADIMG_NDEF } },
    { { NULL,        NULL,        }, PA_FWUPDATE_SUBSYSID_NONE,  { BADIMG_NDEF, BADIMG_NDEF } },
    { { "tz",        "tz",        }, PA_FWUPDATE_SUBSYSID_MODEM, { 0x000000020, 0x000000040 } },
    { { NULL,        NULL,        }, PA_FWUPDATE_SUBSYSID_NONE,  { BADIMG_NDEF, BADIMG_NDEF } },
    { { NULL,        NULL,        }, PA_FWUPDATE_SUBSYSID_NONE,  { BADIMG_NDEF, BADIMG_NDEF } },
    { { "userapp",   "userapp",   }, PA_FWUPDATE_SUBSYSID_LINUX, { BADIMG_NDEF, BADIMG_NDEF } },
    { { NULL,        NULL,        }, PA_FWUPDATE_SUBSYSID_NONE,  { BADIMG_NDEF, BADIMG_NDEF } },
    { { "customer0", "customer1", }, PA_FWUPDATE_SUBSYSID_LINUX, { BADIMG_NDEF, BADIMG_NDEF } },
    { { "customer0", "customer1", }, PA_FWUPDATE_SUBSYSID_LINUX, { BADIMG_NDEF, BADIMG_NDEF } },
    { { "customer2", "customer2", }, PA_FWUPDATE_SUBSYSID_LINUX, { BADIMG_NDEF, BADIMG_NDEF } },
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

//--------------------------------------------------------------------------------------------------
/**
 * Sub system defined by user. If not defined, it set to the default initial boot system.
 */
//--------------------------------------------------------------------------------------------------
static int8_t InitialBootSystem[PA_FWUPDATE_SUBSYSID_MAX] =
{
    -1, -1, -1,
};

//==================================================================================================
//                                       Private Functions
//==================================================================================================

//--------------------------------------------------------------------------------------------------
/**
 * Get the initial MTD number used for modem file-system (ubi1) and rootfs (ubi0)
 *
 * @return
 *      - LE_OK on success
 */
//--------------------------------------------------------------------------------------------------
static le_result_t GetInitialBootSystemByUbi
(
    int* mtdModemNumPtr, ///< [OUT] the MTD number used for modem (ubi1)
    int* mtdLinuxNumPtr  ///< [OUT] the MTD number used for rootfs (ubi0)
)
{
    FILE* flashFdPtr;
    le_result_t le_result = LE_OK;
    int iUbi;
    char ubiPath[PATH_MAX];

    for( iUbi = 0; iUbi <= 1; iUbi++)
    {
        snprintf(ubiPath, sizeof(ubiPath), SYS_CLASS_UBI_PATH "/ubi%d/mtd_num", iUbi);
        // Try to open the MTD belonging to ubi0
        if (NULL == (flashFdPtr = fopen( ubiPath, "r" )))
        {
            LE_ERROR( "Unable to determine ubi%d mtd device: %m", iUbi );
            le_result = LE_FAULT;
            goto end;
        }
        // Read the MTD number
        if (1 != fscanf( flashFdPtr, "%d", ((0 == iUbi) ? mtdLinuxNumPtr : mtdModemNumPtr) ))
        {
            LE_ERROR( "Unable to determine ubi%d mtd device: %m", iUbi );
            le_result = LE_FAULT;
        }
        else
        {
            LE_DEBUG( "ubi%d: %d", iUbi, *((0 == iUbi) ? mtdLinuxNumPtr : mtdModemNumPtr) );
        }
        fclose( flashFdPtr );
    }

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
            if (Partition_Identifier[ partIndex ].namePtr[ partSystem ] &&
                (0 == strcmp( mtdFetchName,
                              Partition_Identifier[ partIndex ].namePtr[ partSystem ])))
            {
                // Found: output partition name and return image type
                *mtdNamePtr = Partition_Identifier[ partIndex ].namePtr[ partSystem ];
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
 * Get the initial boot system using the mtd used for rootfs (ubi0) and modem (ubi1). Read the
 * ssdata to detect the LK boot system. The returned value is an array of three uint8_t as follow:
 *     [0] = modem (tz/rpm/modem)
 *     [1] = lk (aboot)
 *     [2] = linux (boot/system/lefwkro)
 *
 * @return
 *      - LE_OK on success
 *      - LE_FAULT for any other errors
 */
//--------------------------------------------------------------------------------------------------
le_result_t partition_GetInitialBootSystem
(
    uint8_t* initBootSysPtr ///< [OUT] System array for "modem/lk/linux" partition groups
)
{
    // Check if initial boot system is already known. This is immutable until a reboot is performed
    // and a system swap is requested
    if (-1 == InitialBootSystem[PA_FWUPDATE_SUBSYSID_LINUX])
    {
        // Get the initial MTD number for rootfs
        char *iniMtdNamePtr;
        int iniMtdModem, iniMtdLinux;
        le_result_t result;
        cwe_ImageType_t imageType;
        int iniSysLk;

        result = GetInitialBootSystemByUbi(&iniMtdModem, &iniMtdLinux);

        if ((LE_OK != result) || (-1 == iniMtdModem) || (-1 == iniMtdLinux))
        {
            LE_ERROR( "Unable to determine initial boot system" );
            return LE_FAULT;
        }

        // Get the partition name for modem
        if (LE_FAULT == GetImageTypeFromMtd( iniMtdModem, &iniMtdNamePtr, &imageType ))
        {
            LE_ERROR( "Unable to determine initial boot system for modem" );
            return LE_FAULT;
        }
        // "modem2" : The initial boot modem is 2 (return 1)
        if (0 == strcmp( "modem2", iniMtdNamePtr ))
        {
            InitialBootSystem[PA_FWUPDATE_SUBSYSID_MODEM] = 1;
        }
        // "modem" : The initial boot modem is 1 (return 0)
        else if (0 == strcmp( "modem", iniMtdNamePtr ))
        {
            InitialBootSystem[PA_FWUPDATE_SUBSYSID_MODEM] = 0;
        }
        else
        {
            LE_ERROR( "Unable to determine initial boot system for modem" );
            return LE_FAULT;
        }

        // Get the partition name for Linux rootfs (system)
        if (LE_FAULT == GetImageTypeFromMtd( iniMtdLinux, &iniMtdNamePtr, &imageType ))
        {
            LE_ERROR( "Unable to determine initial boot system linux" );
            return LE_FAULT;
        }
        // "system2" : The initial boot system is 2 (return 1)
        if (0 == strcmp( "system2", iniMtdNamePtr ))
        {
            InitialBootSystem[PA_FWUPDATE_SUBSYSID_LINUX] = 1;
        }
        // "system" : The initial boot system is 1 (return 0)
        else if (0 == strcmp( "system", iniMtdNamePtr ))
        {
            InitialBootSystem[PA_FWUPDATE_SUBSYSID_LINUX] = 0;
        }
        else
        {
            LE_ERROR( "Unable to determine initial boot system linux" );
            return LE_FAULT;
        }

        iniSysLk = system("/usr/bin/swidssd read lk");
        if (WIFEXITED(iniSysLk))
        {
            iniSysLk = WEXITSTATUS(iniSysLk);
            if (100 == iniSysLk)
            {
                InitialBootSystem[PA_FWUPDATE_SUBSYSID_LK] = 0;
            }
            else if (200 == iniSysLk)
            {
                InitialBootSystem[PA_FWUPDATE_SUBSYSID_LK] = 1;
            }
            else
            {
                LE_ERROR( "Unable to determine initial boot system lk" );
                return LE_FAULT;
            }
        }
        else
        {
            LE_ERROR( "Unable to determine initial boot system lk" );
            return LE_FAULT;
        }

        LE_INFO("Initial Boot System: Modem %d LK %d Linux %d",
                InitialBootSystem[PA_FWUPDATE_SUBSYSID_MODEM],
                InitialBootSystem[PA_FWUPDATE_SUBSYSID_LK],
                InitialBootSystem[PA_FWUPDATE_SUBSYSID_LINUX]);
    }
    memcpy( initBootSysPtr, InitialBootSystem, sizeof(InitialBootSystem) );
    return LE_OK;
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
    int mtdNum = -1, l;
    pa_fwupdate_SubSysId_t subSysId;
    uint8_t iniBootSystem[PA_FWUPDATE_SUBSYSID_MAX], dualBootSystem[PA_FWUPDATE_SUBSYSID_MAX];

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
    if (LE_OK != partition_GetInitialBootSystem(iniBootSystem))
    {
        LE_ERROR("bad iniBootSystem");
        return -1;
    }
    // Dual system bank
    dualBootSystem[PA_FWUPDATE_SUBSYSID_MODEM] = !iniBootSystem[PA_FWUPDATE_SUBSYSID_MODEM];
    dualBootSystem[PA_FWUPDATE_SUBSYSID_LK] = !iniBootSystem[PA_FWUPDATE_SUBSYSID_LK];
    dualBootSystem[PA_FWUPDATE_SUBSYSID_LINUX] = !iniBootSystem[PA_FWUPDATE_SUBSYSID_LINUX];
    subSysId = Partition_Identifier[partName].subSysId;
    // If PA_FWUPDATE_SUBSYSID_NONE, the partition (even if it exists) is not managed by fwupdate
    // component
    if (PA_FWUPDATE_SUBSYSID_NONE == subSysId)
    {
        LE_ERROR("partition not managed by fwupdate");
        return -1;
    }

    mtdPartNamePtr = Partition_Identifier[partName].namePtr[inDual ? dualBootSystem[subSysId]
                                                                   : iniBootSystem[subSysId]];
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
        *isLogical = ((CWE_IMAGE_TYPE_QRPM == partName) || (CWE_IMAGE_TYPE_TZON == partName));
    }
    if (isDual)
    {
        *isDual = (inDual ? dualBootSystem[subSysId] : iniBootSystem[subSysId]) ? true : false;
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

        // Set bad image flag before writing to partition
        res = partition_SetBadImage(hdrPtr->imageType, true);
        if (LE_OK != res)
        {
            LE_ERROR("Failed to set bad image flag for CWE imageType %d", hdrPtr->imageType);
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


//--------------------------------------------------------------------------------------------------
/**
 * Get bad image bitmask value
 *
 * @return
 *      - LE_OK            The request was accepted
 *      - LE_BAD_PARAMETER The parameter is invalid
 *      - LE_FAULT         If an error occurs
 */
//--------------------------------------------------------------------------------------------------
static le_result_t partition_GetBadImageMask
(
    cwe_ImageType_t imageType,        ///< [IN] CWE image type to get bitmask for
    uint64_t* badImageMaskPtr         ///< [OUT] Pointer to bad image bitmask
)
{
    uint8_t systemArray[PA_FWUPDATE_SUBSYSID_MAX];
    pa_fwupdate_SubSysId_t subSysId;
    uint8_t partSystem;

    // Default value until valid mask is found
    *badImageMaskPtr = BADIMG_NDEF;

    if ((CWE_IMAGE_TYPE_MIN >= imageType) || (CWE_IMAGE_TYPE_MAX <= imageType))
    {
        LE_ERROR("Invalid CWE imageType %d", imageType);
        return LE_BAD_PARAMETER;
    }

    subSysId = Partition_Identifier[imageType].subSysId;
    if ((PA_FWUPDATE_SUBSYSID_NONE >= subSysId) ||
        (PA_FWUPDATE_SUBSYSID_MAX <= subSysId))
    {
        LE_ERROR("Undefined partition for subSysId %d", subSysId);
        return LE_BAD_PARAMETER;
    }

    if (LE_OK != partition_GetInitialBootSystem(systemArray))
    {
        LE_ERROR("Failed to get initial boot system");
        return LE_FAULT;
    }

    // Get mask for UPDATE system partition
    partSystem = !systemArray[subSysId];

    *badImageMaskPtr = Partition_Identifier[imageType].badImageMask[partSystem];
    if (BADIMG_NDEF == *badImageMaskPtr)
    {
        LE_WARN("Undefined badImageMask for CWE imageType %d", imageType);
    }

    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Set bad image flag preventing concurrent partition access
 *
 * @return
 *      - LE_OK            The request was accepted
 *      - LE_BAD_PARAMETER The parameter is invalid
 *      - LE_FAULT         If an error occurs
 */
//--------------------------------------------------------------------------------------------------
le_result_t partition_SetBadImage
(
    cwe_ImageType_t imageType,        ///< [IN] CWE image type to set/clear bad image flag for
    bool isBad                        ///< [IN] True to set bad image flag, false to clear it
)
{
    le_result_t res;
    uint64_t badImageMask = BADIMG_NDEF;

    res = partition_GetBadImageMask(imageType, &badImageMask);
    if (LE_OK != res)
    {
        LE_ERROR("Unable to get bad image mask for CWE image %d (ret %d)", imageType, res);
        return res;
    }

    if (BADIMG_NDEF != badImageMask)
    {
        // Set/Clear bad image flag on UPDATE partition
        res = pa_fwupdate_SetBadImage(badImageMask, isBad);
        if (LE_OK != res)
        {
            LE_ERROR("Unable to %s bad image 0x%llx", isBad ? "set":"clear", badImageMask);
            return LE_FAULT;
        }
    }
    else
    {
        LE_WARN("Bad image flag is not applicable to CWE imageType %d", imageType);
    }

    return LE_OK;
}
