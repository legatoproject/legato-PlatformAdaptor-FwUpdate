/**
 * @file pa_fwupdate.c
 *
 * implementation of @ref c_pa_fwupdate API.
 *
 * This PA supports writing data in device partition and red/write operations in SSDATA (System
 *  Shared Data).
 *
 * Copyright (C) Sierra Wireless Inc. Use of this work is subject to license.
 *
 */

#include "legato.h"
#include "pa_fwupdate.h"
#include "pa_fwupdate_dualsys.h"
#include "interfaces.h"
#include <sys/reboot.h>
#include <linux/reboot.h>


// Tools from mtd-utils package
#define FLASH_ERASE        "/usr/sbin/flash_erase"
#define NANDWRITE          "/usr/sbin/nandwrite"

// SBL number of passes needed to flash low/high and high/low SBL scrub
#define SBL_MAX_PASS              2

// Command buffer length used for popen(3) and system(3)
#define CMD_BUFFER_LENGTH       256

//==================================================================================================
//                                       Static variables
//==================================================================================================
//--------------------------------------------------------------------------------------------------
/**
 * Memory Pool for Data chunk
 */
//--------------------------------------------------------------------------------------------------
static le_mem_PoolRef_t   ChunkPool;

//--------------------------------------------------------------------------------------------------
/**
 * Structure of the current header
 */
//--------------------------------------------------------------------------------------------------
static pa_fwupdate_CweHeader_t CurrentCweHeader;

//--------------------------------------------------------------------------------------------------
/**
 * Read offset of the current component image
 */
//--------------------------------------------------------------------------------------------------
static size_t CurrentImageOffset = 0;

//--------------------------------------------------------------------------------------------------
/**
 * CRC32 variable
 */
//--------------------------------------------------------------------------------------------------
static uint32_t CurrentImageCrc32 = START_CRC32;

//--------------------------------------------------------------------------------------------------
/**
 * Current image format
 */
//--------------------------------------------------------------------------------------------------
static pa_fwupdate_ImageFormat_t CurrentImageFormat = PA_FWUPDATE_IMAGE_FORMAT_INVALID;

//--------------------------------------------------------------------------------------------------
/**
 * Boolean to know if data concerns header or component image
 */
//--------------------------------------------------------------------------------------------------
static bool IsImageToBeRead = false;

//--------------------------------------------------------------------------------------------------
/**
 * Boolean to know if a package download treament was aborted or not
 */
//--------------------------------------------------------------------------------------------------
static bool IsAborted = false;

//--------------------------------------------------------------------------------------------------
/**
 * Boolean to know if a package download treament is on-going
 */
//--------------------------------------------------------------------------------------------------
static bool IsOngoing = false;

//--------------------------------------------------------------------------------------------------
/**
 * Boolean to know if 1st data were written in partition
 */
//--------------------------------------------------------------------------------------------------
static bool IsFirstDataWritten = false;

//--------------------------------------------------------------------------------------------------
/**
 * CRC table
 */
//--------------------------------------------------------------------------------------------------
static const unsigned int Crc32Table[256] =
{
    0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA,     /* 0x00 */
    0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,     /* 0x04 */
    0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988,     /* 0x08 */
    0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,     /* 0x0C */
    0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE,     /* 0x10 */
    0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,     /* 0x14 */
    0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC,     /* 0x18 */
    0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,     /* 0x1C */
    0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172,     /* 0x20 */
    0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,     /* 0x24 */
    0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940,     /* 0x28 */
    0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,     /* 0x2C */
    0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116,     /* 0x30 */
    0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,     /* 0x34 */
    0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,     /* 0x38 */
    0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,     /* 0x3C */
    0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A,     /* 0x40 */
    0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,     /* 0x44 */
    0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818,     /* 0x48 */
    0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,     /* 0x4C */
    0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,     /* 0x50 */
    0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,     /* 0x54 */
    0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C,     /* 0x58 */
    0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,     /* 0x5C */
    0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2,     /* 0x60 */
    0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,     /* 0x64 */
    0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0,     /* 0x68 */
    0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,     /* 0x6C */
    0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086,     /* 0x70 */
    0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,     /* 0x74 */
    0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4,     /* 0x78 */
    0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,     /* 0x7C */
    0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A,     /* 0x80 */
    0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683,     /* 0x84 */
    0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8,     /* 0x88 */
    0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,     /* 0x8C */
    0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE,     /* 0x90 */
    0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,     /* 0x94 */
    0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC,     /* 0x98 */
    0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,     /* 0x9C */
    0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252,     /* 0xA0 */
    0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,     /* 0xA4 */
    0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60,     /* 0xA8 */
    0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79,     /* 0xAC */
    0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236,     /* 0xB0 */
    0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F,     /* 0xB4 */
    0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04,     /* 0xB8 */
    0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,     /* 0xBC */
    0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A,     /* 0xC0 */
    0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,     /* 0xC4 */
    0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38,     /* 0xC8 */
    0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21,     /* 0xCC */
    0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E,     /* 0xD0 */
    0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,     /* 0xD4 */
    0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C,     /* 0xD8 */
    0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,     /* 0xDC */
    0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2,     /* 0xE0 */
    0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB,     /* 0xE4 */
    0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0,     /* 0xE8 */
    0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,     /* 0xEC */
    0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6,     /* 0xF0 */
    0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF,     /* 0xF4 */
    0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,     /* 0xF8 */
    0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D      /* 0xFC */
};

//--------------------------------------------------------------------------------------------------
/**
 * Image type characters as filled in a CWE header
 * The order of entries in this table must match the order of the enums in pa_fwupdate_ImageType_t
 */
//--------------------------------------------------------------------------------------------------
static const char imagestring [CWE_IMAGE_TYPE_COUNT][sizeof(uint32_t)] =
{
    { 'Q', 'P', 'A', 'R' },     ///<  partition
    { 'S', 'B', 'L', '1' },     ///<  SBL1
    { 'S', 'B', 'L', '2' },     ///<  SBL2
    { 'D', 'S', 'P', '1' },     ///<  QDSP1 FW
    { 'D', 'S', 'P', '2' },     ///<  QDSP2 SW
    { 'D', 'S', 'P', '3' },     ///<  QDSP3 SW
    { 'Q', 'R', 'P', 'M' },     ///<  QCT RPM image
    { 'B', 'O', 'O', 'T' },     ///<  boot composite image
    { 'A', 'P', 'P', 'L' },     ///<  appl composite image
    { 'O', 'S', 'B', 'L' },     ///<  OS Second boot loader
    { 'A', 'M', 'S', 'S' },     ///<  amss
    { 'A', 'P', 'P', 'S' },     ///<  apps
    { 'A', 'P', 'B', 'L' },     ///<  apps bootloader
    { 'N', 'V', 'B', 'F' },     ///<  NV Backup (factory)
    { 'N', 'V', 'B', 'O' },     ///<  NV Backup (oem)
    { 'N', 'V', 'B', 'U' },     ///<  NV Backup (user)
    { 'E', 'X', 'E', 'C' },     ///<  Self-contained executable
    { 'S', 'W', 'O', 'C' },     ///<  Software on card image
    { 'F', 'O', 'T', 'O' },     ///<  FOTO image
    { 'F', 'I', 'L', 'E' },     ///<  Generic file
    { 'S', 'P', 'K', 'G' },     ///<  Super package
    { 'M', 'O', 'D', 'M' },     ///<  modem composite image
    { 'S', 'Y', 'S', 'T' },     ///<  image for 0:SYSTEM
    { 'U', 'S', 'E', 'R' },     ///<  image for 0:USERDATA
    { 'H', 'D', 'A', 'T' },     ///<  image for 0:HDATA
    { 'N', 'V', 'B', 'C' },     ///<  Cache NV Backup
    { 'S', 'P', 'L', 'A' },     ///<  Splash screen image file
    { 'N', 'V', 'U', 'P' },     ///<  NV UPdate file
    { 'Q', 'M', 'B', 'A' },     ///<  Modem Boot Authenticator
    { 'T', 'Z', 'O', 'N' },     ///<  QCT Trust-Zone Image
    { 'Q', 'S', 'D', 'I' },     ///<  QCT System Debug Image
    { 'A', 'R', 'C', 'H' },     ///<  Archive
    { 'U', 'A', 'P', 'P' },     ///<  USER APP Image
};

//--------------------------------------------------------------------------------------------------
/**
 * Memory Pool for SBL temporary image
 */
//--------------------------------------------------------------------------------------------------
static le_mem_PoolRef_t   SBLImgPool;

//--------------------------------------------------------------------------------------------------
/**
 * Information of a MTD partition read form /sys/class/mtd directory
 */
//--------------------------------------------------------------------------------------------------
typedef struct pa_fwupdate_MtdInfo {
    uint32_t size;        ///< Total size of the partition, in bytes.
    uint32_t writeSize;   ///< Minimal writable flash unit size.
    uint32_t eraseSize;   ///< "Major" erase size for the device.
    uint32_t startOffset; ///< In case of logical partition, the offset in the physical partition
    uint32_t nbBlk;       ///< number of blocks
    bool     logical;     ///< flag for logical partitions
} pa_fwupdate_MtdInfo_t;

//--------------------------------------------------------------------------------------------------
/**
 * Nand Write file descriptor
 */
//--------------------------------------------------------------------------------------------------
static FILE    *FdNandWrite = NULL;

//--------------------------------------------------------------------------------------------------
/**
 * Image size
 */
//--------------------------------------------------------------------------------------------------
static size_t  ImageSize = 0;

//--------------------------------------------------------------------------------------------------
/**
 * Pointer to the MTD name
 */
//--------------------------------------------------------------------------------------------------
static char    *MtdNamePtr = NULL;

//--------------------------------------------------------------------------------------------------
/**
 * Pointer to the RAW image space used for SBL scrub
 */
//--------------------------------------------------------------------------------------------------
static uint8_t *RawImagePtr = NULL;

//--------------------------------------------------------------------------------------------------
/**
 * SBL preamble to be found at 0 of any first valid block
 */
//--------------------------------------------------------------------------------------------------
static const unsigned char pa_fwupdate_SBLPreamble[8] = {
    0xd1, 0xdc, 0x4b, 0x84,
    0x34, 0x10, 0xd7, 0x73,
};

//--------------------------------------------------------------------------------------------------
/**
 * Partition Name and Image Type matrix
 */
//--------------------------------------------------------------------------------------------------
static char *pa_fwupdate_PartNamePtr[2][ CWE_IMAGE_TYPE_COUNT ] = {
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
    },
};

//==================================================================================================
//                                       Private Functions
//==================================================================================================
//--------------------------------------------------------------------------------------------------

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
   int *MtdNumPtr ///< [OUT] the MTD number used for rootfs (ubi0)
)
{
    FILE *mtdFd;
    le_result_t le_result = LE_OK;

    // Try to open the MTD belonging to ubi0
    if( NULL == (mtdFd = fopen( "/sys/class/ubi/ubi0/mtd_num", "r" )) )
    {
        LE_ERROR( "Unable to determine ubi0 mtd device: %m\n" );
        le_result = LE_FAULT;
        goto end;
    }
    // Read the MTD number
    if( 1 != fscanf( mtdFd, "%d", MtdNumPtr ) )
    {
        LE_ERROR( "Unable to determine ubi0 mtd device: %m\n" );
        le_result = LE_FAULT;
    }
    else
    {
        LE_DEBUG( "GetInitialBootSystemByUbi: %d\n", *MtdNumPtr );
    }
    fclose( mtdFd );
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
    int MtdNum,                             ///< [IN] the MTD number
    char **MtdNamePtr,                      ///< [OUT] the partition name
    pa_fwupdate_ImageType_t *ImageTypePtr   ///< [OUT] the partition type
)
{
    FILE *mtdFd;
    char mtdBuf[100], mtdFetchName[16];
    int partIndex, partSystem;

    // Open the partition name belonging the given MTD number
    snprintf( mtdBuf, sizeof(mtdBuf), "/sys/class/mtd/mtd%d/name", MtdNum );
    if( NULL == (mtdFd = fopen( mtdBuf, "r" )) )
    {
        LE_ERROR( "Unable to open %s: %m\n", mtdBuf );
        return LE_FAULT;
    }
    // Try to read the partition name
    if( 1 != fscanf( mtdFd, "%s", mtdFetchName ))
    {
        LE_ERROR( "Unable to read mtd partition name %s: %m\n", mtdFetchName );
        fclose( mtdFd );
        return LE_FAULT;
    }
    fclose( mtdFd );
    // Look for the image type into the both system matrix
    mtdFetchName[strlen(mtdFetchName)] = '\0';
    for( partSystem = 0; partSystem < 2; partSystem++ )
        for( partIndex = CWE_IMAGE_TYPE_MIN; partIndex < CWE_IMAGE_TYPE_COUNT; partIndex++ )
            if( pa_fwupdate_PartNamePtr[ partSystem ][ partIndex ] &&
                (0 == strcmp( mtdFetchName, pa_fwupdate_PartNamePtr[ partSystem ][ partIndex ])) )
            {
                // Found: output partition name and return image type
                *MtdNamePtr = pa_fwupdate_PartNamePtr[ partSystem ][ partIndex ];
                *ImageTypePtr = partIndex;
                return LE_OK;
            }

    // Not found
    return LE_FAULT;
}

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
static int GetInitialBootSystem
(
    void
)
{
    static int _initialBootSystem = -1;

    // Check if initial boot system is already known. This is immutable until a reboot is performed
    // and a system swap is requested
    if( -1 == _initialBootSystem )
    {
        // Get the initial MTD number for rootfs
        char *iniMtdNamePtr;
        int iniMtd;
        le_result_t result;
        pa_fwupdate_ImageType_t imageType;

        result = GetInitialBootSystemByUbi(&iniMtd);

        if( (LE_OK != result) || (-1 == iniMtd) )
        {
            LE_ERROR( "Unable to determine initial boot system" );
            return -1;
        }

        // Get the partition name
        if( LE_FAULT == GetImageTypeFromMtd( iniMtd, &iniMtdNamePtr, &imageType ) )
        {
            LE_ERROR( "Unable to determine initial boot system" );
            return -1;
        }
        // "system2" : The initial boot system is 2 (return 1)
        if( 0 == strcmp( "system2", iniMtdNamePtr ) )
            _initialBootSystem = 1;
        // "system" : The initial boot system is 1 (return 0)
        else if( 0 == strcmp( "system", iniMtdNamePtr ) )
            _initialBootSystem = 0;
        else
        {
            LE_ERROR( "Unable to determine initial boot system" );
        }
    }
    return _initialBootSystem;
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
static int GetMtdFromImageType
(
    pa_fwupdate_ImageType_t partName,
    bool inDual,
    char **MtdNamePtr,
    pa_fwupdate_MtdInfo_t *mtdInfo
)
{
    FILE *mtdFd;
    char mtdBuf[100], mtdFetchName[16];
    int mtdNum = -1, l, iniBootSystem, dualBootSystem;
    char *mtdPartName;

    *MtdNamePtr = NULL;
    // Valid image type
    if( partName > CWE_IMAGE_TYPE_MAX )
        return -1;
    if( -1 == (iniBootSystem = GetInitialBootSystem()) )
        return -1;
    dualBootSystem = (iniBootSystem ? 0 : 1);

    mtdPartName = pa_fwupdate_PartNamePtr[ inDual ? dualBootSystem : iniBootSystem ][ partName ];
    // If NULL, the partition (even if it exists) is not managed by fwupdate component
    if( !mtdPartName )
        return -1;

    // Build the partition name to fetch into the /proc/mtd
    snprintf( mtdFetchName, sizeof(mtdFetchName), "\"%s\"", mtdPartName );
    l = strlen( mtdFetchName );

    // Open the /proc/mtd partition
    if( NULL == (mtdFd = fopen( "/proc/mtd", "r" )) )
    {
        LE_ERROR( "fopen on /proc/mtd failed: %m" );
        return -1;
    }

    // Read all entries until the partition names match
    while( fgets(mtdBuf, sizeof(mtdBuf), mtdFd ) ) {
        // This is the fetched partition
        if( 0 == strncmp( mtdBuf + strlen( mtdBuf ) - l - 1, mtdFetchName, l ) )
        {
            // Get the MTD number
            if( 1 != sscanf( mtdBuf, "mtd%d", &mtdNum ) )
            {
                LE_ERROR( "Unable to scan the mtd number in %s\n", mtdBuf );
            }
            else
            {
                // Output MTD partition name and MTD number
                *MtdNamePtr = mtdPartName;
                LE_DEBUG( "Partition %s is mtd%d\n", *MtdNamePtr, mtdNum );
            }
            break;
        }
    }
    fclose( mtdFd );
    memset( mtdInfo, 0, sizeof(pa_fwupdate_MtdInfo_t) );
    // If MTD number is valid, try to read the partition size
    if( -1 != mtdNum )
    {
        snprintf( mtdBuf, sizeof(mtdBuf), "/sys/class/mtd/mtd%d/size", mtdNum );
        if( NULL == (mtdFd = fopen( mtdBuf, "r" )) )
        {
            LE_ERROR( "Unable to read page size for mtd %d: %m\n", mtdNum );
        }
        fscanf( mtdFd, "%d", &(mtdInfo->size) );
        fclose( mtdFd );
    }
    // If MTD number is valid, try to read the partition write size
    if( -1 != mtdNum )
    {
        snprintf( mtdBuf, sizeof(mtdBuf), "/sys/class/mtd/mtd%d/writesize", mtdNum );
        if( NULL == (mtdFd = fopen( mtdBuf, "r" )) )
        {
            LE_ERROR( "Unable to read write size for mtd %d: %m\n", mtdNum );
        }
        fscanf( mtdFd, "%d", &(mtdInfo->writeSize) );
        fclose( mtdFd );
    }
    // If MTD number is valid, try to read the partition erase size
    if( -1 != mtdNum )
    {
        snprintf( mtdBuf, sizeof(mtdBuf), "/sys/class/mtd/mtd%d/erasesize", mtdNum );
        if( NULL == (mtdFd = fopen( mtdBuf, "r" )) )
        {
            LE_ERROR( "Unable to read erase size for mtd %d: %m\n", mtdNum );
        }
        fscanf( mtdFd, "%d", &(mtdInfo->eraseSize) );
        fclose( mtdFd );
    }
    mtdInfo->nbBlk = mtdInfo->size / mtdInfo->eraseSize;
    mtdInfo->startOffset = 0;
    // TZ and RPM are logical partitions
    if( (partName == CWE_IMAGE_TYPE_QRPM) ||
        (partName == CWE_IMAGE_TYPE_TZON) ) {
        mtdInfo->logical = true;
        mtdInfo->nbBlk /= 2;
        mtdInfo->size /= 2;
        mtdInfo->startOffset = (inDual ? dualBootSystem : iniBootSystem) ? mtdInfo->size : 0;
    }
    LE_INFO( "mtd %d : \"%s\" size 0x%08x write %u erase %u nbblock %u logical %d start 0x%08x\n",
             mtdNum, *MtdNamePtr, mtdInfo->size, mtdInfo->writeSize, mtdInfo->eraseSize,
             mtdInfo->nbBlk, mtdInfo->logical, mtdInfo->startOffset );

    // Return the MTD number
    return mtdNum;
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
static le_result_t WriteDataSBL
(
    pa_fwupdate_ImageFormat_t format,   ///< [IN] Component image format linked to data
    pa_fwupdate_CweHeader_t* hdr,       ///< [IN] Component image header
    size_t *length,                     ///< [IN] Input data length
    size_t offset,                      ///< [IN] Data offset in the package
    uint8_t* data                       ///< [IN] intput data
)
{
    int mtdNum;
    pa_fwupdate_MtdInfo_t mtdInfo;
    le_result_t res = LE_OK;
    int sblNbBlk, sblMaxBlk;

    mtdNum = GetMtdFromImageType( hdr->ImageType, 1, &MtdNamePtr, &mtdInfo );

    LE_DEBUG ("Format %d image type %d len %d offset %d",
              format, hdr->ImageType, *length, offset);

    if( -1 == mtdNum )
    {
        LE_ERROR( "Unable to find a valid mtd for image type %d\n", hdr->ImageType );
        return LE_FAULT;
    }

    sblNbBlk = (hdr->ImageSize + mtdInfo.eraseSize - 1) / mtdInfo.eraseSize;
    sblMaxBlk = mtdInfo.nbBlk - sblNbBlk;

    if (ImageSize == 0)
    {
        LE_INFO ("Writing \"%s\" (mtd%d) from CWE image %d, size %d\n",
                 MtdNamePtr, mtdNum, hdr->ImageType, hdr->ImageSize );

        // Check that SBL is not greater than the max block for the partition.
        if (sblNbBlk > ((mtdInfo.nbBlk / 2) + 1))
        {
            LE_ERROR("SBL is too big: %d (nbBlock %d)",
                     ImageSize, (ImageSize / mtdInfo.eraseSize));
            goto error;
        }

        // Allocate a block to store the SBL temporary image
        ImageSize = hdr->ImageSize;
        RawImagePtr = (uint8_t *) le_mem_ForceAlloc(SBLImgPool);
    }

    // Check that the chunck is inside the SBL temporary image
    if ((offset + *length) > ImageSize)
    {
        LE_ERROR("SBL image size and offset/length mismatch: %u < %u+%u",
                 ImageSize, offset, *length);
        goto error;
    }

    memcpy( RawImagePtr + offset, data, *length );

    if ((*length + offset) >= ImageSize )
    {
        int rc;
        int sblBlk; // Base of SBL first block
        int nbBlk;
        int atBlk = -1;
        int atOffset = -1;
        int pass = 0;
        char cmdBuf[CMD_BUFFER_LENGTH];
        FILE *mtdFd;

        snprintf( cmdBuf, sizeof(cmdBuf), "/dev/mtd%d", mtdNum );
        if (NULL == (mtdFd = fopen( cmdBuf, "r" )))
        {
            LE_ERROR("Open of MTD %s fails: %m\n", cmdBuf );
            goto error;
        }
        /* Fetch if a valid SBL exists and get its first block */
        for (sblBlk = 0; sblBlk <= sblMaxBlk; sblBlk++ )
        {
            unsigned char sbl[sizeof(pa_fwupdate_SBLPreamble)];

            if (fseek( mtdFd, sblBlk * mtdInfo.eraseSize, SEEK_SET ))
            {
                LE_ERROR("fseek() at offset %d fails: %m", sblBlk * mtdInfo.eraseSize );
                fclose( mtdFd );
                goto error;
            }
            if (fread( sbl, sizeof(sbl), 1, mtdFd ) != 1)
            {
                LE_ERROR("Read of SBL at sector %d fails: %m", sblBlk );
                fclose( mtdFd );
                goto error;
            }
            if (0 == memcmp( sbl, pa_fwupdate_SBLPreamble, sizeof(sbl) ))
            {
                LE_INFO("SBL base found at block %d\n", sblBlk );
                break;
            }
        }
        fclose( mtdFd );

        if (sblBlk > sblMaxBlk)
        {
            // No valid SBL found in the partition. So we use the base at block 0
            LE_ERROR("No valid SBL signature found. Ignoring and assuming SBL at 0");
            sblBlk = 0;
        }
        else if (sblBlk && (sblBlk < (mtdInfo.nbBlk / 2)))
        {
            // If SBL is a lower block, (0..3), SBL is assumed to be in low.
            // Update SBL base according to this.
            sblBlk = 0;
        }
        LE_INFO("Flashing SBL scrub: Size %d, base %d, nbblk %d\n",
                ImageSize, sblBlk, sblNbBlk );

        // Keep at least one block for spare
        sblMaxBlk--;

        do
        {
            // Erase all blocks related to the SBL starting first block
            atOffset = (!pass ?
                        (sblBlk ? 0 : sblMaxBlk) : sblBlk) * mtdInfo.eraseSize;
            snprintf(cmdBuf, sizeof(cmdBuf), FLASH_ERASE " /dev/mtd%d 0x%08x %u >/dev/null",
                     mtdNum, atOffset, sblNbBlk);
            LE_INFO("(%d)cmd: %s\n", pass, cmdBuf);
            rc = system(cmdBuf);
            if (WEXITSTATUS(rc))
            {
                LE_ERROR ("(%d)Flash erase failed: %d\n", pass, WEXITSTATUS(rc));
                goto error;
            }

            // Flash by block loop from last SBL block to first SBL block
            // If SBL base is high, flash the low before, and recopy to high
            // If SBL base is low, flash the high before, and recopy to low
            for( atBlk = (!pass ?
                          (sblBlk ? 0 : sblMaxBlk) : sblBlk) + sblNbBlk - 1,
                 nbBlk = 0;
                 nbBlk < sblNbBlk;
                 nbBlk++, atBlk-- )
            {
                atOffset = atBlk * mtdInfo.eraseSize;
                LE_DEBUG("(%d)sblBlk = %d, atBlk = %d, atOffset = 0x%08x\n",
                        pass, sblBlk, atBlk, atOffset);

                // Flash blocks related to the SBL starting last block
                snprintf(cmdBuf, sizeof(cmdBuf), NANDWRITE " -s %u -p /dev/mtd%d - >/dev/null",
                         atOffset, mtdNum);
                LE_INFO("(%d)Popen to %s\n", pass, cmdBuf);
                LE_DEBUG("(%d)fwrite( offset=%x, length=%d )\n", pass,
                        ((sblNbBlk - nbBlk - 1) * mtdInfo.eraseSize),
                        nbBlk ? mtdInfo.eraseSize :
                                (ImageSize - ((sblNbBlk - nbBlk - 1) * mtdInfo.eraseSize)));
                FdNandWrite = popen( cmdBuf, "we" );
                if (NULL == FdNandWrite)
                {
                    LE_ERROR ("(%d)popen to nandwrite failed : %m\n", pass);
                    goto error;
                }
                if (1 != fwrite( RawImagePtr + ((sblNbBlk - nbBlk - 1) * mtdInfo.eraseSize),
                                 mtdInfo.eraseSize, 1, FdNandWrite) )
                {
                    LE_ERROR("(%d)fwrite to nandwrite fails: %m\n", pass);
                    goto error;
                }
                pclose( FdNandWrite );
                FdNandWrite = NULL;
            }
            // Do low and high or high and low: 2 passes
        } while (++pass < SBL_MAX_PASS);

        atOffset = (sblBlk ? 0 : sblMaxBlk) * mtdInfo.eraseSize;

        // Erase blocks related to the temporary SBL: high if SBL low; low if SBL is high
        snprintf(cmdBuf, sizeof(cmdBuf), FLASH_ERASE " /dev/mtd%d 0x%08x %u >/dev/null",
                 mtdNum, atOffset, sblNbBlk);
        LE_INFO( "(E)cmd: %s\n", cmdBuf);
        rc = system(cmdBuf);
        if (WEXITSTATUS(rc))
        {
             LE_ERROR ("(E)Flash erase failed: %d\n", WEXITSTATUS(rc));
             goto error;
        }

        le_mem_Release(RawImagePtr);
        RawImagePtr = NULL;
        ImageSize = 0;
        FdNandWrite = NULL;
        LE_INFO("Update for partiton %s done with return %d\n",
                MtdNamePtr, res);
        MtdNamePtr = NULL;
    }

    return res;
error:
    if( RawImagePtr )
    {
        le_mem_Release(RawImagePtr);
    }
    RawImagePtr = NULL;
    ImageSize = 0;
    FdNandWrite = NULL;
    LE_ERROR("Update for partiton %s failed with return %d\n",
             MtdNamePtr, LE_FAULT);
    MtdNamePtr = NULL;
    return LE_FAULT;
}
//--------------------------------------------------------------------------------------------------
/**
 * Write data in a partition
 *
 * @return
 *      - LE_OK on success
 *      - LE_FAULT on failure
 */
//--------------------------------------------------------------------------------------------------
static le_result_t WriteData
(
    pa_fwupdate_ImageFormat_t format,   ///< [IN] Component image format linked to data
    pa_fwupdate_CweHeader_t* hdr,       ///< [IN] Component image header
    size_t *length,                     ///< [IN] Input data length
    size_t offset,                      ///< [IN] Data offset in the package
    uint8_t* data                       ///< [IN] intput data
)
{
    int rc;
    le_result_t ret = LE_OK;
    pa_fwupdate_MtdInfo_t mtdInfo;

    LE_DEBUG ("Format %d image type %d len %d offset %d",
              format, hdr->ImageType, *length, offset);

    if (hdr->ImageType == CWE_IMAGE_TYPE_SBL1 )
    {
        // SBL is managed by a specific flash scheme
        return WriteDataSBL( format, hdr, length, offset, data );
    }

    if ((0 == offset) && (NULL == FdNandWrite) && (0 == ImageSize) )
    {
        int mtdNum;
        char cmdBuf[CMD_BUFFER_LENGTH];

        mtdNum = GetMtdFromImageType( hdr->ImageType, 1, &MtdNamePtr, &mtdInfo );

        if( -1 == mtdNum )
        {
            LE_ERROR( "Unable to find a valid mtd for image type %d\n", hdr->ImageType );
            return LE_FAULT;
        }
        LE_INFO ("Writing \"%s\" (mtd%d) from CWE image %d\n",
                 MtdNamePtr, mtdNum, hdr->ImageType );

        /* erase the flash blocks related to the MTD mtdNum */
        snprintf(cmdBuf, sizeof(cmdBuf), FLASH_ERASE " /dev/mtd%d 0x%08x %u >/dev/null", mtdNum,
                 mtdInfo.startOffset, mtdInfo.nbBlk);
        LE_INFO( "cmd: %s\n", cmdBuf);
        rc = system(cmdBuf);
        if (WEXITSTATUS(rc))
        {
            LE_ERROR ("Flash erase failed: %d\n", WEXITSTATUS(rc));
            return LE_FAULT;
        }
        snprintf(cmdBuf, sizeof(cmdBuf), NANDWRITE " -s %u -p /dev/mtd%d - >/dev/null",
                 mtdInfo.startOffset, mtdNum);
        LE_DEBUG( "Popen to %s\n", cmdBuf );
        FdNandWrite = popen( cmdBuf, "we" );
        if (NULL == FdNandWrite)
        {
            LE_ERROR ("popen to nandwrite failed : %m\n");
            MtdNamePtr = NULL;
            return LE_FAULT;
        }
        ImageSize = hdr->ImageSize;
    }

    if (1 != fwrite( data, *length, 1, FdNandWrite) )
    {
        LE_ERROR( "fwrite to nandwrite fails: %m\n" );
        goto error;
    }

    if ((*length + offset) >= ImageSize )
    {
        pclose( FdNandWrite );
        ImageSize = 0;
        FdNandWrite = NULL;
        LE_INFO( "Update for partiton %s done with return %d\n", MtdNamePtr, ret );
        MtdNamePtr = NULL;
    }
    return ret;
error:
    pclose( FdNandWrite );
    ImageSize = 0;
    FdNandWrite = NULL;
    MtdNamePtr = NULL;
    return LE_FAULT;
}

//--------------------------------------------------------------------------------------------------
/**
 * This function is to initialize internal variables to initiate a new package download
 */
//--------------------------------------------------------------------------------------------------
static void ParamsInit
(
    void
)
{
    LE_DEBUG ("ParamsInit" );
    CurrentImageOffset = 0;
    IsAborted = false;
    CurrentImageCrc32 = START_CRC32;
    CurrentImageFormat = PA_FWUPDATE_IMAGE_FORMAT_INVALID;
    memset(&CurrentCweHeader, 0, sizeof(CurrentCweHeader));
    IsImageToBeRead = false;
    IsOngoing = false;
    IsFirstDataWritten = false;
}

//--------------------------------------------------------------------------------------------------
/**
 * This function returns an integer value for the specified CWE image type
 *
 * @return
 *      - uint32_t  integer value for a valid image type or CWE_IMAGE_TYPE_COUNT
 *                  if image type is invalid
 */
//--------------------------------------------------------------------------------------------------
static uint32_t ImageValueGet
(
    pa_fwupdate_ImageType_t imagetype   ///< [IN] CWE Image Type to convert
)
{
    uint32_t imageval = CWE_IMAGE_TYPE_COUNT;

    if (imagetype < CWE_IMAGE_TYPE_COUNT)
    {
        imageval = (imagestring[imagetype][0] << 24) |
                   (imagestring[imagetype][1] << 16) |
                   (imagestring[imagetype][2] <<  8) |
                    imagestring[imagetype][3];
    }

    return imageval;
}

//--------------------------------------------------------------------------------------------------
/**
 * This function validates the image type against supported values
 *
 * @note
 *      enumvalue = CWE_IMAGE_TYPE_COUNT if imagetype is not valid
 *
 * @return
 *      - true      if image type is one of the supported values
 *      - false     otherwise
 */
//--------------------------------------------------------------------------------------------------
static bool ImageTypeValidate
(
    uint32_t imagetype,                 ///< [IN] image type for validation
    pa_fwupdate_ImageType_t* enumvalue   ///< [OUT] enum value for image type
)
{
    bool retVal = true;
    pa_fwupdate_ImageType_t idx;
    uint32_t imageval;

    LE_DEBUG ("imagetype 0x%x", imagetype);

    for (idx = CWE_IMAGE_TYPE_MIN; idx < CWE_IMAGE_TYPE_COUNT; idx++)
    {
        imageval = ImageValueGet(idx);
        if (imageval == imagetype)
        {
            break;
        }
    }

    /* save found index */
    *enumvalue = idx;

    if (idx == CWE_IMAGE_TYPE_COUNT)
    {
        /* imagetype not found */
        retVal = false;
    }

    LE_DEBUG ("retVal %d --> image type %d", retVal, *enumvalue);

    return retVal;
}

//--------------------------------------------------------------------------------------------------
/**
 * This function is used to get a 32 bit value from a packet in network byte order and increment the
 * packet pointer beyond the extracted field
 *
 * @return
 *      - LE_OK            The request was accepted
 *      - LE_BAD_PARAMETER The parameter is invalid
 *      - LE_NOT_POSSIBLE  The action is not compliant with the SW update state (no downloaded pkg)
 *      - LE_FAULT         If an error occurs
 */
//--------------------------------------------------------------------------------------------------
static uint32_t TranslateNetworkByteOrder
(
    uint8_t ** packetpp ///< [IN] memory location of the pointer to the packet from which the 32 bit
                        ///< value will be read
)
{
    uint32_t field;
    uint8_t *packetp;

    packetp = *packetpp;

    field = *packetp++;
    field <<= 8;
    field += *packetp++;
    field <<= 8;
    field += *packetp++;
    field <<= 8;
    field += *packetp++;
    *packetpp = packetp;

    return field;
}

//--------------------------------------------------------------------------------------------------
/**
 * This function is used to get a string of 8-bit fields from a packet and increment the packet
 * pointer beyond the last read 8-bit field
 */
//--------------------------------------------------------------------------------------------------
static void TranslateNetworkByteOrderMulti
(
    uint8_t** packetpp, ///< [IN] memory location of a pointer to a packet from which the string of
                        ///< 8-bit fields is to be read
    uint8_t* bufferp,   ///< [OUT] pointer to a buffer into which the 8-bit fields are to be copied
    uint16_t numfields  ///< [IN] number of 8-bit fields to be copied
)
{
    uint8_t* packetp;
    int32_t i;

    packetp = *packetpp;

    for (i = numfields - 1; i >= 0; i--)
    {
        *bufferp++ = *packetp++;
    }

    *packetpp = packetp;
}

//--------------------------------------------------------------------------------------------------
/**
 * This function is used to calculate a CRC-32
 *
 * @return
 *      - 32-bit CRC
 */
//--------------------------------------------------------------------------------------------------
static uint32_t Crc32
(
    uint8_t* address,   ///< [IN] Input buffer
    uint32_t size,      ///< [IN] Number of bytes to read
    uint32_t crc        ///< [IN] Starting CRC seed
)
{
    for (; size > 0 ; size--)
    {
        //-- byte loop */
        crc = (((crc >> 8) & 0x00FFFFFF) ^ Crc32Table[(crc ^ *address++) & 0x000000FF]);
    }
    return crc;
}

//--------------------------------------------------------------------------------------------------
/**
 * This function indicates the data length to be read according to data type to be read
 *
 * @return
 *      - data length to be read
 */
//--------------------------------------------------------------------------------------------------
static ssize_t LengthToRead
(
    void
)
{
    ssize_t readCount = 0;

    if (IsImageToBeRead == false)
    {
        /* a header can be fully read */
        readCount = HEADER_SIZE;
    }
    else
    {
        /* A component image can be read */
        /* Check if whole component image can be filled in a data chunk */
        if ((CurrentCweHeader.ImageSize - CurrentImageOffset) > CHUNK_LENGTH)
        {
            readCount = CHUNK_LENGTH;
        }
        else
        {
            readCount = CurrentCweHeader.ImageSize - CurrentImageOffset;
        }
    }
    return readCount;
}

//--------------------------------------------------------------------------------------------------
/**
 * This function is used by the Legato SW Update component to read a CWE header
 *
 * @return
 *      - LE_OK            The request was accepted
 *      - LE_BAD_PARAMETER The parameter is invalid
 *      - LE_NOT_POSSIBLE  The action is not compliant with the SW update state (no downloaded pkg)
 *      - LE_FAULT         If an error occurs
 */
//--------------------------------------------------------------------------------------------------
static le_result_t HeaderLoad
(
    uint8_t* startp,                ///< [IN] start address of the CWE header to be read
    pa_fwupdate_CweHeader_t* hdp    ///< [OUT] pointer to a CWE header structure
)
{
    le_result_t result = LE_NOT_POSSIBLE;

    if ((startp == NULL) || (hdp == NULL))
    {
        result = LE_BAD_PARAMETER;
    }
    else
    {
        uint8_t* bufp;
        pa_fwupdate_ImageType_t imagetype;

        /* init the buf pointer */
        bufp = startp;

        /* read in the required number of bytes from product specific buffer */
        TranslateNetworkByteOrderMulti (&bufp, ( uint8_t*) hdp->PSB, sizeof(hdp->PSB));

        /* Get the Header Version: Set our pointer to the header revision number first */
        bufp = startp + HDR_REV_NUM_OFST;

        /* Read the header version number */
        hdp->HdrRevNum = TranslateNetworkByteOrder(&bufp);
        LE_DEBUG ("hdp->HdrRevNum %d", hdp->HdrRevNum);

        /* Continue reading the buffer from the Image Type Offset field */
        bufp = startp + IMAGE_TYPE_OFST;

        /* get the image type */
        hdp->ImageType = TranslateNetworkByteOrder(&bufp);
        LE_DEBUG ("ImageType 0x%x", hdp->ImageType);

        if (hdp->HdrRevNum >= HDRCURVER)
        {
            /* validate image type */
            if (ImageTypeValidate(hdp->ImageType, &imagetype))
            {
                hdp->ImageType = imagetype;
                LE_DEBUG ("ImageType %d", hdp->ImageType);
                /* get product type */
                hdp->ProdType = TranslateNetworkByteOrder(&bufp);
                LE_DEBUG ("ProdType 0x%x", hdp->ProdType);

                /* get application image size */
                hdp->ImageSize = TranslateNetworkByteOrder(&bufp);
                LE_DEBUG ("ImageSize %d 0x%x", hdp->ImageSize, hdp->ImageSize);

                /* get CRC32 of application */
                hdp->CRC32 = TranslateNetworkByteOrder(&bufp);
                LE_DEBUG ("CRC32 0x%x", hdp->CRC32);

                /* get version string */
                TranslateNetworkByteOrderMulti(&bufp, hdp->Version, HVERSTRSIZE);
                LE_DEBUG ("Version %s", hdp->Version);
                /* get date string */
                TranslateNetworkByteOrderMulti(&bufp, hdp->RelDate, HDATESIZE);

                /* get backwards compatibilty field */
                hdp->Compat = TranslateNetworkByteOrder(&bufp);

                /* get the misc options */
                hdp->MiscOpts = *bufp;
                LE_DEBUG ("HeaderLoad: hdp->MiscOpts %d", hdp->MiscOpts);

                /* get the load address and entry point based upon the header version. */
                bufp=startp+STOR_ADDR_OFST;
                hdp->StorAddr  = (uint32_t)(*bufp++);
                hdp->StorAddr |= (uint32_t)(*bufp++ << 8);
                hdp->StorAddr |= (uint32_t)(*bufp++ << 16);
                hdp->StorAddr |= (uint32_t)(*bufp++ << 24);

                bufp=startp+PROG_ADDR_OFST;
                hdp->ProgAddr  = (uint32_t)(*bufp++);
                hdp->ProgAddr |= (uint32_t)(*bufp++ << 8);
                hdp->ProgAddr |= (uint32_t)(*bufp++ << 16);
                hdp->ProgAddr |= (uint32_t)(*bufp++ << 24);

                bufp=startp+ENTRY_OFST;
                hdp->Entry     = (uint32_t)(*bufp++);
                hdp->Entry    |= (uint32_t)(*bufp++ << 8);
                hdp->Entry    |= (uint32_t)(*bufp++ << 16);
                hdp->Entry    |= (uint32_t)(*bufp++ << 24);

                /* get signature */
                hdp->Signature = TranslateNetworkByteOrder(&bufp);

                /* get product specific buffer CRC value */
                bufp = startp + CRC_PROD_BUF_OFST;
                hdp->CRCProdBuf = TranslateNetworkByteOrder(&bufp);

                /* get CRC valid indicator value */
                bufp = startp + CRC_INDICATOR_OFST;
                hdp->CRCIndicator = TranslateNetworkByteOrder(&bufp);

                /* Only check the signature field for application imagetypes (not for
                 * bootloader) since we always want to return false for bootloader
                 * imagetypes. */
                if (imagetype == CWE_IMAGE_TYPE_APPL)
                {
                    /* check application signature */
                    if (hdp->Signature != APPSIGN)
                    {
                        /* application not found */
                        result = LE_FAULT;
                    }
                    else
                    {
                        result = LE_OK;
                    }
                }
                else
                {
                    result = LE_OK;
                }
            }
            else
            {
                LE_ERROR ("Image Type in CWE header is not supported %d", imagetype);
                result = LE_FAULT;
            }
        }
        else
        {
            LE_ERROR ("bad header version %d", hdp->HdrRevNum);
            result = LE_FAULT;
        }

        /* The CWE header was well loaded.
         * Now make some checks
         */
        if (result == LE_OK)
        {
            /* The image type was already checked in le_fwupdate_HeaderLoad */

            /* Validate product ID */
            if (hdp->ProdType != PA_FWUPDATE_PRODUCT_ID)
            {
                LE_ERROR ("Bad Product Id in the header");
                result = LE_FAULT;
            }

            /* Check that the image is not a compressed one:
             * not supported on this platform
             */
            if ((hdp->MiscOpts & MISC_OPTS_COMPRESS) == MISC_OPTS_COMPRESS)
            {
                LE_ERROR( "Compressed image is not supported");
                result = LE_FAULT;
            }

            /* validate PSB CRC */
            if (Crc32(startp, CRC_PROD_BUF_OFST, START_CRC32) != hdp->CRCProdBuf)
            {
                LE_ERROR( "error PSB CRC32");
                result = LE_FAULT;
            }

            /* The image CRC will be checked when all data are retrieved */

            if (result != LE_OK)
            {
                LE_ERROR ("Error when validate the header");
            }
        }
    }
    LE_DEBUG ("HeaderLoad result %d", result);
    return result;
}

//--------------------------------------------------------------------------------------------------
/**
 * This function is used by the Legato SW Update component to parse and store an incoming package
 *
 * @return
 *      - LE_OK            The request was accepted
 *      - LE_BAD_PARAMETER The parameter is invalid
 *      - LE_NOT_POSSIBLE  The action is not compliant with the SW update state (no downloaded pkg)
 *      - LE_FAULT         If an error occurs
 */
//--------------------------------------------------------------------------------------------------
static le_result_t DataParseAndStore
(
    size_t offset,  ///< [IN] Data offset in the package
    size_t length,  ///< [IN] Input data lentg
    uint8_t* chunk  ///< [IN] intput data
)
{
    le_result_t result = LE_OK;
    LE_DEBUG ("start");
    if ((chunk == NULL) || (length > CHUNK_LENGTH))
    {
        result = LE_BAD_PARAMETER;
    }
    else
    {
        size_t Return = 0;
        LE_DEBUG ("parsing a chunk: len %zd, IsImageToBeRead %d",
                    length, IsImageToBeRead);

        /* Check if a header is read or a component image */
        if (IsImageToBeRead == false)
        {
            /* For a header, the full header shall be provided */
            if (length == HEADER_SIZE)
            {
                result = HeaderLoad (chunk, &CurrentCweHeader);
                if (result != LE_OK)
                {
                    LE_ERROR ("Error in parsing the CWE header");
                    result = LE_FAULT;
                }
                else
                {
                    LE_DEBUG ("CWE header read ok");
                    /* Check the value of the CurrentCweHeader.ImageType which is proceed
                     * If the image type is a composite one, the next data is a CWE header
                     */
                    if ((CurrentCweHeader.ImageType != CWE_IMAGE_TYPE_APPL)
                     && (CurrentCweHeader.ImageType != CWE_IMAGE_TYPE_MODM)
                     && (CurrentCweHeader.ImageType != CWE_IMAGE_TYPE_SPKG)
                     && (CurrentCweHeader.ImageType != CWE_IMAGE_TYPE_BOOT))
                    {
                        /* Next data will concern a component image */
                        IsImageToBeRead = true;
                    }
                }
            }
            else
            {
                LE_ERROR ("Bad length for header %d", (uint32_t)length);
                result = LE_BAD_PARAMETER;
            }
        }
        else
        {
            /* Component image is under read: follow it */
            Return = pa_fwupdate_ImageData (&CurrentCweHeader,
                                            chunk,
                                            length);
            if (!Return)
            {
                /* Parsing fails */
                result = LE_FAULT;
            }
            else
            {
                /* Parsing succeeds */
                result = LE_OK;
            }
        }
    }

    LE_DEBUG ("result %d", result);
    return result;
}

//==================================================================================================
//  PUBLIC API FUNCTIONS
//==================================================================================================

//--------------------------------------------------------------------------------------------------
/**
 * Program a synchronization between active and update systems
 *
 * @return
 *      - LE_OK             on success
 *      - LE_UNSUPPORTED    the feature is not supported
 *      - LE_FAULT          on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_fwupdate_DualSysSync
(
    void
)
{
    /* Call flash API to synchronize system
     * This API is a blocking one
     * Partitions to be synchronized:
     * logical partitions: QSSE and RPM
     * physical partitions: MODEM, ABOOT, BOOT, SYSTEM, USER0, USER2
     */
    static pa_fwupdate_ImageType_t syncPartition[] = {
        CWE_IMAGE_TYPE_DSP2,
        CWE_IMAGE_TYPE_APPS,
        CWE_IMAGE_TYPE_APBL,
        CWE_IMAGE_TYPE_SYST,
        CWE_IMAGE_TYPE_USER,
        CWE_IMAGE_TYPE_QRPM,
        CWE_IMAGE_TYPE_TZON,
    };
    int iniBootSystem, dualBootSystem;
    int mtdSrc, mtdDst;
    int idx, rc;
    pa_fwupdate_MtdInfo_t mtdInfoSrc, mtdInfoDst;
    char *mtdSrcName, *mtdDstName;
    char cmdBuf[1024];

    if( -1 == (iniBootSystem = GetInitialBootSystem()) )
    {
        return LE_FAULT;
    }
    dualBootSystem = (iniBootSystem ? 0 : 1);

    /* Set the Sw update state in SSDATA to SYNC */
    if( pa_fwupdate_SetState(PA_FWUPDATE_STATE_SYNC) != LE_OK )
    {
        LE_ERROR ("not possible to update the SW update state to SYNC");
        return LE_FAULT;
    }

    LE_INFO( "Synchronizing from system %d to system %d\n", iniBootSystem + 1, dualBootSystem + 1);
    for( idx = 0; idx < sizeof( syncPartition )/sizeof(pa_fwupdate_ImageType_t); idx++ ) {
        if( -1 == (mtdSrc = GetMtdFromImageType( syncPartition[idx], false, &mtdSrcName,
                                                 &mtdInfoSrc )) )
        {
            LE_ERROR( "Unable to determine initial partition for %d\n", syncPartition[idx] );
            return LE_FAULT;
        }
        if( -1 == (mtdDst = GetMtdFromImageType( syncPartition[idx], true, &mtdDstName,
                                                 &mtdInfoDst )) )
        {
            LE_ERROR( "Unable to determine dual partition for %d\n", syncPartition[idx] );
            return LE_FAULT;
        }
        if( mtdInfoSrc.writeSize != mtdInfoDst.writeSize )
        {
            LE_ERROR( "Can not copy flash with different page size: source = %d, destination = %d\n",
                      mtdInfoSrc.writeSize, mtdInfoDst.writeSize );
            return LE_FAULT;
        }
        if( (mtdSrc == mtdDst) &&
            ((syncPartition[idx] == CWE_IMAGE_TYPE_QRPM) ||
             (syncPartition[idx] == CWE_IMAGE_TYPE_TZON)) )
        {
            LE_INFO( "SRC:mtd%d : size=%u, erasesize=%u block=%u, offset=%08x\n",
                     mtdSrc, mtdInfoSrc.size, mtdInfoSrc.eraseSize, mtdInfoSrc.nbBlk,
                     mtdInfoSrc.startOffset );
            LE_INFO( "DST:mtd%d : size=%u, erasesize=%u block=%u, offset=%08x\n",
                     mtdDst, mtdInfoDst.size, mtdInfoDst.eraseSize, mtdInfoDst.nbBlk,
                     mtdInfoDst.startOffset );
            snprintf( cmdBuf, sizeof(cmdBuf),
                      FLASH_ERASE " /dev/mtd%d 0x%08x %u >/dev/null && "
                      "(/bin/dd if=/dev/mtd%d bs=%u count=%u skip=%u | "
                      NANDWRITE " -s %u /dev/mtd%d >/dev/null)",
                      mtdDst, mtdInfoDst.startOffset, mtdInfoDst.nbBlk,
                      mtdSrc, mtdInfoSrc.eraseSize, mtdInfoSrc.nbBlk,
                      mtdInfoSrc.startOffset / mtdInfoSrc.eraseSize,
                      mtdInfoDst.startOffset, mtdDst );
            LE_ERROR( "Logical %s update: \n%s\n", dualBootSystem ? "2" : "1", cmdBuf );
        }
        else
        {
            /* erase the destination mtd and copy source mtd to destination one */
            snprintf( cmdBuf, sizeof(cmdBuf),
                      FLASH_ERASE " /dev/mtd%d 0 0 >/dev/null && "
                      NANDWRITE " /dev/mtd%d </dev/mtd%d >/dev/null",
                      mtdDst, mtdDst, mtdSrc );
        }
        LE_INFO( "Synchronizing %s partition \"%s%s\" (mtd%d) from \"%s%s\" (mtd%d)\n",
                 mtdDst == mtdSrc ? "logical" : "physical",
                 mtdDstName,
                 mtdDst == mtdSrc && dualBootSystem ? "2" : "",
                 mtdDst,
                 mtdSrcName,
                 mtdDst == mtdSrc && iniBootSystem ? "2" : "",
                 mtdSrc );
        rc = system( cmdBuf );
        if (WEXITSTATUS(rc))
        {
            LE_ERROR ("Synchronization failed failed: %d\n", WEXITSTATUS(rc));
            return LE_FAULT;
        }
    }

    LE_INFO ("pa_fwupdate_DualSysSync done");
    if (LE_OK != pa_fwupdate_SetSyncState())
    {
        LE_ERROR("Failed to call pa_fwupdate_SetSyncState(): Systems are not synchronized");
        return LE_FAULT;
    }
    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Function which issue a system reset
 */
//--------------------------------------------------------------------------------------------------
void pa_fwupdate_Reset
(
    void
)
{
    sync();
    sync();
    sleep(1);
    reboot(LINUX_REBOOT_CMD_RESTART);
    /* at this point the system is reseting */
}

//--------------------------------------------------------------------------------------------------
/**
 * This function writes provided data in corresponding flash partition
 *
 * @return
 *      - Written data length
 *      - 0 in case of failure
 */
//--------------------------------------------------------------------------------------------------
size_t pa_fwupdate_ImageData
(
    pa_fwupdate_CweHeader_t *CweHeader, ///< [IN] CWE header linked to image data
    uint8_t* chunk,                     ///< [IN]Data to be written in flash partition
    size_t length                       ///< [IN]Data length to be written in flash partition
)
{
    size_t result = 0;

    /* Check incoming parameters */
    if (CweHeader == NULL)
    {
        LE_ERROR ("bad parameters");
        return 0;
    }

    LE_DEBUG ("imagetype %d, CurrentImageOffset %d length %d, CurrentImageSize %d",
                CweHeader->ImageType,
                (uint32_t)CurrentImageOffset,
                (uint32_t)length,
                (uint32_t)CweHeader->ImageSize);

    /* Check incoming parameters */
    if ((chunk == NULL) || (length > CHUNK_LENGTH))
    {
        LE_ERROR ("bad parameters");
        result = 0;
    }
    else
    {
        if (CurrentImageOffset == 0)
        {
            CurrentImageCrc32 = START_CRC32;
        }

        if (LE_OK == WriteData (CurrentImageFormat,
                                CweHeader,
                                &length,
                                CurrentImageOffset,
                                chunk))
        {
            CurrentImageCrc32 = Crc32( chunk, (uint32_t)length, CurrentImageCrc32 );
            LE_DEBUG ( "image data write: CRC in header: 0x%x, calculated CRC 0x%x",
                        CweHeader->CRC32, CurrentImageCrc32 );
            CurrentImageOffset += length;
            result = length;

            /* Check if it's the 1st data write for this package */
            if( IsFirstDataWritten == false )
            {
                /* Update the partition synchronization state */
                pa_fwupdate_SetUnsyncState();
                IsFirstDataWritten = true;
            }
            LE_DEBUG ("CurrentImageOffset %d", (uint32_t)CurrentImageOffset);
        }
        else
        {
            /* Error on storing image data */
            result = 0;
            LE_ERROR ("error when writing data in partition");
        }

        if (CurrentImageOffset == CweHeader->ImageSize)
        {
            LE_DEBUG ( "image data write end: CRC in header: 0x%x, calculated CRC 0x%x",
                            CweHeader->CRC32, CurrentImageCrc32 );
            /* The whole image was written: compare CRC */
            if (CweHeader->CRC32 != CurrentImageCrc32)
            {
                /* Error on CRC check */
                LE_ERROR ("Error on CRC check");
                result = 0;
            }
            else
            {
                CurrentImageOffset = 0;
                LE_DEBUG ("CurrentImageOffset %d, CurrentImage %d",
                            (uint32_t)CurrentImageOffset, CweHeader->ImageType);
            }
            IsImageToBeRead = false;
        }
    }

    LE_DEBUG ("result %d", (uint32_t)result);
    return result;
}

//--------------------------------------------------------------------------------------------------
/**
 * This function starts a package download to the device.
 *
 * @warning This API is a blocking API. It needs to be called in a dedicated thread.
 *
 * @return
 *      - LE_OK            The function succeeded
 *      - LE_BAD_PARAMETER The parameter is invalid (needs to be positive)
 *      - LE_TERMINATED    The download was aborted by the user (by calling
 *                          pa_fwupdate_ExecuteCommand( pa_fwupdate_CANCEL )
 *      - LE_FAULT         The function failed
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_fwupdate_Download
(
    int fd  ///< [IN]File descriptor of the file to be downloaded
)
{
    le_result_t result = LE_FAULT;
    size_t totalCount = 0;
    ssize_t readCount = 0;
    ssize_t DataLenToBeRead = 0;
    uint8_t* bufferPtr = le_mem_ForceAlloc (ChunkPool);

    LE_DEBUG ("fd %d", fd);
    if (fd < 0)
    {
        LE_ERROR ("bad parameter");
        result = LE_BAD_PARAMETER;
    }
    /* Check if a download is already on-going */
    else if (IsOngoing)
    {
        result = LE_BUSY;
    }
    else
    {
        bool bSync = false;
        /* Get the systems synchronization state
         * the possible results are:
         * LE_UNSUPPORTED --> return LE_UNSUPPORTED
         * LE_OK --> treat it */
        result = pa_fwupdate_DualSysGetSyncState (&bSync);

        if (result == LE_OK)
        {
            /* check if both systems are synchronized */
            if (bSync == true)
            {
                /* Both sytems are synchronized */
                ParamsInit();
                /* Indicate that a download is launched */
                IsOngoing = true;

                while (true)
                {
                    /* Check if the download was not aborted by another thread */
                    if (IsAborted)
                    {
                        LE_INFO ("Download was aborted by the user");
                        result = LE_TERMINATED;
                        IsAborted = false;
                        close (fd);
                        break;
                    }
                    else
                    {
                        ssize_t LenRead = 0;

                        /* Read a block at a time from the fd, and send to the modem */
                        /* Get the length which can be read */
                        DataLenToBeRead = LengthToRead();
                        readCount = read (fd, bufferPtr, DataLenToBeRead);

                        if ((LenRead == -1) && (errno != EINTR))
                        {
                            LE_FATAL("error during read: errno=%d", errno);
                        }

                        LE_DEBUG ("Read %d", (uint32_t)readCount);

                        if (readCount > 0)
                        {
                            /* In case partial data were read */
                            while( readCount != DataLenToBeRead )
                            {
                                LenRead = read (fd, bufferPtr + LenRead, DataLenToBeRead - LenRead);
                                if ((LenRead == -1) && (errno != EINTR))
                                {
                                    LE_FATAL("error during read: errno=%d",
                                             errno);
                                }
                                readCount += LenRead;
                            }

                            /* Parse the read data and store in partition */
                            /* totalCount is in fact the offset */
                            result = DataParseAndStore (totalCount, readCount,
                                                        bufferPtr);
                            if (result == LE_OK)
                            {
                                /* Update the totalCount variable (offset) with read data length */
                                totalCount += readCount;
                                LE_DEBUG ("--> update totalCount %d",
                                          (uint32_t)totalCount);
                            }
                            else
                            {
                                result = LE_FAULT;
                                /* Done with the file, so close it. */
                                close(fd);
                                break;
                            }
                        }
                        else if (!readCount)
                        {
                            LE_DEBUG ("Read %zd bytes in total", totalCount);
                            result = LE_OK;
                            /* Done with the file, so close it. */
                            close(fd);
                            break;
                        }
                        else
                        {
                            LE_ERROR ("Error while reading fd=%i : %m", fd);
                            result = LE_FAULT;
                            /* Done with the file, so close it. */
                            close (fd);
                            break;
                        }
                    }
                }
                IsOngoing = false;
            }
            else
            {
                /* Both systems are not synchronized
                 * It's not possible to launch a new package download
                 */
                result = LE_NOT_POSSIBLE;
            }
        }
    }

    le_mem_Release(bufferPtr);

    LE_DEBUG ("result %d", result);
    return result;
}

//--------------------------------------------------------------------------------------------------
/**
 * Function which read the initial sub system id
 *
 * @return
 *      - LE_OK            On success
 *      - LE_FAULT         On failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_fwupdate_GetInitialSubSystemId
(
    uint8_t *initialSSId ///< [OUT] if LE_OK, the current boot system
)
{
    if (initialSSId == NULL)
    {
        LE_ERROR("initialSSId null pointer");
        return LE_FAULT;
    }

    *initialSSId = GetInitialBootSystem() + 1; /* add 1 since GetInitialBootSystem returns 0 or 1 */

    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * This function must be called to initialize the FW UPDATE module.
 */
//--------------------------------------------------------------------------------------------------
COMPONENT_INIT
{
    /* Allocate a pool for the data chunk */
    ChunkPool = le_mem_CreatePool("ChunkPool", CHUNK_LENGTH);
    le_mem_ExpandPool(ChunkPool, 1);

    int mtdNum;
    pa_fwupdate_MtdInfo_t mtdInfo;

    /* Get MTD information from SBL partition. This is will be used to fix the
       pool object size and compute the max object size */
    mtdNum = GetMtdFromImageType( CWE_IMAGE_TYPE_SBL1, 1, &MtdNamePtr, &mtdInfo );
    LE_FATAL_IF(-1 == mtdNum, "Unable to find a valid mtd for SBL image\n");

    /* Allocate a pool for the SBL image */
    SBLImgPool = le_mem_CreatePool("SBLImgagePool",
                                   (mtdInfo.nbBlk / 2) * mtdInfo.eraseSize);
    le_mem_ExpandPool(SBLImgPool, 1);
}

