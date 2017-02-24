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
#include "pa_flash.h"
#include "pa_fwupdate.h"
#include "pa_fwupdate_dualsys.h"
#include "interfaces.h"
#include <sys/reboot.h>
#include <linux/reboot.h>
#include <sys/select.h>


// SBL number of passes needed to flash low/high and high/low SBL scrub
#define SBL_MAX_PASS              2

// PBL is looking for SBL signature in the first 2MB of the flash device
// Should avoid to put SBL outside this
#define SBL_MAX_BASE_IN_FIRST_2MB  (2*1024*1024)

// Default timeout
#define DEFAULT_TIMEOUT     900

// Timeout for select(): Set to timeout in seconds to give time for connection
// through fd
#define SET_SELECT_TIMEOUT(tv, timeout) \
        do { \
            (tv)->tv_sec = timeout; \
            (tv)->tv_usec = 0; \
        } while (0)

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
 * Read offset of the fulle CWE image Length
 */
//--------------------------------------------------------------------------------------------------
static size_t FullImageLength = -1;

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
 * Boolean to know if a NVUP file(s) has been downloaded
 */
//--------------------------------------------------------------------------------------------------
static bool IsFirstNvupDownloaded;

//--------------------------------------------------------------------------------------------------
/**
 * Boolean to know if a modem partition has been downloaded
 */
//--------------------------------------------------------------------------------------------------
static bool IsModemDownloaded;

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
static const char ImageString [CWE_IMAGE_TYPE_COUNT][sizeof(uint32_t)] =
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
 * Memory Pool for SBL temporary image pointers to SBL blocks
 */
//--------------------------------------------------------------------------------------------------
static le_mem_PoolRef_t   SblBlockPool;

//--------------------------------------------------------------------------------------------------
/**
 * Memory Pool for SBL temporary image blocks
 */
//--------------------------------------------------------------------------------------------------
static le_mem_PoolRef_t   FlashImgPool;

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
static const unsigned char pa_fwupdate_SBLPreamble[8] = {
    0xd1, 0xdc, 0x4b, 0x84,
    0x34, 0x10, 0xd7, 0x73,
};


//--------------------------------------------------------------------------------------------------
/**
 * Partition Name and Image Type matrix
 */
//--------------------------------------------------------------------------------------------------
static char* pa_fwupdate_PartNamePtr[2][ CWE_IMAGE_TYPE_COUNT ] = {
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


//--------------------------------------------------------------------------------------------------
/**
 * Cwe Header in raw format (before decoding). Used for NVUP.
 */
//--------------------------------------------------------------------------------------------------
static uint8_t CweHeaderRaw[HEADER_SIZE];

//==================================================================================================
//                                       Private Functions
//==================================================================================================
//--------------------------------------------------------------------------------------------------

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
    uint8_t* addressPtr,///< [IN] Input buffer
    uint32_t size,      ///< [IN] Number of bytes to read
    uint32_t crc        ///< [IN] Starting CRC seed
)
{
    for (; size > 0 ; size--)
    {
        //-- byte loop */
        crc = (((crc >> 8) & 0x00FFFFFF) ^ Crc32Table[(crc ^ *addressPtr++) & 0x000000FF]);
    }
    return crc;
}

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
    if( NULL == (flashFdPtr = fopen( "/sys/class/ubi/ubi0/mtd_num", "r" )) )
    {
        LE_ERROR( "Unable to determine ubi0 mtd device: %m\n" );
        le_result = LE_FAULT;
        goto end;
    }
    // Read the MTD number
    if( 1 != fscanf( flashFdPtr, "%d", mtdNumPtr ) )
    {
        LE_ERROR( "Unable to determine ubi0 mtd device: %m\n" );
        le_result = LE_FAULT;
    }
    else
    {
        LE_DEBUG( "GetInitialBootSystemByUbi: %d\n", *mtdNumPtr );
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
    int mtdNum,                             ///< [IN] the MTD number
    char** mtdNamePtr,                      ///< [OUT] the partition name
    pa_fwupdate_ImageType_t* imageTypePtr   ///< [OUT] the partition type
)
{
    FILE* flashFdPtr;
    char mtdBuf[100], mtdFetchName[16];
    int partIndex, partSystem;

    // Open the partition name belonging the given MTD number
    snprintf( mtdBuf, sizeof(mtdBuf), "/sys/class/mtd/mtd%d/name", mtdNum );
    if( NULL == (flashFdPtr = fopen( mtdBuf, "r" )) )
    {
        LE_ERROR( "Unable to open %s: %m\n", mtdBuf );
        return LE_FAULT;
    }
    // Try to read the partition name
    if( 1 != fscanf( flashFdPtr, "%15s", mtdFetchName ))
    {
        LE_ERROR( "Unable to read mtd partition name %s: %m\n", mtdFetchName );
        fclose( flashFdPtr );
        return LE_FAULT;
    }
    fclose( flashFdPtr );
    // Look for the image type into the both system matrix
    mtdFetchName[strlen(mtdFetchName)] = '\0';
    for( partSystem = 0; partSystem < 2; partSystem++ )
        for( partIndex = CWE_IMAGE_TYPE_MIN; partIndex < CWE_IMAGE_TYPE_COUNT; partIndex++ )
            if( pa_fwupdate_PartNamePtr[ partSystem ][ partIndex ] &&
                (0 == strcmp( mtdFetchName, pa_fwupdate_PartNamePtr[ partSystem ][ partIndex ])) )
            {
                // Found: output partition name and return image type
                *mtdNamePtr = pa_fwupdate_PartNamePtr[ partSystem ][ partIndex ];
                *imageTypePtr = partIndex;
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
    pa_fwupdate_ImageType_t partName, ///< [IN] Partition enumerate to get
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

    *mtdNamePtr = NULL;
    // Valid image type
    if( partName > CWE_IMAGE_TYPE_MAX )
        return -1;
    // Active system bank
    if( -1 == (iniBootSystem = GetInitialBootSystem()) )
        return -1;
    // Dual system bank
    dualBootSystem = (iniBootSystem ? 0 : 1);

    mtdPartNamePtr = pa_fwupdate_PartNamePtr[ inDual ? dualBootSystem : iniBootSystem ][ partName ];
    // If NULL, the partition (even if it exists) is not managed by fwupdate component
    if( !mtdPartNamePtr )
        return -1;

    // Build the partition name to fetch into the /proc/mtd
    snprintf( mtdFetchName, sizeof(mtdFetchName), "\"%s\"", mtdPartNamePtr );
    l = strlen( mtdFetchName );

    // Open the /proc/mtd partition
    if( NULL == (flashFdPtr = fopen( "/proc/mtd", "r" )) )
    {
        LE_ERROR( "fopen on /proc/mtd failed: %m" );
        return -1;
    }

    // Read all entries until the partition names match
    while( fgets(mtdBuf, sizeof(mtdBuf), flashFdPtr ) )
    {
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
                *mtdNamePtr = mtdPartNamePtr;
                LE_DEBUG( "Partition %s is mtd%d\n", *mtdNamePtr, mtdNum );
            }
            break;
        }
    }
    fclose( flashFdPtr );

    if( isLogical )
    {
        *isLogical = ((partName == CWE_IMAGE_TYPE_QRPM) ||
                      (partName == CWE_IMAGE_TYPE_TZON)) ? true : false;
    }
    if( isDual )
    {
        *isDual = (inDual ? dualBootSystem : iniBootSystem) ? true : false;
    }

    // Return the MTD number
    return mtdNum;
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
static le_result_t CheckData
(
    int mtdNum,                        ///< [IN] Minor of the MTD device to check
    bool isLogical,                    ///< [IN] true if the partition is logical (TZ or RPM)
    bool isDual,                       ///< [IN] true if the upper partition is concerned (TZ2 or
                                       ///<      RPM2), false in case of lower partition
    size_t sizeToCheck,                ///< [IN] Size to be used to compute the CRC
    off_t atOffset,                    ///< [IN] Force offset to start from
    uint32_t crc32ToCheck              ///< [IN] Expected CRC 32
)
{
    pa_flash_Desc_t flashFd = NULL;
    uint8_t* checkBlockPtr = NULL;

    size_t size, imageSize = 0;
    off_t offset = atOffset;
    uint32_t crc32 = START_CRC32;
    pa_flash_Info_t* flashInfoPtr;
    pa_flash_OpenMode_t mode = PA_FLASH_OPENMODE_READONLY;

    if( isLogical )
    {
        mode |= ((isDual) ? PA_FLASH_OPENMODE_LOGICAL_DUAL
                          : PA_FLASH_OPENMODE_LOGICAL);
    }

    LE_DEBUG( "Size=%08x, Crc32=%08x", sizeToCheck, crc32ToCheck);

    checkBlockPtr = (uint8_t *) le_mem_ForceAlloc(FlashImgPool);

    if (LE_OK != pa_flash_Open( mtdNum, mode, &flashFd, &flashInfoPtr ))
    {
        LE_ERROR("Open of MTD %d fails: %m\n", mtdNum );
        goto error;
    }
    if (LE_OK != pa_flash_Scan( flashFd, NULL ))
    {
        LE_ERROR("Scan of MTD %d fails: %m\n", mtdNum );
        goto error;
    }

    while ((imageSize < sizeToCheck) &&
           (offset < (flashInfoPtr->nbLeb * flashInfoPtr->eraseSize)))
    {
        loff_t blkOff = (loff_t)offset;

        size = (((imageSize + flashInfoPtr->eraseSize) < sizeToCheck)
                   ? flashInfoPtr->eraseSize
                   : (sizeToCheck - imageSize));
        LE_DEBUG("Read %x at offset %lx, block offset %llx", size, offset, blkOff);
        if (LE_OK != pa_flash_ReadAtBlock( flashFd,
                                              ((off_t)blkOff / flashInfoPtr->eraseSize),
                                              checkBlockPtr,
                                              size))
        {
            LE_ERROR("read fails for offset %llx: %m", blkOff);
            goto error;
        }

        crc32 = Crc32( checkBlockPtr, (uint32_t)size, crc32);
        offset += size;
        imageSize += size;
    }
    if (crc32 != crc32ToCheck)
    {
        LE_CRIT( "Bad CRC32 calculated on mtd%d: read %08x != expected %08x",
                 mtdNum, crc32, crc32ToCheck );
        goto error;
    }

    LE_INFO("CRC32 OK for mtd%d\n", mtdNum );

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
static le_result_t WriteDataSBL
(
    pa_fwupdate_ImageFormat_t format,   ///< [IN] Component image format linked to data
    pa_fwupdate_CweHeader_t* hdrPtr,    ///< [IN] Component image header
    size_t* lengthPtr,                  ///< [IN] Input data length
    size_t offset,                      ///< [IN] Data offset in the package
    uint8_t* dataPtr,                   ///< [IN] intput data
    bool *isFlashed                     ///< [OUT] true if flash write was done
)
{
    int mtdNum;
    pa_flash_Info_t flashInfo;
    le_result_t res = LE_OK;
    int sblNbBlk, sblMaxBlk, sblIdxBlk;
    pa_flash_Desc_t flashFd = NULL;
    size_t lengthToCopy;
    size_t lengthCopied;
    off_t offsetToCopy;

    mtdNum = GetMtdFromImageType( hdrPtr->imageType, 1, &MtdNamePtr, NULL, NULL );

    LE_DEBUG("Format %d image type %d len %d offset %d",
             format, hdrPtr->imageType, *lengthPtr, offset);

    if( -1 == mtdNum )
    {
        LE_ERROR( "Unable to find a valid mtd for image type %d\n", hdrPtr->imageType );
        return LE_FAULT;
    }

    if( LE_OK != pa_flash_GetInfo( mtdNum, &flashInfo, false, false ) )
    {
        LE_ERROR( "Open MTD fails for MTD %d\n", mtdNum );
        return LE_FAULT;
    }
    if( isFlashed )
    {
        *isFlashed = false;
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

    if (ImageSize == 0)
    {
        LE_INFO ("Writing \"%s\" (mtd%d) from CWE image %d, size %d\n",
                 MtdNamePtr, mtdNum, hdrPtr->imageType, hdrPtr->imageSize );

        // Allocate a block to store the SBL temporary image
        ImageSize = hdrPtr->imageSize;
        RawImagePtr = (uint8_t **) le_mem_ForceAlloc(SblBlockPool);
        memset(RawImagePtr, 0, sizeof(uint8_t*) * (flashInfo.nbBlk / 2));
    }

    // Check that the chunck is inside the SBL temporary image
    if ((offset + *lengthPtr) > ImageSize)
    {
        LE_ERROR("SBL image size and offset/length mismatch: %u < %u+%u",
                 ImageSize, offset, *lengthPtr);
        goto error;
    }

    lengthToCopy = *lengthPtr;
    lengthCopied = 0;
    offsetToCopy = offset;

    do
    {
        // Compute on what block the offsetToCopy belongs
        sblIdxBlk = (offsetToCopy / flashInfo.eraseSize);
        offsetToCopy = (offsetToCopy & (flashInfo.eraseSize - 1));
        if (RawImagePtr[sblIdxBlk] == NULL)
        {
            RawImagePtr[sblIdxBlk] = (uint8_t *) le_mem_ForceAlloc(FlashImgPool);
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
        lengthToCopy = (*lengthPtr - lengthCopied);
    }
    while( lengthToCopy );

    if ((*lengthPtr + offset) >= ImageSize )
    {
        int sblBlk; // Base of SBL first block
        int nbBadBlk; // Number of BAD blocks inside the half partition
        int sblBaseBlk; // Base block where the SBL will be flashed
        int atBlk = -1;
        int atMaxBlk = -1;
        int atOffset = -1;
        int pass = 0;

        if( LE_OK != pa_flash_Open( mtdNum,
                                    PA_FLASH_OPENMODE_READWRITE | PA_FLASH_OPENMODE_MARKBAD,
                                    &flashFd,
                                    NULL ) )
        {
            LE_ERROR( "Open MTD fails for MTD %d\n", mtdNum );
            return LE_FAULT;
        }

        /* Fetch if a valid SBL exists and get its first block */
        for (sblBlk = 0; sblBlk <= sblMaxBlk; sblBlk++ )
        {
            unsigned char sbl[sizeof(pa_fwupdate_SBLPreamble)];

            if (LE_OK != pa_flash_ReadAtBlock( flashFd, sblBlk, sbl, sizeof(sbl)))
            {
                LE_ERROR("Read of SBL at sector %d fails: %m", sblBlk );
                goto error;
            }
            if (0 == memcmp( sbl, pa_fwupdate_SBLPreamble, sizeof(sbl) ))
            {
                LE_INFO("SBL base found at block %d\n", sblBlk );
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
        LE_INFO("Flashing SBL scrub: Size %d, base %d, nbblk %d\n",
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

                if( LE_OK != pa_flash_CheckBadBlock( flashFd, atBlk, &isBad ) )
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
                if( LE_OK != pa_flash_EraseBlock( flashFd, atBlk ) )
                {
                    LE_ERROR("pa_flash_EraseBlock fails for block %d, offset %lld: %m",
                             atBlk, blkOff);
                    goto error;
                }
            }

            // Not enougth block to flash the SBL
            if ((sblBaseBlk == -1) ||
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

            if( LE_OK != pa_flash_SeekAtOffset( flashFd, atOffset ) )
            {
                LE_CRIT("pa_flash_SeekAtOffset fails for block %d, offset %d: %m",
                         atBlk, atOffset);
                goto critical;
            }
            writeSize = ((((sblNbBlk > 1) ? flashInfo.eraseSize : ImageSize)
                          - flashInfo.writeSize)
                         + (flashInfo.writeSize - 1)) &
                        ~(flashInfo.writeSize - 1);
            if( LE_OK != pa_flash_Write( flashFd,
                                         (RawImagePtr[0] + flashInfo.writeSize),
                                         writeSize ) )
            {
                LE_ERROR("(%d)pa_flash_Write fails: %m\n", pass);
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
                    LE_ERROR("(%d)pa_flash_Write: %m\n", pass);
                    goto critical;
                }
            }

            atOffset = sblBaseBlk * flashInfo.eraseSize;
            if( LE_OK != pa_flash_SeekAtOffset( flashFd, atOffset ) )
            {
                LE_CRIT("pa_flash_SeekAtOffset fails for block %d, offset %d: %m",
                         atBlk, atOffset);
                goto critical;
            }
            if( LE_OK != pa_flash_Write( flashFd, RawImagePtr[0], flashInfo.writeSize) )
            {
                LE_ERROR("(%d)pa_flash_Write fails: %m\n", pass);
                goto critical;
            }

            if (LE_OK != CheckData( mtdNum,
                                    0,
                                    0,
                                    ImageSize,
                                    (atOffset < (flashInfo.nbBlk / 2)
                                        ? 0
                                        : (flashInfo.nbBlk / 2)) * flashInfo.eraseSize,
                                    hdrPtr->crc32 ))
            {
                LE_CRIT("SBL flash failed at block %d. Erasing...", sblBaseBlk);
                for( atBlk = 0; atBlk < (flashInfo.nbBlk / 2); atBlk++ )
                {
                    pa_flash_EraseBlock( flashFd, atBlk + (atOffset / flashInfo.eraseSize) );
                }
                goto critical;
            }

            // Do low and high or high and low: 2 passes
        } while (++pass < SBL_MAX_PASS);

        atOffset = (sblBlk ? 0 : flashInfo.nbBlk / 2) * flashInfo.eraseSize;
        for( atBlk = 0; atBlk < flashInfo.nbBlk / 2; atBlk++ )
        {
            pa_flash_EraseBlock( flashFd, atBlk + (sblBlk ? 0 : flashInfo.nbBlk / 2) );
        }

        pa_flash_Close(flashFd);

        if( isFlashed )
        {
            *isFlashed = true;
        }
        for (sblIdxBlk = 0; (sblIdxBlk < sblNbBlk) && RawImagePtr[sblIdxBlk]; sblIdxBlk++)
        {
            le_mem_Release(RawImagePtr[sblIdxBlk]);
        }
        le_mem_Release(RawImagePtr);
        RawImagePtr = NULL;
        ImageSize = 0;
        LE_INFO("Update for partiton %s done with return %d\n",
                MtdNamePtr, res);
        MtdNamePtr = NULL;
    }

    return res;

critical:
    // The SBL may be partially updated or corrupted
    LE_CRIT("SBL is not updated correctly");
error:
    if (flashFd)
    {
        pa_flash_Close(flashFd);
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
    LE_ERROR("Update for partiton %s failed with return %d\n",
             MtdNamePtr, LE_FAULT);
    MtdNamePtr = NULL;
    return LE_FAULT;
}

//--------------------------------------------------------------------------------------------------
/**
 * Write NVUP files in backup partition by calling QMI commands
 *
 * @return
 *      - LE_OK on success
 *      - LE_FAULT on failure
 */
//--------------------------------------------------------------------------------------------------
static le_result_t WriteNvup
(
    pa_fwupdate_CweHeader_t* hdrPtr,    ///< [IN] Component image header
    size_t* lengthPtr,                  ///< [IN] Input data length
    size_t offset,                      ///< [IN] Data offset in the package
    uint8_t* dataPtr,                   ///< [IN] intput data
    bool *isFlashed                     ///< [OUT] true if flash write was done
)
{
    le_result_t result;
    bool isEnd;

    LE_INFO("Writing NVUP file ...");
    LE_DEBUG("length=%d offset=%d", *lengthPtr, offset);

    if (IsFirstNvupDownloaded == false)
    {
        /* first NVUP file => ask to delete NVUP files */
        result = pa_fwupdate_NvupDelete();
        if (result != LE_OK)
        {
            LE_ERROR("NVUP delete has failed");
            return LE_FAULT;
        }
        IsFirstNvupDownloaded = true;
    }

    if ((ImageSize == 0) && (offset == 0))
    {
        // write the CWE header
        result = pa_fwupdate_NvupWrite(HEADER_SIZE, CweHeaderRaw, false);
        if (result != LE_OK)
        {
            LE_ERROR("Failed to write NVUP CWE header!\n");
            return LE_FAULT;
        }

        // initialize data phase
        ImageSize = hdrPtr->imageSize;
        LE_DEBUG("ImageSize=%d", ImageSize);
    }

    isEnd = (*lengthPtr + offset >= ImageSize) ? true : false;
    LE_DEBUG("isEnd=%d", isEnd);

    result = pa_fwupdate_NvupWrite(*lengthPtr, dataPtr, isEnd);
    if( isFlashed )
    {
        *isFlashed = (isEnd && (LE_OK == result) ? true : false);
    }

    if (isEnd)
    {
        ImageSize = 0;
    }
    return result;
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
    pa_fwupdate_CweHeader_t* hdrPtr,    ///< [IN] Component image header
    size_t *lengthPtr,                  ///< [IN] Input data length
    size_t offset,                      ///< [IN] Data offset in the package
    uint8_t* dataPtr,                   ///< [IN] intput data
    bool *isFlashed                     ///< [OUT] true if flash write was done
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

    LE_DEBUG ("Format %d image type %d len %d offset %d",
              format, hdrPtr->imageType, *lengthPtr, offset);

    if( isFlashed )
    {
        *isFlashed = false;
    }

    /* image type "FILE" must be considered as NVUP file */
    if (hdrPtr->imageType == CWE_IMAGE_TYPE_FILE)
    {
        return WriteNvup(hdrPtr, lengthPtr, offset, dataPtr, isFlashed);
    }

    if (hdrPtr->imageType == CWE_IMAGE_TYPE_SBL1 )
    {
        // SBL is managed by a specific flash scheme
        return WriteDataSBL( format, hdrPtr, lengthPtr, offset, dataPtr, isFlashed );
    }

    if ((0 == offset) && (NULL == MtdFd) && (0 == ImageSize) )
    {
        int iblk;
        le_result_t res;

        mtdNum = GetMtdFromImageType( hdrPtr->imageType, 1, &MtdNamePtr, &isLogical, &isDual );

        if( -1 == mtdNum )
        {
            LE_ERROR( "Unable to find a valid mtd for image type %d\n", hdrPtr->imageType );
            return LE_FAULT;
        }
        LE_INFO ("Writing \"%s\" (mtd%d) from CWE image %d\n",
                 MtdNamePtr, mtdNum, hdrPtr->imageType );

        if(LE_OK != pa_flash_Open( mtdNum,
                             PA_FLASH_OPENMODE_WRITEONLY | PA_FLASH_OPENMODE_MARKBAD |
                                 (isLogical
                                     ? (isDual ? PA_FLASH_OPENMODE_LOGICAL_DUAL
                                               : PA_FLASH_OPENMODE_LOGICAL)
                                     : 0),
                             &MtdFd,
                             &FlashInfoPtr ))
        {
            LE_ERROR("Fails to open MTD %d\n", mtdNum );
            return LE_FAULT;
        }
        if( LE_OK != pa_flash_Scan( MtdFd, NULL ) )
        {
            LE_ERROR("Fails to scan MTD\n");
            goto error;
        }
        for( iblk = 0; iblk < FlashInfoPtr->nbLeb; iblk++ )
        {
            bool isBad;

            if( (LE_OK != (res = pa_flash_CheckBadBlock( MtdFd, iblk, &isBad )))
                && (res != LE_NOT_PERMITTED) )
            {
                LE_ERROR("Fails to check bad block %d\n", iblk);
                goto error;
            }
            if( isBad )
            {
                LE_WARN("Skipping bad block %d\n", iblk);
            }
            else
            {
                res = pa_flash_EraseBlock( MtdFd, iblk );
                if( (LE_OK != res) && (res != LE_NOT_PERMITTED) )
                {
                    LE_ERROR("Fails to erase block %d: res=%d\n", iblk, res);
                    goto error;
                }
            }
        }
        if( LE_OK != pa_flash_SeekAtBlock( MtdFd, 0 ) )
        {
            LE_ERROR("Fails to seek block at %d\n", iblk);
            goto error;
        }
        DataPtr = le_mem_ForceAlloc(FlashImgPool);
        InOffset = 0;
        ImageSize = hdrPtr->imageSize;
    }

    if( ((uint32_t)(*lengthPtr + InOffset)) > FlashInfoPtr->eraseSize )
    {
        memcpy( DataPtr, dataPtr, FlashInfoPtr->eraseSize - InOffset );
        if( LE_OK != pa_flash_Write( MtdFd, DataPtr, FlashInfoPtr->eraseSize ) )
        {
            LE_ERROR( "fwrite to nandwrite fails: %m\n" );
            goto error;
        }
        if( isFlashed )
        {
            *isFlashed = true;
        }
        memcpy( DataPtr, dataPtr, *lengthPtr - (FlashInfoPtr->eraseSize - InOffset) );
        InOffset = *lengthPtr - (FlashInfoPtr->eraseSize - InOffset);
    }
    else
    {
        memcpy( DataPtr + InOffset, dataPtr, *lengthPtr );
        InOffset += *lengthPtr;
    }

    if ((*lengthPtr + offset) >= ImageSize )
    {
        if(InOffset)
        {
            if( InOffset <= FlashInfoPtr->eraseSize )
            {
                memset( DataPtr + InOffset,
                        PA_FLASH_ERASED_VALUE,
                        FlashInfoPtr->eraseSize - InOffset );
            }
            if( LE_OK != pa_flash_Write( MtdFd, DataPtr, FlashInfoPtr->eraseSize ))
            {
                LE_ERROR( "fwrite to nandwrite fails: %m\n" );
                goto error;
            }
            if( isFlashed )
            {
                *isFlashed = true;
            }
        }
        le_mem_Release(DataPtr);
        DataPtr = NULL;
        InOffset = 0;
        pa_flash_Close( MtdFd );
        MtdFd = NULL;
        ImageSize = 0;
        LE_INFO( "Update for partiton %s done with return %d\n", MtdNamePtr, ret );
        MtdNamePtr = NULL;

        mtdNum = GetMtdFromImageType( hdrPtr->imageType, 1, &MtdNamePtr, &isLogical, &isDual );
        if( -1 == mtdNum )
        {
            LE_ERROR( "Unable to find a valid mtd for image type %d\n", hdrPtr->imageType );
            return LE_FAULT;
        }

        ret = CheckData( mtdNum, isLogical, isDual, hdrPtr->imageSize, 0, hdrPtr->crc32 );
    }
    return ret;
error:
    InOffset = 0;
    if( MtdFd )
    {
        pa_flash_Close( MtdFd );
        MtdFd = NULL;
    }
    ImageSize = 0;
    MtdNamePtr = NULL;
    if(DataPtr)
    {
        le_mem_Release(DataPtr);
        DataPtr = NULL;
    }
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
    IsFirstNvupDownloaded = false;
    IsModemDownloaded = false;
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
    pa_fwupdate_ImageType_t imageType   ///< [IN] CWE Image Type to convert
)
{
    uint32_t imageVal = CWE_IMAGE_TYPE_COUNT;

    if (imageType < CWE_IMAGE_TYPE_COUNT)
    {
        imageVal = (ImageString[imageType][0] << 24) |
                   (ImageString[imageType][1] << 16) |
                   (ImageString[imageType][2] <<  8) |
                    ImageString[imageType][3];
    }

    return imageVal;
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
    uint32_t imageType,                     ///< [IN] image type for validation
    pa_fwupdate_ImageType_t* enumValuePtr   ///< [OUT] enum value for image type
)
{
    bool retVal = true;
    pa_fwupdate_ImageType_t idx;
    uint32_t imageVal;

    LE_DEBUG ("imagetype 0x%x", imageType);

    for (idx = CWE_IMAGE_TYPE_MIN; idx < CWE_IMAGE_TYPE_COUNT; idx++)
    {
        imageVal = ImageValueGet(idx);
        if (imageVal == imageType)
        {
            break;
        }
    }

    /* save found index */
    *enumValuePtr = idx;

    if (idx == CWE_IMAGE_TYPE_COUNT)
    {
        /* imagetype not found */
        retVal = false;
    }

    LE_DEBUG ("retVal %d --> image type %d", retVal, *enumValuePtr);

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
    uint8_t** packetPtrPtr ///< [IN] memory location of the pointer to the packet from which the 32 bit
                           ///< value will be read
)
{
    uint32_t field;
    uint8_t* packetPtr;

    packetPtr = *packetPtrPtr;

    field = *packetPtr++;
    field <<= 8;
    field += *packetPtr++;
    field <<= 8;
    field += *packetPtr++;
    field <<= 8;
    field += *packetPtr++;
    *packetPtrPtr = packetPtr;

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
    uint8_t** packetPtrPtr, ///< [IN] memory location of a pointer to a packet from which the string of
                            ///< 8-bit fields is to be read
    uint8_t* bufferPtr,     ///< [OUT] pointer to a buffer into which the 8-bit fields are to be copied
    uint16_t numfields      ///< [IN] number of 8-bit fields to be copied
)
{
    uint8_t* packetPtr;
    int32_t i;

    packetPtr = *packetPtrPtr;

    for (i = numfields - 1; i >= 0; i--)
    {
        *bufferPtr++ = *packetPtr++;
    }

    *packetPtrPtr = packetPtr;
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
        if ((CurrentCweHeader.imageSize - CurrentImageOffset) > CHUNK_LENGTH)
        {
            readCount = CHUNK_LENGTH;
        }
        else
        {
            readCount = CurrentCweHeader.imageSize - CurrentImageOffset;
        }
    }
    LE_DEBUG("readCount=%d", readCount);
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
    uint8_t* startPtr,              ///< [IN] start address of the CWE header to be read
    pa_fwupdate_CweHeader_t* hdpPtr ///< [OUT] pointer to a CWE header structure
)
{
    le_result_t result = LE_NOT_POSSIBLE;

    if ((startPtr == NULL) || (hdpPtr == NULL))
    {
        result = LE_BAD_PARAMETER;
    }
    else
    {
        uint8_t* bufPtr;
        pa_fwupdate_ImageType_t imagetype;

        /* init the buf pointer */
        bufPtr = startPtr;

        /* read in the required number of bytes from product specific buffer */
        TranslateNetworkByteOrderMulti (&bufPtr, ( uint8_t*) hdpPtr->PSB, sizeof(hdpPtr->PSB));

        /* Get the Header Version: Set our pointer to the header revision number first */
        bufPtr = startPtr + HDR_REV_NUM_OFST;

        /* Read the header version number */
        hdpPtr->hdrRevNum = TranslateNetworkByteOrder(&bufPtr);
        LE_DEBUG ("hdpPtr->hdrRevNum %d", hdpPtr->hdrRevNum);

        /* Continue reading the buffer from the Image Type Offset field */
        bufPtr = startPtr + IMAGE_TYPE_OFST;

        /* get the image type */
        hdpPtr->imageType = TranslateNetworkByteOrder(&bufPtr);
        LE_DEBUG ("ImageType 0x%x", hdpPtr->imageType);

        if (hdpPtr->hdrRevNum >= HDRCURVER)
        {
            /* validate image type */
            if (ImageTypeValidate(hdpPtr->imageType, &imagetype))
            {
                hdpPtr->imageType = imagetype;
                LE_DEBUG ("ImageType %d", hdpPtr->imageType);
                /* get product type */
                hdpPtr->prodType = TranslateNetworkByteOrder(&bufPtr);
                LE_DEBUG ("ProdType 0x%x", hdpPtr->prodType);

                /* get application image size */
                hdpPtr->imageSize = TranslateNetworkByteOrder(&bufPtr);
                LE_DEBUG ("ImageSize %d 0x%x", hdpPtr->imageSize, hdpPtr->imageSize);

                /* get CRC32 of application */
                hdpPtr->crc32 = TranslateNetworkByteOrder(&bufPtr);
                LE_DEBUG ("CRC32 0x%x", hdpPtr->crc32);

                /* get version string */
                TranslateNetworkByteOrderMulti(&bufPtr, hdpPtr->version, HVERSTRSIZE);
                LE_DEBUG ("Version %s", hdpPtr->version);
                /* get date string */
                TranslateNetworkByteOrderMulti(&bufPtr, hdpPtr->relDate, HDATESIZE);

                /* get backwards compatibilty field */
                hdpPtr->compat = TranslateNetworkByteOrder(&bufPtr);

                /* get the misc options */
                hdpPtr->miscOpts = *bufPtr;
                LE_DEBUG ("HeaderLoad: hdpPtr->miscOpts %d", hdpPtr->miscOpts);

                /* get the load address and entry point based upon the header version. */
                bufPtr=startPtr+STOR_ADDR_OFST;
                hdpPtr->storAddr  = (uint32_t)(*bufPtr++);
                hdpPtr->storAddr |= (uint32_t)(*bufPtr++ << 8);
                hdpPtr->storAddr |= (uint32_t)(*bufPtr++ << 16);
                hdpPtr->storAddr |= (uint32_t)(*bufPtr++ << 24);

                bufPtr=startPtr+PROG_ADDR_OFST;
                hdpPtr->progAddr  = (uint32_t)(*bufPtr++);
                hdpPtr->progAddr |= (uint32_t)(*bufPtr++ << 8);
                hdpPtr->progAddr |= (uint32_t)(*bufPtr++ << 16);
                hdpPtr->progAddr |= (uint32_t)(*bufPtr++ << 24);

                bufPtr=startPtr+ENTRY_OFST;
                hdpPtr->entry     = (uint32_t)(*bufPtr++);
                hdpPtr->entry    |= (uint32_t)(*bufPtr++ << 8);
                hdpPtr->entry    |= (uint32_t)(*bufPtr++ << 16);
                hdpPtr->entry    |= (uint32_t)(*bufPtr++ << 24);

                /* get signature */
                hdpPtr->signature = TranslateNetworkByteOrder(&bufPtr);

                /* get product specific buffer CRC value */
                bufPtr = startPtr + CRC_PROD_BUF_OFST;
                hdpPtr->crcProdBuf = TranslateNetworkByteOrder(&bufPtr);

                /* get CRC valid indicator value */
                bufPtr = startPtr + CRC_INDICATOR_OFST;
                hdpPtr->crcIndicator = TranslateNetworkByteOrder(&bufPtr);

                /* Only check the signature field for application imagetypes (not for
                 * bootloader) since we always want to return false for bootloader
                 * imagetypes. */
                if (imagetype == CWE_IMAGE_TYPE_APPL)
                {
                    /* check application signature */
                    if (hdpPtr->signature != APPSIGN)
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
            LE_ERROR ("bad header version %d", hdpPtr->hdrRevNum);
            result = LE_FAULT;
        }

        /* The CWE header was well loaded.
         * Now make some checks
         */
        if (result == LE_OK)
        {
            /* The image type was already checked in le_fwupdate_HeaderLoad */

            /* Validate product ID */
            if (hdpPtr->prodType != PA_FWUPDATE_PRODUCT_ID)
            {
                LE_ERROR ("Bad Product Id in the header");
                result = LE_FAULT;
            }

            /* Check that the image is not a compressed one:
             * not supported on this platform
             */
            if ((hdpPtr->miscOpts & MISC_OPTS_COMPRESS) == MISC_OPTS_COMPRESS)
            {
                LE_ERROR( "Compressed image is not supported");
                result = LE_FAULT;
            }

            /* validate PSB CRC */
            if (Crc32(startPtr, CRC_PROD_BUF_OFST, START_CRC32) != hdpPtr->crcProdBuf)
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
    size_t offset,     ///< [IN] Data offset in the package
    size_t length,     ///< [IN] Input data lentg
    uint8_t* chunkPtr  ///< [IN] intput data
)
{
    le_result_t result = LE_OK;
    LE_DEBUG ("start");
    if ((chunkPtr == NULL) || (length > CHUNK_LENGTH))
    {
        result = LE_BAD_PARAMETER;
    }
    else
    {
        size_t Return = 0;
        LE_DEBUG ("parsing a chunkPtr: len %zd, IsImageToBeRead %d",
                    length, IsImageToBeRead);

        /* Check if a header is read or a component image */
        if (IsImageToBeRead == false)
        {
            /* For a header, the full header shall be provided */
            if (length == HEADER_SIZE)
            {
                result = HeaderLoad (chunkPtr, &CurrentCweHeader);
                if (result != LE_OK)
                {
                    LE_ERROR ("Error in parsing the CWE header");
                    result = LE_FAULT;
                }
                else
                {
                    LE_DEBUG ("CWE header read ok");
                    if (-1 == FullImageLength)
                    {
                        /*
                         * Full length of the CWE image is provided inside the
                         * first CWE header
                         */
                        FullImageLength = CurrentCweHeader.imageSize + HEADER_SIZE;
                        LE_DEBUG("New CWE: FullImageLength = %u", FullImageLength);
                    }
                    /* Check the value of the CurrentCweHeader.imageType which is proceed
                     * If the image type is a composite one, the next data is a CWE header
                     */
                    if ((CurrentCweHeader.imageType != CWE_IMAGE_TYPE_APPL)
                     && (CurrentCweHeader.imageType != CWE_IMAGE_TYPE_MODM)
                     && (CurrentCweHeader.imageType != CWE_IMAGE_TYPE_SPKG)
                     && (CurrentCweHeader.imageType != CWE_IMAGE_TYPE_BOOT))
                    {
                        /* Next data will concern a component image */
                        IsImageToBeRead = true;
                    }
                    if (CurrentCweHeader.imageType == CWE_IMAGE_TYPE_FILE)
                    {
                        memcpy(CweHeaderRaw, chunkPtr, HEADER_SIZE);
                    }
                    if (CurrentCweHeader.imageType == CWE_IMAGE_TYPE_MODM)
                    {
                        IsModemDownloaded = true;
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
                                            chunkPtr,
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
    int idx;
    pa_flash_Desc_t flashFdSrc = NULL, flashFdDst = NULL;
    pa_flash_Info_t *flashInfoSrcPtr, *flashInfoDstPtr;
    char* mtdSrcNamePtr;
    char* mtdDstNamePtr;
    uint8_t* flashBlockPtr = NULL;
    uint32_t crc32Src;
    bool isLogicalSrc, isLogicalDst, isDualSrc, isDualDst;

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

    flashBlockPtr = (uint8_t *) le_mem_ForceAlloc(FlashImgPool);

    LE_INFO( "Synchronizing from system %d to system %d\n", iniBootSystem + 1, dualBootSystem + 1);
    for( idx = 0; idx < sizeof( syncPartition )/sizeof(pa_fwupdate_ImageType_t); idx++ ) {
        if( -1 == (mtdSrc = GetMtdFromImageType( syncPartition[idx], false, &mtdSrcNamePtr,
                                                 &isLogicalSrc, &isDualSrc )) )
        {
            LE_ERROR( "Unable to determine initial partition for %d\n", syncPartition[idx] );
            goto error;
        }
        if( -1 == (mtdDst = GetMtdFromImageType( syncPartition[idx], true, &mtdDstNamePtr,
                                                 &isLogicalDst, &isDualDst)) )
        {
            LE_ERROR( "Unable to determine dual partition for %d\n", syncPartition[idx] );
            goto error;
        }
        LE_INFO( "Synchronizing %s partition \"%s%s\" (mtd%d) from \"%s%s\" (mtd%d)\n",
                 mtdDst == mtdSrc ? "logical" : "physical",
                 mtdDstNamePtr,
                 mtdDst == mtdSrc && dualBootSystem ? "2" : "",
                 mtdDst,
                 mtdSrcNamePtr,
                 mtdDst == mtdSrc && iniBootSystem ? "2" : "",
                 mtdSrc );

        if( LE_OK != pa_flash_Open( mtdSrc,
                              PA_FLASH_OPENMODE_READONLY |
                              (isLogicalSrc
                                  ? (isDualSrc ? PA_FLASH_OPENMODE_LOGICAL_DUAL
                                               : PA_FLASH_OPENMODE_LOGICAL)
                                  : 0),
                              &flashFdSrc,
                              &flashInfoSrcPtr ))
        {
            LE_ERROR("Open of SRC MTD %d fails\n", mtdSrc);
            goto error;
        }
        if( LE_OK != pa_flash_Open( mtdDst,
                              PA_FLASH_OPENMODE_WRITEONLY | PA_FLASH_OPENMODE_MARKBAD |
                              (isLogicalDst
                                  ? (isDualDst ? PA_FLASH_OPENMODE_LOGICAL_DUAL
                                               : PA_FLASH_OPENMODE_LOGICAL)
                                  : 0),
                              &flashFdDst,
                              &flashInfoDstPtr ))
        {
            LE_ERROR("Open of DST MTD %d fails\n", mtdDst);
            goto error;
        }
        if( flashInfoSrcPtr->writeSize != flashInfoDstPtr->writeSize )
        {
            LE_ERROR( "Can not copy flash with different page size: source = %d, destination = %d\n",
                      flashInfoSrcPtr->writeSize, flashInfoDstPtr->writeSize );
            goto error;
        }

        int nbBlk, nbSrcBlkCnt; // Counter to maximum block to be checked
        size_t srcSize;

        crc32Src = START_CRC32;

        if( LE_OK != pa_flash_Scan( flashFdSrc, NULL ) )
        {
            LE_ERROR("Scan of SRC MTD %d fails\n", mtdSrc);
            goto error;
        }
        if( LE_OK != pa_flash_Scan( flashFdDst, NULL ) )
        {
            LE_ERROR("Scan of DST MTD %d fails\n", mtdDst);
            goto error;
        }

        if( LE_OK != pa_flash_SeekAtBlock( flashFdSrc, 0 ) )
        {
            LE_ERROR("Scan of SRC MTD %d fails\n", mtdSrc);
            goto error;
        }
        if( LE_OK != pa_flash_SeekAtBlock( flashFdDst, 0 ) )
        {
            LE_ERROR("Scan of DST MTD %d fails\n", mtdDst);
            goto error;
        }
        for (nbSrcBlkCnt = nbBlk = 0;
             (nbBlk < flashInfoSrcPtr->nbLeb) && (nbBlk < flashInfoDstPtr->nbLeb);
             nbBlk++)
        {
            if( LE_OK != pa_flash_ReadAtBlock( flashFdSrc,
                                               nbBlk,
                                               flashBlockPtr,
                                               flashInfoSrcPtr->eraseSize ))
            {
                LE_ERROR("pa_flash_Read fails for block %d: %m", nbBlk);
                goto error;
            }

            if( LE_OK != pa_flash_EraseBlock( flashFdDst, nbBlk ))
            {
                LE_ERROR("EraseMtd fails for block %d: %m", nbBlk);
                goto error;
            }
            if( LE_OK != pa_flash_WriteAtBlock( flashFdDst,
                                                nbBlk,
                                                flashBlockPtr,
                                                flashInfoDstPtr->eraseSize ))
            {
                LE_ERROR("pa_flash_Write fails for block %d: %m", nbBlk);
                goto error;
            }
            else
            {
                crc32Src = Crc32(flashBlockPtr, flashInfoSrcPtr->eraseSize, crc32Src);
                nbSrcBlkCnt ++;
            }
        }
        if( nbBlk < flashInfoSrcPtr->nbLeb )
        {
            LE_WARN("Bad block on destination MTD ? Missing %d blocks\n",
                    flashInfoSrcPtr->nbLeb - nbBlk);
        }
        for( ; nbBlk < flashInfoDstPtr->nbLeb; nbBlk++ )
        {
            // Erase remaing blocks of the destination
            pa_flash_EraseBlock( flashFdDst, nbBlk );
        }

        srcSize = nbSrcBlkCnt * flashInfoSrcPtr->eraseSize;
        pa_flash_Close(flashFdSrc);
        flashFdSrc = NULL;
        pa_flash_Close(flashFdDst);
        flashFdDst = NULL;

        if( LE_OK != CheckData( mtdDst,
                                isLogicalDst,
                                isDualDst,
                                srcSize,
                                0,
                                crc32Src ) ) {
            goto error;
        }
    }

    le_mem_Release(flashBlockPtr);

    LE_INFO ("pa_fwupdate_DualSysSync done");
    if (LE_OK != pa_fwupdate_SetSyncState())
    {
        LE_ERROR("Failed to call pa_fwupdate_SetSyncState(): Systems are not synchronized");
        return LE_FAULT;
    }
    return LE_OK;

error:
    if (flashBlockPtr)
    {
        le_mem_Release(flashBlockPtr);
    }
    if (flashFdSrc)
    {
        pa_flash_Close(flashFdSrc);
    }
    if (flashFdDst)
    {
        pa_flash_Close(flashFdDst);
    }
    return LE_FAULT;
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
    pa_fwupdate_CweHeader_t* cweHeaderPtr, ///< [IN] CWE header linked to image data
    uint8_t* chunkPtr,                     ///< [IN]Data to be written in flash partition
    size_t length                          ///< [IN]Data length to be written in flash partition
)
{
    size_t result = 0;
    bool isFlashed;

    /* Check incoming parameters */
    if (cweHeaderPtr == NULL)
    {
        LE_ERROR ("bad parameters");
        return 0;
    }

    LE_DEBUG ("imagetype %d, CurrentImageOffset %d length %d, CurrentImageSize %d",
                cweHeaderPtr->imageType,
                (uint32_t)CurrentImageOffset,
                (uint32_t)length,
                (uint32_t)cweHeaderPtr->imageSize);

    /* Check incoming parameters */
    if ((chunkPtr == NULL) || (length > CHUNK_LENGTH))
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
                                cweHeaderPtr,
                                &length,
                                CurrentImageOffset,
                                chunkPtr,
                                &isFlashed))
        {
            CurrentImageCrc32 = Crc32( chunkPtr, (uint32_t)length, CurrentImageCrc32 );
            LE_DEBUG ( "image data write: CRC in header: 0x%x, calculated CRC 0x%x",
                        cweHeaderPtr->crc32, CurrentImageCrc32 );
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

        if (CurrentImageOffset == cweHeaderPtr->imageSize)
        {
            LE_DEBUG ( "image data write end: CRC in header: 0x%x, calculated CRC 0x%x",
                            cweHeaderPtr->crc32, CurrentImageCrc32 );
            /* The whole image was written: compare CRC */
            if (cweHeaderPtr->crc32 != CurrentImageCrc32)
            {
                /* Error on CRC check */
                LE_ERROR ("Error on CRC check");
                result = 0;
            }
            else
            {
                CurrentImageOffset = 0;
                LE_DEBUG ("CurrentImageOffset %d, CurrentImage %d",
                            (uint32_t)CurrentImageOffset, cweHeaderPtr->imageType);
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
 *      - LE_TIMEOUT       The download fails after 900 seconds without data recieved
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
    ssize_t readCount;
    ssize_t DataLenToBeRead;
    uint8_t* bufferPtr = le_mem_ForceAlloc (ChunkPool);

    FullImageLength = -1;

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
                fd_set fdSetRead;
                struct timeval timeRead;

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
                        int rc;

                        /* Read a block at a time from the fd, and send to the modem */
                        /* Get the length which can be read */
                        DataLenToBeRead = LengthToRead();

                        do
                        {
                            FD_ZERO(&fdSetRead);
                            FD_SET(fd, &fdSetRead);
                            SET_SELECT_TIMEOUT(&timeRead, DEFAULT_TIMEOUT);
                            if (0 == (rc = select( fd + 1, &fdSetRead, NULL, NULL, &timeRead)))
                            {
                                LE_CRIT("Timeout on reception. Aborting");
                                goto timeout;
                            }
                            else if ((1 == rc) && FD_ISSET(fd, &fdSetRead))
                            {
                                readCount = read (fd, bufferPtr, DataLenToBeRead);
                                if ((readCount == -1) && (errno == EAGAIN))
                                {
                                    readCount = 0;
                                }
                                else if ((readCount == -1) && (errno != EINTR))
                                {
                                    LE_ERROR("error during read: %m");
                                    goto error;
                                }

                                LE_DEBUG ("Read %d", (uint32_t)readCount);
                            }
                            else
                            {
                                LE_CRIT("select() fails or fd is not set: %d, %m\n", rc);
                                goto error;
                            }
                        }
                        while ((readCount == -1) && (errno == EINTR));

                        if (readCount > 0)
                        {
                            /* In case partial data were read */
                            while( readCount != DataLenToBeRead )
                            {
                                FD_ZERO(&fdSetRead);
                                FD_SET(fd, &fdSetRead);
                                SET_SELECT_TIMEOUT(&timeRead, DEFAULT_TIMEOUT);
                                if (0 == (rc = select( fd + 1, &fdSetRead, NULL, NULL, &timeRead)))
                                {
                                    LE_CRIT("Timeout on reception. Aborting");
                                    goto timeout;
                                }
                                else if ((1 == rc) && FD_ISSET(fd, &fdSetRead))
                                {
                                    LenRead = read (fd, bufferPtr + LenRead,
                                                    DataLenToBeRead - LenRead);
                                    // If read(2) returns 0 as length read, this is an error because
                                    // a length > 0 is expected here
                                    if (!LenRead)
                                    {
                                        LE_CRIT("Nothing to read! CWE file is corrupted ?");
                                        goto error;
                                    }
                                    else if ((LenRead == -1) && (errno != EINTR))
                                    {
                                        LE_ERROR("error during read: %m");
                                        goto error;
                                    }
                                    else if (LenRead > 0)
                                    {
                                        readCount += LenRead;
                                    }
                                }
                                else
                                {
                                    LE_CRIT("select() fails or fd is not set: %d, %m\n", rc);
                                    goto error;
                                }
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
                                if(totalCount >= FullImageLength)
                                {
                                    LE_INFO("End of update: total read %zd, full length expected %zd",
                                             totalCount, FullImageLength);
                                    readCount = 0;
                                }
                            }
                            else
                            {
                                goto error;
                            }
                        }
                        else if (readCount < 0)
                        {
                            LE_ERROR ("Error while reading fd=%i : %m", fd);
                            goto error;
                        }

                        if (!readCount)
                        {
                            LE_DEBUG ("Read %zd bytes in total", totalCount);
                            if (totalCount == 0)
                            {
                                LE_ERROR("No data to read !!!");
                                goto error;
                            }
                            if (IsModemDownloaded != IsFirstNvupDownloaded)
                            {
                                /* a modem as been downloaded but no nvup files
                                 * OR
                                 * nvup files have been downloaded but no modem
                                 *
                                 * => delete the NVUP files
                                 */
                                pa_fwupdate_NvupDelete();
                                if (IsModemDownloaded)
                                {
                                    LE_ERROR("Bad package: MODEM without NVUP");
                                }
                                else
                                {
                                    LE_ERROR("Bad package: NVUP without MODEM");
                                }
                                result = LE_FAULT;
                            }
                            else
                            {
                                result = LE_OK;
                            }
                            /* Done with the file, so close it. */
                            close(fd);
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

    FullImageLength = -1;
    LE_DEBUG ("result %d", result);
    return result;

timeout:
    result = LE_TIMEOUT;
error:
    le_mem_Release(bufferPtr);
    if (IsFirstNvupDownloaded)
    {
        /* almost one NVUP file has been downloaded => delete it */
        pa_fwupdate_NvupDelete();
    }
    /* Done with the file, so close it. */
    close (fd);
    FullImageLength = -1;
    IsOngoing = false;
    return LE_TIMEOUT == result ? LE_TIMEOUT : LE_FAULT;
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
    uint8_t* initialSsidPtr ///< [OUT] if LE_OK, the current boot system
)
{
    if (initialSsidPtr == NULL)
    {
        LE_ERROR("initialSSId null pointer");
        return LE_FAULT;
    }

    *initialSsidPtr = GetInitialBootSystem() + 1; /* add 1 since GetInitialBootSystem returns 0 or 1 */

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
    pa_flash_Info_t flashInfo;

    /* Get MTD information from SBL partition. This is will be used to fix the
       pool object size and compute the max object size */
    mtdNum = GetMtdFromImageType( CWE_IMAGE_TYPE_SBL1, 1, &MtdNamePtr, NULL, NULL );
    LE_FATAL_IF(-1 == mtdNum, "Unable to find a valid MTD for SBL image\n");

    LE_FATAL_IF(LE_OK != pa_flash_GetInfo( mtdNum, &flashInfo, false, false ),
                "Unable to get MTD informations for SBL image");

    /* Allocate a pool for the blocks to be flashed and checked */
    FlashImgPool = le_mem_CreatePool("FlashImagePool", flashInfo.eraseSize);
    /* Request 3 blocks: 1 for flash, 1 spare, 1 for check */
    le_mem_ExpandPool(FlashImgPool, 3);

    /* Allocate a pool for the array to SBL blocks */
    SblBlockPool = le_mem_CreatePool("SBL Block Pool",
                                     sizeof(uint8_t*) * (flashInfo.nbBlk / 2));
    le_mem_ExpandPool(SblBlockPool, 1);
}

