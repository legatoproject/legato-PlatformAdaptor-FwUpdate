/**
 * @file pa_fwupdate.c
 *
 * implementation of @ref c_pa_fwupdate API.
 *
 * This PA supports writing data in device partition and red/write operations in SSDATA (System
 *  Shared Data).
 *
 * Copyright (C) Sierra Wireless Inc.
 *
 */

#include "legato.h"
#include "pa_flash.h"
#include "pa_patch.h"
#include "bspatch.h"
#include "pa_fwupdate.h"
#include "pa_fwupdate_dualsys.h"
#include "interfaces.h"
#include <sys/reboot.h>
#include <linux/reboot.h>
#include <sys/select.h>
#include <netinet/in.h>


// SBL number of passes needed to flash low/high and high/low SBL scrub
#define SBL_MAX_PASS              2

// PBL is looking for SBL signature in the first 2MB of the flash device
// Should avoid to put SBL outside this
#define SBL_MAX_BASE_IN_FIRST_2MB  (2*1024*1024)

// Default timeout
#define DEFAULT_TIMEOUT_MS     900000

// Timeout for select(): Set to timeout in seconds to give time for connection
// through fd
#define SET_SELECT_TIMEOUT(tv, timeout) \
        do { \
            (tv)->tv_sec = timeout; \
            (tv)->tv_usec = 0; \
        } while (0)

// File hosting the last download status
#define EFS_DWL_STATUS_FILE "/fwupdate/dwl_status.nfo"

// Record the download status
#define RECORD_DWL_STATUS(x)                                                          \
    do {                                                                              \
        if (LE_OK != WriteDwlStatus(x))                                               \
        {                                                                             \
            LE_ERROR("Unable to record the download status!");                        \
        }                                                                             \
        LE_INFO("Current download status : %s", pa_fwupdate_GetUpdateStatusLabel(x)); \
    } while (0)

//--------------------------------------------------------------------------------------------------
/**
 * max events managed by epoll
 */
//--------------------------------------------------------------------------------------------------
#define MAX_EVENTS 10

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

/**
 * Define the resume context filename
 */
//--------------------------------------------------------------------------------------------------
#define RESUME_CTX_FILENAME "/fwupdate/fwupdate_ResumeCtx_"

//--------------------------------------------------------------------------------------------------
/**
 * Define the temporary patch path
 */
//--------------------------------------------------------------------------------------------------
#define TMP_PATCH_PATH "/tmp/.tmp.patch"

//--------------------------------------------------------------------------------------------------
/**
 * Define the maximum length for a package data chunk
 */
//--------------------------------------------------------------------------------------------------
#define CHUNK_LENGTH 65536

/* constants for image header */
#define HDRSOURCEVERSION    16    ///< Size of source version (in PSB)
#define HDRPSBLEN           8     ///< Size PSB
#define HDRCURVER           3     ///< Current version of the header
#define HVERSTRSIZE         84    ///< Size of download file's version name string
#define HDATESIZE           8     ///< Size of release data string

/* header field offset constants (relative to the first byte of image in flash) */
#define CRC_PROD_BUF_OFST  0x100
#define HDR_REV_NUM_OFST   0x104
#define CRC_INDICATOR_OFST 0x108
#define IMAGE_TYPE_OFST    0x10C
#define STOR_ADDR_OFST     0x180
#define PROG_ADDR_OFST     0x184
#define ENTRY_OFST         0x188
#define HEADER_SIZE        0x190
#define APPSIGN            0x00000001 ///<  Default appl signature


/* Misc Options Field Bit Map */
#define MISC_OPTS_COMPRESS      0x01  ///< image following header is compressed
#define MISC_OPTS_ENCRYPT       0x02  ///< image following header is encrypted
#define MISC_OPTS_SIGNED        0x04  ///< image following header is signed
#define MISC_OPTS_DELTAPATCH    0x08  ///< image following header is a delta patch
#define MISC_OPTS_UNUSED3       0x10
#define MISC_OPTS_UNUSED2       0x20
#define MISC_OPTS_UNUSED1       0x40
#define MISC_OPTS_UNUSED0       0x80

//--------------------------------------------------------------------------------------------------
/**
 * Delta patch DIFF magic signature
 */
//--------------------------------------------------------------------------------------------------
#define DIFF_MAGIC   "BSDIFF40\0\0\0\0\0\0\0\0"

//--------------------------------------------------------------------------------------------------
/**
 * Enumerate all supported component image types
 */
//--------------------------------------------------------------------------------------------------
typedef enum
{
    CWE_IMAGE_TYPE_MIN = 0,
    CWE_IMAGE_TYPE_QPAR = CWE_IMAGE_TYPE_MIN,     ///<  partition
    CWE_IMAGE_TYPE_SBL1,                          ///<  SBL1
    CWE_IMAGE_TYPE_SBL2,                          ///<  SBL2
    CWE_IMAGE_TYPE_DSP1,                          ///<  QDSP1 FW
    CWE_IMAGE_TYPE_DSP2,                          ///<  QDSP2 SW
    CWE_IMAGE_TYPE_DSP3,                          ///<  QDSP3 SW
    CWE_IMAGE_TYPE_QRPM,                          ///<  QCT RPM image
    CWE_IMAGE_TYPE_BOOT,                          ///<  boot composite image
    CWE_IMAGE_TYPE_APPL,                          ///<  appl composite image
    CWE_IMAGE_TYPE_OSBL,                          ///<  OS Second boot loader
    CWE_IMAGE_TYPE_AMSS,                          ///<  amss
    CWE_IMAGE_TYPE_APPS,                          ///<  apps
    CWE_IMAGE_TYPE_APBL,                          ///<  apps bootloader
    CWE_IMAGE_TYPE_NVBF,                          ///<  NV Backup (factory)
    CWE_IMAGE_TYPE_NVBO,                          ///<  NV Backup (oem)
    CWE_IMAGE_TYPE_NVBU,                          ///<  NV Backup (user)
    CWE_IMAGE_TYPE_EXEC,                          ///<  Self-contained executable
    CWE_IMAGE_TYPE_SWOC,                          ///<  Software on card image
    CWE_IMAGE_TYPE_FOTO,                          ///<  FOTO image
    CWE_IMAGE_TYPE_FILE,                          ///<  Generic file
    CWE_IMAGE_TYPE_SPKG,                          ///<  Super package
    CWE_IMAGE_TYPE_MODM,                          ///<  modem composite image
    CWE_IMAGE_TYPE_SYST,                          ///<  image for 0:SYSTEM
    CWE_IMAGE_TYPE_USER,                          ///<  image for 0:USERDATA
    CWE_IMAGE_TYPE_HDAT,                          ///<  image for 0:HDATA
    CWE_IMAGE_TYPE_NVBC,                          ///<  Cache NV Backup
    CWE_IMAGE_TYPE_SPLA,                          ///<  Splash screen image file
    CWE_IMAGE_TYPE_NVUP,                          ///<  NV UPdate file
    CWE_IMAGE_TYPE_QMBA,                          ///<  Modem Boot Authenticator
    CWE_IMAGE_TYPE_TZON,                          ///<  QCT Trust-Zone Image
    CWE_IMAGE_TYPE_QSDI,                          ///<  QCT System Debug Image
    CWE_IMAGE_TYPE_ARCH,                          ///<  Archive
    CWE_IMAGE_TYPE_UAPP,                          ///<  USER APP Image
    CWE_IMAGE_TYPE_LRAM,                          ///<  Linux RAM image
    CWE_IMAGE_TYPE_CUS0,                          ///<  User image image 0 or 1, for customer0
                                                  ///<  partition
    CWE_IMAGE_TYPE_CUS1,                          ///<  User image image 0 or 1, for customer1
                                                  ///<  partition
    CWE_IMAGE_TYPE_CUS2,                          ///<  User image image 2, for customer2 partition    CWE_IMAGE_TYPE_MAX,                           ///<  End of list
    CWE_IMAGE_TYPE_MAX  = CWE_IMAGE_TYPE_CUS2,    ///<  End of list
    CWE_IMAGE_TYPE_COUNT,                         ///<  Number of entries in list
}
ImageType_t;

//--------------------------------------------------------------------------------------------------
/**
 * CWE file: Product Specific Buffer (PSB).
 */
//--------------------------------------------------------------------------------------------------
typedef struct
{
    uint8_t descriptorVersion;                  ///< Descriptor version
    uint8_t type;                               ///< Component type
    uint8_t flag;                               ///< Component flag (for extended descriptor enable
                                                ///< /disable)
    uint8_t reserved;                           ///< Reserved for future use
    uint32_t offset;                            ///< offset from start of update package to start
                                                ///< of component
    uint32_t size;                              ///< Size of component (in bytes)
    uint8_t sourceVersion[HDRSOURCEVERSION];    ///< Source version
    uint32_t reserved2;                         ///< Reserved for future use
}
CweFilePsb_t;

//--------------------------------------------------------------------------------------------------
/**
 * CWE image header structure
 */
//--------------------------------------------------------------------------------------------------
typedef struct
{
    CweFilePsb_t PSB[HDRPSBLEN];              ///< Product specific buffer
    uint32_t crcProdBuf;                      ///< CRC of Product Specific Buffer
    uint32_t hdrRevNum;                       ///< Header revision number
    uint32_t crcIndicator;                    ///< Update Package CRC valid indicator
    uint32_t imageType;                       ///< Image type
    uint32_t prodType;                        ///< Product type
    uint32_t imageSize;                       ///< Update Package size
    uint32_t crc32;                           ///< CRC32 of Update Package image body
    uint8_t  version[HVERSTRSIZE];            ///< Version/Time
    uint8_t  relDate[HDATESIZE];              ///< Release Date string
    uint32_t compat;                          ///< Backward compat field
    uint8_t  miscOpts;                        ///< Misc Options field
    uint8_t  hdrRes[3];                       ///< Header reserved
    uint32_t storAddr;                        ///< Storage address
    uint32_t progAddr;                        ///< Program reloc. Address
    uint32_t entry;                           ///< Entry Point address
    uint32_t signature;                       ///< Application Signature
}
CweHeader_t;

//--------------------------------------------------------------------------------------------------
/**
 * Resume context to save
 */
//--------------------------------------------------------------------------------------------------
typedef struct
{
    uint32_t ctxCounter;            ///< Context counter, incremented each time the context is
                                    ///< updated
    uint32_t imageType;             ///< Image type
    uint32_t imageSize;             ///< Image size
    uint32_t imageCrc;              ///< Image CRC
    uint32_t currentImageCrc;       ///< current image CRC
    size_t   totalRead;             ///< total read from the beginning to the end of the latest cwe
                                    ///< header read
    uint32_t currentOffset;         ///< offset in the current partition (must be a block erase
                                    ///< limit)
    ssize_t  fullImageLength;       ///< total size of the package (read from the first CWE header)
    bool     isFirstNvupDownloaded; ///< Boolean to know if a NVUP file(s) has been downloaded
    bool     isModemDownloaded;     ///< Boolean to know if a modem partition has been downloaded
    uint32_t ctxCrc;                ///< context CRC, Computed on all previous fields of this struct
}
ResumeCtxSave_t;

//--------------------------------------------------------------------------------------------------
/**
 * Resume context to save
 */
//--------------------------------------------------------------------------------------------------
typedef struct
{
    ResumeCtxSave_t saveCtx;    ///< context to save
    uint32_t fileIndex;         ///< file index to use to save the above context [0..1]
}
ResumeCtx_t;

//--------------------------------------------------------------------------------------------------
/**
 * Delta patch Meta header (one for each image. May be splitted into several slices)
 * Note: Use uint32_t type for all 32-bits fields
 */
//--------------------------------------------------------------------------------------------------
typedef struct
{
    uint8_t  diffType[16];    ///< Patch diff magic signature
    uint32_t segmentSize;     ///< Segment size for every slices. May be device dependant
    uint32_t numPatches;      ///< Number of patch slices
    uint32_t ubiVolId;        ///< UBI Vol Id. Set to -1 if not used.
    uint32_t origSize;        ///< Size of the original image
    uint32_t origCrc32;       ///< CRC32 of the original image
    uint32_t destSize;        ///< Size of the destination image (after patch is applied)
    uint32_t destCrc32;       ///< CRC32 of the destination image (after patch is applied)
}
PatchMetaHdr_t;

//--------------------------------------------------------------------------------------------------
/**
 * Delta patch slice header (one per slice)
 * Note: Use uint32_t type for all 32-bits fields
 */
//--------------------------------------------------------------------------------------------------
typedef struct
{
    uint32_t offset;          ///< Offset of the patch slice into the destination image
    uint32_t number;          ///< Current number of the patch slice
    uint32_t size;            ///< Size of the patch slice
}
PatchHdr_t;

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
static CweHeader_t CurrentCweHeader;

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
static uint32_t CurrentImageCrc32 = LE_CRC_START_CRC32;

//--------------------------------------------------------------------------------------------------
/**
 * Boolean to know if data concerns header or component image
 */
//--------------------------------------------------------------------------------------------------
static bool IsImageToBeRead = false;

//--------------------------------------------------------------------------------------------------
/**
 * Boolean to know if 1st data were written in partition
 */
//--------------------------------------------------------------------------------------------------
static bool IsFirstDataWritten = false;

//--------------------------------------------------------------------------------------------------
/**
 * Image type characters as filled in a CWE header
 * The order of entries in this table must match the order of the enums in ImageType_t
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
    { 'U', 'A', 'P', 'P' },     ///<  USER APP image
    { 'L', 'R', 'A', 'M' },     ///<  Linux RAM image
    { 'C', 'U', 'S', '0' },     ///<  Customer 0 or 1 image in dual system
    { 'C', 'U', 'S', '1' },     ///<  Customer 0 or 1 image in dual system
    { 'C', 'U', 'S', '2' },     ///<  Customer 2 image
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
 * Current patch Meta Header (The CWE contains a patch)
 */
//--------------------------------------------------------------------------------------------------
static PatchMetaHdr_t PatchMetaHdr;

//--------------------------------------------------------------------------------------------------
/**
 * Current patch Header (a "slice" of the whole patch)
 */
//--------------------------------------------------------------------------------------------------
static PatchHdr_t PatchHdr;

//--------------------------------------------------------------------------------------------------
/**
 * State of the patch
 */
//--------------------------------------------------------------------------------------------------
static bool InPatch = false;

//--------------------------------------------------------------------------------------------------
/**
 * File descriptor to create the patch file
 */
//--------------------------------------------------------------------------------------------------
static int PatchFd = -1;

//--------------------------------------------------------------------------------------------------
/**
 * Expected remaining length of the patch when a patch is crossing a chunk
 */
//--------------------------------------------------------------------------------------------------
static int PatchRemLen = 0;

//--------------------------------------------------------------------------------------------------
/**
 * In progress CRC32 of the destination when applying a patch
 */
//--------------------------------------------------------------------------------------------------
static uint32_t PatchCrc32;

//--------------------------------------------------------------------------------------------------
/**
 * Cwe Header in raw format (before decoding). Used for NVUP.
 */
//--------------------------------------------------------------------------------------------------
static uint8_t CweHeaderRaw[HEADER_SIZE];

//--------------------------------------------------------------------------------------------------
/**
 * Resume context
 */
//--------------------------------------------------------------------------------------------------
static ResumeCtx_t ResumeCtx;

//==================================================================================================
//                                       Private Functions
//==================================================================================================
//--------------------------------------------------------------------------------------------------

//--------------------------------------------------------------------------------------------------
/**
 * This function is used to get a 32 bit value from a packet in network byte order and increment the
 * packet pointer beyond the extracted field
 *
 * @return
 *          the translated value
 */
//--------------------------------------------------------------------------------------------------
static uint32_t TranslateNetworkByteOrder
(
    uint8_t** packetPtrPtr ///< [IN] memory location of the pointer to the packet from which the 32
                           ///<      bits value will be read
)
{
    uint32_t field;
    uint8_t* packetPtr;

    packetPtr = *packetPtrPtr;

    field = be32toh(*(uint32_t*)packetPtr);
    LE_DEBUG("packet=0x%x, field=0x%x", *packetPtr, field);
    packetPtr += sizeof(field);

    *packetPtrPtr = packetPtr;

    return field;
}

//--------------------------------------------------------------------------------------------------
/**
 * This function is used to get a string of 8-bit fields from a packet and increment the packet
 * pointer beyond the last read 8-bit field
 */
//--------------------------------------------------------------------------------------------------
static void CopyAndIncrPtr
(
    uint8_t** packetPtrPtr, ///< [IN] memory location of a pointer to a packet from which the string
                            ///<      of 8-bit fields is to be read
    uint8_t* bufferPtr,     ///< [OUT] pointer to a buffer into which the 8-bit fields are to be copied
    size_t numfields        ///< [IN] number of 8-bit fields to be copied
)
{
    uint8_t* packetPtr;

    packetPtr = *packetPtrPtr;

    memcpy(bufferPtr, packetPtr, numfields);
    packetPtr += numfields;

    *packetPtrPtr = packetPtr;
}

//--------------------------------------------------------------------------------------------------
/**
 * update the resume context
 *
 * @return
 *      - LE_OK             on success
 *      - LE_FAULT          on failure
 */
//--------------------------------------------------------------------------------------------------
static le_result_t UpdateResumeCtx
(
    ResumeCtx_t* resumeCtxPtr   ///< [INOUT] the resume context, ctxCrc and ctxCounter
                                ///<         will be updated
)
{
    int ret;
    le_result_t result = LE_OK;
    char str[LE_FS_PATH_MAX_LEN];

    ret = snprintf(str, sizeof(str), RESUME_CTX_FILENAME "%d", resumeCtxPtr->fileIndex);
    if (ret < 0)
    {
        LE_ERROR("error when creating filename (fileIndex=%d)", resumeCtxPtr->fileIndex);
        result = LE_FAULT;
    }
    else
    {
        le_fs_FileRef_t fd;

        LE_DEBUG("Input fileIndex=%d filename %s", resumeCtxPtr->fileIndex, str);

        result = le_fs_Open(str, LE_FS_WRONLY|LE_FS_CREAT, &fd);
        if (result != LE_OK)
        {// an error is occurred
            LE_ERROR("Error when opening %s", str);
            result = LE_FAULT;
        }
        else
        {
            // swap the fileIndex
            resumeCtxPtr->fileIndex ^= 1UL;
            resumeCtxPtr->saveCtx.ctxCounter++;
            resumeCtxPtr->saveCtx.ctxCrc = le_crc_Crc32((uint8_t*)&resumeCtxPtr->saveCtx,
                                                        sizeof(resumeCtxPtr->saveCtx) -
                                                        sizeof(resumeCtxPtr->saveCtx.ctxCrc),
                                                        LE_CRC_START_CRC32);
            LE_DEBUG("resumeCtx: ctxCounter %d, imageType %d, imageSize %d, imageCrc 0x%x,",
                     resumeCtxPtr->saveCtx.ctxCounter, resumeCtxPtr->saveCtx.imageType,
                     resumeCtxPtr->saveCtx.imageSize, resumeCtxPtr->saveCtx.imageCrc);
            LE_DEBUG("            currentImageCrc 0x%x totalRead %d currentOffset 0x%x,",
                     resumeCtxPtr->saveCtx.currentImageCrc,resumeCtxPtr->saveCtx.totalRead,
                     resumeCtxPtr->saveCtx.currentOffset);
            LE_DEBUG("            fullImageLength %d isFirstNvupDownloaded %d isModemDownloaded %d "
                     "ctxCrc 0x%x",
                     resumeCtxPtr->saveCtx.fullImageLength,
                     resumeCtxPtr->saveCtx.isFirstNvupDownloaded,
                     resumeCtxPtr->saveCtx.isModemDownloaded, resumeCtxPtr->saveCtx.ctxCrc);
            result = le_fs_Write(fd, (uint8_t*)&resumeCtxPtr->saveCtx,
                                 sizeof(resumeCtxPtr->saveCtx));
            if (result != LE_OK)
            {
                LE_ERROR("Error while writing %s", str);
                result = LE_FAULT;
            }

            le_fs_Close(fd);
        }
    }

    LE_DEBUG("Result %s, Output fileIndex=%d", LE_RESULT_TXT(result), resumeCtxPtr->fileIndex);

    return result;
}

//--------------------------------------------------------------------------------------------------
/**
 * erase the resume context
 *
 * @return
 *      - LE_OK             on success
 *      - LE_FAULT          on failure
 */
//--------------------------------------------------------------------------------------------------
static le_result_t EraseResumeCtx
(
    ResumeCtx_t* resumeCtxPtr       ///< [OUT] resume context
)
{
    int ret, i, j;
    le_result_t result = LE_OK;

    for (i = 2; i--;)
    {
        char str[LE_FS_PATH_MAX_LEN];

        ret = snprintf(str, sizeof(str), RESUME_CTX_FILENAME "%d", i);
        if (ret < 0)
        {
            LE_ERROR("error when creating filename (i=%d)", i);
            result = LE_FAULT;
            break;
        }
        LE_DEBUG("filename %s", str);

        result = le_fs_Delete(str);
        if ((result != LE_NOT_FOUND) &&(result != LE_OK))
        {
            LE_ERROR("Error when deleting %s", str);
            result = LE_FAULT;
        }
        else
        {
            // initialize the two context file with empty values
            memset(resumeCtxPtr, 0, sizeof(*resumeCtxPtr));
            for (j = 2; j--;)
            {
                result = UpdateResumeCtx(resumeCtxPtr);
                if (LE_OK != result)
                {
                    LE_WARN("Error while updating context #%d", j);
                    result = LE_OK;
                }
            }
        }
    }

    LE_DEBUG("result %s", LE_RESULT_TXT(result));
    return result;
}

//--------------------------------------------------------------------------------------------------
/**
 * Get the resume context
 *
 * @return
 *      - LE_OK             on success
 *      - LE_FAULT          on failure
 */
//--------------------------------------------------------------------------------------------------
static le_result_t GetResumeCtx
(
    ResumeCtx_t* resumeCtxPtr   ///< [OUT] the resume context, filled if LE_OK
)
{
    int ret, i;
    le_result_t result = LE_OK, resultFs;
    le_fs_FileRef_t fd[2];

    // open the 2 context files
    for (i = 2; i--;)
    {
        char str[LE_FS_PATH_MAX_LEN];

        ret = snprintf(str, sizeof(str), RESUME_CTX_FILENAME "%d", i);
        if (ret < 0)
        {
            LE_ERROR("error when creating filename (i=%d)", i);
            result = LE_FAULT;
        }
        else
        {
            LE_DEBUG("filename %s", str);

            resultFs = le_fs_Open(str, LE_FS_RDONLY, &fd[i]);
            if (resultFs != LE_OK)
            {
                LE_ERROR("Error when opening %s", str);
                fd[i] = NULL;
            }
        }
    }

    memset(resumeCtxPtr, 0, sizeof(*resumeCtxPtr));

    if ((fd[0] || fd[1]))
    {
        ResumeCtxSave_t ctx[2], *currentCtxSave;

        // read the 2 context files
        for (i = 2; i--;)
        {
            result = LE_FAULT;
            if (fd[i])
            {
                size_t readSize = sizeof(ctx[0]);

                resultFs = le_fs_Read(fd[i], (uint8_t*)&ctx[i], &readSize);
                if ((resultFs != LE_OK) || (readSize != sizeof(ctx[0])))
                {
                    LE_ERROR("Error while reading fd[%d]!", i);
                    // set context to zero to ensure that the crc will be false
                    memset(&ctx[i], 0, readSize);
                }
                else
                {
                    result = LE_OK;
                }
            }
        }

        if (result == LE_OK)
        {
            uint32_t crc32;
            uint32_t idx;
            int i;

            // select the context with the higher counter
            idx =  (ctx[0].ctxCounter > ctx[1].ctxCounter) ? 0 : 1;

            // check the context CRC
            for (i = 2; i--;)
            {
                currentCtxSave = &ctx[idx];
                crc32 = le_crc_Crc32((uint8_t*)currentCtxSave,
                                     sizeof(*currentCtxSave) - sizeof(currentCtxSave->ctxCrc),
                                     LE_CRC_START_CRC32);
                if (crc32 != currentCtxSave->ctxCrc)
                {
                    LE_ERROR("file #%d Bad CRC32: expected 0x%x, get 0x%x",
                             idx, currentCtxSave->ctxCrc, crc32);
                    // swap the index
                    idx ^= 1UL;
                    result = LE_FAULT;
                }
                else
                {
                    result = LE_OK;
                    break;
                }
            }

            if (result == LE_OK)
            {// a valid context has been found
                // save the current fileIndex
                resumeCtxPtr->fileIndex = idx;

                memcpy(&resumeCtxPtr->saveCtx, currentCtxSave, sizeof(resumeCtxPtr->saveCtx));

                LE_DEBUG("resumeCtx: ctxCounter %d, imageType %d, imageSize %d, imageCrc 0x%x,",
                         resumeCtxPtr->saveCtx.ctxCounter, resumeCtxPtr->saveCtx.imageType,
                         resumeCtxPtr->saveCtx.imageSize, resumeCtxPtr->saveCtx.imageCrc);
                LE_DEBUG("            currentImageCrc 0x%x totalRead %d currentOffset 0x%x,",
                         resumeCtxPtr->saveCtx.currentImageCrc,resumeCtxPtr->saveCtx.totalRead,
                         resumeCtxPtr->saveCtx.currentOffset);
                LE_DEBUG("            fullImageLength %d isFirstNvupDownloaded %d isModemDownloaded %d "
                         "ctxCrc 0x%x",
                         resumeCtxPtr->saveCtx.fullImageLength,
                         resumeCtxPtr->saveCtx.isFirstNvupDownloaded,
                         resumeCtxPtr->saveCtx.isModemDownloaded, resumeCtxPtr->saveCtx.ctxCrc);
            }
            else
            {// no valid context found => re-initialize them
                result = EraseResumeCtx(resumeCtxPtr);
                if (result == LE_OK)
                {
                    resumeCtxPtr->fileIndex = 0;
                }
                else
                {
                    LE_ERROR("context erase failed (%s)", LE_RESULT_TXT(result));
                }
                result = LE_FAULT;
            }
        }
    }

    if (result != LE_OK)
    {
        LE_ERROR("none valid context found");
        result = LE_FAULT;
    }

    for (i = 2; i--;)
    {
        if (fd[i])
        {
            le_fs_Close(fd[i]);
        }
    }

    LE_DEBUG("Result %s, Output fileIndex=%d", LE_RESULT_TXT(result), resumeCtxPtr->fileIndex);

    return result;
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
    int mtdNum,                 ///< [IN] the MTD number
    char** mtdNamePtr,          ///< [OUT] the partition name
    ImageType_t* imageTypePtr   ///< [OUT] the partition type
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
            if (pa_fwupdate_PartNamePtr[ partSystem ][ partIndex ] &&
                (0 == strcmp( mtdFetchName, pa_fwupdate_PartNamePtr[ partSystem ][ partIndex ])))
            {
                // Found: output partition name and return image type
                *mtdNamePtr = pa_fwupdate_PartNamePtr[ partSystem ][ partIndex ];
                *imageTypePtr = partIndex;
                return LE_OK;
            }
        }
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
    if (-1 == _initialBootSystem)
    {
        // Get the initial MTD number for rootfs
        char *iniMtdNamePtr;
        int iniMtd;
        le_result_t result;
        ImageType_t imageType;

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
            _initialBootSystem = 1;
        }
        // "system" : The initial boot system is 1 (return 0)
        else if (0 == strcmp( "system", iniMtdNamePtr ))
        {
            _initialBootSystem = 0;
        }
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
    ImageType_t partName,             ///< [IN] Partition enumerate to get
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
    if (partName > CWE_IMAGE_TYPE_MAX)
    {
        LE_ERROR("partName > CWE_IMAGE_TYPE_MAX");
        return -1;
    }
    // Active system bank
    if (-1 == (iniBootSystem = GetInitialBootSystem()))
    {
        LE_ERROR("bad iniBootSystem");
        return -1;
    }
    // Dual system bank
    dualBootSystem = (iniBootSystem ? 0 : 1);

    mtdPartNamePtr = pa_fwupdate_PartNamePtr[ inDual ? dualBootSystem : iniBootSystem ][ partName ];
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
                *mtdNamePtr = mtdPartNamePtr;
                LE_DEBUG( "Partition %s is mtd%d", *mtdNamePtr, mtdNum );
            }
            break;
        }
    }
    fclose( flashFdPtr );

    if (isLogical)
    {
        *isLogical = ((partName == CWE_IMAGE_TYPE_QRPM) ||
                      (partName == CWE_IMAGE_TYPE_TZON)) ? true : false;
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
static le_result_t CheckIfMounted
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
    uint32_t crc32 = LE_CRC_START_CRC32;
    pa_flash_Info_t* flashInfoPtr;
    pa_flash_OpenMode_t mode = PA_FLASH_OPENMODE_READONLY;

    if (isLogical)
    {
        mode |= ((isDual) ? PA_FLASH_OPENMODE_LOGICAL_DUAL : PA_FLASH_OPENMODE_LOGICAL);
    }

    LE_DEBUG( "Size=%d, Crc32=0x%08x", sizeToCheck, crc32ToCheck);

    checkBlockPtr = (uint8_t *) le_mem_ForceAlloc(FlashImgPool);

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

        crc32 = le_crc_Crc32( checkBlockPtr, (uint32_t)size, crc32);
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
    uint32_t crc32ToCheck              ///< [IN] Expected CRC 32
)
{
    pa_flash_Desc_t desc = NULL;
    uint8_t* checkBlockPtr = NULL;

    size_t size, imageSize = 0;
    uint32_t blk, crc32 = LE_CRC_START_CRC32;
    pa_flash_Info_t *mtdInfoPtr;
    le_result_t res = LE_FAULT;

    LE_INFO( "MTD %d VolId %d Size=0x%08x, Crc32=0x%08x",
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

    checkBlockPtr = le_mem_ForceAlloc(FlashImgPool);
    for (blk = 0; imageSize < sizeToCheck; blk++)
    {
        size = (sizeToCheck - imageSize);
        LE_DEBUG("LEB %d : Read 0x%x", blk, size);
        res = pa_flash_ReadUbiAtBlock( desc, blk, checkBlockPtr, &size);
        if (LE_OK != res )
        {
            goto error;
        }

        crc32 = le_crc_Crc32( checkBlockPtr, (uint32_t)size, crc32);
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
 * Apply patch to a partition
 *
 * @return
 *      - LE_OK            on success
 *      - LE_FAULT         on failure
 *      - LE_NOT_PERMITTED if the patch is applied to the SBL
 *      - others           depending of the UBI or flash functions return
 */
//--------------------------------------------------------------------------------------------------
static le_result_t ApplyPatch
(
    CweHeader_t* hdrPtr,    ///< [IN] Component image header
    size_t length,          ///< [IN] Input data length
    size_t offset,          ///< [IN] Data offset in the package
    uint8_t* dataPtr,       ///< [IN] intput data
    bool forceClose         ///< [IN] Force close of device and resources
)
{
    int mtdDestNum, mtdOrigNum;
    size_t inLen, wrLen, inOffset = 0;
    int remLen = 0;
    uint8_t *dataToHdrPtr;
    bool isOrigLogical, isOrigDual, isDestLogical, isDestDual;
    le_result_t res;

    if (forceClose)
    {
        // If forceClose set, close descriptor and release all resources
        LE_CRIT( "Closing and releasing MTD due to forceClose\n" );
        goto error;
    }

    if ((!dataPtr) || (!length))
    {
        goto error;
    }

    inLen = length;

    LE_INFO("Image type %d len %d offset %d (%d)",
            hdrPtr->imageType, length, offset, hdrPtr->imageSize);

    if (hdrPtr->imageType == CWE_IMAGE_TYPE_SBL1)
    {
        LE_ERROR("SBL could not be flashed as a patch");
        return LE_NOT_PERMITTED;
    }

    LE_DEBUG( "InPatch %d, len %d, offset %d\n", InPatch, length, offset );
    mtdOrigNum = GetMtdFromImageType( hdrPtr->imageType, 0,
                                      &MtdNamePtr, &isOrigLogical, &isOrigDual );
    mtdDestNum = GetMtdFromImageType( hdrPtr->imageType, 1,
                                      &MtdNamePtr, &isDestLogical, &isDestDual );

    if ((-1 == mtdDestNum) || (-1 == mtdOrigNum))
    {
        LE_ERROR( "Unable to find a valid mtd for image type %d\n", hdrPtr->imageType );
        goto error;
    }

    if (!InPatch)
    {
        if (LE_OK != CheckIfMounted( mtdDestNum ))
        {
            LE_ERROR("MTD %d is mounted", mtdDestNum);
            goto error;
        }

        // No patch in progress. This is a new patch
        memset( &PatchHdr, 0, sizeof(PatchHdr) );
        PatchCrc32 = LE_CRC_START_CRC32;

        // Check patch magic
        if (memcmp( ((PatchMetaHdr_t*)dataPtr)->diffType, DIFF_MAGIC,
                    sizeof(PatchMetaHdr.diffType)))
        {
            LE_ERROR("Patch type is not correct: %s", ((PatchMetaHdr_t*)dataPtr)->diffType);
            goto error;
        }
        // Copy patch meta header and take care of byte order BIG endian vs LITTLE endian
        memcpy( &PatchMetaHdr.diffType, dataPtr, sizeof(PatchMetaHdr.diffType) );
        dataToHdrPtr = (uint8_t*)&(((PatchMetaHdr_t*)dataPtr)->segmentSize);
        PatchMetaHdr.segmentSize = TranslateNetworkByteOrder( &dataToHdrPtr );
        PatchMetaHdr.numPatches = TranslateNetworkByteOrder( &dataToHdrPtr );
        PatchMetaHdr.ubiVolId = TranslateNetworkByteOrder( &dataToHdrPtr );
        PatchMetaHdr.origSize = TranslateNetworkByteOrder( &dataToHdrPtr );
        PatchMetaHdr.origCrc32 = TranslateNetworkByteOrder( &dataToHdrPtr );
        PatchMetaHdr.destSize = TranslateNetworkByteOrder( &dataToHdrPtr );
        PatchMetaHdr.destCrc32 = TranslateNetworkByteOrder( &dataToHdrPtr );

        LE_INFO("Meta Header: SegSz 0x%X NumPtch 0x%X UbiVolId 0x%X "
                "OrigSz 0x%X OrigCrc 0x%X DestSz 0x%X DestCrc 0x%X",
                PatchMetaHdr.segmentSize, PatchMetaHdr.numPatches,
                PatchMetaHdr.ubiVolId,
                PatchMetaHdr.origSize, PatchMetaHdr.origCrc32,
                PatchMetaHdr.destSize, PatchMetaHdr.destCrc32);

        if (PatchMetaHdr.ubiVolId != 0xFFFFFFFFU)
        {
            if (LE_OK != CheckUbiData( mtdOrigNum,
                                       PatchMetaHdr.ubiVolId,
                                       PatchMetaHdr.origSize,
                                       PatchMetaHdr.origCrc32 ))
            {
                LE_CRIT("Cannot apply patch. Partition \%s\" is not conform", MtdNamePtr);
                goto error;
            }
            if (LE_OK != CheckUbiData( mtdDestNum,
                                       PatchMetaHdr.ubiVolId,
                                       0,
                                       LE_CRC_START_CRC32 ))
            {
                LE_CRIT("Cannot apply patch. Partition \%s\" is not UBI", MtdNamePtr);
                goto error;
            }
        }
        else if (LE_OK != CheckData( mtdOrigNum,
                                     isOrigLogical,
                                     isOrigDual,
                                     PatchMetaHdr.origSize,
                                     0,
                                     PatchMetaHdr.origCrc32 ))
        {
            LE_CRIT("Cannot apply patch. Partition \"%s\" CRC32 does not match",
                    MtdNamePtr);
            return LE_FAULT;
        }

        inOffset += sizeof(PatchMetaHdr_t);
        inLen -= sizeof(PatchMetaHdr_t);

        InPatch = true;
    }

    do
    {
        if (-1 == PatchFd)
        {
            dataToHdrPtr = (uint8_t*)(inOffset + dataPtr);

            if ((remLen > 0) && (remLen < sizeof(PatchHdr_t)))
            {
                // Header is across this chunk and the next
                memcpy(&PatchHdr, dataToHdrPtr, remLen);
                PatchRemLen = remLen - sizeof(PatchHdr_t);
                LE_DEBUG("Patch header need to continue on next header... 0x%x\n", PatchRemLen);
                break;
            }
            else if (PatchRemLen < 0)
            {
                // This patch overlaps the chunk
                PatchRemLen = -PatchRemLen;
                LE_DEBUG("Patch header continue here... 0x%x\n", PatchRemLen);
                memcpy((uint8_t*)&PatchHdr + (sizeof(PatchHdr_t) - PatchRemLen),
                       dataToHdrPtr,
                       PatchRemLen);
                inOffset = PatchRemLen - sizeof(PatchHdr_t);
                dataToHdrPtr = (uint8_t*)(&PatchHdr);
                PatchHdr.offset = TranslateNetworkByteOrder( &dataToHdrPtr );
                PatchHdr.number = TranslateNetworkByteOrder( &dataToHdrPtr );
                PatchHdr.size = TranslateNetworkByteOrder( &dataToHdrPtr );
                LE_DEBUG("Patch %d complete: At offset 0x%x size 0x%x\n",
                         PatchHdr.number, PatchHdr.offset, PatchHdr.size);
                dataToHdrPtr = (uint8_t*)(inOffset + dataPtr);
                inLen += (sizeof(PatchHdr_t) - PatchRemLen);
            }
            else
            {
                PatchHdr.offset = TranslateNetworkByteOrder( &dataToHdrPtr );
                PatchHdr.number = TranslateNetworkByteOrder( &dataToHdrPtr );
                PatchHdr.size = TranslateNetworkByteOrder( &dataToHdrPtr );
            }

            LE_DEBUG("Patch %d: At offset 0x%x size 0x%x\n",
                     PatchHdr.number, PatchHdr.offset, PatchHdr.size);
            inOffset += sizeof(PatchHdr_t);
            inLen -= sizeof(PatchHdr_t);

            PatchFd = open( TMP_PATCH_PATH, O_TRUNC | O_CREAT | O_WRONLY, 0600 );
            if (PatchFd < 0 )
            {
                LE_CRIT("Failed to create patch file: %m");
                goto error;
            }
            PatchRemLen = PatchHdr.size;
        }

        // > 0 if several patches are in chunk
        // < 0 if this patch overlaps the chunk
        remLen = inLen - (int)PatchRemLen;
        wrLen = (inLen > (int)PatchRemLen ? (int)PatchRemLen : inLen);

        LE_DEBUG("Patch %u: Writing to patch file %d: wrLen = %d, remLen %d, "
                 "inOffset 0x%x, Patch.size %u, PatchRemLen %d\n",
                 PatchHdr.number, PatchFd, (int)wrLen, (int)remLen,
                 (int)inOffset, PatchHdr.size, PatchRemLen);
        if (wrLen != write( PatchFd, dataPtr + inOffset, wrLen ))
        {
            LE_ERROR("Write to patch fails: %m");
            goto error;
        }

        PatchRemLen -= wrLen;

        if (PatchRemLen == 0)
        {
            pa_patch_Context_t ctx;
            le_result_t res;

            close(PatchFd);
            PatchFd = -1;
            LE_INFO("Applying patch %d, size %d at 0x%x\n",
                    PatchHdr.number, PatchHdr.size, PatchHdr.offset);

            ctx.segmentSize = PatchMetaHdr.segmentSize;
            ctx.patchOffset = PatchHdr.offset;
            if (PatchMetaHdr.ubiVolId == 0xFFFFFFFFU)
            {
                ctx.origImage = PA_PATCH_IMAGE_RAWFLASH;
                ctx.destImage = PA_PATCH_IMAGE_RAWFLASH;
            }
            else
            {
                ctx.origImage = PA_PATCH_IMAGE_UBIFLASH;
                ctx.destImage = PA_PATCH_IMAGE_UBIFLASH;
            }
            ctx.origImageSize = PatchMetaHdr.origSize;
            ctx.origImageCrc32 = PatchMetaHdr.origCrc32;
            ctx.origImageDesc.flash.mtdNum = mtdOrigNum;
            ctx.origImageDesc.flash.ubiVolId = PatchMetaHdr.ubiVolId;
            ctx.origImageDesc.flash.isLogical = isOrigLogical;
            ctx.origImageDesc.flash.isDual = isOrigDual;
            ctx.destImageSize = PatchMetaHdr.destSize;
            ctx.destImageCrc32 = PatchMetaHdr.destCrc32;
            ctx.destImageDesc.flash.mtdNum = mtdDestNum;
            ctx.destImageDesc.flash.ubiVolId = PatchMetaHdr.ubiVolId;
            ctx.destImageDesc.flash.isLogical = isDestLogical;
            ctx.destImageDesc.flash.isDual = isDestDual;

            res = bsPatch( &ctx,
                           TMP_PATCH_PATH,
                           &PatchCrc32,
                           PatchMetaHdr.numPatches == PatchHdr.number,
                           false);
            unlink(TMP_PATCH_PATH);
            if (LE_OK != res)
            {
                goto error;
            }
        }
        inOffset += wrLen;
        inLen -= wrLen;

        if (remLen > 0)
        {
            LE_DEBUG("NewPatch expected wrLen %d, remLen %d at 0x%x\n",
                     (int)wrLen, (int)remLen, (int)inOffset);
        }
    } while (remLen > 0);

    if ((offset + length) >= hdrPtr->imageSize )
    {
        InPatch = false;
        LE_INFO( "Patch applied\n");
        close(PatchFd);
        PatchFd = -1;
        if (PatchMetaHdr.ubiVolId != 0xFFFFFFFFU)
        {
            if (LE_OK != CheckUbiData( mtdDestNum,
                                       PatchMetaHdr.ubiVolId,
                                       PatchMetaHdr.destSize,
                                       PatchMetaHdr.destCrc32 ))
            {
                LE_CRIT("UBI Patch failed Partition %d (\"%s\") CRC32 does not match",
                        mtdDestNum, MtdNamePtr);
                return LE_FAULT;
            }
        }
        else
        {
            CheckData( mtdDestNum,
                       isDestLogical,
                       isDestDual,
                       PatchMetaHdr.destSize,
                       0,
                       PatchMetaHdr.destCrc32 );
        }
        LE_DEBUG( "CRC32: Expected 0x%X patched 0x%X\n", PatchMetaHdr.destCrc32, PatchCrc32 );
    }

    return LE_OK;

error:
    InPatch = false;
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
 * Write data into SBL (SBL scrub)
 *
 * @return
 *      - LE_OK on success
 *      - LE_FAULT on failure
 */
//--------------------------------------------------------------------------------------------------
static le_result_t WriteDataSBL
(
    CweHeader_t* hdrPtr,    ///< [IN] Component image header
    size_t length,          ///< [IN] Input data length
    size_t offset,          ///< [IN] Data offset in the package
    uint8_t* dataPtr,       ///< [IN] intput data
    bool forceClose,        ///< [IN] Force close of device and resources
    bool *isFlashedPtr      ///< [OUT] true if flash write was done
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

    if (forceClose)
    {
        // If forceClose set, close descriptor and release all resources
        LE_CRIT( "Closing and releasing MTD due to forceClose" );
        goto forceclose;
    }

    mtdNum = GetMtdFromImageType( hdrPtr->imageType, true, &MtdNamePtr, NULL, NULL );

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

    if (ImageSize == 0)
    {
        LE_INFO ("Writing \"%s\" (mtd%d) from CWE image %d, size %d",
                 MtdNamePtr, mtdNum, hdrPtr->imageType, hdrPtr->imageSize );

        // Allocate a block to store the SBL temporary image
        ImageSize = hdrPtr->imageSize;
        RawImagePtr = (uint8_t **) le_mem_ForceAlloc(SblBlockPool);
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
            unsigned char sbl[sizeof(pa_fwupdate_SBLPreamble)];

            if (LE_OK != pa_flash_ReadAtBlock( flashFd, sblBlk, sbl, sizeof(sbl)))
            {
                LE_ERROR("Read of SBL at sector %d fails: %m", sblBlk );
                goto error;
            }
            if (0 == memcmp( sbl, pa_fwupdate_SBLPreamble, sizeof(sbl) ))
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
            if (LE_OK != pa_flash_Write( flashFd, RawImagePtr[0], flashInfo.writeSize))
            {
                LE_ERROR("(%d)pa_flash_Write fails: %m", pass);
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

        if (isFlashedPtr)
        {
            *isFlashedPtr = true;
        }
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
    LE_ERROR("Update for partiton %s failed with return %d", MtdNamePtr, LE_FAULT);
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
 * Write NVUP files in backup partition by calling QMI commands
 *
 * @note if forceClose is true then the NVUP files will be deleted
 *
 * @return
 *      - LE_OK on success
 *      - LE_FAULT on failure
 */
//--------------------------------------------------------------------------------------------------
static le_result_t WriteNvup
(
    CweHeader_t* hdrPtr,    ///< [IN] Component image header
    size_t length,          ///< [IN] Input data length
    size_t offset,          ///< [IN] Data offset in the package
    uint8_t* dataPtr,       ///< [IN] intput data
    bool forceClose,        ///< [IN] Force close of device and resources
    bool *isFlashedPtr      ///< [OUT] true if flash write was done
)
{
    le_result_t result;
    bool isEnd;

    if ((ResumeCtx.saveCtx.isFirstNvupDownloaded == false) || forceClose)
    {
        /* first NVUP file => ask to delete NVUP files */
        result = pa_fwupdate_NvupDelete();
        if (result != LE_OK)
        {
            LE_ERROR("NVUP delete has failed");
            return LE_FAULT;
        }
        ResumeCtx.saveCtx.isFirstNvupDownloaded = true;
    }

    if (forceClose)
    {
        return LE_OK;
    }

    LE_INFO("Writing NVUP file ...");
    LE_DEBUG("length=%d offset=%d", length, offset);

    if ((ImageSize == 0) && (offset == 0))
    {
        // write the CWE header
        result = pa_fwupdate_NvupWrite(HEADER_SIZE, CweHeaderRaw, false);
        if (result != LE_OK)
        {
            LE_ERROR("Failed to write NVUP CWE header!");
            return LE_FAULT;
        }

        // initialize data phase
        ImageSize = hdrPtr->imageSize;
        LE_DEBUG("ImageSize=%d", ImageSize);
    }

    isEnd = (length+ offset >= ImageSize) ? true : false;
    LE_DEBUG("isEnd=%d", isEnd);

    result = pa_fwupdate_NvupWrite(length, dataPtr, isEnd);
    if (isFlashedPtr)
    {
        *isFlashedPtr = (isEnd && (LE_OK == result) ? true : false);
    }

    if (isEnd)
    {
        ImageSize = 0;
    }
    return result;
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
static le_result_t WriteUpdatePartition
(
    CweHeader_t* hdrPtr,    ///< [IN] Component image header
    size_t length,          ///< [IN] Input data length
    size_t offset,          ///< [IN] Data offset in the package
    uint8_t* dataPtr,       ///< [IN] intput data
    bool forceClose,        ///< [IN] Force close of device and resources
    bool *isFlashedPtr      ///< [OUT] true if flash write was done
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

        mtdNum = GetMtdFromImageType( hdrPtr->imageType, true, &MtdNamePtr, &isLogical, &isDual );

        if (-1 == mtdNum)
        {
            LE_ERROR( "Unable to find a valid mtd for image type %d", hdrPtr->imageType );
            return LE_FAULT;
        }
        LE_INFO ("Writing \"%s\" (mtd%d) from CWE image %d",
                 MtdNamePtr, mtdNum, hdrPtr->imageType );

        if (LE_OK != CheckIfMounted( mtdNum ))
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
        DataPtr = le_mem_ForceAlloc(FlashImgPool);
        InOffset = 0;
        ImageSize = hdrPtr->imageSize;
    }

    if ((FlashInfoPtr == NULL) || (DataPtr == NULL))
    {
        LE_ERROR("Bad behavior !!!");
        goto error;
    }

    if (((uint32_t)(length + InOffset)) >= FlashInfoPtr->eraseSize)
    {
        memcpy( DataPtr + InOffset, dataPtr, FlashInfoPtr->eraseSize - InOffset );
        if (LE_OK != pa_flash_Write( MtdFd, DataPtr, FlashInfoPtr->eraseSize ))
        {
            LE_ERROR( "fwrite to nandwrite fails: %m" );
            goto error;
        }
        if (isFlashedPtr)
        {
            *isFlashedPtr = true;
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
            if (LE_OK != pa_flash_Write( MtdFd, DataPtr, FlashInfoPtr->eraseSize))
            {
                LE_ERROR( "fwrite to nandwrite fails: %m" );
                goto error;
            }
            if (isFlashedPtr)
            {
                *isFlashedPtr = true;
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

        mtdNum = GetMtdFromImageType( hdrPtr->imageType, true, &MtdNamePtr, &isLogical, &isDual );
        if (-1 == mtdNum)
        {
            LE_ERROR( "Unable to find a valid mtd for image type %d", hdrPtr->imageType );
            return LE_FAULT;
        }

        ret = CheckData( mtdNum, isLogical, isDual, hdrPtr->imageSize, 0, hdrPtr->crc32 );
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
 * Write data in a partition
 *
 * @return
 *      - LE_OK on success
 *      - LE_FAULT on failure
 */
//--------------------------------------------------------------------------------------------------
static le_result_t WriteData
(
    CweHeader_t* hdrPtr,    ///< [IN] Component image header
    size_t length,          ///< [IN] Input data length
    size_t offset,          ///< [IN] Data offset in the package
    uint8_t* dataPtr,       ///< [IN] intput data
    bool forceClose,        ///< [IN] Force close of device and resources
    bool *isFlashedPtr      ///< [OUT] true if flash write was done
)
{
    le_result_t ret = LE_OK;

    if (!forceClose)
    {
        LE_DEBUG ("image type %d len %d offset 0x%x", hdrPtr->imageType, length, offset);
    }

    if (isFlashedPtr)
    {
        *isFlashedPtr = false;
    }

    switch (hdrPtr->imageType)
    {
        // image type "FILE" must be considered as NVUP file
        case CWE_IMAGE_TYPE_FILE:
            ret = WriteNvup(hdrPtr, length, offset, dataPtr, forceClose, isFlashedPtr);
            break;

            // SBL is managed by a specific flash scheme
        case CWE_IMAGE_TYPE_SBL1:
            ret = WriteDataSBL(hdrPtr, length, offset, dataPtr, forceClose, isFlashedPtr);
            break;

        default:
            // Delta patch
            if (hdrPtr->miscOpts & MISC_OPTS_DELTAPATCH)
            {
                LE_INFO( "Applying delta patch to %u\n", hdrPtr->imageType );
                ret = ApplyPatch( hdrPtr, length, offset, dataPtr, forceClose );
            }
            else
            {
                ret = WriteUpdatePartition(hdrPtr, length, offset, dataPtr, forceClose,
                                           isFlashedPtr);
            }
            break;
    }

    return ret;
}

//--------------------------------------------------------------------------------------------------
/**
 * This function is to initialize internal variables to initiate a new package download
 */
//--------------------------------------------------------------------------------------------------
static void InitParameters
(
    bool isResume       ///< true if we're a resuming
)
{
    ResumeCtxSave_t *saveCtxPtr = &ResumeCtx.saveCtx;

    LE_DEBUG ("InitParameters, isResume=%d", isResume);
    if (isResume)
    {
        CurrentImageOffset = saveCtxPtr->currentOffset;
        CurrentImageCrc32 = saveCtxPtr->currentImageCrc;
        CurrentCweHeader.imageType = saveCtxPtr->imageType;
        CurrentCweHeader.imageSize = saveCtxPtr->imageSize;
        CurrentCweHeader.crc32 = saveCtxPtr->imageCrc;
        IsImageToBeRead = (CurrentImageOffset != CurrentCweHeader.imageSize);
        IsFirstDataWritten = true;
    }
    else
    {
        CurrentImageOffset = 0;
        CurrentImageCrc32 = LE_CRC_START_CRC32;
        memset(&CurrentCweHeader, 0, sizeof(CurrentCweHeader));
        IsImageToBeRead = false;
        IsFirstDataWritten = false;
        saveCtxPtr->fullImageLength = -1;
    }
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
static uint32_t GetImageValue
(
    ImageType_t imageType   ///< [IN] CWE Image Type to convert
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
static bool ValidateImageType
(
    uint32_t imageType,         ///< [IN] image type for validation
    ImageType_t* enumValuePtr   ///< [OUT] enum value for image type
)
{
    bool retVal = true;
    ImageType_t idx;
    uint32_t imageVal;

    LE_DEBUG ("imagetype 0x%x", imageType);

    for (idx = CWE_IMAGE_TYPE_MIN; idx < CWE_IMAGE_TYPE_COUNT; idx++)
    {
        imageVal = GetImageValue(idx);
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
static le_result_t LoadHeader
(
    uint8_t* startPtr,  ///< [IN] start address of the CWE header to be read
    CweHeader_t* hdpPtr ///< [OUT] pointer to a CWE header structure
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
        ImageType_t imagetype;

        /* init the buf pointer */
        bufPtr = startPtr;

        /* read in the required number of bytes from product specific buffer */
        CopyAndIncrPtr (&bufPtr, (uint8_t*) hdpPtr->PSB, sizeof(hdpPtr->PSB));

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
            if (ValidateImageType(hdpPtr->imageType, &imagetype))
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
                CopyAndIncrPtr(&bufPtr, hdpPtr->version, HVERSTRSIZE);
                LE_DEBUG ("Version %s", hdpPtr->version);
                /* get date string */
                CopyAndIncrPtr(&bufPtr, hdpPtr->relDate, HDATESIZE);

                /* get backwards compatibilty field */
                hdpPtr->compat = TranslateNetworkByteOrder(&bufPtr);

                /* get the misc options */
                hdpPtr->miscOpts = *bufPtr;
                LE_DEBUG ("hdpPtr->miscOpts %d", hdpPtr->miscOpts);

                /* get the load address and entry point based upon the header version. */
                bufPtr=startPtr+STOR_ADDR_OFST;
                hdpPtr->storAddr = TranslateNetworkByteOrder(&bufPtr);

                bufPtr=startPtr+PROG_ADDR_OFST;
                hdpPtr->progAddr = TranslateNetworkByteOrder(&bufPtr);

                bufPtr=startPtr+ENTRY_OFST;
                hdpPtr->entry = TranslateNetworkByteOrder(&bufPtr);

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
            /* The image type was already checked in le_fwupdate_LoadHeader */

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
            if (le_crc_Crc32(startPtr, CRC_PROD_BUF_OFST, LE_CRC_START_CRC32) != hdpPtr->crcProdBuf)
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
    LE_DEBUG ("result %d", result);
    return result;
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
static size_t WriteImageData
(
    CweHeader_t* cweHeaderPtr, ///< [IN] CWE header linked to image data
    uint8_t* chunkPtr,         ///< [IN]Data to be written in flash partition
    size_t length,             ///< [IN]Data length to be written in flash partition
    ResumeCtx_t* resumeCtxPtr  ///< [INOUT] resume context
)
{
    size_t result = 0;
    bool isFlashed;

    /* Check incoming parameters */
    if ((cweHeaderPtr == NULL) || (resumeCtxPtr == NULL))
    {
        LE_ERROR ("bad parameters");
        return 0;
    }

    LE_DEBUG ("imagetype %d, CurrentImageOffset 0x%x length %d, CurrentImageSize %d",
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
        static size_t lenToFlash = 0;

        if (CurrentImageOffset == 0)
        {
            CurrentImageCrc32 = LE_CRC_START_CRC32;
        }

        if (LE_OK == WriteData (cweHeaderPtr,
                                length,
                                CurrentImageOffset,
                                chunkPtr,
                                false,
                                &isFlashed))
        {
            CurrentImageCrc32 = le_crc_Crc32( chunkPtr, (uint32_t)length, CurrentImageCrc32 );
            LE_DEBUG ( "image data write: CRC in header: 0x%x, calculated CRC 0x%x",
                       cweHeaderPtr->crc32, CurrentImageCrc32 );
            CurrentImageOffset += length;
            lenToFlash += length;
            result = length;

            /* Check if it's the 1st data write for this package */
            if (IsFirstDataWritten == false)
            {
                /* Update the partition synchronization state */
                pa_fwupdate_SetUnsyncState();
                IsFirstDataWritten = true;
            }
            LE_DEBUG ("CurrentImageOffset %d", (uint32_t)CurrentImageOffset);
            if (isFlashed)
            {// some data have been flashed => update the resume context
                le_result_t ret;

                LE_DEBUG("Store resume context ...");
                ResumeCtxSave_t *saveCtxPtr = &resumeCtxPtr->saveCtx;
                saveCtxPtr->currentImageCrc = CurrentImageCrc32;
                saveCtxPtr->totalRead += lenToFlash;
                lenToFlash = 0;
                saveCtxPtr->currentOffset = CurrentImageOffset;
                ret = UpdateResumeCtx(resumeCtxPtr);
                if (ret != LE_OK)
                {
                    LE_WARN("Failed to update Resume context");
                }
            }
        }
        else
        {
            /* Error on storing image data */
            result = 0;
            LE_ERROR ("error when writing data in partition");
        }

        if (result && (CurrentImageOffset == cweHeaderPtr->imageSize))
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
 * This function is used by the Legato SW Update component to parse and store an incoming package
 *
 * @return
 *      - LE_OK            The request was accepted
 *      - LE_BAD_PARAMETER The parameter is invalid
 *      - LE_NOT_POSSIBLE  The action is not compliant with the SW update state (no downloaded pkg)
 *      - LE_FAULT         If an error occurs
 */
//--------------------------------------------------------------------------------------------------
static le_result_t ParseAndStoreData
(
    size_t length,              ///< [IN] Input data lentg
    uint8_t* chunkPtr,          ///< [IN] intput data
    ResumeCtx_t* resumeCtxPtr   ///< [INOUT] resume context
)
{
    le_result_t result = LE_OK;
    LE_DEBUG ("start");
    if ((NULL == chunkPtr) || (length > CHUNK_LENGTH) || (NULL == resumeCtxPtr))
    {
        LE_DEBUG("Bad parameter");
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
                result = LoadHeader (chunkPtr, &CurrentCweHeader);
                if (result != LE_OK)
                {
                    LE_ERROR ("Error in parsing the CWE header");
                    result = LE_FAULT;
                }
                else
                {
                    ResumeCtxSave_t *saveCtxPtr = &(resumeCtxPtr->saveCtx);

                    LE_DEBUG ("CWE header read ok");
                    if (-1 == saveCtxPtr->fullImageLength)
                    {
                        /*
                         * Full length of the CWE image is provided inside the
                         * first CWE header
                         */
                        saveCtxPtr->fullImageLength = CurrentCweHeader.imageSize + HEADER_SIZE;
                        LE_DEBUG("New CWE: fullImageLength = %u", saveCtxPtr->fullImageLength);
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
                        /* save the resume context */
                        saveCtxPtr->imageType = CurrentCweHeader.imageType;
                        saveCtxPtr->imageSize = CurrentCweHeader.imageSize;
                        saveCtxPtr->imageCrc = CurrentCweHeader.crc32;
                        saveCtxPtr->currentImageCrc = LE_CRC_START_CRC32;
                        saveCtxPtr->currentOffset = 0;
                    }
                    saveCtxPtr->totalRead += HEADER_SIZE;
                    result = UpdateResumeCtx(resumeCtxPtr);
                    if (result != LE_OK)
                    {
                        LE_WARN("Failed to save the resume ctx");
                        result = LE_OK;
                    }

                    if (CurrentCweHeader.imageType == CWE_IMAGE_TYPE_FILE)
                    {
                        memcpy(CweHeaderRaw, chunkPtr, HEADER_SIZE);
                    }
                    if (CurrentCweHeader.imageType == CWE_IMAGE_TYPE_MODM)
                    {
                        saveCtxPtr->isModemDownloaded = true;
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
            Return = WriteImageData (&CurrentCweHeader, chunkPtr, length, resumeCtxPtr);
            if (!Return)
            {
                /* Parsing fails */
                LE_DEBUG("Parsing failed");
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

//--------------------------------------------------------------------------------------------------
/**
 * This function returns the last download status.
 *
 * @return
 *      - LE_OK            The request was accepted
 *      - LE_BAD_PARAMETER The parameter is invalid
 */
//--------------------------------------------------------------------------------------------------
static le_result_t ReadDwlStatus
(
    pa_fwupdate_InternalStatus_t *statusPtr ///< [OUT] Status of the last download
)
{
    le_result_t result;
    le_fs_FileRef_t fileRef;

    // Check the parameter
    if (NULL == statusPtr)
    {
        LE_ERROR("Invalid status parameter!");
        return LE_BAD_PARAMETER;
    }

    *statusPtr = PA_FWUPDATE_INTERNAL_STATUS_UNKNOWN;

    // Open the file in RO
    if (LE_OK == le_fs_Open(EFS_DWL_STATUS_FILE, LE_FS_RDONLY, &fileRef))
    {
        size_t nbBytes = sizeof(le_fwupdate_UpdateStatus_t);
        // Get the status
        result = le_fs_Read(fileRef, (uint8_t *)statusPtr, &nbBytes);

        // Close the file
        le_fs_Close(fileRef);

        if (LE_OK != result)
        {
            LE_ERROR("Unable to read the FW update download status!");
        }
        else
        {
            // Check the validity of the values
            if (PA_FWUPDATE_INTERNAL_STATUS_UNKNOWN >= *statusPtr)
            {
                LE_INFO("FW update download status : %s",
                    pa_fwupdate_GetUpdateStatusLabel(*statusPtr));
                result = LE_OK;
            }
            else
            {
                // Invalid value so remove the file
                le_fs_Delete(EFS_DWL_STATUS_FILE);
                LE_ERROR("Invalid FW update download status!");
            }
        }
    }
    else
    {
        LE_INFO("Unable to access to %s!", EFS_DWL_STATUS_FILE);
        result = LE_OK;
    }

    return result;
}

//--------------------------------------------------------------------------------------------------
/**
 * This function stores the last download status.
 *
 * @return
 *      - LE_OK            The request was accepted
 *      - LE_BAD_PARAMETER The parameter is invalid
 *      - LE_FAULT         If an error occurs
 */
//--------------------------------------------------------------------------------------------------
static le_result_t WriteDwlStatus
(
    pa_fwupdate_InternalStatus_t status ///< [IN] Status of the last download
)
{
    le_result_t result = LE_FAULT;
    le_fs_FileRef_t fileRef;

    // Check the parameter
    if (status > PA_FWUPDATE_INTERNAL_STATUS_UNKNOWN)
    {
        LE_ERROR("Invalid status parameter!");
        return LE_BAD_PARAMETER;
    }

    // Open the file in RW
    if (LE_OK == le_fs_Open(EFS_DWL_STATUS_FILE, LE_FS_CREAT | LE_FS_RDWR, &fileRef))
    {
        result = le_fs_Write(fileRef, (uint8_t *)&status, sizeof(le_fwupdate_UpdateStatus_t));
        if (LE_OK != result)
        {
            LE_ERROR("Unable to write the FW update download status!");
        }
        else
        {
            LE_INFO("FW update download status : %s", pa_fwupdate_GetUpdateStatusLabel(status));
            LE_INFO("FW update download status stored.");
            result = LE_OK;
        }
        // Close the file
        le_fs_Close(fileRef);
    }
    else
    {
        LE_ERROR("Unable to save the FW update download status!");
    }

    return result;
}

//--------------------------------------------------------------------------------------------------
/**
 * Function to be treated at device init
 */
//--------------------------------------------------------------------------------------------------
static void CheckSyncAtStartup
(
    void
)
{
    bool sync;
    le_result_t result;
    /* Check if a SYNC operation needs to be made */
    result = pa_fwupdate_DualSysCheckSync (&sync);
    LE_DEBUG ("pa_fwupdate_DualSysCheckSync %d sync %d", result, sync);
    if ((result == LE_OK) && sync)
    {
        /* Make a sync operation */
        result = pa_fwupdate_DualSysSync();
        if (result != LE_OK)
        {
            LE_ERROR ("FW update component init: Sync failure %d", result);
        }
    }
}


//--------------------------------------------------------------------------------------------------
/**
 * Do synchronous read on a NON-BLOCK file descriptor
 *
 * @return
 *      - LE_OK             On success
 *      - LE_TIMEOUT        After DEFAULT_TIMEOUT without data received
 *      - LE_CLOSED         The file descriptor has been closed
 *      - LE_FAULT          On failure
 */
//--------------------------------------------------------------------------------------------------
static le_result_t ReadSync
(
    int fd,             ///< [IN] file descriptor
    int efd,            ///< [IN] event file descriptor
    void* bufferPtr,    ///< [IN] pointer on data
    ssize_t *lengthPtr  ///< [INOUT] input: max length to read,
                        ///<         output: read length, (if 0 then fd has been closed)
)
{
    int n;
    struct epoll_event events[MAX_EVENTS];

    while(1)
    {
        n = epoll_wait(efd, events, sizeof(events), DEFAULT_TIMEOUT_MS);
        LE_DEBUG("n=%d", n);
        switch (n)
        {
            case -1:
                LE_ERROR("epoll_wait error %m");
                return LE_FAULT;
            case 0:
                LE_DEBUG("Timeout");
                return LE_TIMEOUT;
            default:
                for(;n--;)
                {
                    LE_DEBUG("events[%d] .data.fd=%d .events=0x%x",
                             n, events[n].data.fd, events[n].events);
                    if (events[n].data.fd == fd)
                    {
                        uint32_t evts = events[n].events;

                        if (evts & EPOLLERR)
                        {
                            return LE_FAULT;
                        }
                        else if ((evts & EPOLLRDHUP ) || (evts & EPOLLHUP))
                        {
                            // file descriptor has been closed
                            LE_INFO("file descriptor %d has been closed", fd);
                            return LE_CLOSED;
                        }
                        else if (evts & EPOLLIN)
                        {
                            *lengthPtr = read (fd, bufferPtr, *lengthPtr);
                            LE_DEBUG("read %d bytes", *lengthPtr);
                            if (*lengthPtr == 0)
                            {
                                return LE_CLOSED;
                            }
                            return LE_OK;
                        }
                        else
                        {
                            LE_WARN("unexpected event received 0x%x",
                                    evts & ~(EPOLLRDHUP|EPOLLHUP|EPOLLERR|EPOLLIN));
                        }
                    }
                }
                break;
        }

    }

    return LE_FAULT;
}

//--------------------------------------------------------------------------------------------------
/**
 * Configure a file descriptor as NON-BLOCK
 *
 * @return
 *      - LE_OK             On success
 *      - LE_FAULT          On failure
 */
//--------------------------------------------------------------------------------------------------
static le_result_t MakeFdNonBlocking
(
    int fd      ///< [IN] file descriptor
)
{
    int flags;

    flags = fcntl(fd, F_GETFL);
    if (-1 == flags)
    {
        LE_ERROR("Fails to GETFL fd %d: %m", fd);
        return LE_FAULT;
    }
    else
    {
        if (-1 == fcntl(fd, F_SETFL, flags | O_NONBLOCK))
        {
            LE_ERROR("Fails to SETFL fd %d: %m", fd);
            return LE_FAULT;
        }
    }
    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Create and configure an event notification
 *
 * @return
 *      - LE_OK             On success
 *      - LE_FAULT          On failure
 */
//--------------------------------------------------------------------------------------------------
static le_result_t CreateAndConfEpoll
(
    int  fd,            ///< [IN] file descriptor
    int* efdPtr         ///< [OUT] event file descriptor
)
{
    struct epoll_event event;
    int efd = epoll_create1(0);
    if (efd == -1)
    {
        return LE_FAULT;
    }

    event.data.fd = fd;
    event.events = EPOLLIN | EPOLLRDHUP | EPOLLET;
    if (-1 == epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event))
    {
        LE_ERROR("epoll_ctl error %m");
        return LE_FAULT;
    }

    *efdPtr = efd;

    return LE_OK;
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
     * physical partitions: MODEM, ABOOT, BOOT, SYSTEM, USER, CUS0
     */
    static const ImageType_t syncPartition[] = {
        CWE_IMAGE_TYPE_DSP2,
        CWE_IMAGE_TYPE_APPS,
        CWE_IMAGE_TYPE_APBL,
        CWE_IMAGE_TYPE_SYST,
        CWE_IMAGE_TYPE_USER,
        CWE_IMAGE_TYPE_QRPM,
        CWE_IMAGE_TYPE_TZON,
        CWE_IMAGE_TYPE_CUS0,
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
    pa_fwupdate_InternalStatus_t internalUpdateStatus;

    if (-1 == (iniBootSystem = GetInitialBootSystem()))
    {
        return LE_FAULT;
    }
    dualBootSystem = (iniBootSystem ? 0 : 1);

    // erase the resume context files
    if (LE_OK != EraseResumeCtx(&ResumeCtx))
    {
        LE_ERROR("Error during EraseResumeCtx()");
        return LE_FAULT;
    }

    le_result_t result = ReadDwlStatus(&internalUpdateStatus);
    if ((LE_OK != result) ||
        ((LE_OK == result) && (
        (PA_FWUPDATE_INTERNAL_STATUS_DWL_ONGOING == internalUpdateStatus) ||
        (PA_FWUPDATE_INTERNAL_STATUS_DWL_TIMEOUT == internalUpdateStatus))))
    {
        RECORD_DWL_STATUS(PA_FWUPDATE_INTERNAL_STATUS_UNKNOWN);
    }

    /* Set the Sw update state in SSDATA to SYNC */
    if (pa_fwupdate_SetState(PA_FWUPDATE_STATE_SYNC) != LE_OK)
    {
        LE_ERROR ("not possible to update the SW update state to SYNC");
        return LE_FAULT;
    }

    flashBlockPtr = (uint8_t *) le_mem_ForceAlloc(FlashImgPool);

    LE_INFO( "Synchronizing from system %d to system %d", iniBootSystem + 1, dualBootSystem + 1);
    for (idx = 0; idx < sizeof( syncPartition )/sizeof(ImageType_t); idx++) {
        if (-1 == (mtdSrc = GetMtdFromImageType( syncPartition[idx], false, &mtdSrcNamePtr,
                                                 &isLogicalSrc, &isDualSrc )))
        {
            LE_ERROR( "Unable to determine initial partition for %d", syncPartition[idx] );
            goto error;
        }
        if (-1 == (mtdDst = GetMtdFromImageType( syncPartition[idx], true, &mtdDstNamePtr,
                                                 &isLogicalDst, &isDualDst)))
        {
            LE_ERROR( "Unable to determine dual partition for %d", syncPartition[idx] );
            goto error;
        }
        LE_INFO( "Synchronizing %s partition \"%s%s\" (mtd%d) from \"%s%s\" (mtd%d)",
                 mtdDst == mtdSrc ? "logical" : "physical",
                 mtdDstNamePtr,
                 mtdDst == mtdSrc && dualBootSystem ? "2" : "",
                 mtdDst,
                 mtdSrcNamePtr,
                 mtdDst == mtdSrc && iniBootSystem ? "2" : "",
                 mtdSrc );

        if ( LE_OK != pa_flash_Open( mtdSrc,
                                     PA_FLASH_OPENMODE_READONLY |
                                     (isLogicalSrc
                                      ? (isDualSrc ? PA_FLASH_OPENMODE_LOGICAL_DUAL
                                         : PA_FLASH_OPENMODE_LOGICAL)
                                      : 0),
                                     &flashFdSrc,
                                     &flashInfoSrcPtr ))
        {
            LE_ERROR("Open of SRC MTD %d fails", mtdSrc);
            goto error;
        }
        if ( LE_OK != pa_flash_Open( mtdDst,
                                     PA_FLASH_OPENMODE_WRITEONLY | PA_FLASH_OPENMODE_MARKBAD |
                                     (isLogicalDst
                                      ? (isDualDst ? PA_FLASH_OPENMODE_LOGICAL_DUAL
                                         : PA_FLASH_OPENMODE_LOGICAL)
                                      : 0),
                                     &flashFdDst,
                                     &flashInfoDstPtr ))
        {
            LE_ERROR("Open of DST MTD %d fails", mtdDst);
            goto error;
        }
        if (flashInfoSrcPtr->writeSize != flashInfoDstPtr->writeSize)
        {
            LE_ERROR( "Can not copy flash with different page size: source = %d, destination = %d",
                      flashInfoSrcPtr->writeSize, flashInfoDstPtr->writeSize );
            goto error;
        }

        int nbBlk, nbSrcBlkCnt; // Counter to maximum block to be checked
        size_t srcSize;

        crc32Src = LE_CRC_START_CRC32;

        if (LE_OK != pa_flash_Scan( flashFdSrc, NULL ))
        {
            LE_ERROR("Scan of SRC MTD %d fails", mtdSrc);
            goto error;
        }
        if (LE_OK != pa_flash_Scan( flashFdDst, NULL ))
        {
            LE_ERROR("Scan of DST MTD %d fails", mtdDst);
            goto error;
        }

        if (LE_OK != pa_flash_SeekAtBlock( flashFdSrc, 0 ))
        {
            LE_ERROR("Scan of SRC MTD %d fails", mtdSrc);
            goto error;
        }
        if (LE_OK != pa_flash_SeekAtBlock( flashFdDst, 0 ))
        {
            LE_ERROR("Scan of DST MTD %d fails", mtdDst);
            goto error;
        }
        for (nbSrcBlkCnt = nbBlk = 0;
             (nbBlk < flashInfoSrcPtr->nbLeb) && (nbBlk < flashInfoDstPtr->nbLeb);
             nbBlk++)
        {
            if (LE_OK != pa_flash_ReadAtBlock( flashFdSrc,
                                               nbBlk,
                                               flashBlockPtr,
                                               flashInfoSrcPtr->eraseSize ))
            {
                LE_ERROR("pa_flash_Read fails for block %d: %m", nbBlk);
                goto error;
            }

            if (LE_OK != pa_flash_EraseBlock( flashFdDst, nbBlk ))
            {
                LE_ERROR("EraseMtd fails for block %d: %m", nbBlk);
                goto error;
            }
            if (LE_OK != pa_flash_WriteAtBlock( flashFdDst,
                                                nbBlk,
                                                flashBlockPtr,
                                                flashInfoDstPtr->eraseSize ))
            {
                LE_ERROR("pa_flash_Write fails for block %d: %m", nbBlk);
                goto error;
            }
            else
            {
                crc32Src = le_crc_Crc32(flashBlockPtr, flashInfoSrcPtr->eraseSize, crc32Src);
                nbSrcBlkCnt ++;
            }
        }
        if (nbBlk < flashInfoSrcPtr->nbLeb)
        {
            LE_WARN("Bad block on destination MTD ? Missing %d blocks",
                    flashInfoSrcPtr->nbLeb - nbBlk);
        }
        for (; nbBlk < flashInfoDstPtr->nbLeb; nbBlk++)
        {
            // Erase remaing blocks of the destination
            pa_flash_EraseBlock( flashFdDst, nbBlk );
        }

        srcSize = nbSrcBlkCnt * flashInfoSrcPtr->eraseSize;
        pa_flash_Close(flashFdSrc);
        flashFdSrc = NULL;
        pa_flash_Close(flashFdDst);
        flashFdDst = NULL;

        if (LE_OK != CheckData( mtdDst,
                                isLogicalDst,
                                isDualDst,
                                srcSize,
                                0,
                                crc32Src ) ) {
            goto error;
        }
    }

    le_mem_Release(flashBlockPtr);

    LE_INFO ("done");
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
    LE_DEBUG ("sync failure --> pass SW update to NORMAL");
    pa_fwupdate_SetState (PA_FWUPDATE_STATE_NORMAL);
    /* do not get the result, we must return the previous error */
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
 * This function starts a package download to the device.
 *
 * @warning This API is a blocking API. It needs to be called in a dedicated thread.
 *
 * @return
 *      - LE_OK              On success
 *      - LE_BAD_PARAMETER   If an input parameter is not valid
 *      - LE_TIMEOUT         After 900 seconds without data received
 *      - LE_NOT_POSSIBLE    The systems are not synced
 *      - LE_CLOSED          File descriptor has been closed before all data have been received
 *      - LE_FAULT           On failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_fwupdate_Download
(
    int fd  ///< [IN] File descriptor of the file to be downloaded
)
{
    le_result_t result;
    size_t totalCount;
    pa_fwupdate_InternalStatus_t updateStatus = PA_FWUPDATE_INTERNAL_STATUS_UNKNOWN;
    uint8_t* bufferPtr = le_mem_ForceAlloc (ChunkPool);
    int efd = -1;

    LE_DEBUG ("fd %d", fd);
    if (fd < 0)
    {
        updateStatus = PA_FWUPDATE_INTERNAL_STATUS_DWL_FAILED;
        LE_ERROR ("bad parameter");
        result = LE_BAD_PARAMETER;
        goto error;
    }

    ResumeCtxSave_t *saveCtxPtr = &ResumeCtx.saveCtx;

    // check if the resume context is empty or not
    if (saveCtxPtr->totalRead == 0)
    {// resume context is empty so this is a new download
        bool bSync = false;

        // Get the systems synchronization state
        result = pa_fwupdate_DualSysGetSyncState (&bSync);
        if ((LE_OK == result) && (false == bSync))
        {
            /* Both systems are not synchronized
             * It's not possible to launch a new package download
             */
            result = LE_NOT_POSSIBLE;
            goto error;
        }
        else if (LE_OK != result)
        {
            LE_ERROR("check sync state error !!!");
            goto error;
        }
        else
        {
            totalCount = 0;
        }
    }
    else
    {
        totalCount = saveCtxPtr->totalRead;
    }

    /* Like we use select(2), force the O_NONBLOCK flags in fd */
    result = MakeFdNonBlocking(fd);
    if (result != LE_OK)
    {
        goto error;
    }

    result = CreateAndConfEpoll(fd, &efd);
    if (result != LE_OK)
    {
        goto error;
    }

    /* Both systems are synchronized or a valid resume context has been found */
    InitParameters((totalCount != 0));

    // Record the fact that the download starts.
    updateStatus = PA_FWUPDATE_INTERNAL_STATUS_DWL_ONGOING;
    // Record the download status
    RECORD_DWL_STATUS(updateStatus);

    while (true)
    {
        ssize_t dataLenToBeRead;
        ssize_t readCount;

        /* Read a block at a time from the fd, and send to the modem */
        /* Get the length which can be read */
        dataLenToBeRead = LengthToRead();

        do
        {
            readCount = read (fd, bufferPtr, dataLenToBeRead);
            if (((-1 == readCount) && (EAGAIN == errno)) || (!readCount))
            {
                readCount = dataLenToBeRead;
                result = ReadSync(fd, efd, bufferPtr, &readCount);
                if (result != LE_OK)
                {
                    goto error;
                }
            }
            if ((-1 == readCount) && (EAGAIN == errno))
            {
                readCount = 0;
            }
            else if ((-1 == readCount) && (EINTR != errno))
            {
                LE_ERROR("error during read: %m");
                goto error;
            }

            LE_DEBUG ("Read %d", (uint32_t)readCount);
        }
        while ((-1 == readCount) && (EINTR == errno));

        if (readCount > 0)
        {
            ssize_t lenRead = 0;

            /* In case partial data were read */
            while (readCount != dataLenToBeRead)
            {
                lenRead = read (fd, bufferPtr + readCount, dataLenToBeRead - readCount);
                // If read(2) returns 0 as length read, this is an error because
                // a length > 0 is expected here
                if ((!lenRead) || ((-1 == lenRead) && (EAGAIN == errno)))
                {
                    lenRead = dataLenToBeRead - readCount;
                    result = ReadSync(fd, efd, bufferPtr + readCount, &lenRead);
                    if (result != LE_OK)
                    {
                        goto error;
                    }
                }

                if (lenRead > 0)
                {
                    readCount += lenRead;
                }
                else if ((-1 == lenRead) && ((EINTR != errno) && (EAGAIN != errno)))
                {
                    LE_ERROR("error during read: %m");
                    goto error;
                }
            }

            /* Parse the read data and store in partition */
            /* totalCount is in fact the offset */
            result = ParseAndStoreData (readCount, bufferPtr, &ResumeCtx);
            if (result == LE_OK)
            {
                /* Update the totalCount variable (offset) with read data length */
                totalCount += readCount;
                LE_DEBUG ("--> update totalCount %d", (uint32_t)totalCount);
                if (totalCount >= saveCtxPtr->fullImageLength)
                {
                    LE_INFO("End of update: total read %zd, full length expected %zd",
                            totalCount, saveCtxPtr->fullImageLength);
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
            if (totalCount > saveCtxPtr->fullImageLength)
            {
                LE_ERROR("Too much data have been received");
                goto error;
            }
            else if (totalCount < saveCtxPtr->fullImageLength)
            {
                LE_INFO("Download is not complete, resume allowed");
                result = LE_CLOSED;
                goto error;
            }
            else
            {
                LE_INFO("End of download");
            }

            if (saveCtxPtr->isModemDownloaded && (!saveCtxPtr->isFirstNvupDownloaded))
            {
                /* a modem as been downloaded but no nvup files
                 * => delete the NVUP files
                 */
                pa_fwupdate_NvupDelete();
                LE_INFO("MODEM without NVUP, NVUP have been deleted");
            }
            updateStatus = PA_FWUPDATE_INTERNAL_STATUS_OK;
            result = LE_OK;
            // erase resume context
            EraseResumeCtx(&ResumeCtx);
            break;
        }
    }

    // Record the download status
    RECORD_DWL_STATUS(updateStatus);

    le_mem_Release(bufferPtr);
    if (fd != -1)
    {
        close(fd);
    }
    if (efd != -1)
    {
        close(efd);
    }

    LE_DEBUG ("result %s", LE_RESULT_TXT(result));
    return result;

error:
    if (result != LE_CLOSED) // if LE_CLOSED updateStatus is already to ONGOING
    {
        updateStatus = (result == LE_TIMEOUT) ? PA_FWUPDATE_INTERNAL_STATUS_DWL_TIMEOUT :
                                                PA_FWUPDATE_INTERNAL_STATUS_DWL_FAILED;
        // Record the download status
        RECORD_DWL_STATUS(updateStatus);
    }

    le_mem_Release(bufferPtr);
    // Done with the file, so close it.
    close (fd);
    if (efd != -1)
    {
        close(efd);
    }
    if (LE_OK != WriteData(&CurrentCweHeader, 0, 0, NULL, true, NULL))
    {
        LE_CRIT("Failed to force close of MTD.");
    }
    // we avoid to affect LE_FAULT before goto error so we can have LE_OK at this point
    result = (result == LE_OK) ? LE_FAULT : result;
    if (LE_FAULT == result)
    {
        pa_fwupdate_InitDownload();
        // don't care to the result we're already in error treatment
    }

    LE_DEBUG ("result %s", LE_RESULT_TXT(result));
    return result;
}

//--------------------------------------------------------------------------------------------------
/**
 * Return the update package write position.
 *
 * @note This is actually the position within the update package, not the one once the update
 * package is processed (unzipping, extracting, ... ).
 *
 * @return
 *      - LE_OK            on success
 *      - LE_BAD_PARAMETER bad parameter
 *      - LE_FAULT         on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_fwupdate_GetResumePosition
(
    size_t *positionPtr     ///< [OUT] Update package read position
)
{
    // Check the parameter
    if (NULL == positionPtr)
    {
        LE_ERROR("Invalid parameter.");
        return LE_BAD_PARAMETER;
    }

    *positionPtr = ResumeCtx.saveCtx.totalRead;

    return LE_OK;
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

    *initialSsidPtr = GetInitialBootSystem() + 1; // add 1 since GetInitialBootSystem returns 0 or 1

    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Request a full system reset with a systems swap and optionally a sync
 *
 * @note On success, a device reboot is initiated without returning any value.
 *
 * @return
 *      - LE_BUSY  download is ongoing, swap is not allowed
 *      - LE_FAULT on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_fwupdate_DualSysSwap
(
    bool isSyncReq      ///< [IN] Indicate if a synchronization is requested after the swap
)
{
    le_result_t result;
    size_t position = 0;

    // check if a resume is ongoing
    result = pa_fwupdate_GetResumePosition(&position);
    if ((LE_OK != result) || position)
    {
        LE_ERROR("swap not possible, a download is ongoing");
        return LE_BUSY;
    }

    /* Program the SWAP */
    result = pa_fwupdate_Swap (isSyncReq);
    if (result == LE_OK)
    {
        /* request modem to check if there is NVUP files to apply
         * no need to check the result as SSID are already modified we need to reset */
        pa_fwupdate_NvupApply();
        /* make a system reset */
        pa_fwupdate_Reset();
        /* at this point the system is reseting */
    }

    LE_DEBUG ("Swap result %d", result);
    return LE_FAULT;
}

//--------------------------------------------------------------------------------------------------
/**
 * Initialize the resume context
 *
 * @return
 *      - LE_OK             on success
 *      - LE_UNSUPPORTED    the feature is not supported
 *      - LE_FAULT          on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_fwupdate_InitDownload
(
    void
)
{
    le_result_t result, ret;
    bool isSync = false;

    // Check whether both systems are synchronized and eventually initiate the synchronization.
    result = pa_fwupdate_DualSysGetSyncState(&isSync);
    if (LE_OK != result)
    {
        LE_ERROR("Checking synchronization has failed (%s)!", LE_RESULT_TXT(result));
        return LE_FAULT;
    }
    else if (false == isSync)
    {
        // Perform the synchronization
        result = pa_fwupdate_DualSysSync();
        if (result != LE_OK)
        {
            LE_ERROR("failed to SYNC (%s)", LE_RESULT_TXT(result));
            result = LE_FAULT;
        }
    }
    else
    {
        // for sonar: nothing to do
    }

    // Clear the context out
    ret = EraseResumeCtx(&ResumeCtx);

    return ((result == LE_OK) ? ret : result);
}

//--------------------------------------------------------------------------------------------------
/**
 * Return the last update status.
 *
 * @return
 *      - LE_OK on success
 *      - LE_BAD_PARAMETER Invalid parameter
 *      - LE_FAULT on failure
 *      - LE_UNSUPPORTED not supported
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_fwupdate_GetUpdateStatus
(
    pa_fwupdate_UpdateStatus_t *statusPtr, ///< [OUT] Returned update status
    char *statusLabelPtr,                  ///< [OUT] String matching the status
    size_t statusLabelLength               ///< [IN] Maximum length of the status description
)
{
    le_result_t                   result;
    pa_fwupdate_InternalStatus_t  internalStatus;
    const char                   *labelPtr;

    // Look-Up Table of error codes
    // Used to translate internal PA error codes into generic ones.
    const pa_fwupdate_UpdateStatus_t updateStatus[] =
    {
        PA_FWUPDATE_UPDATE_STATUS_OK,              // PA_FWUPDATE_INTERNAL_STATUS_OK
        PA_FWUPDATE_UPDATE_STATUS_PARTITION_ERROR, // PA_FWUPDATE_INTERNAL_STATUS_SBL
        PA_FWUPDATE_UPDATE_STATUS_PARTITION_ERROR, // PA_FWUPDATE_INTERNAL_STATUS_MIBIB
        PA_FWUPDATE_UPDATE_STATUS_PARTITION_ERROR, // PA_FWUPDATE_INTERNAL_STATUS_RESERVED1
        PA_FWUPDATE_UPDATE_STATUS_PARTITION_ERROR, // PA_FWUPDATE_INTERNAL_STATUS_SEDB
        PA_FWUPDATE_UPDATE_STATUS_PARTITION_ERROR, // PA_FWUPDATE_INTERNAL_STATUS_RESERVED2
        PA_FWUPDATE_UPDATE_STATUS_PARTITION_ERROR, // PA_FWUPDATE_INTERNAL_STATUS_TZ1
        PA_FWUPDATE_UPDATE_STATUS_PARTITION_ERROR, // PA_FWUPDATE_INTERNAL_STATUS_TZ2
        PA_FWUPDATE_UPDATE_STATUS_PARTITION_ERROR, // PA_FWUPDATE_INTERNAL_STATUS_RPM1
        PA_FWUPDATE_UPDATE_STATUS_PARTITION_ERROR, // PA_FWUPDATE_INTERNAL_STATUS_RPM2
        PA_FWUPDATE_UPDATE_STATUS_PARTITION_ERROR, // PA_FWUPDATE_INTERNAL_STATUS_MODEM1
        PA_FWUPDATE_UPDATE_STATUS_PARTITION_ERROR, // PA_FWUPDATE_INTERNAL_STATUS_MODEM2
        PA_FWUPDATE_UPDATE_STATUS_PARTITION_ERROR, // PA_FWUPDATE_INTERNAL_STATUS_LK1
        PA_FWUPDATE_UPDATE_STATUS_PARTITION_ERROR, // PA_FWUPDATE_INTERNAL_STATUS_LK2
        PA_FWUPDATE_UPDATE_STATUS_PARTITION_ERROR, // PA_FWUPDATE_INTERNAL_STATUS_KERNEL1
        PA_FWUPDATE_UPDATE_STATUS_PARTITION_ERROR, // PA_FWUPDATE_INTERNAL_STATUS_KERNEL2
        PA_FWUPDATE_UPDATE_STATUS_PARTITION_ERROR, // PA_FWUPDATE_INTERNAL_STATUS_ROOT_FS1
        PA_FWUPDATE_UPDATE_STATUS_PARTITION_ERROR, // PA_FWUPDATE_INTERNAL_STATUS_ROOT_FS2
        PA_FWUPDATE_UPDATE_STATUS_PARTITION_ERROR, // PA_FWUPDATE_INTERNAL_STATUS_USER_DATA1
        PA_FWUPDATE_UPDATE_STATUS_PARTITION_ERROR, // PA_FWUPDATE_INTERNAL_STATUS_USER_DATA2
        PA_FWUPDATE_UPDATE_STATUS_PARTITION_ERROR, // PA_FWUPDATE_INTERNAL_STATUS_CUST_APP1
        PA_FWUPDATE_UPDATE_STATUS_PARTITION_ERROR, // PA_FWUPDATE_INTERNAL_STATUS_CUST_APP2
        PA_FWUPDATE_UPDATE_STATUS_DWL_ONGOING,     // PA_FWUPDATE_INTERNAL_STATUS_DWL_ONGOING
        PA_FWUPDATE_UPDATE_STATUS_DWL_FAILED,      // PA_FWUPDATE_INTERNAL_STATUS_DWL_FAILED
        PA_FWUPDATE_UPDATE_STATUS_DWL_TIMEOUT,     // PA_FWUPDATE_INTERNAL_STATUS_DWL_TIMEOUT
        PA_FWUPDATE_UPDATE_STATUS_UNKNOWN          // PA_FWUPDATE_INTERNAL_STATUS_UNKNOWN
    };

    // Check the parameter
    if (NULL == statusPtr)
    {
        LE_ERROR("Invalid parameter.");
        return LE_BAD_PARAMETER;
    }

    // Try first to read the stored status if it exists
    result = ReadDwlStatus(&internalStatus);

    // Fetch the correponding label
    labelPtr = pa_fwupdate_GetUpdateStatusLabel(internalStatus);

    if (LE_OK == result)
    {
        if ((PA_FWUPDATE_INTERNAL_STATUS_DWL_ONGOING == internalStatus) ||
            (PA_FWUPDATE_INTERNAL_STATUS_DWL_TIMEOUT == internalStatus) ||
            (PA_FWUPDATE_INTERNAL_STATUS_DWL_FAILED == internalStatus))
        {
            if (NULL != statusLabelPtr)
            {
                if (statusLabelLength > 0)
                {
                    // Update the status label
                    strncpy(statusLabelPtr, labelPtr, statusLabelLength);
                }
                else
                {
                    // At least, reset the label
                    *statusLabelPtr = '\0';
                }
            }
            LE_INFO("FW update status (from last download): %s", labelPtr);
            return LE_OK;
        }
        else
        {
            LE_INFO("FW update status (from last download): %s", labelPtr);
        }
    }

    result = pa_fwupdate_GetInternalUpdateStatus(
            &internalStatus,
            statusLabelPtr,
            statusLabelLength);

    if (LE_OK == result)
    {
        if (PA_FWUPDATE_INTERNAL_STATUS_UNKNOWN >= internalStatus)
        {
            *statusPtr = updateStatus[internalStatus];
        }
    }
    else
    {
        LE_ERROR("Unable to get internal FW update status!");
    }

    return result;
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
    mtdNum = GetMtdFromImageType( CWE_IMAGE_TYPE_SBL1, true, &MtdNamePtr, NULL, NULL );
    LE_FATAL_IF(-1 == mtdNum, "Unable to find a valid MTD for SBL image");

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

    CheckSyncAtStartup();

    if (GetResumeCtx(&ResumeCtx) != LE_OK)
    {
        le_result_t result;
        pa_fwupdate_UpdateStatus_t status = PA_FWUPDATE_UPDATE_STATUS_UNKNOWN;

        LE_ERROR("Error when getting the resume context");
        result = pa_fwupdate_GetUpdateStatus(&status, NULL, 0);
        if ((result != LE_OK) ||
            (PA_FWUPDATE_UPDATE_STATUS_DWL_ONGOING == status) ||
            (PA_FWUPDATE_UPDATE_STATUS_DWL_TIMEOUT == status))
        {
            pa_fwupdate_InitDownload();
        }
        else
        {
            EraseResumeCtx(&ResumeCtx);
        }
    }
}

