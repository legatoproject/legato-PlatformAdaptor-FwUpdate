/**
 * @file pa_fwupdate_dualsys.c
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
#include "pa_fwupdate.h"
#include "pa_fwupdate_dualsys.h"
#include "cwe_local.h"
#include "deltaUpdate_local.h"
#include "partition_local.h"
#include "interfaces.h"
#include "watchdogChain.h"
#include "fwupdate_local.h"
#include <sys/select.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include "flash-ubi.h"
#include <openssl/sha.h>
#include <openssl/err.h>

//--------------------------------------------------------------------------------------------------
/**
 * Default timeout
 */
//--------------------------------------------------------------------------------------------------
#define DEFAULT_TIMEOUT_MS     900000

//--------------------------------------------------------------------------------------------------
/**
 * File hosting the last download status
 */
//--------------------------------------------------------------------------------------------------
#define EFS_DWL_STATUS_FILE "/fwupdate/dwl_status.nfo"

//--------------------------------------------------------------------------------------------------
/**
 * Path to save CUSG image
 */
//--------------------------------------------------------------------------------------------------
static char* CusgPathPtr = NULL;

//--------------------------------------------------------------------------------------------------
/**
 * Record the download status
 */
//--------------------------------------------------------------------------------------------------
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
 * Define the resume context filename
 */
//--------------------------------------------------------------------------------------------------
#define RESUME_CTX_FILENAME "/fwupdate/fwupdate_ResumeCtx_"

//--------------------------------------------------------------------------------------------------
/**
 * Define the maximum length for a package data chunk
 */
//--------------------------------------------------------------------------------------------------
#define CHUNK_LENGTH 65536

//--------------------------------------------------------------------------------------------------
/**
 * Maximum UBI volumes for DM-verity checks
 */
//--------------------------------------------------------------------------------------------------
#define MAX_UBI_VOL_FOR_DM_VERITY     3

//--------------------------------------------------------------------------------------------------
/**
 * UBI volumes name format path into /sys
 */
//--------------------------------------------------------------------------------------------------
#define SYS_UBI_VOLUME_NAME_PATH      "/sys/class/ubi/ubi%d_%d/name"

//--------------------------------------------------------------------------------------------------
/**
 * Path to swi_auth tool used to detect SECURE BOOT and authentify the root hash
 */
//--------------------------------------------------------------------------------------------------
#define SWI_AUTH_PATH                 "/usr/bin/swi_auth"

//--------------------------------------------------------------------------------------------------
/**
 * Expected return code from swi_auth tool
 */
//--------------------------------------------------------------------------------------------------
typedef enum
{
    SWI_NON_SECURE = 4,           ///< Non-Secure boot
    SWI_SECURE_VERSION,           ///< Secure boot enabled
    SWI_AUTH_SIGNATURE_SUCCEED,   ///< Root-hash authentication succeed
    SWI_AUTH_SIGNATURE_FAILED,    ///< Root-hash authentication failed
}
SwiAuth_t;

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
    uint32_t globalCrc;             ///< CRC of all the package (crc in first cwe header)
    uint32_t currentGlobalCrc;      ///< current global CRC
    size_t   totalRead;             ///< total read from the beginning to the end of the latest cwe
                                    ///< header read
    uint32_t currentOffset;         ///< offset in the current partition (must be a block erase
                                    ///< limit)
    ssize_t  fullImageLength;       ///< total size of the package (read from the first CWE header)
    uint8_t  miscOpts;              ///< Misc Options field from CWE header
    bool     isFirstNvupDownloaded; ///< Boolean to know if a NVUP file(s) has been downloaded
    bool     isModemDownloaded;     ///< Boolean to know if a modem partition has been downloaded
    bool     isImageToBeRead;       ///< Boolean to know if data concerns header or component image
    deltaUpdate_PatchMetaHdr_t patchMetaHdr;    ///< Patch Meta Header
    deltaUpdate_PatchHdr_t     patchHdr;        ///< Patch Header
    SHA256_CTX sha256Ctx;           ///< buffer to save sha256 context
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
    SHA256_CTX  *sha256CtxPtr;  ///< sha256 context pointer used for calculating
}
ResumeCtx_t;

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
static cwe_Header_t CurrentCweHeader;

//--------------------------------------------------------------------------------------------------
/**
 * Read offset of the current component image
 */
//--------------------------------------------------------------------------------------------------
static size_t CurrentImageOffset = 0;

//--------------------------------------------------------------------------------------------------
/**
 * CRC32 variables
 */
//--------------------------------------------------------------------------------------------------
static uint32_t CurrentImageCrc32 = LE_CRC_START_CRC32;
static uint32_t CurrentGlobalCrc32 = LE_CRC_START_CRC32;

//--------------------------------------------------------------------------------------------------
/**
 * Boolean to know if 1st data were written in partition
 */
//--------------------------------------------------------------------------------------------------
static bool IsFirstDataWritten = false;

//--------------------------------------------------------------------------------------------------
/**
 * Memory Pool for flash temporary image blocks
 */
//--------------------------------------------------------------------------------------------------
static le_mem_PoolRef_t   FlashImgPool;

//--------------------------------------------------------------------------------------------------
/**
 * Cwe Header in raw format (before decoding). Used for NVUP.
 */
//--------------------------------------------------------------------------------------------------
static uint8_t CweHeaderRaw[CWE_HEADER_SIZE];

//--------------------------------------------------------------------------------------------------
/**
 * Resume context
 */
//--------------------------------------------------------------------------------------------------
static ResumeCtx_t ResumeCtx;

//--------------------------------------------------------------------------------------------------
/**
 * Delta update context
 */
//--------------------------------------------------------------------------------------------------
static deltaUpdate_Ctx_t DeltaUpdateCtx = {
    .cweHdrPtr = &CurrentCweHeader,
    .hdrPtr = &ResumeCtx.saveCtx.patchHdr,
    .metaHdrPtr = &ResumeCtx.saveCtx.patchMetaHdr,
    .poolPtr = &FlashImgPool,
    .patchRemLen = 0
};

//--------------------------------------------------------------------------------------------------
/**
 * Partition context
 */
//--------------------------------------------------------------------------------------------------
static partition_Ctx_t PartitionCtx = {
    .cweHdrPtr = &CurrentCweHeader,
    .flashPoolPtr = &FlashImgPool
};

//--------------------------------------------------------------------------------------------------
/**
 * Disable check of sync before update (default false)
 */
//--------------------------------------------------------------------------------------------------
static bool IsSyncBeforeUpdateDisabled = false;

//--------------------------------------------------------------------------------------------------
/**
 * Running a secure boot version
 */
//--------------------------------------------------------------------------------------------------
static bool IsSecureBootVersion = false;

//--------------------------------------------------------------------------------------------------
/**
 * Internal partition table of the allowed partition managed.
 */
//--------------------------------------------------------------------------------------------------
static pa_fwupdate_MtdPartition_t MtdPartTab[] =
{
    { "tz",        { "tz",        "tz",        }, PA_FWUPDATE_SUBSYSID_MODEM, true,  },
    { "rpm",       { "rpm",       "rpm",       }, PA_FWUPDATE_SUBSYSID_MODEM, true,  },
    { "modem",     { "modem",     "modem2",    }, PA_FWUPDATE_SUBSYSID_MODEM, false, },
    { "aboot",     { "aboot",     "aboot2",    }, PA_FWUPDATE_SUBSYSID_LK,    false, },
    { "boot",      { "boot",      "boot2",     }, PA_FWUPDATE_SUBSYSID_LINUX, false, },
    { "system",    { "system",    "system2",   }, PA_FWUPDATE_SUBSYSID_LINUX, false, },
    { "lefwkro",   { "lefwkro",   "lefwkro2",  }, PA_FWUPDATE_SUBSYSID_LINUX, false, },
    { "customer",  { "customer0", "customer1", }, PA_FWUPDATE_SUBSYSID_LINUX, false, },
    { "customer0", { "customer0", "customer0", }, PA_FWUPDATE_SUBSYSID_LINUX, false, },
    { "customer1", { "customer1", "customer1", }, PA_FWUPDATE_SUBSYSID_LINUX, false, },
    { "customer2", { "customer2", "customer2", }, PA_FWUPDATE_SUBSYSID_LINUX, false, },
    { NULL,        { NULL,        NULL,        }, PA_FWUPDATE_SUBSYSID_NONE,  false, },
};

//==================================================================================================
//                                       Private Functions
//==================================================================================================

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
            LE_DEBUG("            currentImageCrc 0x%x totalRead %zu currentOffset 0x%x,",
                     resumeCtxPtr->saveCtx.currentImageCrc,resumeCtxPtr->saveCtx.totalRead,
                     resumeCtxPtr->saveCtx.currentOffset);
            LE_DEBUG("            fullImageLength %zd isFirstNvupDownloaded %d "
                     "isModemDownloaded %d " "ctxCrc 0x%08" PRIx32,
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
    cwe_ImageType_t imageType;
    le_result_t result = LE_OK;

    if (NULL == resumeCtxPtr)
    {
        LE_ERROR("resumeCtxPtr is NULL");
        return LE_FAULT;
    }

    imageType = resumeCtxPtr->saveCtx.imageType;
    // Clear bad image flag before erasing resumeCtx
    result = partition_SetBadImage(imageType, false);
    if (LE_OK != result)
    {
        LE_ERROR("Failed to clear bad image flag for CWE imageType %d", imageType);
    }

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
        if ((result != LE_NOT_FOUND) && (result != LE_OK))
        {
            LE_ERROR("Error when deleting %s: %d", str, result);
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
 * Print OpenSSL errors of SHA256 calculation
 */
//--------------------------------------------------------------------------------------------------
static void PrintOpenSSLErrors
(
    void
)
{
    char errorString[128] = {0};
    unsigned long error;

    // Retrieve the first error and remove it from the queue
    error = ERR_get_error();
    while (0 != error)
    {
        // Convert the error code to a human-readable string and print it
        ERR_error_string_n(error, errorString, sizeof(errorString));
        LE_ERROR("%s", errorString);

        // Retrieve the next error and remove it from the queue
        error = ERR_get_error();
    }
}

//--------------------------------------------------------------------------------------------------
/**
 * Init the SHA256 context pointer
 *
 * @return
 *      - LE_OK             on success
 *      - LE_FAULT          on failure
 *      - LE_BAD_PARAMETER  on parameter invalid
 */
//--------------------------------------------------------------------------------------------------
static le_result_t StartSha256
(
    SHA256_CTX** sha256CtxPtr    ///< [INOUT] SHA1 context pointer
)
{
    static SHA256_CTX sha256Ctx;
    // Check if SHA256 context pointer is set
    if (!sha256CtxPtr)
    {
        LE_ERROR("No SHA256 context pointer");
        return LE_BAD_PARAMETER;
    }

    // Load the error strings
    ERR_load_crypto_strings();

    // Initialize the SHA256 context
    // SHA256_Init function returns 1 for success, 0 otherwise
    if (1 != SHA256_Init(&sha256Ctx))
    {
        LE_ERROR("SHA256_Init failed");
        PrintOpenSSLErrors();
        return LE_FAULT;
    }
    else
    {
        *sha256CtxPtr = &sha256Ctx;
        return LE_OK;
    }
}

//--------------------------------------------------------------------------------------------------
/**
 * Hash input data buffer and update SHA256 digest.
 *
 * @return
 *      - LE_OK             on success
 *      - LE_FAULT          on failure
 *      - LE_BAD_PARAMETER  on parameter invalid
 */
//--------------------------------------------------------------------------------------------------
static le_result_t ProcessSha256
(
    SHA256_CTX*    sha256CtxPtr,     ///< [IN] SHA256 context pointer
    uint8_t* bufPtr,                 ///< [IN] Data buffer to hash
    size_t   len                     ///< [IN] Data buffer length
)
{
    // Check if pointers are set
    if ((!sha256CtxPtr) || (!bufPtr))
    {
        printf("NULL pointer provided\n");
        return LE_BAD_PARAMETER;
    }

    // Update SHA256 digest
    // SHA256_Update function returns 1 for success, 0 otherwise
    if (1 != SHA256_Update(sha256CtxPtr, bufPtr, len))
    {
        printf("SHA256_Update failed\n");
        PrintOpenSSLErrors();
        return LE_FAULT;
    }

    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Finish the SHA256 calculation and get the digest
 *
 * @return
 *      - LE_OK             on success
 *      - LE_FAULT          on failure
 *      - LE_BAD_PARAMETER  on parameter invalid
 */
//--------------------------------------------------------------------------------------------------
static le_result_t EndSha256
(
    SHA256_CTX* sha256CtxPtr,     ///< [IN] SHA256 context pointer
    unsigned char * digestBuf,    ///< [INOUT] SHA256 digest buffer pointer
    size_t bufSize                ///< [IN] SHA256 digest buffer size
)
{
    // Check if pointers are set
    if ((!sha256CtxPtr) || (!digestBuf))
    {
        LE_ERROR("Null pointer provided");
        return LE_BAD_PARAMETER;
    }

    // Check buffer length
    if (bufSize < SHA256_DIGEST_LENGTH)
    {
        LE_ERROR("Buffer is too short (%zu < %d)", bufSize, SHA256_DIGEST_LENGTH);
        return LE_BAD_PARAMETER;
    }

    if (1 != SHA256_Final(digestBuf, sha256CtxPtr))
    {
        printf("SHA256_Final failed\n");
        PrintOpenSSLErrors();
        return LE_FAULT;
    }

    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Restore the SHA256 context
 *
 * @return
 *      - LE_OK             on success
 *      - LE_FAULT          on failure
 *      - LE_BAD_PARAMETER  on parameter invalid
 */
//--------------------------------------------------------------------------------------------------
static le_result_t RestoreSha256
(
    SHA256_CTX*  bufPtr,         ///< [IN] SHA256 context Buffer to restore
    size_t bufSize,              ///< [IN] SHA256 context Buffer size
    SHA256_CTX** sha256CtxPtr    ///< [INOUT] SHA256 context pointer
)
{
    // Check if pointers are set
    if ((!sha256CtxPtr) || (!bufPtr))
    {
        LE_ERROR("Null pointer provided");
        return LE_BAD_PARAMETER;
    }

    // Check buffer length
    if (bufSize < sizeof(SHA256_CTX))
    {
        LE_ERROR("Buffer is too short (%zu < %zd)", bufSize, sizeof(SHA256_CTX));
        return LE_BAD_PARAMETER;
    }

    // Initialize SHA256 context
    if (LE_OK != StartSha256(sha256CtxPtr))
    {
        LE_ERROR("Unable to initialize SHA256 context");
        return LE_FAULT;
    }

    // Restore the SHA256 context
    memcpy(*sha256CtxPtr, bufPtr, sizeof(SHA256_CTX));
    return LE_OK;
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

        if (LE_OK == result)
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

            if (LE_OK == result)
            {// a valid context has been found
                // save the current fileIndex
                resumeCtxPtr->fileIndex = idx;

                memcpy(&resumeCtxPtr->saveCtx, currentCtxSave, sizeof(resumeCtxPtr->saveCtx));

                LE_DEBUG("resumeCtx: ctxCounter %d, imageType %d, imageSize %d, imageCrc 0x%x,",
                         resumeCtxPtr->saveCtx.ctxCounter, resumeCtxPtr->saveCtx.imageType,
                         resumeCtxPtr->saveCtx.imageSize, resumeCtxPtr->saveCtx.imageCrc);
                LE_DEBUG("           currentImageCrc 0x%08" PRIx32 "totalRead %zu "
                         "currentOffset 0x%08" PRIx32,
                         resumeCtxPtr->saveCtx.currentImageCrc,resumeCtxPtr->saveCtx.totalRead,
                         resumeCtxPtr->saveCtx.currentOffset);
                LE_DEBUG("           fullImageLength %zd isFirstNvupDownloaded %d "
                         "isModemDownloaded %d ctxCrc 0x%08" PRIx32,
                         resumeCtxPtr->saveCtx.fullImageLength,
                         resumeCtxPtr->saveCtx.isFirstNvupDownloaded,
                         resumeCtxPtr->saveCtx.isModemDownloaded, resumeCtxPtr->saveCtx.ctxCrc);
            }
            else
            {// no valid context found => re-initialize them
                result = EraseResumeCtx(resumeCtxPtr);
                if (LE_OK == result)
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
 * This function requests the access to flash update
 *
 * @return
 *      - LE_OK            The access is granted to fwupdate and update can begin
 *      - LE_UNAVAILABLE   The access is not granted because flash is in use
 *      - LE_FAULT         If an error occurs
 */
//--------------------------------------------------------------------------------------------------
static le_result_t RequestSwUpdate
(
    void
)
{
    le_result_t res;

    // Request the SW update access to flash
    res = pa_fwupdate_RequestUpdate();
    if (LE_UNAVAILABLE == res)
    {
        // SW update is not allowed to access to the flash
        LE_CRIT("access to flash not granted");
    }
    else if (LE_OK != res)
    {
        LE_ERROR("not possible to request SW update");
    }
    else
    {
        // Access is granted
        LE_DEBUG("SW update has access granted");
    }
    return res;
}

//--------------------------------------------------------------------------------------------------
/**
 * This function releases the access to flash update
 */
//--------------------------------------------------------------------------------------------------
static void ReleaseSwUpdate
(
    void
)
{
    // Complete. Release the flash access
    pa_fwupdate_CompleteUpdate();
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
    const cwe_Header_t* hdrPtr,   ///< [IN] Component image header
    size_t length,                ///< [IN] Input data length
    size_t offset,                ///< [IN] Data offset in the package
    const uint8_t* dataPtr,       ///< [IN] input data
    bool forceClose,              ///< [IN] Force close of device and resources
    bool *isFlashedPtr            ///< [OUT] true if flash write was done
)
{
    static size_t  ImageSize = 0;
    le_result_t result;
    bool isEnd;

    if ((false == ResumeCtx.saveCtx.isFirstNvupDownloaded) || forceClose)
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
    LE_DEBUG("length=%zu offset=%zu", length, offset);

    if ((0 == ImageSize) && (0 == offset))
    {
        // write the CWE header
        result = pa_fwupdate_NvupWrite(CWE_HEADER_SIZE, CweHeaderRaw, false);
        if (result != LE_OK)
        {
            LE_ERROR("Failed to write NVUP CWE header!");
            return LE_FAULT;
        }

        // initialize data phase
        ImageSize = hdrPtr->imageSize;
        LE_DEBUG("ImageSize=%zu", ImageSize);
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
 * Write CUSG image into CusgPathPtr
 *
 * @return
 *      - LE_OK             on success
 *      - LE_FAULT          on failure
 */
//--------------------------------------------------------------------------------------------------
static le_result_t WriteCusg
(
    const cwe_Header_t* hdrPtr,   ///< [IN] Component image header
    size_t length,                ///< [IN] Input data length
    size_t offset,                ///< [IN] Data offset in the package
    const uint8_t* dataPtr,       ///< [IN] Input data
    bool forceClose,              ///< [IN] Force close of device and resources
    bool *isFlashedPtr            ///< [OUT] True if flash write was done
)
{
    // Create a new file containing the patch body
    static int cusgFd = -1;
    int writeTry = 5;
    int writeLength = 0;
    int writeResult = 0;

    if (forceClose)
    {
        return LE_OK;
    }

    if (-1 == cusgFd)
    {
        cusgFd = open(CusgPathPtr, O_TRUNC | O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);

        if (-1 == cusgFd)
        {
            LE_CRIT("Failed to create CUSG image: %m");
            goto error;
        }
    }

    LE_DEBUG("Download length %zu offset %zu total %"PRIu32"", length, offset, hdrPtr->imageSize);

    //bypass download failed.
    if (0 == length)
    {
        return LE_OK;
    }

    while(writeTry > 0)
    {
        writeResult = write(cusgFd, dataPtr+writeLength, length-writeLength);
        if (writeResult < 0)
        {
            if(EINTR == errno)
            {
                LE_ERROR("Write to image file interrupted, retry: %m");
            }
            else
            {
                LE_ERROR("Write to image file failed: %m");
                writeTry = 0;
                break;
            }
        }
        else
        {
            writeLength += writeResult;
            if (writeLength == length)
            {
                //write length bytes finish
                break;
            }
        }
        writeTry--;
    }

    if(0 == writeTry)
    {
        LE_ERROR("Write %zu bytes to image file fails: %m", length);
        close(cusgFd);
        unlink(CusgPathPtr);
        cusgFd = -1;
        goto error;
    }

    if ((length + offset) >= hdrPtr->imageSize)
    {
        LE_INFO("Write finish");
        close(cusgFd);
        cusgFd = -1;

        if (isFlashedPtr)
        {
            *isFlashedPtr = true;
        }
    }

    return LE_OK;

error:
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
    const cwe_Header_t* hdrPtr,   ///< [IN] Component image header
    size_t length,                ///< [IN] Input data length
    size_t offset,                ///< [IN] Data offset in the package
    const uint8_t* dataPtr,       ///< [IN] input data
    bool forceClose,              ///< [IN] Force close of device and resources
    bool *isFlashedPtr            ///< [OUT] true if flash write was done
)
{
    le_result_t ret = LE_OK;

    if (!forceClose)
    {
        LE_DEBUG ("image type %"PRIu32" len %zu offset 0x%zx", hdrPtr->imageType, length, offset);
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
            ret = partition_WriteDataSBL(&PartitionCtx, length, offset, dataPtr, forceClose,
                                         isFlashedPtr);
            break;

        //save the CUSG image as a file
        case CWE_IMAGE_TYPE_CUSG:
            ret = WriteCusg(hdrPtr, length, offset, dataPtr, forceClose, isFlashedPtr);
            break;

        default:
            // Delta patch
            if (hdrPtr->miscOpts & CWE_MISC_OPTS_DELTAPATCH)
            {
                LE_INFO( "Applying delta patch to %u\n", hdrPtr->imageType );
                ret = deltaUpdate_ApplyPatch(&DeltaUpdateCtx,length, offset, dataPtr, forceClose,
                                             isFlashedPtr);
            }
            else
            {
                ret = partition_WriteUpdatePartition(&PartitionCtx, length, offset, dataPtr,
                                                     forceClose, isFlashedPtr);
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
    bool isResume,                  ///< [IN] true if we're a resuming
    ResumeCtxSave_t *saveCtxPtr     ///< [INOUT] resume context
)
{
    LE_DEBUG ("InitParameters, isResume=%d", isResume);
    if (isResume)
    {
        DeltaUpdateCtx.patchRemLen = saveCtxPtr->patchHdr.size;
        CurrentImageOffset = saveCtxPtr->currentOffset;
        CurrentImageCrc32 = saveCtxPtr->currentImageCrc;
        CurrentGlobalCrc32 = saveCtxPtr->currentGlobalCrc;
        CurrentCweHeader.imageType = saveCtxPtr->imageType;
        CurrentCweHeader.imageSize = saveCtxPtr->imageSize;
        CurrentCweHeader.crc32 = saveCtxPtr->imageCrc;
        CurrentCweHeader.miscOpts = saveCtxPtr->miscOpts;
        IsFirstDataWritten = true;
        RestoreSha256(&(saveCtxPtr->sha256Ctx), sizeof(saveCtxPtr->sha256Ctx),
                      &ResumeCtx.sha256CtxPtr);
    }
    else
    {
        CurrentImageOffset = 0;
        CurrentImageCrc32 = LE_CRC_START_CRC32;
        CurrentGlobalCrc32 = LE_CRC_START_CRC32;
        memset(&CurrentCweHeader, 0, sizeof(CurrentCweHeader));
        saveCtxPtr->isImageToBeRead = false;
        IsFirstDataWritten = false;
        saveCtxPtr->fullImageLength = -1;
        // erase the diffType to allow to detect a new Patch Meta header
        memset(saveCtxPtr->patchMetaHdr.diffType, 0, sizeof(saveCtxPtr->patchMetaHdr.diffType));
    }
}

//--------------------------------------------------------------------------------------------------
/**
 * This function indicates the data length to be read according to data type to be read
 *
 * @return
 *      - data length to be read
 *      - -1 on error
 */
//--------------------------------------------------------------------------------------------------
static ssize_t LengthToRead
(
    ResumeCtxSave_t *saveCtxPtr     ///< [IN] resume context
)
{
    ssize_t readCount = 0;

    if (CurrentCweHeader.miscOpts & CWE_MISC_OPTS_DELTAPATCH)
    {
        readCount = deltaUpdate_GetPatchLengthToRead(&DeltaUpdateCtx, CHUNK_LENGTH,
                                                     saveCtxPtr->isImageToBeRead);
    }
    else
    {
        if (false == saveCtxPtr->isImageToBeRead)
        {
            // a header can be fully read
            readCount = CWE_HEADER_SIZE;
        }
        else
        {
            /* A component image can be read
               Check if whole component image can be filled in a data chunk */
            if ((CurrentCweHeader.imageSize - CurrentImageOffset) > CHUNK_LENGTH)
            {
                readCount = CHUNK_LENGTH;
            }
            else
            {
                readCount = CurrentCweHeader.imageSize - CurrentImageOffset;
            }
        }
    }
    LE_DEBUG("readCount=%zd", readCount);
    return readCount;
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
    cwe_Header_t* cweHeaderPtr, ///< [INOUT] CWE header linked to image data
    const uint8_t* chunkPtr,    ///< [IN]Data to be written in flash partition
    size_t length,              ///< [IN]Data length to be written in flash partition
    ResumeCtx_t* resumeCtxPtr   ///< [INOUT] resume context
)
{
    size_t result = 0;
    bool isFlashed;

    /* Check incoming parameters */
    if ((NULL == cweHeaderPtr) || (NULL == resumeCtxPtr))
    {
        LE_ERROR ("bad parameters");
        return 0;
    }

    LE_DEBUG ("imagetype %d, CurrentImageOffset 0x%zx length %zu, CurrentImageSize %d",
              cweHeaderPtr->imageType,
              CurrentImageOffset,
              length,
              cweHeaderPtr->imageSize);

    /* Check incoming parameters */
    if ((NULL == chunkPtr) || (length > CHUNK_LENGTH))
    {
        LE_ERROR ("bad parameters");
        result = 0;
    }
    else
    {
        static size_t LenToFlash = 0;
        ResumeCtxSave_t *saveCtxPtr = &resumeCtxPtr->saveCtx;

        if(!resumeCtxPtr->sha256CtxPtr)
        {
            if (LE_OK != StartSha256(&resumeCtxPtr->sha256CtxPtr))
            {
                LE_ERROR("Unable to initialize SHA256 context");
                return 0;
            }
        }

        // There are 3 cases where (saveCtxPtr->currentOffset == CurrentImageOffset):
        // 1. Data actually written to the flash and ResumeCtx updated (isFlashed == true)
        // 2. New download case, set in InitParameters()
        // 3. Download resume case, set in InitParameters()
        // Case 1 is already handled in the following, and in this case LenToFlash == 0.
        // For cases 2 and 3, there is a possibility that the download was previously suspended or
        // stopped, leaving LenToFlash != 0. In these cases, LenToFlash should be cleared here to
        // keep correct calculation of ResumeCtx (saveCtxPtr->totalRead).
        if ((saveCtxPtr->currentOffset == CurrentImageOffset) && LenToFlash)
        {
            LE_DEBUG ("Clear LenToFlash %zu in a new download cycle", LenToFlash);
            LenToFlash = 0;
        }

        if (LE_OK == WriteData (cweHeaderPtr,
                                length,
                                CurrentImageOffset,
                                chunkPtr,
                                false,
                                &isFlashed))
        {
            CurrentGlobalCrc32 = le_crc_Crc32((uint8_t*)chunkPtr, length, CurrentGlobalCrc32);
            CurrentImageCrc32 = le_crc_Crc32((uint8_t*)chunkPtr, length, CurrentImageCrc32);
            LE_DEBUG ( "image data write: CRC in header: 0x%x, calculated CRC 0x%x",
                       cweHeaderPtr->crc32, CurrentImageCrc32 );
            CurrentImageOffset += length;
            LenToFlash += length;
            result = length;

            if ((cweHeaderPtr->imageType != CWE_IMAGE_TYPE_CUSG)
             && (cweHeaderPtr->imageType != CWE_IMAGE_TYPE_FILE))
            {
                // SHA256 digest is updated with all image data
                if (LE_OK != ProcessSha256(resumeCtxPtr->sha256CtxPtr,(uint8_t*)chunkPtr, length))
                {
                    LE_ERROR("Unable to update SHA256 digest");
                    return 0;
                }
            }

            LE_DEBUG ("CurrentImageOffset %zu", CurrentImageOffset);
            if (isFlashed)
            {// some data have been flashed => update the resume context
                le_result_t ret;

                LE_DEBUG("Store resume context ...");

                if (cweHeaderPtr->miscOpts & CWE_MISC_OPTS_DELTAPATCH)
                {
                    // a patch has been completely received => wait a new header
                    saveCtxPtr->isImageToBeRead = false;
                }
                saveCtxPtr->currentImageCrc = CurrentImageCrc32;
                saveCtxPtr->currentGlobalCrc = CurrentGlobalCrc32;
                saveCtxPtr->totalRead += LenToFlash;
                LenToFlash = 0;
                saveCtxPtr->currentOffset = CurrentImageOffset;

                //save new ctx to buf before update resume ctx
                memcpy(&(saveCtxPtr->sha256Ctx), resumeCtxPtr->sha256CtxPtr,
                    sizeof(saveCtxPtr->sha256Ctx));

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

        /* Check if it's the 1st data write for this package */
        if ((false == IsFirstDataWritten) && isFlashed)
        {
            if (false == IsSyncBeforeUpdateDisabled)
            {
                /* Update the partition synchronization state */
                pa_fwupdate_SetUnsyncState();
            }
            IsFirstDataWritten = true;
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
                // Clear bad image flag
                if (LE_OK != partition_SetBadImage(cweHeaderPtr->imageType, false))
                {
                    LE_ERROR("Failed to clear bad image flag for CWE imageType %d",
                             cweHeaderPtr->imageType);
                    result = 0;
                }

                // erase the path flag in options to allow new cwe header to be read
                cweHeaderPtr->miscOpts &= (uint8_t)~((uint8_t)CWE_MISC_OPTS_DELTAPATCH);
                LE_DEBUG ("CurrentImageOffset %zu, CurrentImage %d",
                          CurrentImageOffset, cweHeaderPtr->imageType);
            }
            resumeCtxPtr->saveCtx.isImageToBeRead = false;
        }
    }

    LE_DEBUG ("result %d", (uint32_t)result);
    return result;
}

//--------------------------------------------------------------------------------------------------
/**
 * Parse CWE header
 *
 * @return
 *      - LE_OK            On success
 *      - LE_BAD_PARAMETER The parameter is invalid
 *      - LE_FAULT         On failure
 */
//--------------------------------------------------------------------------------------------------
static le_result_t ParseCweHeader
(
    const uint8_t* chunkPtr,    ///< [IN] input data
    ResumeCtx_t *resumeCtxPtr   ///< [OUT] resume context
)
{
    le_result_t result;

    if ((NULL == chunkPtr) || (NULL == resumeCtxPtr))
    {
        LE_ERROR("Bad parameter");
        return LE_BAD_PARAMETER;
    }

    result = cwe_LoadHeader (chunkPtr, &CurrentCweHeader);
    if (result != LE_OK)
    {
        LE_ERROR ("Error in parsing the CWE header");
        return LE_FAULT;
    }

    ResumeCtxSave_t *saveCtxPtr = &(resumeCtxPtr->saveCtx);

    LE_DEBUG ("CWE header read ok");
    if (-1 == saveCtxPtr->fullImageLength)
    {
        /*
         * Full length and global CRC of the CWE image is provided inside the
         * first CWE header
         */
        saveCtxPtr->fullImageLength = CurrentCweHeader.imageSize + CWE_HEADER_SIZE;
        saveCtxPtr->globalCrc = CurrentCweHeader.crc32;
        saveCtxPtr->currentGlobalCrc = LE_CRC_START_CRC32;
        LE_DEBUG("New CWE: fullImageLength = %zd, CRC=0x%08" PRIx32, saveCtxPtr->fullImageLength,
                 saveCtxPtr->globalCrc);
    }
    else
    {
        // update the current global CRC with the current header
        CurrentGlobalCrc32 = le_crc_Crc32((uint8_t*)chunkPtr, CWE_HEADER_SIZE, CurrentGlobalCrc32);
        saveCtxPtr->currentGlobalCrc = CurrentGlobalCrc32;
    }

    /* Check the value of the CurrentCweHeader.imageType which is proceed
     * If the image type is a composite one, the next data is a CWE header
     */
    if ((CurrentCweHeader.imageType != CWE_IMAGE_TYPE_APPL)
        && (CurrentCweHeader.imageType != CWE_IMAGE_TYPE_MODM)
        && (CurrentCweHeader.imageType != CWE_IMAGE_TYPE_SPKG)
        && (CurrentCweHeader.imageType != CWE_IMAGE_TYPE_BOOT))
    {
        if (!(CurrentCweHeader.miscOpts & CWE_MISC_OPTS_DELTAPATCH))
        {
            /* Next data will concern a component image */
            saveCtxPtr->isImageToBeRead = true;
        }
        CurrentImageOffset = 0;
        CurrentImageCrc32 = LE_CRC_START_CRC32;
        /* save the resume context */
        saveCtxPtr->imageType = CurrentCweHeader.imageType;
        saveCtxPtr->imageSize = CurrentCweHeader.imageSize;
        saveCtxPtr->imageCrc = CurrentCweHeader.crc32;
        saveCtxPtr->miscOpts = CurrentCweHeader.miscOpts;
        saveCtxPtr->currentImageCrc = LE_CRC_START_CRC32;
        saveCtxPtr->currentOffset = 0;
    }

    if (CWE_IMAGE_TYPE_FILE == CurrentCweHeader.imageType)
    {
        // cwe header must be save because it'll be necessary to send it to the
        // modem later
        memcpy(CweHeaderRaw, chunkPtr, CWE_HEADER_SIZE);
    }
    if (CWE_IMAGE_TYPE_MODM == CurrentCweHeader.imageType)
    {
        saveCtxPtr->isModemDownloaded = true;
    }
    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Parse patch headers
 *
 * @return
 *      - LE_OK            On success
 *      - LE_BAD_PARAMETER The parameter is invalid
 *      - LE_FAULT         On failure
 */
//--------------------------------------------------------------------------------------------------
static le_result_t ParsePatchHeaders
(
    size_t length,              ///< [IN] Input data length
    const uint8_t* chunkPtr,    ///< [IN] input data
    ResumeCtx_t *resumeCtxPtr   ///< [OUT] resume context
)
{
    if ((NULL == chunkPtr) || (NULL == resumeCtxPtr))
    {
        LE_ERROR("Bad parameter");
        return LE_BAD_PARAMETER;
    }

    le_result_t res = (PATCH_META_HEADER_SIZE == length) ?
        deltaUpdate_LoadPatchMetaHeader(chunkPtr, &resumeCtxPtr->saveCtx.patchMetaHdr) :
        deltaUpdate_LoadPatchHeader(chunkPtr, &DeltaUpdateCtx);
    if (LE_OK != res)
    {
        LE_ERROR ("Error in parsing the Patch Meta or Patch header");
        return LE_FAULT;
    }

    LE_DEBUG ("Patch Meta or Patch header read ok");

    ResumeCtxSave_t *saveCtxPtr = &(resumeCtxPtr->saveCtx);
    CurrentImageOffset += length;
    saveCtxPtr->currentOffset = CurrentImageOffset;
    CurrentImageCrc32 = le_crc_Crc32((uint8_t*)chunkPtr, length, CurrentImageCrc32);
    saveCtxPtr->currentImageCrc = CurrentImageCrc32;
    CurrentGlobalCrc32 = le_crc_Crc32((uint8_t*)chunkPtr, length, CurrentGlobalCrc32);
    saveCtxPtr->currentGlobalCrc = CurrentGlobalCrc32;
    LE_DEBUG ( "patch header: CRC in header: 0x%x, calculated CRC 0x%x",
               CurrentCweHeader.crc32, CurrentImageCrc32 );

    if (PATCH_HEADER_SIZE == length)
    {
        // Next data will concern a component image
        resumeCtxPtr->saveCtx.isImageToBeRead = true;
    }
    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * This function is used by the Legato SW Update component to parse and store an incoming package
 *
 * @return
 *      - LE_OK            The request was accepted
 *      - LE_BAD_PARAMETER The parameter is invalid
 *      - LE_UNAVAILABLE   The action is not compliant with the SW update state (no downloaded pkg)
 *      - LE_FAULT         If an error occurs
 */
//--------------------------------------------------------------------------------------------------
static le_result_t ParseAndStoreData
(
    size_t length,              ///< [IN] Input data length
    const uint8_t* chunkPtr,    ///< [IN] input data
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
        LE_DEBUG ("parsing a chunkPtr: len %zd, isImageToBeRead %d",
                  length, resumeCtxPtr->saveCtx.isImageToBeRead);

        /* Check if a header is read or a component image */
        if (false == resumeCtxPtr->saveCtx.isImageToBeRead)
        {
            /* For a header, the full header shall be provided */
            switch (length)
            {
                case CWE_HEADER_SIZE:
                    result = ParseCweHeader(chunkPtr, resumeCtxPtr);
                    break;

                case PATCH_META_HEADER_SIZE:
                case PATCH_HEADER_SIZE:
                    result = ParsePatchHeaders(length, chunkPtr, resumeCtxPtr);
                    break;

                default:
                    LE_ERROR ("Bad length for header %d", (uint32_t)length);
                    result = LE_BAD_PARAMETER;
                    break;
            }
            if (LE_OK == result)
            {
                resumeCtxPtr->saveCtx.totalRead += length;
                result = UpdateResumeCtx(resumeCtxPtr);
                if (result != LE_OK)
                {
                    LE_WARN("Failed to save the resume ctx");
                }
            }
        }
        else
        {
            /* Component image is under read: follow it */
            if (WriteImageData (&CurrentCweHeader, chunkPtr, length, resumeCtxPtr))
            {
                /* Parsing succeeds */
                result = LE_OK;
            }
            else
            {
                /* Parsing fails */
                LE_DEBUG("Parsing failed");
                result = LE_FAULT;
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
    if ((LE_OK == result) && sync)
    {
        /* Make a sync operation */
        result = pa_fwupdate_MarkGood();
        if (result != LE_OK)
        {
            LE_ERROR ("FW update component init: Sync failure %d", result);
        }
    }
}

//--------------------------------------------------------------------------------------------------
/**
 * Wait EPOLLIN before read
 *
 * @return
 *      - LE_OK             On success
 *      - LE_TIMEOUT        After DEFAULT_TIMEOUT without data received
 *      - LE_CLOSED         The file descriptor has been closed
 *      - LE_FAULT          On failure
 */
//--------------------------------------------------------------------------------------------------
static le_result_t EpollinRead
(
    int fd,             ///< [IN] file descriptor
    int efd,            ///< [IN] event file descriptor
    void* bufferPtr,    ///< [OUT] pointer where to store data
    ssize_t *lengthPtr  ///< [INOUT] input: max length to read,
                        ///<         output: read length (if LE_OK)
)
{
    while(1)
    {
        int n;
        struct epoll_event events[MAX_EVENTS];

        if (-1 == efd)
        {
            // fd is a regular file, not compliant with epoll, simulate it
            n = 1;
            events[0].events = EPOLLIN;
            events[0].data.fd = fd;
        }
        else
        {
            n = epoll_wait(efd, events, sizeof(events), DEFAULT_TIMEOUT_MS);
            LE_DEBUG("n=%d", n);
        }
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
                        else if (evts & EPOLLIN)
                        {
                            *lengthPtr = read (fd, bufferPtr, *lengthPtr);
                            LE_DEBUG("read %zd bytes", *lengthPtr);
                            if (0 == *lengthPtr)
                            {
                                return LE_CLOSED;
                            }
                            return LE_OK;
                        }
                        else if ((evts & EPOLLRDHUP ) || (evts & EPOLLHUP))
                        {
                            // file descriptor has been closed
                            LE_INFO("file descriptor %d has been closed", fd);
                            return LE_CLOSED;
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
    void* bufferPtr,    ///< [OUT] pointer where to store data
    ssize_t *lengthPtr  ///< [INOUT] input: max length to read,
                        ///<         output: read length (if LE_OK),
                        ///<                 if -1 then check errno (see read(2))
)
{
    ssize_t size = read(fd, bufferPtr, *lengthPtr);
    if (((-1 == size) && (EAGAIN == errno)) || (0 == size))
    {
        return EpollinRead(fd, efd, bufferPtr, lengthPtr);
    }
    *lengthPtr = size;

    return LE_OK;
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
    if (-1 == fcntl(fd, F_SETFL, flags | O_NONBLOCK))
    {
        LE_ERROR("Fails to SETFL fd %d: %m", fd);
        return LE_FAULT;
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
    if (-1 == efd)
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

//--------------------------------------------------------------------------------------------------
/**
 * Prepare the file descriptor to be used for download
 *
 * @return
 *      - LE_OK             On success
 *      - LE_FAULT          On failure
 */
//--------------------------------------------------------------------------------------------------
static le_result_t PrepareFd
(
    int  fd,            ///< [IN] file descriptor
    bool isRegularFile, ///< [IN] flag to indicate if the file descriptor is related to a regular
                        ///<      file or not
    int* efdPtr         ///< [OUT] event file descriptor
)
{
    /* Like we use epoll(2), force the O_NONBLOCK flags in fd */
    if (LE_OK != MakeFdNonBlocking(fd))
    {
        return LE_FAULT;
    }

    if (!isRegularFile)
    {
        if (LE_OK != CreateAndConfEpoll(fd, efdPtr))
        {
            return LE_FAULT;
        }
    }

    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Check the file descriptor type
 *
 * @return
 *      - LE_OK             If fd is socket, pipe or regular file
 *      - LE_FAULT          On other file descriptor type
 */
//--------------------------------------------------------------------------------------------------
static le_result_t CheckFdType
(
    int fd,                     ///< [IN] file descriptor to test
    bool *isRegularFilePtr      ///< [OUT] true if fd is a regular file
)
{
    struct stat buf;

    if (-1 == fstat(fd, &buf))
    {
        LE_ERROR("fstat error %m");
        return LE_FAULT;
    }

    switch (buf.st_mode & S_IFMT)
    {
        case 0:       // unknown type
        case S_IFDIR: // directory
        case S_IFLNK: // link
            LE_ERROR("Bad file descriptor type 0x%x", buf.st_mode & S_IFMT);
            return LE_FAULT;

        case S_IFIFO:  // fifo or pipe
        case S_IFSOCK: // socket
            LE_DEBUG("Socket, fifo or pipe");
            *isRegularFilePtr = false;
            break;

        default:
            LE_DEBUG("Regular file");
            *isRegularFilePtr = true;
            break;
    }

    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Check DM verity integrity of a MTD partition.
 *
 * @return
 *      - LE_OK             The DM-verity integrity succeeded
 *      - LE_FORMAT_ERROR   The partition is not an UBI container. Cannot check DM-verity integrity
 *      - LE_NOT_PERMITTED  The DM-verity integrity check failed or cannot authentify the root hash
 *      - others            Depending on the MTD/UBI PA access
 */
//--------------------------------------------------------------------------------------------------
static le_result_t CheckDmVerityIntegrity
(
    int mtdSrc   ///< [IN] MTD number to be checked
)
{
    le_result_t res;
    int ubiId, nbUbiVol;

    res = partition_CheckIfUbiAndGetUbiVolumes( mtdSrc, &ubiId, &nbUbiVol );
    // Do not test for other error code. Just report them to the caller
    if (LE_OK != res)
    {
        return res;
    }

    if (MAX_UBI_VOL_FOR_DM_VERITY <= nbUbiVol)
    {
        // Assume that if there are at least 3 volumes, the image belongs in volume 0
        // with a volume name "....", the hash into volume 1 with a name "...._hs" and
        // the root hash in volume 2 with a name "...._rhs"
        char ubiTmpStr[PATH_MAX];
        char ubiVol0Str[PATH_MAX];
        FILE* ubiNameFdPtr;
        int ubiDmVerity = 0, ubiVol0NameLen = 0, ubiTmpNameLen, ubiIndex;
        int rc;
        char* ubiVolSuffix[MAX_UBI_VOL_FOR_DM_VERITY] = { NULL, "_hs", "_rhs" };
        char* rcPtr;

        snprintf(ubiTmpStr, sizeof(ubiTmpStr), SYS_UBI_VOLUME_NAME_PATH, ubiId, 0);
        ubiNameFdPtr = fopen(ubiTmpStr, "r");
        *ubiVol0Str = '\0';
        if (ubiNameFdPtr)
        {
            rcPtr = fgets(ubiVol0Str, sizeof(ubiVol0Str), ubiNameFdPtr);
            fclose(ubiNameFdPtr);
            if (rcPtr)
            {
                ubiDmVerity++;
                ubiVol0NameLen = strlen(ubiVol0Str);
                if ((ubiVol0NameLen > 1) && ('\n' == ubiVol0Str[ubiVol0NameLen - 1]))
                {
                    ubiVol0Str[ubiVol0NameLen - 1] = '\0';
                    ubiVol0NameLen--;
                }
            }
        }
        else
        {
            // Do not raise error if the UBI volume name entry could not be opened as
            // the volume index may be any integer between 0 and 127
        }

        for (ubiIndex = 1;
             (ubiDmVerity) && (ubiIndex < MAX_UBI_VOL_FOR_DM_VERITY);
             ubiIndex++)
        {
            snprintf(ubiTmpStr, sizeof(ubiTmpStr), SYS_UBI_VOLUME_NAME_PATH,
                     ubiId, ubiIndex);
            ubiNameFdPtr = fopen(ubiTmpStr, "r");
            *ubiTmpStr = '\0';
            if (ubiNameFdPtr)
            {
                rcPtr = fgets(ubiTmpStr, sizeof(ubiTmpStr), ubiNameFdPtr);
                fclose(ubiNameFdPtr);
                if (rcPtr)
                {
                    ubiTmpNameLen = strlen(ubiTmpStr);
                    if ((ubiTmpNameLen > 1) && ('\n' == ubiTmpStr[ubiTmpNameLen - 1]))
                    {
                        ubiTmpStr[ubiTmpNameLen - 1] = '\0';
                        ubiTmpNameLen--;
                    }
                    if ((ubiVol0NameLen < ubiTmpNameLen) &&
                        (0 == strncmp(ubiVol0Str, ubiTmpStr, ubiVol0NameLen)) &&
                        (0 == strcmp(ubiTmpStr + ubiVol0NameLen, ubiVolSuffix[ubiIndex])))
                    {
                        // Naming matches!
                        ubiDmVerity++;
                    }
                }
            }
            else
            {
                // Do not raise error if the UBI volume name entry could not be opened as
                // the volume index may be any integer between 0 and 127
            }
        }

        // If all expected volume names match expected naming for DM-verity, perform the
        // integrity check on the UBI images/hash/root hash
        if (MAX_UBI_VOL_FOR_DM_VERITY == ubiDmVerity)
        {
            // Need another 4th volume on UBI for this authentication
            if ((IsSecureBootVersion) && (MAX_UBI_VOL_FOR_DM_VERITY < nbUbiVol))
            {
                // Secure boot: Need to authentify the root hash of the UBI partition
                snprintf(ubiTmpStr, sizeof(ubiTmpStr), SWI_AUTH_PATH " nfuse ubi%d",
                         ubiId);
                rc = system(ubiTmpStr);
                if (WIFEXITED(rc) && (SWI_AUTH_SIGNATURE_SUCCEED == WEXITSTATUS(rc)))
                {
                    LE_INFO("Root hash authenfication succeed");
                }
                else
                {
                    LE_ERROR("Unable to authentify the root hash for mtd%d ubi%d: 0x%08x"
                             " Synchronize aborted.",
                             mtdSrc, ubiId, rc);
                    return LE_NOT_PERMITTED;
                }
            }

            LE_INFO("Checking DM-verity integrity on ubi%d", ubiId);
            snprintf(ubiTmpStr, sizeof(ubiTmpStr),
                     "/usr/sbin/veritysetup verify /dev/ubiblock%d_0 /dev/ubiblock%d_1 "
                     "$(cat /dev/ubi%d_2)",
                     ubiId, ubiId, ubiId);
            rc = system(ubiTmpStr);
            if ((0 != WEXITSTATUS(rc)) || (0 != WIFSIGNALED(rc)))
            {
                LE_ERROR("DM Verity check failed for mtd%d ubi%d: 0x%08x."
                         " Synchronize aborted.",
                         mtdSrc, ubiId, rc);
                return LE_NOT_PERMITTED;
            }
        }
    }
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
 *      - LE_UNAVAILABLE    the flash access is not granted for SW update
 *      - LE_FAULT          on failure
 *      - LE_IO_ERROR       on unrecoverable ECC errors detected on active partition
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_fwupdate_MarkGood
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
    static const cwe_ImageType_t syncPartition[] = {
        CWE_IMAGE_TYPE_DSP2,
        CWE_IMAGE_TYPE_QRPM,
        CWE_IMAGE_TYPE_TZON,
        CWE_IMAGE_TYPE_APBL,
        CWE_IMAGE_TYPE_APPS,
        CWE_IMAGE_TYPE_SYST,
        CWE_IMAGE_TYPE_USER,
        CWE_IMAGE_TYPE_CUS0,
    };
    uint8_t iniBootSystem[PA_FWUPDATE_SUBSYSID_MAX], dualBootSystem[PA_FWUPDATE_SUBSYSID_MAX];
    int mtdSrc, mtdDst;
    int idx;
    pa_flash_Desc_t flashFdSrc = NULL, flashFdDst = NULL;
    pa_flash_Info_t *flashInfoSrcPtr, *flashInfoDstPtr;
    pa_flash_EccStats_t flashEccStats;
    char* mtdSrcNamePtr;
    char* mtdDstNamePtr;
    uint8_t* flashBlockPtr = NULL;
    uint32_t crc32Src, dataLen;
    bool isLogicalSrc, isLogicalDst, isDualSrc, isDualDst, isUbiPartition, isRetryNeeded;
    pa_fwupdate_InternalStatus_t internalUpdateStatus;
    le_result_t res, returnedRes = LE_FAULT;

    if (LE_OK != partition_GetInitialBootSystem(iniBootSystem))
    {
        return LE_FAULT;
    }
    dualBootSystem[PA_FWUPDATE_SUBSYSID_MODEM] = !iniBootSystem[PA_FWUPDATE_SUBSYSID_MODEM];
    dualBootSystem[PA_FWUPDATE_SUBSYSID_LK] = !iniBootSystem[PA_FWUPDATE_SUBSYSID_LK];
    dualBootSystem[PA_FWUPDATE_SUBSYSID_LINUX] = !iniBootSystem[PA_FWUPDATE_SUBSYSID_LINUX];

    // Request the SW update access to flash
    res = RequestSwUpdate();
    if( LE_OK != res )
    {
        return res;
    }

    // erase the resume context files
    if (LE_OK != EraseResumeCtx(&ResumeCtx))
    {
        LE_ERROR("Error during EraseResumeCtx()");
        goto error;
    }

    le_result_t result = ReadDwlStatus(&internalUpdateStatus);
    if ((LE_OK != result) ||
        ((LE_OK == result) && (
        (PA_FWUPDATE_INTERNAL_STATUS_DWL_ONGOING == internalUpdateStatus) ||
        (PA_FWUPDATE_INTERNAL_STATUS_DWL_TIMEOUT == internalUpdateStatus))))
    {
        RECORD_DWL_STATUS(PA_FWUPDATE_INTERNAL_STATUS_UNKNOWN);
    }

    // Set the system as Out-Of-Sync. If the synchronization fails, the system MUST be
    // seen as Out-Of-Sync.
    if (LE_OK != pa_fwupdate_SetUnsyncState() )
    {
        LE_CRIT ("Failed to mark system as Out-Of-Sync");
        goto error;
    }

    // Set the Sw update state in SSDATA to SYNC
    if (LE_OK != pa_fwupdate_SetState(PA_FWUPDATE_STATE_SYNC))
    {
        LE_ERROR ("Not possible to update the SW update state to SYNC");
        goto error;
    }

    flashBlockPtr = (uint8_t *) le_mem_ForceAlloc(FlashImgPool);

    LE_INFO( "Synchronizing from sub system MODEM from %d to %d",
             iniBootSystem[PA_FWUPDATE_SUBSYSID_MODEM] + 1,
             dualBootSystem[PA_FWUPDATE_SUBSYSID_MODEM] + 1);
    LE_INFO( "Synchronizing from sub system LK from %d to %d",
             iniBootSystem[PA_FWUPDATE_SUBSYSID_LK] + 1,
             dualBootSystem[PA_FWUPDATE_SUBSYSID_LK] + 1);
    LE_INFO( "Synchronizing from sub system LINUX from %d to %d",
             iniBootSystem[PA_FWUPDATE_SUBSYSID_LINUX] + 1,
             dualBootSystem[PA_FWUPDATE_SUBSYSID_LINUX] + 1);
    for (idx = 0; idx < sizeof( syncPartition )/sizeof(cwe_ImageType_t); idx++) {
        int subSysId = Partition_Identifier[syncPartition[idx]].subSysId;

        if (-1 == (mtdSrc = partition_GetMtdFromImageType( syncPartition[idx],
                                                           false, &mtdSrcNamePtr,
                                                           &isLogicalSrc, &isDualSrc )))
        {
            LE_ERROR( "Unable to determine initial partition for %d", syncPartition[idx] );
            goto error;
        }
        if (-1 == (mtdDst = partition_GetMtdFromImageType( syncPartition[idx], true, &mtdDstNamePtr,
                                                           &isLogicalDst, &isDualDst)))
        {
            LE_ERROR( "Unable to determine dual partition for %d", syncPartition[idx] );
            goto error;
        }

        if (LE_OK != partition_CheckIfMounted( mtdDst ))
        {
            // CUST0 is expected to be managed by customer only. If it is mounted or attached,
            // the synchronize will be skipped for this one.
            if (CWE_IMAGE_TYPE_CUS0 == syncPartition[idx])
            {
                LE_WARN("Customer partition mtd%d is mounted or attached. Synchronize skipped.",
                        mtdDst);
                continue;
            }
            else
            {
                LE_ERROR("Partition mtd%d is mounted or attached. Synchronize aborted.", mtdDst);
                goto error;
            }
        }

        res = CheckDmVerityIntegrity(mtdSrc);
        // In case of LE_FORMAT_ERROR, this is not an UBI container. Skip it
        if ((LE_OK != res) && (LE_FORMAT_ERROR != res))
        {
            LE_ERROR("Error when checking for UBI on mtd%d. Synchronize aborted.", mtdSrc);
            goto error;
        }

        LE_INFO( "Synchronizing %s partition \"%s%s\" (mtd%d) from \"%s%s\" (mtd%d)",
                 mtdDst == mtdSrc ? "logical" : "physical",
                 mtdDstNamePtr,
                 mtdDst == mtdSrc && dualBootSystem[subSysId] ? "2" : "",
                 mtdDst,
                 mtdSrcNamePtr,
                 mtdDst == mtdSrc && iniBootSystem[subSysId] ? "2" : "",
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

        // Try to check the integrity of UBI. If the isUbiPartition is false, the partition is
        // not an UBI container
        res = pa_flash_CheckUbi( flashFdSrc, &isUbiPartition );
        if (LE_OK != res)
        {
            LE_ERROR("CheckUbi of SRC MTD %d fails: res=%d", mtdSrc, res);
            goto error;
        }

        // Check for unrecoverable ECC errors on active partition and abort if some.
        res = pa_flash_GetEccStats( flashFdSrc, &flashEccStats );
        if( LE_OK != res )
        {
            LE_ERROR("Getting ECC stats on SRC MTD %d fails: res=%d", mtdSrc, res);
            goto error;
        }
        // Corrected ECC errors are ignored, because normally the data are valid.
        // Abort in case of unrecoverable ECC errors.
        if( flashEccStats.failed )
        {
            LE_ERROR("Unrecoverable ECC errors on SRC MTD %d: Corrected %u Unrecoverable %u ",
                     mtdSrc, flashEccStats.corrected, flashEccStats.failed);
            returnedRes = LE_IO_ERROR;
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
        bool onlyChkValidUbiData;

        // In case of UBI partition, a second try will be performed if the checksum of active
        // changed during the copy.
        isRetryNeeded = false;
        onlyChkValidUbiData = isUbiPartition? true:false;

        do
        {
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

                dataLen = flashInfoSrcPtr->eraseSize;
                if (isUbiPartition)
                {
                    if ( LE_OK != partition_GetUbiBlockValidDataLen(&dataLen,
                                                                    flashInfoSrcPtr->writeSize,
                                                                    flashBlockPtr))
                    {
                        LE_ERROR("failed to get UBI block valid data length");
                        goto error;
                    }
                }

                if (LE_OK != pa_flash_EraseBlock( flashFdDst, nbBlk ))
                {
                    LE_ERROR("EraseMtd fails for block %d: %m", nbBlk);
                    goto error;
                }

                if (LE_OK != pa_flash_WriteAtBlock( flashFdDst,
                                                    nbBlk,
                                                    flashBlockPtr,
                                                    dataLen ))
                {
                    LE_ERROR("pa_flash_Write fails for block %d: %m", nbBlk);
                    goto error;
                }
                else
                {
                   /* Here calculate the CRC with erase block by erase block, and later
                    * also check CRC again with real data length by real data length.
                    * Skip all data set to 0xFF at the end of erase block.
                    */
                    crc32Src = le_crc_Crc32(flashBlockPtr, dataLen, crc32Src);
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
            // Check the integrity if the partition is expected to be an UBI container
            if (isUbiPartition)
            {
                // In this case, we need to recompute the checksum of the MTD to ensure that it is
                // conform to what we read first.
                res = partition_CheckData(mtdSrc, isLogicalSrc, isDualSrc, srcSize, 0,
                                                 crc32Src, FlashImgPool, true, onlyChkValidUbiData);
                if (LE_OK != res)
                {
                    // If first try fails, redo another attempt
                    LE_ERROR("Checksum failed after rereading source MTD %d", mtdSrc);
                    isRetryNeeded = !isRetryNeeded;
                }
                else
                {
                    // The copy is good, no do any retry
                    isRetryNeeded = false;
                }
                if ((LE_OK != res) && (!isRetryNeeded))
                {
                    // The second try fails: Abort the sync
                    goto error;
                }
                res = LE_OK;
            }

            if (LE_OK != res)
            {
                // The UBI integrity is corrupt.
                LE_ERROR("IsUbi of SRC MTD %d fails: res=%d", mtdSrc, res);
                goto error;
            }

            // Check for unrecoverable ECC errors on active partition and abort if some.
            res = pa_flash_GetEccStats( flashFdSrc, &flashEccStats );
            if( LE_OK != res )
            {
                LE_ERROR("Getting ECC stats on SRC MTD %d fails: res=%d", mtdSrc, res);
                goto error;
            }
            // Corrected ECC errors are ignored, because normally the data are valid.
            // Abort in case of unrecoverable ECC errors.
            if( flashEccStats.failed )
            {
                LE_ERROR("Unrecoverable ECC errors on SRC MTD %d: Corrected %u Unrecoverable %u ",
                         mtdSrc, flashEccStats.corrected, flashEccStats.failed);
                returnedRes = LE_IO_ERROR;
                goto error;
            }
        }
        while (isRetryNeeded);

        pa_flash_Close(flashFdSrc);
        flashFdSrc = NULL;
        pa_flash_Close(flashFdDst);
        flashFdDst = NULL;

        // Verify the checksum of the destination MTD to ensure it matches the source checksum
        if (LE_OK != partition_CheckData(mtdDst, isLogicalDst, isDualDst, srcSize, 0, crc32Src,
                                         FlashImgPool, false, onlyChkValidUbiData))
        {
            goto error;
        }
        if (LE_OK != partition_SetBadImage(syncPartition[idx], false))
        {
            goto error;
        }
    }

    ReleaseSwUpdate();

    le_mem_Release(flashBlockPtr);

    LE_INFO ("done");
    if (LE_OK != pa_fwupdate_SetSyncState())
    {
        LE_ERROR("Failed to call pa_fwupdate_SetSyncState(): Systems are not synchronized");
        return LE_FAULT;
    }
    return LE_OK;

error:
    ReleaseSwUpdate();

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
    return returnedRes;
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
    le_thread_Sleep(1);
    if (-1 != system("/sbin/reboot"))
    {
        // the system reset is not done immediately so we need to keep here
        while(1)
        {
            le_thread_Sleep(2);
            LE_DEBUG("Waiting for reboot");
        }
    }
}

//--------------------------------------------------------------------------------------------------
/**
 * Save the customer security check script result
 *
 * @return
 *      - LE_OK             on success
 *      - LE_FAULT          on failure
 */
//--------------------------------------------------------------------------------------------------
static le_result_t SaveCustResult
(
    uint8_t secCheckResult    ///< [IN] Customer security check result
)
{
    le_result_t result;
    le_fs_FileRef_t resFileRef;
    char * filePath = "/cus_sec_result";

    result = le_fs_Open(filePath, LE_FS_WRONLY | LE_FS_CREAT, &resFileRef);
    if (LE_OK != result)
    {
        LE_ERROR("failed to open %s: %s", filePath, LE_RESULT_TXT(result));
        return result;
    }

    result = le_fs_Write(resFileRef, &secCheckResult, sizeof(secCheckResult));
    if (LE_OK != result)
    {
        LE_ERROR("failed to write %s: %s", filePath, LE_RESULT_TXT(result));
        if (LE_OK != le_fs_Close(resFileRef))
        {
            LE_ERROR("failed to close %s", filePath);
        }
        return result;
    }

    result = le_fs_Close(resFileRef);
    if (LE_OK != result)
    {
        LE_ERROR("failed to close %s: %s", filePath, LE_RESULT_TXT(result));
    }

    return result;
}

//--------------------------------------------------------------------------------------------------
/**
 * Execute the customer security check script and save the result
 *
 * @return
 *      - LE_OK             on success
 *      - LE_FAULT          on failure
 */
//--------------------------------------------------------------------------------------------------
static le_result_t CustSecCheck
(
    const char* filePathPtr,          ///< [IN] File path pointer of CUSG image
    const char* digestCharBufPtr,     ///< [IN] Digest buffer
    size_t digestBufLength            ///< [IN] Digest buffer length
)
{
    pid_t cusStatus;
    char secCmd[PATH_MAX];
    le_result_t result = LE_OK;

    if (access(filePathPtr, F_OK) < 0)
    {
        LE_INFO("No CUSG image, skip cus check.");
        return result;
    }

    //reserve 400 bytes for script path and CUSG image path
    if (digestBufLength > (PATH_MAX - 400))
    {
        LE_ERROR("Digest buffer too large to handle.");
        return LE_FAULT;
    }

    snprintf(secCmd, sizeof(secCmd), "/legato/systems/current/bin/cus_sec.sh %s %s",
        filePathPtr, digestCharBufPtr);

    // Execute the program.
    cusStatus = system(secCmd);

    //delete the CUSG file
    if (unlink(filePathPtr) == -1)
    {
        LE_ERROR("Could not unlink CUSG file. Reason, %s (%d).", LE_ERRNO_TXT(errno), errno);
    }

    if(-1 == cusStatus)
    {
        LE_ERROR("No cus check script.");
        return result;
    }

    if(WIFEXITED(cusStatus))
    {
        LE_INFO("Exit status = [%d]\n", WEXITSTATUS(cusStatus));
        if (0 == WEXITSTATUS(cusStatus))
        {
            LE_INFO("CustSecCheck successed.");
        }
        else
        {
            LE_ERROR("CustSecCheck failed.");
            result = LE_FAULT;
        }
    }
    else
    {
        LE_ERROR("Run cus check script failed.");
        result = LE_FAULT;
        return result;
    }

    //save the result of the hook app
    if(LE_OK != SaveCustResult(WEXITSTATUS(cusStatus)))
    {
        LE_ERROR("Save CustSecCheck result failed.");
        result = LE_FAULT;
    }
    else
    {
        LE_INFO("Cus check result saved.");
    }
    return result;
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
 *      - LE_NOT_PERMITTED   The systems are not synced
 *      - LE_UNAVAILABLE     The flash access is not granted for SW update
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
    bool isRegularFile;

    LE_DEBUG ("fd %d", fd);
    if ((fd < 0) || (LE_OK != CheckFdType(fd, &isRegularFile)))
    {
        LE_ERROR ("bad parameter");
        result = LE_BAD_PARAMETER;
        goto error;
    }

    le_clk_Time_t startTime = le_clk_GetAbsoluteTime();

    ResumeCtxSave_t *saveCtxPtr = &ResumeCtx.saveCtx;

    result = RequestSwUpdate();
    if (LE_OK != result)
    {
        goto error_noswupdatecomplete;
    }

    // check if the resume context is empty or not
    if (0 == saveCtxPtr->totalRead)
    {// resume context is empty so this is a new download
        bool bSync = false;

        // Get the systems synchronization state
        result = pa_fwupdate_GetSystemState (&bSync);
        if ((LE_OK == result) && ((false == bSync) && (false == IsSyncBeforeUpdateDisabled)))
        {
            /* Both systems are not synchronized
             * It's not possible to launch a new package download
             */
            result = LE_NOT_PERMITTED;
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

    /* Like we use epoll(2), force the O_NONBLOCK flags in fd */
    result = PrepareFd(fd, isRegularFile, &efd);
    if (result != LE_OK)
    {
        goto error;
    }

    /* Both systems are synchronized or a valid resume context has been found */
    InitParameters((totalCount != 0), saveCtxPtr);

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
        dataLenToBeRead = LengthToRead(saveCtxPtr);
        if (-1 == dataLenToBeRead)
        {
            goto error;
        }

        do
        {
            readCount = dataLenToBeRead;
            result = ReadSync(fd, efd, bufferPtr, &readCount);
            if (result != LE_OK)
            {
                goto error;
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
                lenRead = dataLenToBeRead - readCount;
                result = ReadSync(fd, efd, bufferPtr + readCount, &lenRead);
                if (result != LE_OK)
                {
                    goto error;
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
            if (LE_OK == result)
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

                unsigned char sha256DigestBuf[SHA256_DIGEST_LENGTH];
                char sha256CharBuf[SHA256_DIGEST_LENGTH*2+1];
                int i;
                memset(sha256DigestBuf, 0, sizeof(sha256DigestBuf));
                memset(sha256CharBuf, 0, sizeof(sha256CharBuf));

                if(LE_OK != EndSha256(ResumeCtx.sha256CtxPtr,sha256DigestBuf,
                    SHA256_DIGEST_LENGTH))
                {
                    LE_ERROR("Failed ending sha256");
                    goto error;
                }

                //convert digest to char
                for(i = 0; i < SHA256_DIGEST_LENGTH; i++)
                {
                    snprintf(&sha256CharBuf[i*2], sizeof(sha256CharBuf) - (i*2),
                        "%02X", sha256DigestBuf[i]);
                }

                if(LE_OK != CustSecCheck(CusgPathPtr, (const char*)sha256CharBuf,
                    sizeof(sha256CharBuf)))
                {
                    LE_ERROR("Customer sec check failed");
                    goto error;
                }
                else
                {
                    LE_INFO("Customer sec check passed.");
                }

                if (saveCtxPtr->globalCrc != saveCtxPtr->currentGlobalCrc)
                {
                    LE_ERROR("Bad global CRC check");
                    goto error;
                }
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
        else
        {
            //Reset Watchdog if it isn't done for certain time interval
            le_clk_Time_t curTime = le_clk_GetAbsoluteTime();
            le_clk_Time_t diffTime = le_clk_Sub(curTime, startTime);
            if (diffTime.sec >= FWUPDATE_WDOG_KICK_INTERVAL)
            {
                LE_DEBUG("Kicking watchdog");
                startTime = curTime;
                le_wdogChain_Kick(FWUPDATE_WDOG_TIMER);
            }
        }
    }

    ReleaseSwUpdate();

    // Record the download status
    RECORD_DWL_STATUS(updateStatus);

    le_mem_Release(bufferPtr);
    close(fd);
    if (efd != -1)
    {
        close(efd);
    }

    LE_DEBUG ("result %s", LE_RESULT_TXT(result));
    return result;

error:
    ReleaseSwUpdate();

error_noswupdatecomplete:
    if (result != LE_CLOSED) // if LE_CLOSED updateStatus is already to ONGOING
    {
        updateStatus = (LE_TIMEOUT == result) ? PA_FWUPDATE_INTERNAL_STATUS_DWL_TIMEOUT :
                                                PA_FWUPDATE_INTERNAL_STATUS_DWL_FAILED;
        // Record the download status
        RECORD_DWL_STATUS(updateStatus);
    }

    le_mem_Release(bufferPtr);
    // Done with the file, so close it.
    if (fd != -1)
    {
        close (fd);
    }
    if (efd != -1)
    {
        close(efd);
    }
    if (LE_OK != WriteData(&CurrentCweHeader, 0, 0, NULL, true, NULL))
    {
        LE_CRIT("Failed to force close of MTD.");
    }
    // we avoid to affect LE_FAULT before goto error so we can have LE_OK at this point
    result = (LE_OK == result) ? LE_FAULT : result;
    if (LE_FAULT == result)
    {
        LE_DEBUG("Kicking watchdog");
        le_wdogChain_Kick(FWUPDATE_WDOG_TIMER);
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
 * Read the initial system as follow:
 *     [0] = modem sub-system
 *     [1] = lk sub-system
 *     [2] = linux sub-system
 *
 * @return
 *      - LE_OK            On success
 *      - LE_FAULT         On failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_fwupdate_GetSystem
(
    pa_fwupdate_System_t systemArray[PA_FWUPDATE_SUBSYSID_MAX]
                         ///< [OUT] System array for "modem/lk/linux" partition groups
)
{
    uint8_t iniBootSys[PA_FWUPDATE_SUBSYSID_MAX];
    if (NULL == systemArray)
    {
        LE_ERROR("systemArray null pointer");
        return LE_FAULT;
    }

    if (LE_OK != partition_GetInitialBootSystem(iniBootSys))
    {
        LE_ERROR("Failed to get initial boot system");
        return LE_FAULT;
    }

    int iSSid;

    // In partition.c, the system are 0 and 1. Convert to PA_FWUPDATE_SYSTEM_1/2 enum
    for (iSSid = PA_FWUPDATE_SUBSYSID_MODEM; iSSid <PA_FWUPDATE_SUBSYSID_MAX; iSSid++ )
    {
         systemArray[iSSid] = (iniBootSys[iSSid] ? PA_FWUPDATE_SYSTEM_2 : PA_FWUPDATE_SYSTEM_1);
    }
    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Set the system. This function will perform a reset if no error are reported
 * The new system is defined by an array of 3 pa_fwupdate_System_t as follow:
 *     [0] = modem sub-system
 *     [1] = lk sub-system
 *     [2] = linux sub-system
 *
 * @note On success, a device reboot is initiated without returning any value.
 *
 * @return
 *      - LE_FAULT         On failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_fwupdate_SetSystem
(
    pa_fwupdate_System_t systemArray[PA_FWUPDATE_SUBSYSID_MAX]
                         ///< [IN] System array for "modem/lk/linux" partition groups
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

    LE_INFO("Set Sub System: Modem %d Lk %d Linux %d",
            systemArray[PA_FWUPDATE_SUBSYSID_MODEM], systemArray[PA_FWUPDATE_SUBSYSID_LK],
            systemArray[PA_FWUPDATE_SUBSYSID_LINUX]);

    /* Program the new "active" system */
    result = pa_fwupdate_SetActiveSystem(systemArray, false);
    if (result == LE_OK)
    {
        /* request modem to check if there is NVUP files to apply
         * no need to check the result as SSID are already modified we need to reset */
        pa_fwupdate_NvupApply();
        /* make a system reset */
        pa_fwupdate_Reset();
        /* at this point the system is resetting */
    }

    LE_DEBUG ("Set result %d", result);
    return LE_FAULT;
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
le_result_t pa_fwupdate_Install
(
    bool isMarkGoodReq      ///< [IN] Indicate if a mark good operation is required after install
)
{
    le_result_t result;
    size_t position = 0;
    pa_fwupdate_System_t systemArray[PA_FWUPDATE_SUBSYSID_MAX];
    int ssid;

    // Check if a resume is ongoing
    result = pa_fwupdate_GetResumePosition(&position);
    if ((LE_OK != result) || position)
    {
        LE_ERROR("swap not possible, a download is ongoing");
        return LE_BUSY;
    }

    // Note that programming the swap (ssdata) via QMI takes 3~4 seconds to complete. If a reboot
    // occurs during this phase, the internal status SWAP ONGOING will be catched at startup.
    if (isMarkGoodReq)
    {
        RECORD_DWL_STATUS(PA_FWUPDATE_INTERNAL_STATUS_SWAP_MG_ONGOING);
    }
    else
    {
        RECORD_DWL_STATUS(PA_FWUPDATE_INTERNAL_STATUS_SWAP_ONGOING);
    }

    // Program the SWAP
    result = pa_fwupdate_GetSystem(systemArray);
    if (LE_OK == result)
    {
        for (ssid = PA_FWUPDATE_SUBSYSID_MODEM; ssid < PA_FWUPDATE_SUBSYSID_MAX; ssid++)
        {
            systemArray[ssid] ^= (PA_FWUPDATE_SYSTEM_1 | PA_FWUPDATE_SYSTEM_2);
        }

        result = pa_fwupdate_SetActiveSystem(systemArray, isMarkGoodReq);
        if (LE_OK == result)
        {
            // Request modem to check if there is NVUP files to apply
            // no need to check the result as SSID are already modified we need to reset
            pa_fwupdate_NvupApply();

            // Make a system reset
            pa_fwupdate_Reset();

            // At this point the system is resetting
        }
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
 *      - LE_IO_ERROR       if SYNC fails due to unrecoverable ECC errors. In this case, the update
 *                          without sync is forced, but the whole system must be updated to ensure
 *                          that the new update system will be workable
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_fwupdate_InitDownload
(
    void
)
{
    le_result_t result, ret;
    bool isSystemGood = false;

    // Check whether both systems are synchronized and eventually initiate the synchronization.
    result = pa_fwupdate_GetSystemState(&isSystemGood);
    if (LE_OK != result)
    {
        LE_ERROR("Checking synchronization has failed (%s)!", LE_RESULT_TXT(result));
        return LE_FAULT;
    }
    else if ((false == isSystemGood) && (false == IsSyncBeforeUpdateDisabled))
    {
        // Perform the synchronization
        result = pa_fwupdate_MarkGood();
        if (result != LE_OK)
        {
            LE_ERROR("failed to SYNC (%s)", LE_RESULT_TXT(result));
            result = (LE_IO_ERROR == result ? LE_IO_ERROR : LE_FAULT);
            if (LE_IO_ERROR == result)
            {
                LE_WARN("SYNC failed due to ECC errors. Forcing UPDATE without SYNC mode.");
                pa_fwupdate_DisableSyncBeforeUpdate(true);
            }
        }
    }
    else
    {
        // for sonar: nothing to do
    }

    // Clear the context out
    ret = EraseResumeCtx(&ResumeCtx);

    return ((LE_OK == result) ? ret : result);
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
        PA_FWUPDATE_UPDATE_STATUS_UNKNOWN,         // PA_FWUPDATE_INTERNAL_STATUS_SWAP_MG_ONGOING
        PA_FWUPDATE_UPDATE_STATUS_UNKNOWN,         // PA_FWUPDATE_INTERNAL_STATUS_SWAP_ONGOING
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
        if ((PA_FWUPDATE_INTERNAL_STATUS_DWL_ONGOING == internalStatus)     ||
            (PA_FWUPDATE_INTERNAL_STATUS_DWL_TIMEOUT == internalStatus)     ||
            (PA_FWUPDATE_INTERNAL_STATUS_DWL_FAILED == internalStatus)      ||
            (PA_FWUPDATE_INTERNAL_STATUS_SWAP_MG_ONGOING == internalStatus) ||
            (PA_FWUPDATE_INTERNAL_STATUS_SWAP_ONGOING == internalStatus))
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
            *statusPtr = updateStatus[internalStatus];
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
 * Disable (true) or enable (false) the synchronisation check before performing an update.
 * The default behavior at startup is always to have the check enabled. It remains enabled
 * until this service is called with the value true. To re-enable the synchronization check
 * call this service with the value false.
 *
 * @note Upgrading some partitions without performing a sync before may let the whole system
 *       into a unworkable state. THIS IS THE RESPONSABILITY OF THE CALLER TO KNOW WHAT IMAGES
 *       ARE ALREADY FLASHED INTO THE UPDATE SYSTEM.
 *
 * @return
 *      - LE_OK              On success
 *      - LE_UNSUPPORTED     The feature is not supported
 *      - LE_FAULT           On failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_fwupdate_DisableSyncBeforeUpdate
(
    bool isDisabled  ///< [IN] State of sync check : true (disable) or false (enable)
)
{
    IsSyncBeforeUpdateDisabled = isDisabled;
    LE_DEBUG("Sync before update is %sabled", IsSyncBeforeUpdateDisabled ? "dis" : "en");
    if (true == IsSyncBeforeUpdateDisabled)
    {
        LE_WARN("Sync before update is now DISABLED. Updating without performing a sync before");
        LE_WARN("may let the whole system into a unworkable state !");

    }
    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * This function must be called to initialize the FW UPDATE module.
 */
//--------------------------------------------------------------------------------------------------
COMPONENT_INIT
{
    // Allocate a pool for the data chunk
    ChunkPool = le_mem_CreatePool("ChunkPool", CHUNK_LENGTH);
    le_mem_ExpandPool(ChunkPool, 1);

    int mtdNum;
    le_result_t result;
    pa_flash_Info_t flashInfo;
    pa_fwupdate_InternalStatus_t internalStatus;

    // Get MTD information from SBL partition. This is will be used to fix the
    // pool object size and compute the max object size
    mtdNum = partition_GetMtdFromImageType( CWE_IMAGE_TYPE_SBL1, true, NULL, NULL, NULL );
    LE_FATAL_IF(-1 == mtdNum, "Unable to find a valid MTD for SBL image");

    LE_FATAL_IF(LE_OK != pa_flash_GetInfo( mtdNum, &flashInfo, false, false ),
                "Unable to get MTD informations for SBL image");

    // Allocate a pool for the blocks to be flashed and checked
    FlashImgPool = le_mem_CreatePool("FlashImagePool", flashInfo.eraseSize);
    // Request 3 blocks: 1 for flash, 1 spare, 1 for check
    le_mem_ExpandPool(FlashImgPool, 3);

    // Allocate a pool for the array to SBL blocks
    PartitionCtx.sblPool = le_mem_CreatePool("SBL Block Pool",
                                             sizeof(uint8_t*) * (flashInfo.nbBlk / 2));
    le_mem_ExpandPool(PartitionCtx.sblPool, 1);

    // Just to get the SSID. This is used to initialize the Initial sub-system variables internally
    pa_fwupdate_System_t systemArray[PA_FWUPDATE_SUBSYSID_MAX];

    if (LE_OK != pa_fwupdate_GetSystem(systemArray))
    {
        LE_CRIT("Failed to get the Initial Sub System Id. fwupdateDaemon may be unusable");
    }

    // Force release in case of crash between request and release
    ReleaseSwUpdate();

    // In case of an ongoing installation, check the swap state.
    result = ReadDwlStatus(&internalStatus);
    if ((LE_OK == result) &&
       ((PA_FWUPDATE_INTERNAL_STATUS_SWAP_ONGOING == internalStatus) ||
        (PA_FWUPDATE_INTERNAL_STATUS_SWAP_MG_ONGOING == internalStatus)))
    {
        bool isLegatoSwapReq = false;
        result = pa_fwupdate_IsSwapRequestedByLegato(&isLegatoSwapReq);
        if (LE_OK == result)
        {
            if (isLegatoSwapReq)
            {
                LE_INFO("Package installed successfuly");
                RECORD_DWL_STATUS(PA_FWUPDATE_INTERNAL_STATUS_OK);
            }
            else
            {
                LE_ERROR("An unexpected reboot occured during last installation. Redo the install");
                pa_fwupdate_Install(PA_FWUPDATE_INTERNAL_STATUS_SWAP_MG_ONGOING == internalStatus);
            }
        }
    }

    CheckSyncAtStartup();

    //Use different path to save CUSG image for RO and RW system
    if (0 == access("/legato/systems/current/read-only", F_OK))
    {
        LE_INFO("In read-only system.");
        CusgPathPtr = "/tmp/cusgimage";
    }
    else
    {
        LE_INFO("In read-write system.");
        CusgPathPtr = "/legato/cusgimage";
    }

    if (GetResumeCtx(&ResumeCtx) != LE_OK)
    {
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

    // If the swi_auth tool exists, try to detect if SECURE BOOT is enabled
    if (0 == access(SWI_AUTH_PATH, (R_OK|X_OK)))
    {
        int rc;

        // If this fails, we assume that we run secure!
        rc = system(SWI_AUTH_PATH " fuse");
        if (WIFEXITED(rc))
        {
            if (SWI_SECURE_VERSION == WEXITSTATUS(rc))
            {
                IsSecureBootVersion = true;
            }
            else if (SWI_NON_SECURE == WEXITSTATUS(rc))
            {
                IsSecureBootVersion = false;
            }
            else
            {
                LE_CRIT("Detecting SECURE BOOT returns an unexpected value: %d", WEXITSTATUS(rc));
                LE_CRIT("Assuming SECURE BOOT");
                IsSecureBootVersion = true;
            }
        }
        else
        {
            LE_CRIT("Unable to detecte if SECURE BOOT is enabled: %08x", rc);
            LE_CRIT("Assuming SECURE BOOT");
            IsSecureBootVersion = true;
        }
    }
}

//--------------------------------------------------------------------------------------------------
/**
 * Get the MTD partition table
 *
 * @return
 *      - LE_OK            on success
 *      - LE_BAD_PARAMETER if mtdPartPtr is NULL
 *      - LE_FAULT         on other errors
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_fwupdate_GetMtdPartitionTab
(
    pa_fwupdate_MtdPartition_t **mtdPartPtr
)
{
    if (NULL == mtdPartPtr)
    {
        return LE_BAD_PARAMETER;
    }
    *mtdPartPtr = MtdPartTab;
    return LE_OK;
}

