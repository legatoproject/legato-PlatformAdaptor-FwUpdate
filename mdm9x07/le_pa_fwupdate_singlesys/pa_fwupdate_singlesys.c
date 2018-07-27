/**
 * @file pa_fwupdate_singlesys.c
 *
 * implementation of @ref c_pa_fwupdate API.
 *
 * This PA supports some services required to port le_flash API on single systems.
 *
 * Copyright (C) Sierra Wireless Inc.
 *
 */

#include "legato.h"
#include "pa_flash.h"
#include "pa_fwupdate.h"
#include "pa_fwupdate_singlesys.h"
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

//--------------------------------------------------------------------------------------------------
/**
 * File hosting the last download status
 */
//--------------------------------------------------------------------------------------------------
#ifdef LEGATO_EMBEDDED
#define EFS_DWL_STATUS_FILE "/fwupdate/dwl_status.nfo"
#else
#define EFS_DWL_STATUS_FILE "/tmp/dwl_status.nfo"
#endif

//--------------------------------------------------------------------------------------------------
/**
 * Define the resume context filename
 */
//--------------------------------------------------------------------------------------------------
#ifdef LEGATO_EMBEDDED
#define RESUME_CTX_FILENAME "/fwupdate/fwupdate_ResumeCtx_"
#else
#define RESUME_CTX_FILENAME "/tmp/data/le_fs/fwupdate_ResumeCtx_"
#endif

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
    } while (0)

//--------------------------------------------------------------------------------------------------
/**
 * Default timeout
 */
//--------------------------------------------------------------------------------------------------
#define DEFAULT_TIMEOUT_MS      900000

//--------------------------------------------------------------------------------------------------
/**
 * Max events managed by epoll
 */
//--------------------------------------------------------------------------------------------------
#define MAX_EVENTS              10

//--------------------------------------------------------------------------------------------------
/**
 * Define the maximum length for a package data chunk
 */
//--------------------------------------------------------------------------------------------------
#define CHUNK_LENGTH            65536

//--------------------------------------------------------------------------------------------------
/**
 * Magic numbers used in the Meta data structure
 */
//--------------------------------------------------------------------------------------------------
#define SLOT_MAGIC_BEG          0x92B15380U
#define SLOT_MAGIC_END          0x31DDF742U

//--------------------------------------------------------------------------------------------------
/**
 * Meta data structure
 */
//--------------------------------------------------------------------------------------------------
typedef struct __attribute__((__packed__))
{
  uint8_t   cweHeaderRaw[CWE_HEADER_SIZE];  ///< Raw CWE header copied from image
  uint32_t  magicBegin;                     ///< Magic number
  uint32_t  version;                        ///< Version of the structure
  uint32_t  offset;                         ///< Offset of partition to store image
  uint32_t  logicalBlock;                   ///< Logical start block number to store image
  uint32_t  phyBlock;                       ///< Physical start block number to store image
  uint32_t  imageSize;                      ///< Size of the image including CWE header
  uint32_t  dldSource;                      ///< Image download source, local or FOTA
  uint32_t  nbComponents;                   ///< Number of component images in slot
  uint8_t   reserved[108];                  ///< Reserved for future use
  uint32_t  magicEnd;                       ///< Magic number
  uint32_t  crc32;                          ///< CRC of the structure
}
Metadata_t;

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
    uint32_t currentImageCrc;       ///< Current image CRC
    uint32_t globalCrc;             ///< CRC of all the package (crc in first cwe header)
    uint32_t currentGlobalCrc;      ///< Current global CRC
    size_t   totalRead;             ///< Total read from the beginning to the end of the latest cwe
                                    ///< header read
    uint32_t currentOffset;         ///< Offset in the current partition (must be a block erase
                                    ///< limit)
    uint32_t fullImageCrc;          ///< Current CRC of the full image
    ssize_t  fullImageLength;       ///< Total size of the package (read from the first CWE header)
    uint8_t  miscOpts;              ///< Misc Options field from CWE header
    bool     isFirstNvupDownloaded; ///< Boolean to know if a NVUP file(s) has been downloaded
    bool     isModemDownloaded;     ///< Boolean to know if a modem partition has been downloaded
    bool     isImageToBeRead;       ///< Boolean to know if data concerns header or component image
    deltaUpdate_PatchMetaHdr_t patchMetaHdr;    ///< Patch Meta Header
    deltaUpdate_PatchHdr_t     patchHdr;        ///< Patch Header
    Metadata_t metaData;            ///< Meta data of the current package
    uint32_t ctxCrc;                ///< Context CRC, Computed on all previous fields of this struct
}
ResumeCtxSave_t;

//--------------------------------------------------------------------------------------------------
/**
 * Resume context to save
 */
//--------------------------------------------------------------------------------------------------
typedef struct
{
    ResumeCtxSave_t saveCtx;    ///< Context to save
    uint32_t fileIndex;         ///< File index to use to save the above context [0..1]
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
 * Read offset of the current package
 */
//--------------------------------------------------------------------------------------------------
static size_t CurrentPackageOffset = 0;

//--------------------------------------------------------------------------------------------------
/**
 * CRC32 variables
 */
//--------------------------------------------------------------------------------------------------
static uint32_t CurrentImageCrc32 = LE_CRC_START_CRC32;
static uint32_t CurrentGlobalCrc32 = LE_CRC_START_CRC32;

//--------------------------------------------------------------------------------------------------
/**
 * Memory Pool for flash temporary image blocks
 */
//--------------------------------------------------------------------------------------------------
static le_mem_PoolRef_t   FlashImgPool;

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
    .cweHdrPtr   = &CurrentCweHeader,
    .hdrPtr      = &ResumeCtx.saveCtx.patchHdr,
    .metaHdrPtr  = &ResumeCtx.saveCtx.patchMetaHdr,
    .poolPtr     = &FlashImgPool,
    .patchRemLen = 0
};

//--------------------------------------------------------------------------------------------------
/**
 * Partition context
 */
//--------------------------------------------------------------------------------------------------
static partition_Ctx_t PartitionCtx = {
    .cweHdrPtr    = &CurrentCweHeader,
    .flashPoolPtr = &FlashImgPool
};

//--------------------------------------------------------------------------------------------------
/**
 * Data passed to flash APIs but not yet written.
 */
//--------------------------------------------------------------------------------------------------
static size_t LenToFlash = 0;

//==================================================================================================
//                                       Private Functions
//==================================================================================================

//--------------------------------------------------------------------------------------------------
/**
 * Update the resume context
 *
 * @return
 *      - LE_OK             on success
 *      - LE_FAULT          on failure
 */
//--------------------------------------------------------------------------------------------------
static le_result_t UpdateResumeCtx
(
    ResumeCtx_t* resumeCtxPtr   ///< [INOUT] The resume context, ctxCrc and ctxCounter
                                ///<         will be updated
)
{
    int ret;
    le_result_t result = LE_OK;
    char str[LE_FS_PATH_MAX_LEN];

    ret = snprintf(str, sizeof(str), RESUME_CTX_FILENAME "%d", resumeCtxPtr->fileIndex);
    if (ret < 0)
    {
        LE_ERROR("Error when creating filename (fileIndex=%d)", resumeCtxPtr->fileIndex);
        result = LE_FAULT;
    }
    else
    {
        le_fs_FileRef_t fd;

        LE_DEBUG("Input fileIndex=%d filename %s", resumeCtxPtr->fileIndex, str);

        result = le_fs_Open(str, LE_FS_WRONLY|LE_FS_CREAT, &fd);
        if (result != LE_OK)
        {
            LE_ERROR("Error when opening %s", str);
            result = LE_FAULT;
        }
        else
        {
            // Swap the fileIndex
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
                     resumeCtxPtr->saveCtx.currentImageCrc, resumeCtxPtr->saveCtx.totalRead,
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
 * Erase the resume context
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
            LE_ERROR("Error when creating filename (i=%d)", i);
            result = LE_FAULT;
            break;
        }
        LE_DEBUG("Filename %s", str);

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

    LE_DEBUG("Result %s", LE_RESULT_TXT(result));
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
    le_fs_FileRef_t fd[2] = {NULL, NULL};

    // Open the 2 context files
    for (i = 2; i--;)
    {
        char str[LE_FS_PATH_MAX_LEN];

        ret = snprintf(str, sizeof(str), RESUME_CTX_FILENAME "%d", i);
        if (ret < 0)
        {
            LE_ERROR("Error when creating filename (i=%d)", i);
            result = LE_FAULT;
        }
        else
        {
            LE_DEBUG("Filename %s", str);

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

        // Read the 2 context files
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
                    // Set context to zero to ensure that the crc will be false
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

            // Select the context with the higher counter
            idx =  (ctx[0].ctxCounter > ctx[1].ctxCounter) ? 0 : 1;

            // Check the context CRC
            for (i = 2; i--;)
            {
                currentCtxSave = &ctx[idx];
                crc32 = le_crc_Crc32((uint8_t*)currentCtxSave,
                                     sizeof(*currentCtxSave) - sizeof(currentCtxSave->ctxCrc),
                                     LE_CRC_START_CRC32);
                if (crc32 != currentCtxSave->ctxCrc)
                {
                    LE_ERROR("File #%d Bad CRC32: expected 0x%x, get 0x%x",
                             idx, currentCtxSave->ctxCrc, crc32);
                    // Swap the index
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
            {
                // A valid context has been found, save the current fileIndex
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
            {
                // No valid context found, re-initialize files
                result = EraseResumeCtx(resumeCtxPtr);
                if (LE_OK == result)
                {
                    resumeCtxPtr->fileIndex = 0;
                }
                else
                {
                    LE_ERROR("Context erase failed (%s)", LE_RESULT_TXT(result));
                }
                result = LE_FAULT;
            }
        }
    }

    if (result != LE_OK)
    {
        LE_ERROR("Valid context not found");
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
    size_t* lengthPtr,            ///< [INOUT] Data length pointer
    size_t offset,                ///< [IN] Data offset in the package
    const uint8_t* dataPtr,       ///< [IN] input data
    bool forceClose,              ///< [IN] Force close of device and resources
    bool *isFlashedPtr            ///< [OUT] true if flash write was done
)
{
    le_result_t ret;

    if (!forceClose)
    {
        LE_DEBUG("Type %"PRIu32" len %zu offset 0x%zx", hdrPtr->imageType, *lengthPtr, offset);
    }

    if (isFlashedPtr)
    {
        *isFlashedPtr = false;
    }

    // Delta patch
    if (hdrPtr->miscOpts & CWE_MISC_OPTS_DELTAPATCH)
    {
        LE_ERROR( "Delta patch not supported");
        ret = LE_FAULT;
    }
    else
    {
        ret = partition_WriteSwifotaPartition(&PartitionCtx, lengthPtr, offset, dataPtr,
                                              forceClose, isFlashedPtr);
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
    ResumeCtxSave_t* saveCtxPtr     ///< [INOUT] resume context
)
{
    LE_DEBUG ("InitParameters, isResume=%d", isResume);

    if (isResume)
    {
        DeltaUpdateCtx.patchRemLen = saveCtxPtr->patchHdr.size;
        CurrentImageOffset = saveCtxPtr->currentOffset;
        CurrentPackageOffset = saveCtxPtr->totalRead;
        CurrentImageCrc32 = saveCtxPtr->currentImageCrc;
        CurrentGlobalCrc32 = saveCtxPtr->currentGlobalCrc;
        CurrentCweHeader.imageType = saveCtxPtr->imageType;
        CurrentCweHeader.imageSize = saveCtxPtr->imageSize;
        CurrentCweHeader.crc32 = saveCtxPtr->imageCrc;
        PartitionCtx.fullImageCrc = saveCtxPtr->fullImageCrc;
        PartitionCtx.fullImageSize = saveCtxPtr->fullImageLength;
        PartitionCtx.logicalBlock = saveCtxPtr->metaData.logicalBlock;
        PartitionCtx.phyBlock = saveCtxPtr->metaData.phyBlock;
        CurrentCweHeader.miscOpts = saveCtxPtr->miscOpts;
    }
    else
    {
        CurrentImageOffset = 0;
        CurrentPackageOffset = 0;
        CurrentImageCrc32 = LE_CRC_START_CRC32;
        CurrentGlobalCrc32 = LE_CRC_START_CRC32;
        PartitionCtx.fullImageCrc = LE_CRC_START_CRC32;
        PartitionCtx.fullImageSize = 0;
        PartitionCtx.logicalBlock = 0;
        PartitionCtx.phyBlock = 0;
        memset(&CurrentCweHeader, 0, sizeof(CurrentCweHeader));
        saveCtxPtr->isImageToBeRead = false;
        saveCtxPtr->fullImageLength = -1;
        // Erase the diffType to allow to detect a new Patch Meta header
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
        LE_ERROR( "Delta patch not supported");
    }
    else
    {
        if (false == saveCtxPtr->isImageToBeRead)
        {
            // A header can be fully read
            readCount = CWE_HEADER_SIZE;
        }
        else
        {
            // A component image can be read
            // Check if whole component image can be filled in a data chunk
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
 * Store current download position and update the resume context.
 *
 * This function needs to be called when data has been flashed in the target. It represents a
 * checkpoint position for any further suspend/resume.
 *
 */
//--------------------------------------------------------------------------------------------------
static void StoreCurrentPosition
(
    ResumeCtx_t* resumeCtxPtr   ///< [INOUT] resume context
)
{
    ResumeCtxSave_t *saveCtxPtr = &resumeCtxPtr->saveCtx;

    // Some data have been flashed => update the resume context
    LE_DEBUG("Store resume context ...");

    saveCtxPtr->fullImageCrc = PartitionCtx.fullImageCrc;
    saveCtxPtr->totalRead += LenToFlash;
    saveCtxPtr->currentOffset = CurrentImageOffset;
    saveCtxPtr->currentImageCrc = CurrentImageCrc32;
    saveCtxPtr->currentGlobalCrc = CurrentGlobalCrc32;
    LenToFlash = 0;

    if (UpdateResumeCtx(resumeCtxPtr) != LE_OK)
    {
        LE_WARN("Failed to update Resume context");
    }
}


//--------------------------------------------------------------------------------------------------
/**
 * This function writes cwe data in corresponding flash partition
 *
 * @return
 *      - Written data length
 *      - 0 in case of failure
 */
//--------------------------------------------------------------------------------------------------
static size_t WriteCweHeader
(
    cwe_Header_t* cweHeaderPtr, ///< [INOUT] CWE header
    const uint8_t* chunkPtr,    ///< [IN]Data to be written in flash partition
    size_t length,              ///< [IN]Data length to be written in flash partition
    ResumeCtx_t* resumeCtxPtr   ///< [INOUT] resume context
)
{
    bool isFlashed = false;
    size_t writtenLength = 0;
    size_t tmpLength = length;
    ResumeCtxSave_t *saveCtxPtr = &resumeCtxPtr->saveCtx;

    // Check incoming parameters
    if (length > CWE_HEADER_SIZE)
    {
        LE_ERROR("Length: %zu higher than allowed: %d", length, (int)CWE_HEADER_SIZE);
        return 0;
    }

    while (writtenLength < length)
    {
        // Remaining length to read
        tmpLength = length - writtenLength;

        if (LE_OK == WriteData(cweHeaderPtr,
                               &tmpLength,
                               CurrentPackageOffset,
                               chunkPtr + writtenLength,
                               false,
                               &isFlashed))
        {
            writtenLength += tmpLength;
            LenToFlash += tmpLength;
            CurrentPackageOffset += tmpLength;

            saveCtxPtr->metaData.logicalBlock = PartitionCtx.logicalBlock;
            saveCtxPtr->metaData.phyBlock = PartitionCtx.phyBlock;

            if (isFlashed)
            {
                StoreCurrentPosition(resumeCtxPtr);
            }
        }
        else
        {
            // Error on storing image data
            LE_ERROR ("Error when writing cwe data in partition");
            return 0;
        }
    }

    return writtenLength;
}

//--------------------------------------------------------------------------------------------------
/**
 * This function writes image data in corresponding flash partition
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
    bool isFlashed = false;
    size_t writtenLength = 0;
    size_t tmpLength = length;
    ResumeCtxSave_t *saveCtxPtr = &resumeCtxPtr->saveCtx;

    while (writtenLength < length)
    {
        tmpLength = length - writtenLength;

        if (LE_OK == WriteData(cweHeaderPtr,
                               &tmpLength,
                               CurrentPackageOffset,
                               chunkPtr + writtenLength,
                               false,
                               &isFlashed))
        {
            CurrentGlobalCrc32 = le_crc_Crc32((uint8_t*)chunkPtr + writtenLength,
                                              tmpLength,
                                              CurrentGlobalCrc32);

            CurrentImageCrc32 = le_crc_Crc32((uint8_t*)chunkPtr+ writtenLength,
                                             tmpLength,
                                             CurrentImageCrc32);

            LE_INFO("Image data write: CRC in header: 0x%x, calculated CRC 0x%x",
                    cweHeaderPtr->crc32, CurrentImageCrc32);

            writtenLength += tmpLength;
            CurrentImageOffset += tmpLength;
            CurrentPackageOffset += tmpLength;
            LenToFlash += tmpLength;

            if (isFlashed)
            {
                if (cweHeaderPtr->miscOpts & CWE_MISC_OPTS_DELTAPATCH)
                {
                    // Patch has been completely received => wait a new header
                    saveCtxPtr->isImageToBeRead = false;
                }

                StoreCurrentPosition(resumeCtxPtr);
            }
        }
        else
        {
            // Error on storing image data
            LE_ERROR ("Error when writing image data in partition");
            return 0;
        }
    }

    if (CurrentImageOffset == CurrentCweHeader.imageSize)
    {
        LE_DEBUG("Image data write end: CRC in header: 0x%x, calculated CRC 0x%x",
                 cweHeaderPtr->crc32, CurrentImageCrc32 );

        /* The whole image was written: compare CRC */
        if (cweHeaderPtr->crc32  != CurrentImageCrc32)
        {
            /* Error on CRC check */
            LE_ERROR ("Error on CRC check");
            return 0;
        }
        else
        {
            // Erase the path flag in options to allow new cwe header to be read
            cweHeaderPtr->miscOpts &= (uint8_t)~((uint8_t)CWE_MISC_OPTS_DELTAPATCH);
            LE_DEBUG ("CurrentImageOffset %zu, CurrentImage %d",
                      CurrentImageOffset, cweHeaderPtr->imageType);
        }
        resumeCtxPtr->saveCtx.isImageToBeRead = false;
    }

    return writtenLength;
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
    ResumeCtxSave_t *saveCtxPtr = &(resumeCtxPtr->saveCtx);

    if (cwe_LoadHeader(chunkPtr, &CurrentCweHeader) != LE_OK)
    {
        LE_ERROR("Error in parsing the CWE header");
        return LE_FAULT;
    }

    LE_DEBUG("CWE header read ok");
    if (-1 == saveCtxPtr->fullImageLength)
    {
        /*
         * Full length and global CRC of the CWE image is provided inside the
         * first CWE header
         */
        saveCtxPtr->fullImageLength = CurrentCweHeader.imageSize + CWE_HEADER_SIZE;
        saveCtxPtr->globalCrc = CurrentCweHeader.crc32;
        PartitionCtx.fullImageSize = saveCtxPtr->fullImageLength;
        saveCtxPtr->currentGlobalCrc = LE_CRC_START_CRC32;
        LE_DEBUG("New CWE: fullImageLength = %zd, CRC=0x%08" PRIx32, saveCtxPtr->fullImageLength,
                 saveCtxPtr->globalCrc);

        // First CWE header. Copy it in MetaData structure
        memcpy(&saveCtxPtr->metaData.cweHeaderRaw, chunkPtr, CWE_HEADER_SIZE);
    }
    else
    {
        // Update the current global CRC with the current header
        CurrentGlobalCrc32 = le_crc_Crc32((uint8_t*)chunkPtr, CWE_HEADER_SIZE, CurrentGlobalCrc32);
        saveCtxPtr->currentGlobalCrc = CurrentGlobalCrc32;
    }

    /*
     * Check the value of the CurrentCweHeader.imageType which is proceed
     * If the image type is a composite one, the next data is a CWE header
     */
    if ((CurrentCweHeader.imageType != CWE_IMAGE_TYPE_APPL)
        && (CurrentCweHeader.imageType != CWE_IMAGE_TYPE_MODM)
        && (CurrentCweHeader.imageType != CWE_IMAGE_TYPE_SPKG)
        && (CurrentCweHeader.imageType != CWE_IMAGE_TYPE_BOOT))
    {
        if (!(CurrentCweHeader.miscOpts & CWE_MISC_OPTS_DELTAPATCH))
        {
            // Next data will concern a component image
            saveCtxPtr->isImageToBeRead = true;
        }
        else
        {
            LE_ERROR("Delta update not supported");
        }

        CurrentImageOffset = 0;
        CurrentImageCrc32 = LE_CRC_START_CRC32;
        // Save the resume context
        saveCtxPtr->imageType = CurrentCweHeader.imageType;
        saveCtxPtr->imageSize = CurrentCweHeader.imageSize;
        saveCtxPtr->imageCrc = CurrentCweHeader.crc32;
        saveCtxPtr->miscOpts = CurrentCweHeader.miscOpts;
        saveCtxPtr->currentImageCrc = LE_CRC_START_CRC32;
        saveCtxPtr->currentOffset = 0;
    }

    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * This function is used by the Legato SW Update component to parse and store an incoming package
 *
 * @return
 *      - LE_OK            The request was accepted
 *      - LE_NOT_POSSIBLE  The action is not compliant with the SW update state (no downloaded pkg)
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

    LE_DEBUG("Parsing a chunkPtr: len %zd, isImageToBeRead %d",
              length, resumeCtxPtr->saveCtx.isImageToBeRead);

    // Check if a header is read or a component image
    if (false == resumeCtxPtr->saveCtx.isImageToBeRead)
    {
        // Full header shall be provided each time
        switch (length)
        {
            case CWE_HEADER_SIZE:
                result = ParseCweHeader(chunkPtr, resumeCtxPtr);
                break;

            case PATCH_META_HEADER_SIZE:
            case PATCH_HEADER_SIZE:
                LE_ERROR("Delta patch not supported");
                break;

            default:
                LE_ERROR ("Bad length for header %d", (uint32_t)length);
                result = LE_BAD_PARAMETER;
                break;
        }
        if (LE_OK == result)
        {
            if (WriteCweHeader(&CurrentCweHeader, chunkPtr, length, resumeCtxPtr))
            {
                // Write to flash sucess
                result = LE_OK;
            }
            else
            {
                // Write to flash failed
                LE_DEBUG("Write to flash failed");
                result = LE_FAULT;
            }
        }
        else
        {
            LE_WARN("Failed to parse a CWE header");
        }
    }
    else
    {
        // Component image is under read: follow it
        if (WriteImageData(&CurrentCweHeader, chunkPtr, length, resumeCtxPtr))
        {
            // Write to flash sucess
            result = LE_OK;
        }
        else
        {
            // Write to flash failed
            LE_DEBUG("Parsing failed");
            result = LE_FAULT;
        }
    }

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

    // Set the status as unknown
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

            // Set the status as unknown
            *statusPtr = PA_FWUPDATE_INTERNAL_STATUS_UNKNOWN;
        }
        else
        {
            // Check the validity of the values
            if (PA_FWUPDATE_INTERNAL_STATUS_UNKNOWN < *statusPtr)
            {
                // Invalid value so remove the file
                le_fs_Delete(EFS_DWL_STATUS_FILE);
                LE_ERROR("Invalid FW update download status!");

                // Set the status as unknown
                *statusPtr = PA_FWUPDATE_INTERNAL_STATUS_UNKNOWN;
            }
        }
    }
    else
    {
        LE_INFO("Unable to access to %s!", EFS_DWL_STATUS_FILE);
    }

    return LE_OK;
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
    ssize_t* lengthPtr  ///< [INOUT] input: max length to read,
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
                            LE_DEBUG("Read %zd bytes", *lengthPtr);
                            if (0 == *lengthPtr)
                            {
                                return LE_CLOSED;
                            }
                            return LE_OK;
                        }
                        else if ((evts & EPOLLRDHUP) || (evts & EPOLLHUP))
                        {
                            // File descriptor has been closed
                            LE_INFO("File descriptor %d has been closed", fd);
                            return LE_CLOSED;
                        }
                        else
                        {
                            LE_WARN("Unexpected event received 0x%x",
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
    int  fd,            ///< [IN] File descriptor
    bool isRegularFile, ///< [IN] Flag to indicate if the file descriptor is related to a regular
                        ///<      file or not
    int* efdPtr         ///< [OUT] Event file descriptor
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
    int fd,                     ///< [IN] File descriptor to test
    bool *isRegularFilePtr      ///< [OUT] True if fd is a regular file
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
 * Build Meta Data
 *
 * @return
 *      - LE_OK             If meta data are generated correctly
 *      - LE_FAULT          On bad parameters
 */
//--------------------------------------------------------------------------------------------------
static le_result_t BuildMetaData
(
    Metadata_t* metaDataPtr,    ///< [INOUT] Generated meta data
    ResumeCtx_t* resumeCtxPtr   ///< [IN] Resume context
)
{
    ResumeCtxSave_t* saveCtxPtr = &(resumeCtxPtr->saveCtx);

    memset(metaDataPtr, 0x00, sizeof(Metadata_t));

    memcpy(&metaDataPtr->cweHeaderRaw, &saveCtxPtr->metaData.cweHeaderRaw, CWE_HEADER_SIZE);

    metaDataPtr->magicBegin    = SLOT_MAGIC_BEG;
    metaDataPtr->version       = 1;
    metaDataPtr->offset        = 0;
    metaDataPtr->logicalBlock  = PartitionCtx.logicalBlock;
    metaDataPtr->phyBlock      = PartitionCtx.phyBlock;
    metaDataPtr->imageSize     = PartitionCtx.fullImageSize;
    metaDataPtr->dldSource     = 0;
    metaDataPtr->nbComponents  = 1;
    metaDataPtr->magicEnd      = SLOT_MAGIC_END;

    metaDataPtr->crc32 = le_crc_Crc32((uint8_t*)metaDataPtr,
                                       sizeof(Metadata_t) - sizeof(metaDataPtr->crc32),
                                       LE_CRC_START_CRC32);

    LE_INFO("Image length: %x",metaDataPtr->imageSize);
    LE_INFO("Logical block: %x, Physical block: %x",
            metaDataPtr->logicalBlock, metaDataPtr->phyBlock);

    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Add that the meta data are stored in the 2 first blocks of SWIFOTA partition
 *
 * @return
 *      - LE_OK             If fd is socket, pipe or regular file
 *      - LE_FAULT          On other errors
 */
//--------------------------------------------------------------------------------------------------
static le_result_t WriteMetaData
(
    ResumeCtx_t* resumeCtxPtr   ///< [INOUT] resume context
)
{
    le_result_t status;
    ResumeCtxSave_t* saveCtxPtr = &(resumeCtxPtr->saveCtx);
    Metadata_t* metaDataPtr = &(saveCtxPtr->metaData);

    if (SLOT_MAGIC_BEG != metaDataPtr->magicBegin)
    {
        LE_ERROR("Invalid Meta Data");
        return LE_FAULT;
    }

    status = partition_WriteMetaData(&PartitionCtx, sizeof(Metadata_t), 0, (uint8_t*)metaDataPtr,0);
    if (status != LE_OK)
    {
        LE_ERROR("Unable to write Meta Data in SWIFOTA partition");
    }

    return status;
}

//==================================================================================================
//  PUBLIC API FUNCTIONS
//==================================================================================================


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
    if (-1 != system("/sbin/reboot"))
    {
        // System reset is not done immediately so we need to keep here
        while(1)
        {
            sleep(2);
            LE_DEBUG("Waiting for reboot");
        }
    }
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
    uint8_t* bufferPtr = le_mem_ForceAlloc(ChunkPool);
    int efd = -1;
    bool isRegularFile;

    LE_DEBUG ("fd %d", fd);
    if ((fd < 0) || (LE_OK != CheckFdType(fd, &isRegularFile)))
    {
        LE_ERROR ("Bad parameter");
        result = LE_BAD_PARAMETER;
        goto error;
    }

    le_clk_Time_t startTime = le_clk_GetAbsoluteTime();

    ResumeCtxSave_t *saveCtxPtr = &ResumeCtx.saveCtx;

    result = pa_fwupdate_OpenSwifota();
    if (LE_OK != result)
    {
        goto error_noswupdatecomplete;
    }

    totalCount = saveCtxPtr->totalRead;

    /* Like we use epoll(2), force the O_NONBLOCK flags in fd */
    result = PrepareFd(fd, isRegularFile, &efd);
    if (result != LE_OK)
    {
        goto error;
    }

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
                LE_ERROR("Error during read: %m");
                goto error;
            }

            LE_DEBUG("Read %d", (uint32_t)readCount);
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
                    LE_ERROR("Error during read: %m");
                    goto error;
                }
            }

            /* Parse the read data and store in partition */
            /* totalCount is in fact the offset */
            result = ParseAndStoreData(readCount, bufferPtr, &ResumeCtx);
            if (LE_OK == result)
            {
                /* Update the totalCount variable (offset) with read data length */
                totalCount += readCount;
                LE_DEBUG("Update totalCount %d", (uint32_t)totalCount);
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

                if (saveCtxPtr->globalCrc != saveCtxPtr->currentGlobalCrc)
                {
                    LE_ERROR("Bad global CRC check");
                    goto error;
                }
            }

            // Generate the meta data based on the downloaded package
            Metadata_t metaData;
            result = BuildMetaData(&metaData, &ResumeCtx);
            if (LE_OK != result)
            {
                goto error;
            }

            updateStatus = PA_FWUPDATE_INTERNAL_STATUS_OK;
            result = LE_OK;

            EraseResumeCtx(&ResumeCtx);

            // Save the generated meta data in the resume context. It will be used later when
            // installing the downloaded package.
            memcpy(&ResumeCtx.saveCtx.metaData, &metaData, sizeof(Metadata_t));

            if (UpdateResumeCtx(&ResumeCtx) != LE_OK)
            {
                LE_WARN("Failed to update Resume context");
            }
            break;
        }
        else
        {
            // Reset Watchdog if not done for certain time interval
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

    // Record the download status
    RECORD_DWL_STATUS(updateStatus);

    le_mem_Release(bufferPtr);
    close(fd);
    if (efd != -1)
    {
        close(efd);
    }

    LE_DEBUG ("result %s", LE_RESULT_TXT(result));
    pa_fwupdate_CloseSwifota();
    return result;

error:
    pa_fwupdate_CloseSwifota();

error_noswupdatecomplete:
    // If LE_CLOSED updateStatus is already to ONGOING
    if (result != LE_CLOSED)
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

    LenToFlash = 0;

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
 * Request a full system reset
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
    RECORD_DWL_STATUS(PA_FWUPDATE_INTERNAL_STATUS_INST_ONGOING);

    // Write the Meta data paritition
    if (LE_OK != WriteMetaData(&ResumeCtx))
    {
        return LE_FAULT;
    }

    // Clean the resume context as it contains a valid meta data structure
    EraseResumeCtx(&ResumeCtx);

    pa_fwupdate_Reset();

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
    return EraseResumeCtx(&ResumeCtx);
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
    pa_fwupdate_InternalStatus_t internalStatus;
    le_result_t result;

    // Look-Up Table of error codes
    // Used to translate internal PA error codes into generic ones.
    const pa_fwupdate_UpdateStatus_t updateStatus[] =
    {
        PA_FWUPDATE_UPDATE_STATUS_OK,              // PA_FWUPDATE_INTERNAL_STATUS_OK
        PA_FWUPDATE_UPDATE_STATUS_PARTITION_ERROR, // PA_FWUPDATE_INTERNAL_STATUS_SWIFOTA
        PA_FWUPDATE_UPDATE_STATUS_UNKNOWN,         // PA_FWUPDATE_INTERNAL_UPDATE_STATUS_UA
        PA_FWUPDATE_UPDATE_STATUS_UNKNOWN,         // PA_FWUPDATE_INTERNAL_UPDATE_STATUS_BL
        PA_FWUPDATE_UPDATE_STATUS_DWL_ONGOING,     // PA_FWUPDATE_INTERNAL_STATUS_DWL_ONGOING
        PA_FWUPDATE_UPDATE_STATUS_DWL_FAILED,      // PA_FWUPDATE_INTERNAL_STATUS_DWL_FAILED
        PA_FWUPDATE_UPDATE_STATUS_DWL_TIMEOUT,     // PA_FWUPDATE_INTERNAL_STATUS_DWL_TIMEOUT
        PA_FWUPDATE_UPDATE_STATUS_UNKNOWN,         // PA_FWUPDATE_INTERNAL_STATUS_INST_ONGOING
        PA_FWUPDATE_UPDATE_STATUS_UNKNOWN,         // PA_FWUPDATE_INTERNAL_STATUS_UNKNOWN
    };

    // Look up table of error labels
    // Used to get the correct error label
    const char *updateStatusLabel[] =
    {
        "Success",                          // PA_FWUPDATE_INTERNAL_STATUS_OK
        "Partition error",                  // PA_FWUPDATE_INTERNAL_STATUS_SWIFOTA
        "Update agent failed",              // PA_FWUPDATE_INTERNAL_UPDATE_STATUS_UA
        "Bootloader failed",                // PA_FWUPDATE_INTERNAL_UPDATE_STATUS_BL
        "Download in progress",             // PA_FWUPDATE_INTERNAL_STATUS_DWL_ONGOING
        "Download failed",                  // PA_FWUPDATE_INTERNAL_STATUS_DWL_FAILED
        "Download timeout",                 // PA_FWUPDATE_INTERNAL_STATUS_DWL_TIMEOUT
        "Install ongoing",                  // PA_FWUPDATE_INTERNAL_STATUS_INST_ONGOING
        "Unknown status"                    // PA_FWUPDATE_INTERNAL_STATUS_UNKNOWN
    };

    // Check the parameter
    if (NULL == statusPtr)
    {
        LE_ERROR("Invalid parameter.");
        return LE_BAD_PARAMETER;
    }

    // Try first to read the stored status if it exists
    result = ReadDwlStatus(&internalStatus);
    if (result == LE_OK)
    {
        *statusPtr = updateStatus[internalStatus];
        strncpy(statusLabelPtr, updateStatusLabel[internalStatus], statusLabelLength);
    }
    else
    {
        *statusPtr = PA_FWUPDATE_UPDATE_STATUS_UNKNOWN;
        *statusLabelPtr = '\0';
    }

    LE_INFO("Update status: %d, Label: %s", *statusPtr, statusLabelPtr);

    return result;
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
    pa_flash_Info_t flashInfo;
    le_result_t result;
    pa_fwupdate_InternalStatus_t internalStatus;

    // Get MTD information from SWIFOTA partition. This is will be used to set the
    // pool object size and compute the max object size
    mtdNum = partition_GetMtdFromImageTypeOrName( 0, "swifota", NULL );
    LE_FATAL_IF(-1 == mtdNum, "Unable to find a valid MTD for \"swifota\"");

    LE_FATAL_IF(LE_OK != pa_flash_GetInfo( mtdNum, &flashInfo, false, false ),
                "Unable to get MTD informations for \"swifota\"");

    // Allocate a pool for the blocks to be flashed and checked
    FlashImgPool = le_mem_CreatePool("FlashImagePool", flashInfo.eraseSize);
    // Request 3 blocks: 1 for flash, 1 spare, 1 for check
    le_mem_ExpandPool(FlashImgPool, 3);

    // In case of an ongoing installation, check the install result and save it.
    result = ReadDwlStatus(&internalStatus);
    if ((LE_OK == result) &&
       (PA_FWUPDATE_INTERNAL_STATUS_INST_ONGOING == internalStatus))
    {
        result = pa_fwupdate_GetInternalUpdateStatus(&internalStatus);
        if (LE_OK == result)
        {
            RECORD_DWL_STATUS(internalStatus);
        }
    }

    if (GetResumeCtx(&ResumeCtx) != LE_OK)
    {
        LE_ERROR("Error when getting the resume context");
        pa_fwupdate_InitDownload();
    }
}
