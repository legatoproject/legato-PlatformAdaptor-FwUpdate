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
#include "pa_flash_local.h"
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

//--------------------------------------------------------------------------------------------------
/**
 * File hosting the last download status
 */
//--------------------------------------------------------------------------------------------------
#define EFS_DWL_STATUS_FILE "/fwupdate/dwl_status.nfo"

//--------------------------------------------------------------------------------------------------
/**
 * Define the resume context filename
 */
//--------------------------------------------------------------------------------------------------
#define RESUME_CTX_FILENAME "/fwupdate/fwupdate_ResumeCtx_"

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
 * Data structure to track meta image data
 */
//--------------------------------------------------------------------------------------------------
typedef struct
{
    uint8_t metaCweHdrRaw[CWE_HDRPSBLEN+1][CWE_HEADER_SIZE];   ///< Array to store cwe headers in
                                                               ///< meta image
    uint8_t currentIndex;                                      ///< Index of current cwe header in
                                                               ///< meta
}
MetaImgData_t;

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
    uint32_t imageCrc;              ///< Image component CRC
    uint32_t currentImageCrc;       ///< Current image component CRC
    uint32_t globalCrc;             ///< CRC of all the package (CRC in first cwe header)
    uint32_t currentGlobalCrc;      ///< Current global CRC
    size_t   totalRead;             ///< Total read from the beginning to the end of the latest cwe
                                    ///< header read
    uint32_t currentInImageOffset;  ///< Offset in the current partition (must be a block erase
                                    ///< limit)
    uint32_t fullImageCrc;          ///< Current CRC of the full image (used in partition layer)
    ssize_t  fullImageLength;       ///< Total size of the package (read from the first CWE header)
    ssize_t  inImageLength;         ///< Total size of the package (read from the first CWE header)
    uint8_t  miscOpts;              ///< Misc Options field from CWE header
    bool     isImageToBeRead;       ///< Boolean to know if data concerns header or component image

    deltaUpdate_PatchMetaHdr_t patchMetaHdr;    ///< Patch Meta Header
    deltaUpdate_PatchHdr_t     patchHdr;        ///< Patch Header
    applyPatch_Ctx_t   imgdiffCtx;  ///< Imgdiff contxt
    MetaImgData_t metaImgData;      ///< Meta image data
    Metadata_t metaData;            ///< Meta data of the current package

    bool       ubiVolumeCreated;    ///< True if the UBI volume has been created
    size_t     partitionCtxSize;    ///< Partition context size
    off_t      partitionOffset;     ///< Partition offset
    uint8_t    padding[2];          ///< This padding is to make sure that the crc32 is computed
                                    ///< correctly
    uint32_t partitionCtxCrc;       ///< CRC for partition resume data.
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
 * Memory Pool for partition context
 */
//--------------------------------------------------------------------------------------------------
static le_mem_PoolRef_t   PartitionContextPool = NULL;

//--------------------------------------------------------------------------------------------------
/**
 * Structure of the current header and delta header if a delta patch is in progress
 */
//--------------------------------------------------------------------------------------------------
static cwe_Header_t CurrentCweHeader;

//--------------------------------------------------------------------------------------------------
/**
 * Read offset of the current component image
 */
//--------------------------------------------------------------------------------------------------
static size_t CurrentInImageOffset = 0;

//--------------------------------------------------------------------------------------------------
/**
 * Read offset of the current package
 */
//--------------------------------------------------------------------------------------------------
static size_t CurrentReadPackageOffset = 0;

//--------------------------------------------------------------------------------------------------
/**
 * Pointer to the partition context
 */
//--------------------------------------------------------------------------------------------------
static uint8_t* PartitionContextPtr = NULL;

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
    .cweHdrPtr           = &CurrentCweHeader,
    .hdrPtr              = &ResumeCtx.saveCtx.patchHdr,
    .metaHdrPtr          = &ResumeCtx.saveCtx.patchMetaHdr,
    .imgCtxPtr           = &ResumeCtx.saveCtx.imgdiffCtx,
    .poolPtr             = &FlashImgPool,
    .patchRemLen         = 0,
    .ubiVolumeCreatedPtr = &ResumeCtx.saveCtx.ubiVolumeCreated
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
            resumeCtxPtr->saveCtx.partitionCtxCrc = le_crc_Crc32(PartitionContextPtr,
                                                           resumeCtxPtr->saveCtx.partitionCtxSize,
                                                           LE_CRC_START_CRC32);

            resumeCtxPtr->saveCtx.ctxCrc = le_crc_Crc32((uint8_t*)&resumeCtxPtr->saveCtx,
                                                        sizeof(resumeCtxPtr->saveCtx) -
                                                        sizeof(resumeCtxPtr->saveCtx.ctxCrc),
                                                        LE_CRC_START_CRC32);

            LE_DEBUG("resumeCtx: ctxCounter %d, imageType %d, imageSize %d, imageCrc 0x%x,",
                     resumeCtxPtr->saveCtx.ctxCounter, resumeCtxPtr->saveCtx.imageType,
                     resumeCtxPtr->saveCtx.imageSize, resumeCtxPtr->saveCtx.imageCrc);
            LE_DEBUG("            currentImageCrc 0x%x totalRead %" PRIuS
                     "currentInImageOffset 0x%x",
                     resumeCtxPtr->saveCtx.currentImageCrc, resumeCtxPtr->saveCtx.totalRead,
                     resumeCtxPtr->saveCtx.currentInImageOffset);
            LE_DEBUG("            fullImageLength %" PRIdS "ctxCrc 0x%08" PRIx32
                     " partitionCtxCrc 0x%08" PRIx32,
                     resumeCtxPtr->saveCtx.fullImageLength, resumeCtxPtr->saveCtx.ctxCrc,
                     resumeCtxPtr->saveCtx.partitionCtxCrc);

            // Write the resume context
            result = le_fs_Write(fd, (uint8_t*)&resumeCtxPtr->saveCtx,
                                             sizeof(resumeCtxPtr->saveCtx));

            // Write the partition context
            result |= le_fs_Write(fd, PartitionContextPtr,
                                  resumeCtxPtr->saveCtx.partitionCtxSize);

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
            uint32_t partitionCtxCrc32;
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
                size_t readSize = currentCtxSave->partitionCtxSize;

                memset(PartitionContextPtr, 0, readSize);

                result = le_fs_Read(fd[idx], PartitionContextPtr, &readSize);

                if ((result != LE_OK) || (readSize != currentCtxSave->partitionCtxSize))
                {
                    LE_ERROR("Unable to read partition context, read: %" PRIuS", expected: %" PRIuS,
                             readSize, currentCtxSave->partitionCtxSize);
                    // Swap the index
                   idx ^= 1UL;
                   result = LE_FAULT;
                   continue;
                }

                partitionCtxCrc32 = le_crc_Crc32(PartitionContextPtr,
                                                 currentCtxSave->partitionCtxSize,
                                                 LE_CRC_START_CRC32);

                if ((crc32 != currentCtxSave->ctxCrc) ||
                        (partitionCtxCrc32 != currentCtxSave->partitionCtxCrc))
                {
                    LE_ERROR("File #%d Bad CRC32: expected (resumeCtx) 0x%x, get 0x%x"
                             " expected (partitionCtx) 0x%x, get 0x%x",
                             idx, currentCtxSave->ctxCrc, crc32,
                             currentCtxSave->partitionCtxCrc, partitionCtxCrc32);
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
                LE_DEBUG("           currentImageCrc 0x%08" PRIx32 "totalRead %" PRIuS
                         " currentInImageOffset 0x%08" PRIx32,
                         resumeCtxPtr->saveCtx.currentImageCrc,resumeCtxPtr->saveCtx.totalRead,
                         resumeCtxPtr->saveCtx.currentInImageOffset);
                LE_DEBUG("           fullImageLength %" PRIdS " ctxCrc 0x%x contentSize: %" PRIuS
                         ", paritionCtxCrc: 0x%x",
                         resumeCtxPtr->saveCtx.fullImageLength,
                         resumeCtxPtr->saveCtx.ctxCrc, resumeCtxPtr->saveCtx.partitionCtxSize,
                         resumeCtxPtr->saveCtx.partitionCtxCrc);
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
 * Write data in a partition. In case of delta, apply the patch.
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
    const uint8_t* dataPtr,       ///< [IN] input data
    size_t* wrLenPtr,             ///< [INOUT] Data length pointer
    bool forceClose              ///< [IN] Force close of device and resources
)
{
    le_result_t ret;

    if (!forceClose)
    {
        LE_DEBUG("Type %"PRIu32" len %" PRIuS, hdrPtr->imageType, *lengthPtr);
    }

    // Delta patch
    if (hdrPtr->miscOpts & CWE_MISC_OPTS_DELTAPATCH)
    {
        deltaUpdate_PatchMetaHdr_t* hdpPtr = DeltaUpdateCtx.metaHdrPtr;
        if (0 == memcmp(hdpPtr->diffType, BSDIFF_MAGIC, strlen(BSDIFF_MAGIC)))
        {
            LE_INFO( "Applying delta patch to %u\n", hdrPtr->imageType );
            ret = deltaUpdate_ApplyPatch(&DeltaUpdateCtx, lengthPtr ? *lengthPtr : 0,
                                          0, dataPtr, &PartitionCtx, lengthPtr, wrLenPtr,
                                          forceClose, NULL);
        }
        else if ((0 == memcmp(hdpPtr->diffType, IMGDIFF_MAGIC, strlen(IMGDIFF_MAGIC))) ||
                 (0 == memcmp(hdpPtr->diffType, NODIFF_MAGIC, strlen(NODIFF_MAGIC))))
        {
            LE_INFO( "Applying delta patch to UBI partition. ImageType: %u\n", hdrPtr->imageType );
            ret = deltaUpdate_ApplyUbiImgPatch(&DeltaUpdateCtx, lengthPtr ? *lengthPtr : 0,
                                               0, dataPtr, &PartitionCtx, lengthPtr, wrLenPtr,
                                               forceClose, NULL);
        }
        else
        {
            LE_ERROR("Bad diff type: %s", hdpPtr->diffType);
            ret = LE_FAULT;
        }
    }
    else
    {
        ret = partition_WriteSwifotaPartition(&PartitionCtx, lengthPtr, dataPtr, forceClose, NULL);

        if( !forceClose )
        {
            *wrLenPtr = *lengthPtr;
        }
    }

    if( !forceClose )
    {
        LE_INFO("Type %"PRIu32" len %" PRIuS " wr %" PRIuS,
                hdrPtr->imageType, lengthPtr ? *lengthPtr : 0, *wrLenPtr);
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
        CurrentInImageOffset = saveCtxPtr->currentInImageOffset;
        CurrentReadPackageOffset = saveCtxPtr->totalRead;
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

        // Open SWIFOTA partition
        if (LE_OK != partition_OpenSwifotaPartition(&PartitionCtx, saveCtxPtr->partitionOffset))
        {
            LE_ERROR("Failed to open SWIFOTA partition for update");
        }

        // Restore partition internal context
        if (NULL != PartitionContextPtr)
        {
            partition_SetPartitionInternals((void*)PartitionContextPtr);
        }

        // Restore resume context
        deltaUpdate_ResumeCtx(&PartitionCtx, &DeltaUpdateCtx);
    }
    else
    {
        CurrentInImageOffset = 0;
        CurrentReadPackageOffset = 0;
        CurrentImageCrc32 = LE_CRC_START_CRC32;
        CurrentGlobalCrc32 = LE_CRC_START_CRC32;
        PartitionCtx.fullImageCrc = LE_CRC_START_CRC32;
        PartitionCtx.fullImageSize = 0;
        PartitionCtx.logicalBlock = 0;
        PartitionCtx.phyBlock = 0;
        memset(&CurrentCweHeader, 0, sizeof(CurrentCweHeader));
        saveCtxPtr->isImageToBeRead = false;
        saveCtxPtr->fullImageLength = -1;
        saveCtxPtr->ubiVolumeCreated = false;
        // Erase the diffType to allow to detect a new Patch Meta header
        memset(saveCtxPtr->patchMetaHdr.diffType, 0, sizeof(saveCtxPtr->patchMetaHdr.diffType));
        // Open SWIFOTA partition
        if (LE_OK != partition_OpenSwifotaPartition(&PartitionCtx, 0))
        {
            LE_ERROR("Failed to open SWIFOTA partition for update");
        }
        saveCtxPtr->metaData.logicalBlock = PartitionCtx.logicalBlock;
        saveCtxPtr->metaData.phyBlock = PartitionCtx.phyBlock;
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
            // A header can be fully read
            readCount = CWE_HEADER_SIZE;
        }
        else
        {
            // A component image can be read
            // Check if whole component image can be filled in a data chunk
            if ((CurrentCweHeader.imageSize - CurrentInImageOffset) > CHUNK_LENGTH)
            {
                readCount = CHUNK_LENGTH;
            }
            else
            {
                readCount = CurrentCweHeader.imageSize - CurrentInImageOffset;
            }
        }
    }
    LE_DEBUG("readCount=%" PRIdS, readCount);
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
    void* contextPtr;

    // Some data have been flashed => update the resume context
    LE_DEBUG("Store resume context ...");

    saveCtxPtr->fullImageCrc = PartitionCtx.fullImageCrc;
    saveCtxPtr->totalRead = CurrentReadPackageOffset;
    saveCtxPtr->currentInImageOffset = CurrentInImageOffset;
    saveCtxPtr->currentImageCrc = CurrentImageCrc32;
    saveCtxPtr->currentGlobalCrc = CurrentGlobalCrc32;
    saveCtxPtr->miscOpts = CurrentCweHeader.miscOpts;

    partition_GetPartitionInternals(&contextPtr, &(saveCtxPtr->partitionCtxSize));
    memcpy(PartitionContextPtr, contextPtr, saveCtxPtr->partitionCtxSize);
    partition_GetSwifotaOffsetPartition(&(saveCtxPtr->partitionOffset));

    if (UpdateResumeCtx(resumeCtxPtr) != LE_OK)
    {
        LE_WARN("Failed to update Resume context");
    }
}

//--------------------------------------------------------------------------------------------------
/**
 * This function processes and stores the meta image data
 *
 * @return
 *      - LE_OK on success
 *      - LE_FAULT on failure
 */
//--------------------------------------------------------------------------------------------------
static le_result_t ProcessMetaImgData
(
    const uint8_t* chunkPtr,    ///< [IN] Input data chunk
    uint32_t length,            ///< [IN] Length of data chunk
    ResumeCtx_t* resumeCtxPtr   ///< [INOUT] resume context
)
{
    ResumeCtxSave_t *saveCtxPtr = &(resumeCtxPtr->saveCtx);
    // Meta contains original cwe headers of delta subimages, so store them

    // Length must be integer multiple of CWE HEADER length
    if ((length % CWE_HEADER_SIZE) != 0)
    {
        LE_ERROR("Wrong meta data. Meta size: %u", length);
        return LE_FAULT;
    }

    // Throw away old meta data store the current meta data
    int cweHeaderNo = length / CWE_HEADER_SIZE;

    LE_INFO("DBUG: Number of cwe headers in meta: %d", cweHeaderNo);

    if (cweHeaderNo > (CWE_HDRPSBLEN+1))
    {
        LE_ERROR("Too many cwe headers (%d) in meta", cweHeaderNo);
        return LE_FAULT;
    }

    // Throw away old meta, so reset everything to zero and save the current one.
    memset(&(saveCtxPtr->metaImgData), 0, sizeof(saveCtxPtr->metaImgData));
    memcpy(saveCtxPtr->metaImgData.metaCweHdrRaw, chunkPtr, length);

    // Parsing complete, update and store context
    CurrentGlobalCrc32 = le_crc_Crc32((uint8_t*)chunkPtr,
                                       length,
                                       CurrentGlobalCrc32);

    CurrentImageCrc32 = le_crc_Crc32((uint8_t*)chunkPtr,
                                     length,
                                     CurrentImageCrc32);

    LE_INFO("Image data write: CRC in header: 0x%x, calculated CRC 0x%x",
             resumeCtxPtr->saveCtx.imageCrc, CurrentImageCrc32);

    CurrentInImageOffset += length;

    // Meta image is very small, all data must be read at one shot. If not, then this should be
    // an error
    if (CurrentInImageOffset == CurrentCweHeader.imageSize)
    {
        LE_DEBUG("Image data write end: CRC in header: 0x%x, calculated CRC 0x%x",
               CurrentCweHeader.crc32, CurrentImageCrc32 );

        /* The whole meta data was written: compare CRC */
        if (CurrentCweHeader.crc32  != CurrentImageCrc32)
        {
          /* Error on CRC check */
          LE_ERROR ("Error on CRC check");
          return LE_FAULT;
        }

        LE_DEBUG ("CurrentInImageOffset %" PRIuS ", CurrentImage %d",
                CurrentInImageOffset, CurrentCweHeader.imageType);
        resumeCtxPtr->saveCtx.isImageToBeRead = false;
    }
    else
    {
        LE_ERROR("Meta image wasn't read fully");
        return LE_FAULT;
    }

    return LE_OK;
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
    size_t* wrLenPtr,           ///< [OUT]Size really written to flash
    ResumeCtx_t* resumeCtxPtr   ///< [INOUT] resume context
)
{
    size_t writtenLength = 0;
    size_t tmpLength = length;

    // Check incoming parameters
    if (length > CWE_HEADER_SIZE)
    {
        LE_ERROR("Length: %" PRIuS "higher than allowed: %d", length, (int)CWE_HEADER_SIZE);
        return 0;
    }

    while (writtenLength < length)
    {
        // Remaining length to read
        tmpLength = length - writtenLength;

        if (LE_OK == WriteData(cweHeaderPtr,
                               &tmpLength,
                               chunkPtr + writtenLength,
                               wrLenPtr,
                               false))
        {
            CurrentGlobalCrc32 = le_crc_Crc32((uint8_t*)chunkPtr + writtenLength,
                                              tmpLength,
                                              CurrentGlobalCrc32);

            writtenLength += tmpLength;
            CurrentReadPackageOffset += tmpLength;
            StoreCurrentPosition(resumeCtxPtr);

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
 * This function writes META image data (mainly the cwe headers) in corresponding flash partition.
 * It only writes one cwe header at a time.
 *
 * @return
 *      - LE_OK on Success
 *      - LE_FAULT on failure
 */
//--------------------------------------------------------------------------------------------------
static le_result_t WriteMetaImageData
(
    ResumeCtx_t* resumeCtxPtr,   ///< [INOUT] resume context
    uint32_t totalLength         ///< [IN] Input data length
)
{
    size_t writtenLength = 0;
    size_t length = CWE_HEADER_SIZE;
    size_t tmpLength = length;
    ResumeCtxSave_t *saveCtxPtr = &resumeCtxPtr->saveCtx;

    int currentCweIndex = saveCtxPtr->metaImgData.currentIndex;
    uint8_t *dataPtr = saveCtxPtr->metaImgData.metaCweHdrRaw[currentCweIndex];

    LE_INFO("Meta Image Index to write SWIFOTA : %d", currentCweIndex);
    // Data must be always non zero, so don't do-while loop
    while (writtenLength < length)
    {
        tmpLength = length - writtenLength;
        if (LE_OK != partition_WriteSwifotaPartition(&PartitionCtx,
                                              &tmpLength,
                                              dataPtr+writtenLength,
                                              false, NULL))
        {

            // Error on storing image data
            LE_ERROR ("Error cwe header from meta image data");
            return LE_FAULT;
        }
        else
        {
            writtenLength += tmpLength;
        }
    }

    // Increase index in metadata
    saveCtxPtr->metaImgData.currentIndex += 1;
    CurrentReadPackageOffset += totalLength;

    LE_INFO("currentCweIndex: %d", saveCtxPtr->metaImgData.currentIndex);
    return LE_OK;
}


//--------------------------------------------------------------------------------------------------
/**
 * This function writes image data in corresponding flash partition
 *
 * @return
 *      - LE_OK on success
 *      - LE_FAULT in case of failure
 */
//--------------------------------------------------------------------------------------------------
static le_result_t WriteImageData
(
    cwe_Header_t* cweHeaderPtr, ///< [INOUT] CWE header linked to image data
    const uint8_t* chunkPtr,    ///< [IN]Data to be written in flash partition
    size_t length,              ///< [IN]Data length to be written in flash partition
    size_t* wrLenPtr,           ///< [OUT]Size really written to flash
    ResumeCtx_t* resumeCtxPtr   ///< [INOUT] resume context
)
{
    size_t writtenLength = 0;
    size_t tmpLength = length;
    ResumeCtxSave_t *saveCtxPtr = &resumeCtxPtr->saveCtx;

    // Some of imgdiff patch length can be zero (no body), they have only meta data. That's why
    // put do-while loop, instead of while loop
    do
    {
        tmpLength = length - writtenLength;

        if (LE_OK == WriteData(cweHeaderPtr,
                               &tmpLength,
                               chunkPtr + writtenLength,
                               wrLenPtr,
                               false))
        {
            LE_INFO("chunk length: %" PRIuS, length);

            CurrentGlobalCrc32 = le_crc_Crc32((uint8_t*)chunkPtr + writtenLength,
                                              tmpLength,
                                              CurrentGlobalCrc32);

            CurrentImageCrc32 = le_crc_Crc32((uint8_t*)chunkPtr+ writtenLength,
                                             tmpLength,
                                             CurrentImageCrc32);

            LE_INFO("Image data write: CRC in header: 0x%x, calculated CRC 0x%x",
                    cweHeaderPtr->crc32, CurrentImageCrc32);

            writtenLength += tmpLength;
            CurrentInImageOffset += tmpLength;
            CurrentReadPackageOffset += tmpLength;

            if ((*wrLenPtr) != 0)
            {
                if (cweHeaderPtr->miscOpts & CWE_MISC_OPTS_DELTAPATCH)
                {
                    // Patch has been completely received => wait a new header
                    saveCtxPtr->isImageToBeRead = false;
                }

                StoreCurrentPosition(resumeCtxPtr);
            }
            LE_INFO("CurrentInImgOffset: %" PRIuS "CurrentImageSize: %"PRIu32 " wrLen: %" PRIuS,
                    CurrentInImageOffset, CurrentCweHeader.imageSize,  *wrLenPtr);
        }
        else
        {
            // Error on storing image data
            LE_ERROR ("Error when writing image data in partition");
            return LE_FAULT;
        }
    }
    while (writtenLength < length);

    if (CurrentInImageOffset == CurrentCweHeader.imageSize)
    {
        LE_INFO("Image data write end: CRC in header: 0x%x, calculated CRC 0x%x",
                 cweHeaderPtr->crc32, CurrentImageCrc32 );

        /* The whole image was written: compare CRC */
        if (cweHeaderPtr->crc32  != CurrentImageCrc32)
        {
            /* Error on CRC check */
            LE_ERROR ("Error on CRC check");
            return LE_FAULT;
        }
        if ((cweHeaderPtr->miscOpts & CWE_MISC_OPTS_DELTAPATCH) && // && UBI partition
                deltaUpdate_IsImgPatch(cweHeaderPtr->imageType))
        {
            cwe_Header_t closeUbiCweHdr;
            int metaIndex = saveCtxPtr->metaImgData.currentIndex;
            LE_INFO("Meta index: %d", metaIndex);
            if ( LE_OK != cwe_LoadHeader(
                            saveCtxPtr->metaImgData.metaCweHdrRaw[metaIndex - 1], &closeUbiCweHdr))
            {
                LE_ERROR("Failed to load cwe header from meta image");
                return LE_FAULT;
            }

            uint32_t ubiImgSize = 0;
            uint32_t ubiImgCrc32 = 0;

            le_result_t result = partition_ComputeUbiCrc32SwifotaPartition(
                                                    &PartitionCtx, &ubiImgSize, &ubiImgCrc32);
            if (LE_OK != result)
            {
                LE_ERROR("Failed to compute UBI partition crc32 in SWIFOTA, result; %d", result);
                return LE_FAULT;
            }

            if ((ubiImgSize != closeUbiCweHdr.imageSize) || (ubiImgCrc32 != closeUbiCweHdr.crc32))
            {
                LE_ERROR("Constructed ubiImage mismatch. OrigSize: %u, OrigCrc32: %08x, "
                         "Computed size: %u, Computed Crc32: %08x",
                         closeUbiCweHdr.imageSize, closeUbiCweHdr.crc32,
                         ubiImgSize, ubiImgCrc32);
                return LE_FAULT;
            }

            LE_INFO("Closing ubi swifota partition");
            if (LE_OK != partition_CloseUbiSwifotaPartition(&PartitionCtx, false, NULL))
            {
                /* Error on closing ubi */
                LE_ERROR ("Error on ubi close");
                return LE_FAULT;
            }
        }
        // Erase the path flag in options to allow new cwe header to be read
        cweHeaderPtr->miscOpts &= (uint8_t)~((uint8_t)CWE_MISC_OPTS_DELTAPATCH);
        LE_DEBUG ("CurrentInImageOffset %" PRIuS ", CurrentImage %d",
                  CurrentInImageOffset, cweHeaderPtr->imageType);
        resumeCtxPtr->saveCtx.isImageToBeRead = false;
        StoreCurrentPosition(resumeCtxPtr);
    }

    return LE_OK;
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

    LE_DEBUG("CWE type %u pid %08x size %u crc %08x opts %hhx",
             CurrentCweHeader.imageType, CurrentCweHeader.prodType, CurrentCweHeader.imageSize,
             CurrentCweHeader.crc32, CurrentCweHeader.miscOpts);
    if (CurrentCweHeader.miscOpts & CWE_MISC_OPTS_DELTAPATCH)
    {
        saveCtxPtr->isImageToBeRead = false;
    }
    if (-1 == saveCtxPtr->fullImageLength)
    {
        if( !(CurrentCweHeader.miscOpts & CWE_MISC_OPTS_DELTAPATCH) &&
              (CurrentCweHeader.imageType != CWE_IMAGE_TYPE_META))
        {
            /*
             * Full length and global CRC of the CWE image is provided inside the
             * first CWE header
             */
            saveCtxPtr->fullImageLength = CurrentCweHeader.imageSize + CWE_HEADER_SIZE;
            saveCtxPtr->globalCrc = CurrentCweHeader.crc32;
            saveCtxPtr->currentGlobalCrc = LE_CRC_START_CRC32;
            PartitionCtx.fullImageSize = saveCtxPtr->fullImageLength;
            LE_INFO("TOP CWE header: fullImageLength = %" PRIdS ", CRC=0x%08" PRIx32,
                    saveCtxPtr->fullImageLength, saveCtxPtr->globalCrc);

            // First CWE header. Copy it in MetaData structure
            memcpy(&saveCtxPtr->metaData.cweHeaderRaw, chunkPtr, CWE_HEADER_SIZE);
            saveCtxPtr->inImageLength = CurrentCweHeader.imageSize + CWE_HEADER_SIZE;
        }
        else
        {
            if( !saveCtxPtr->inImageLength )
            {
                saveCtxPtr->inImageLength = CurrentCweHeader.imageSize + CWE_HEADER_SIZE;
            }
        }
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
        CurrentInImageOffset = 0;
        CurrentImageCrc32 = LE_CRC_START_CRC32;
        // Save the resume context
        saveCtxPtr->imageType = CurrentCweHeader.imageType;
        saveCtxPtr->imageSize = CurrentCweHeader.imageSize;
        saveCtxPtr->imageCrc = CurrentCweHeader.crc32;
        saveCtxPtr->miscOpts = CurrentCweHeader.miscOpts;
        saveCtxPtr->currentImageCrc = LE_CRC_START_CRC32;
        saveCtxPtr->currentInImageOffset = 0;
    }

    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Update context after read patch meta data
 */
//--------------------------------------------------------------------------------------------------
static void UpdateCtxOnMetaRead
(
    size_t length,              ///< [IN] Input data length
    const uint8_t* chunkPtr,    ///< [IN] input data
    ResumeCtx_t *resumeCtxPtr   ///< [OUT] resume context
)
{
    CurrentInImageOffset += length;
    CurrentReadPackageOffset += length;
    CurrentImageCrc32 = le_crc_Crc32((uint8_t*)chunkPtr, length, CurrentImageCrc32);
    CurrentGlobalCrc32 = le_crc_Crc32((uint8_t*)chunkPtr, length, CurrentGlobalCrc32);
    LE_DEBUG ( "patch header: CRC in header: 0x%x, calculated CRC 0x%x",
               CurrentCweHeader.crc32, CurrentImageCrc32 );
}

//--------------------------------------------------------------------------------------------------
/**
 * Parse patch meta headers
 *
 * @return
 *      - LE_OK            On success
 *      - LE_BAD_PARAMETER The parameter is invalid
 *      - LE_FAULT         On failure
 */
//--------------------------------------------------------------------------------------------------
static le_result_t ParsePatchMetaHeaders
(
    size_t length,              ///< [IN] Input data length
    const uint8_t* chunkPtr,    ///< [IN] input data
    ResumeCtx_t *resumeCtxPtr   ///< [OUT] resume context
)
{
    if ((NULL == chunkPtr) || (NULL == resumeCtxPtr) || (PATCH_META_HEADER_SIZE != length))
    {
        LE_ERROR("Bad parameter");
        return LE_BAD_PARAMETER;
    }

    le_result_t res = deltaUpdate_LoadPatchMetaHeader(chunkPtr,
                                                      &(resumeCtxPtr->saveCtx.patchMetaHdr));
    if (LE_OK != res)
    {
        LE_ERROR ("Error in parsing the Patch Meta header");
        return LE_FAULT;
    }

    LE_DEBUG ("Patch Meta read ok");

    UpdateCtxOnMetaRead(length, chunkPtr, resumeCtxPtr);

    // If no diff, then do only copy. This is true for small ubi volume(i.e. dm-verity hash etc)
    if (0 == memcmp(resumeCtxPtr->saveCtx.patchMetaHdr.diffType, NODIFF_MAGIC, strlen(NODIFF_MAGIC)))
    {
        resumeCtxPtr->saveCtx.isImageToBeRead = true;
        DeltaUpdateCtx.patchRemLen = resumeCtxPtr->saveCtx.patchMetaHdr.destSize;
    }

    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Parse bsdiff patch headers
 *
 * @return
 *      - LE_OK            On success
 *      - LE_BAD_PARAMETER The parameter is invalid
 *      - LE_FAULT         On failure
 */
//--------------------------------------------------------------------------------------------------
static le_result_t ParseBsdiffPatchHeaders
(
    size_t length,              ///< [IN] Input data length
    const uint8_t* chunkPtr,    ///< [IN] input data
    ResumeCtx_t *resumeCtxPtr   ///< [OUT] resume context
)
{
    if ((NULL == chunkPtr) || (NULL == resumeCtxPtr) || (PATCH_HEADER_SIZE != length))
    {
        LE_ERROR("Bad parameter");
        return LE_BAD_PARAMETER;
    }

    le_result_t res = deltaUpdate_LoadPatchHeader(chunkPtr, &DeltaUpdateCtx);
    if (LE_OK != res)
    {
        LE_ERROR ("Error in parsing the Patch header");
        return LE_FAULT;
    }

    LE_DEBUG ("BSDIFF Patch header read ok");

    UpdateCtxOnMetaRead(length, chunkPtr, resumeCtxPtr);

    // Next data will concern a component image
    resumeCtxPtr->saveCtx.isImageToBeRead = true;
    DeltaUpdateCtx.patchRemLen = resumeCtxPtr->saveCtx.patchHdr.size;

    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Parse imgdiff patch headers
 *
 * @return
 *      - LE_OK            On success
 *      - LE_BAD_PARAMETER The parameter is invalid
 *      - LE_FAULT         On failure
 */
//--------------------------------------------------------------------------------------------------
static le_result_t ParseImgdiffPatchHeaders
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

    bool shouldLoad = false;
    le_result_t res = applyPatch_ShouldLoadContext(&(resumeCtxPtr->saveCtx.imgdiffCtx),
                                     &shouldLoad);
    if (LE_OK != res)
    {
        LE_ERROR ("Error in parsing the Imgdiff Patch Meta or Patch header");
        return LE_FAULT;
    }

    if (shouldLoad)
    {
        res = applyPatch_LoadPatchContext(chunkPtr,
                                          length,
                                          &(resumeCtxPtr->saveCtx.imgdiffCtx));
        if (LE_OK != res)
        {
            LE_ERROR("Failed to load imgdiff patch context");
            return LE_FAULT;
        }

        LE_DEBUG("Imgdiff Patch header read ok");

        UpdateCtxOnMetaRead(length, chunkPtr, resumeCtxPtr);


        res = applyPatch_ShouldLoadContext(&(resumeCtxPtr->saveCtx.imgdiffCtx),
                                             &shouldLoad);
        if ( (false == shouldLoad) && (LE_OK == res))
        {
            // Next data will be a component patch data
             int32_t patch_len = applyPatch_GetPatchLengthToRead(
                                                  &(resumeCtxPtr->saveCtx.imgdiffCtx),
                                                  CHUNK_LENGTH,
                                                  resumeCtxPtr->saveCtx.isImageToBeRead);
             if (patch_len > 0)
             {
                 resumeCtxPtr->saveCtx.isImageToBeRead = true;
                 DeltaUpdateCtx.patchRemLen = patch_len;
             }
             else if (0 == patch_len)
             {
                 // TODO: No patch. Imgdiff should internally copy data. So call applyImgdiff
                 resumeCtxPtr->saveCtx.isImageToBeRead = false;
                 DeltaUpdateCtx.patchRemLen = patch_len;
                 size_t writeLen = 0;
                 if (LE_OK != WriteImageData(&CurrentCweHeader, chunkPtr, 0,
                                             &writeLen, resumeCtxPtr))
                 {
                     LE_ERROR("Failed to apply imgdiff copy command");
                     return LE_FAULT;
                 }
                 LE_INFO("Imgdiff copy command. Data written in flash: %" PRIuS, writeLen);
             }
             else
             {
                 LE_ERROR("Received bad patch_len: %d", patch_len);
                 return LE_FAULT;
             }

        }
        return LE_OK;
    }
    else
    {
        LE_ERROR("Nothing to load for imgdiff patch header");
        return LE_FAULT;
    }

}

//--------------------------------------------------------------------------------------------------
/**
 * This function is used by the Legato SW Update component to parse and store an incoming package
 *
 * @return
 *      - LE_OK            The request was accepted
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
    ResumeCtxSave_t *saveCtxPtr = &(resumeCtxPtr->saveCtx);
    size_t tmpLen;

    LE_DEBUG("Parsing a chunkPtr: len %" PRIuS ", isImageToBeRead %d",
              length, resumeCtxPtr->saveCtx.isImageToBeRead);

    // Check if a header is read or a component image
    if (false == resumeCtxPtr->saveCtx.isImageToBeRead)
    {
        // Full header shall be provided each time
        if (CWE_HEADER_SIZE == length)
        {
            result = ParseCweHeader(chunkPtr, resumeCtxPtr);
            if (LE_OK != result)
            {
                LE_WARN("Failed to parse a CWE header");
                return result;
            }
        }
        else
        {
            if (PATCH_META_HEADER_SIZE == length)
            {
                result = ParsePatchMetaHeaders(length, chunkPtr, resumeCtxPtr);


                if ((LE_OK == result) &&
                    (resumeCtxPtr->saveCtx.patchMetaHdr.ubiVolId == 0) &&
                    deltaUpdate_IsImgPatch(CurrentCweHeader.imageType))
                {
                    // Patch Meta is read, hence we get the ubi sequence number. Now UBI partition
                    // can be created with ubi sequence number.

                    // Set UBI image seq number to any value and its validity to false. This will
                    // force the UBI layer to take the default UBI image sequence number.
                    // If an UBI image seq number is present inside the delta patch meta data,
                    // set the value and its validity to true.
                    if (LE_OK != partition_OpenUbiSwifotaPartition(&PartitionCtx,
                                                   resumeCtxPtr->saveCtx.patchMetaHdr.patchInfo,
                                                   true, true, NULL))
                    {
                        LE_ERROR("Failed to create ubi partition inside swifota");
                        return LE_FAULT;
                    }
                }

                return result;
            }
            else
            {
                deltaUpdate_PatchMetaHdr_t* hdpPtr= &(resumeCtxPtr->saveCtx.patchMetaHdr);
                if (0 == memcmp(hdpPtr->diffType, BSDIFF_MAGIC, strlen(BSDIFF_MAGIC)))
                {
                     return ParseBsdiffPatchHeaders(length, chunkPtr, resumeCtxPtr);
                }
                else if (0 == memcmp(hdpPtr->diffType, IMGDIFF_MAGIC, strlen(IMGDIFF_MAGIC)))
                {
                    return ParseImgdiffPatchHeaders(length, chunkPtr, resumeCtxPtr);
                }
                else
                {
                    LE_ERROR ("Bad patch meta header");
                    return LE_BAD_PARAMETER;
                }
            }
        }

        if (CurrentCweHeader.imageType == CWE_IMAGE_TYPE_META)
        {
            CurrentReadPackageOffset += length;
            // Do nothing
            return LE_OK;
        }
        else if (CurrentCweHeader.miscOpts & CWE_MISC_OPTS_DELTAPATCH)
        {
            if (  (CurrentCweHeader.imageType == CWE_IMAGE_TYPE_APPL)
               || (CurrentCweHeader.imageType == CWE_IMAGE_TYPE_MODM)
               || (CurrentCweHeader.imageType == CWE_IMAGE_TYPE_SPKG)
               || (CurrentCweHeader.imageType == CWE_IMAGE_TYPE_BOOT))
            {
                // Do nothing for composite delta image. There should be META image which
                // will contain its original header, META processing function should take
                // care of writing that header
                LE_INFO("Composite image has delta package. ImgType: %u",
                        CurrentCweHeader.imageType);
                LE_INFO("Clearing DELTAPATCH options in CWE header for %u",
                        CurrentCweHeader.imageType);
                CurrentCweHeader.miscOpts &= ~(CWE_MISC_OPTS_DELTAPATCH);
                CurrentReadPackageOffset += length;
                return LE_OK;
            }

             // This is not a composite image, so write its original cwe header from meta
             // img data
             if (LE_OK != WriteMetaImageData(resumeCtxPtr, length))
             {
                 LE_ERROR("Failed to write original cwe header from meta image");
                 return LE_FAULT;
             }

        }
        else if (WriteCweHeader(&CurrentCweHeader, chunkPtr, length, &tmpLen, resumeCtxPtr))
        {
            // Write to flash sucess
            result = LE_OK;
        }
        else
        {
            // Write to flash failed
            LE_ERROR("Write to flash failed");
            result = LE_FAULT;
        }
    }
    else
    {
        // Component image is under read: follow it
        if (CWE_IMAGE_TYPE_META == CurrentCweHeader.imageType)
        {

            if (LE_OK != ProcessMetaImgData(chunkPtr, length, resumeCtxPtr))
            {
                LE_ERROR("Failed to process meta image data");
                return LE_OK;
            }

            // Only parse and write the first cwe header, rest will be handled once we incur more
            // delta packages inside this composite package.
            cwe_Header_t cweHdr;

            if (cwe_LoadHeader(chunkPtr, &cweHdr) != LE_OK)
            {
                LE_ERROR("Error in parsing the CWE header");
                return LE_FAULT;
            }

            if (-1 == saveCtxPtr->fullImageLength)
            {
                // Copy the first cwe header to meta data. This is required for SBL to program
                // image properly
                memset(saveCtxPtr->metaData.cweHeaderRaw, 0,
                       sizeof(saveCtxPtr->metaData.cweHeaderRaw));
                memcpy(saveCtxPtr->metaData.cweHeaderRaw,
                                       chunkPtr,
                                       CWE_HEADER_SIZE);

                /*
                 * Full length and global CRC of the CWE image is provided inside the
                 * first CWE header
                 */
                saveCtxPtr->currentGlobalCrc = LE_CRC_START_CRC32;
                saveCtxPtr->globalCrc = cweHdr.crc32;
                saveCtxPtr->fullImageLength = cweHdr.imageSize + CWE_HEADER_SIZE;
                PartitionCtx.fullImageSize = saveCtxPtr->fullImageLength;
                LE_INFO("META CWE header: fullImageLength = %" PRIdS ", CRC=0x%08" PRIx32,
                        saveCtxPtr->fullImageLength, saveCtxPtr->globalCrc);
            }
            // Now write only the first cweHeader and store others

            if (LE_OK != WriteMetaImageData(resumeCtxPtr, length))
            {
                LE_ERROR("Writing CWE header from meta data failed");
                return LE_FAULT;
            }
            // Meta data processing passed, no need write it again. Return now
            return LE_OK;
        }

        if (LE_OK != WriteImageData(&CurrentCweHeader, chunkPtr, length, &tmpLen, resumeCtxPtr))
        {
            // Write to flash failed
            LE_ERROR("Writing image data failed");
            return LE_FAULT;
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
        // If the download status file not found, query the status from the modem
        LE_INFO("Unable to access to %s!", EFS_DWL_STATUS_FILE);
        result = pa_fwupdate_GetInternalUpdateStatus(statusPtr);
        if (LE_OK != result)
        {
            LE_INFO("Can't retrieve the download status from QMI, err %s", LE_RESULT_TXT(result));
        }
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
                            LE_DEBUG("Read %" PRIdS "bytes", *lengthPtr);
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

    memcpy(metaDataPtr->cweHeaderRaw,
           saveCtxPtr->metaData.cweHeaderRaw,
           sizeof(metaDataPtr->cweHeaderRaw));

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

    LE_INFO("Image length: %" PRIdS, PartitionCtx.fullImageSize);
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
    le_thread_Sleep(1);
    if (-1 != system("/sbin/reboot"))
    {
        // System reset is not done immediately so we need to keep here
        while(1)
        {
            le_thread_Sleep(2);
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
    ResumeCtxSave_t *saveCtxPtr = &ResumeCtx.saveCtx;
    le_clk_Time_t startTime = le_clk_GetAbsoluteTime();

    LE_DEBUG ("fd %d", fd);
    if ((fd < 0) || (LE_OK != CheckFdType(fd, &isRegularFile)))
    {
        LE_ERROR ("Bad parameter");
        result = LE_BAD_PARAMETER;
        goto error;
    }

    if (GetResumeCtx(&ResumeCtx) != LE_OK)
    {
        LE_ERROR("Error when getting the resume context");
        pa_fwupdate_InitDownload();
    }

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
                if (totalCount >= saveCtxPtr->inImageLength)
                {
                    LE_INFO("End of update: total read %" PRIuS ", full length expected %" PRIdS,
                            totalCount, saveCtxPtr->inImageLength);
                    readCount = 0;
                    StoreCurrentPosition(&ResumeCtx);
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
            LE_DEBUG ("Read %" PRIuS "bytes in total", totalCount);
            if (totalCount > saveCtxPtr->inImageLength)
            {
                LE_ERROR("Too much data have been received");
                goto error;
            }
            else if (totalCount < saveCtxPtr->inImageLength)
            {
                LE_INFO("Download is not complete, resume allowed");
                result = LE_CLOSED;
                goto error;
            }
            else
            {
                uint32_t globalCrc;

                if (LE_OK != partition_ComputeDataCrc32SwifotaPartition(&PartitionCtx,
                                                                        CWE_HEADER_SIZE,
                                                                        saveCtxPtr->fullImageLength
                                                                            - CWE_HEADER_SIZE,
                                                                        &globalCrc))
                {
                    LE_ERROR("Failure while computing global CRC");
                    goto error;
                }
                LE_INFO("End of download: globalCrc %08x length %u",
                        globalCrc, (uint32_t)(saveCtxPtr->fullImageLength - CWE_HEADER_SIZE));
                LE_INFO("Expected CRC %08x", globalCrc);

                if (saveCtxPtr->globalCrc != globalCrc)
                {
                    LE_ERROR("Bad CRC check global: %08x != %08x",
                             saveCtxPtr->globalCrc, globalCrc);
                    goto error;
                }

                LE_INFO("Closing swifota partiton");
                result = partition_CloseSwifotaPartition(&PartitionCtx,
                                                         saveCtxPtr->fullImageLength,
                                                         false,
                                                         NULL);
                if (LE_OK != result)
                {
                    LE_ERROR("partition_CloseSwifotaPartition fails: %d", result);
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
    if (LE_OK != WriteData(&CurrentCweHeader, 0, NULL, NULL, true))
    {
        LE_CRIT("Failed to force close of MTD.");
    }

    (void)partition_CloseSwifotaPartition(&PartitionCtx, 0, true, NULL);

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

    // Write the Meta data in swifota partition
    if (LE_OK != WriteMetaData(&ResumeCtx))
    {
        return LE_FAULT;
    }

    // Clean the resume context as it contains a valid meta data structure
    EraseResumeCtx(&ResumeCtx);

    // Change the status after writing the metadata. Otherwise if power-cut happens after changing
    // status but before writing metadata, SBL won't do any firmware installation although fwupdate
    // changed the status to INSTALL ONGOING
    RECORD_DWL_STATUS(PA_FWUPDATE_INTERNAL_STATUS_INST_ONGOING);

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
    size_t partitionCtxSize = 0;
    void* partitionCtxPtr;

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

    // Allocate a pool for the partition context
    partition_GetPartitionInternals(&partitionCtxPtr, &partitionCtxSize);
    PartitionContextPool = le_mem_CreatePool("PartitionCtxPool", partitionCtxSize);
    le_mem_ExpandPool(PartitionContextPool, 1);
    PartitionContextPtr = le_mem_AssertAlloc(PartitionContextPool);

    // Check if we need to resume
    if (GetResumeCtx(&ResumeCtx) != LE_OK)
    {
        LE_ERROR("Error when getting the resume context");
        pa_fwupdate_InitDownload();
    }
}
