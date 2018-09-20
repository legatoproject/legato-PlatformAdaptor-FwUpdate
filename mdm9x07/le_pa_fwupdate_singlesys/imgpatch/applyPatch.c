/**
 * @file deltaUpdate.c
 *
 * implementation of the delta update process.
 *
 * Copyright (C) Sierra Wireless Inc.
 *
 */

#include "applyPatch.h"

#include "deltaUpdate_local.h"
#include "legato.h"
#include "pa_flash.h"
#include "pa_patch.h"
#include "cwe_local.h"
#include "imgdiff.h"
#include "imgpatch_utils.h"
#include "imgpatch.h"
#include "utils_local.h"

//--------------------------------------------------------------------------------------------------
/**
 * State of imgpatch.
 */
//--------------------------------------------------------------------------------------------------
typedef enum
{
    STATE_READ_HEADER = 0,
    STATE_READ_TYPE,
    STATE_READ_META,
    STATE_READ_PATCH,
    STATE_APPLY_PATCH
}
ApplyPatchState_t;

//==================================================================================================
//  PUBLIC API FUNCTIONS
//==================================================================================================

//--------------------------------------------------------------------------------------------------
/**
 * This function is used to initialize a Patch Context
 */
//--------------------------------------------------------------------------------------------------
void applyPatch_Init
(
    applyPatch_Ctx_t *ctxPtr              ///< [INOUT] Apply patch context
)
{
    if (NULL == ctxPtr)
    {
        LE_CRIT("Bad context ptr: %p", ctxPtr);
        return;
    }
    ctxPtr->applyPatchState = 0;
    ctxPtr->curIndex = 0;
    memset(&(ctxPtr->hdr), 0, sizeof(ctxPtr->hdr));
    memset(&(ctxPtr->metaHdr), 0, sizeof(ctxPtr->metaHdr));;

}
//--------------------------------------------------------------------------------------------------
/**
 * This function is used by the Legato SW Update component to read a Patch Context
 *
 * @return
 *      - LE_OK            The request was accepted
 *      - LE_FAULT         If an error occurs
 */
//--------------------------------------------------------------------------------------------------
le_result_t applyPatch_LoadPatchContext
(
    const uint8_t* startPtr,             ///< [IN] start address of the Patch header to be read
    uint32_t length,                     ///< [IN] Length of supplied data
    applyPatch_Ctx_t *ctxPtr             ///< [INOUT] Apply patch context
)
{
    if ((NULL == startPtr) || (NULL == ctxPtr))
    {
        LE_ERROR("Bad parameters, startPtr: %p, applyPatchCtx: %p", startPtr, ctxPtr);
        return LE_FAULT;
    }

    uint8_t *dataPtr = (uint8_t *)startPtr;
    ApplyPatchState_t applyPatchState = (ApplyPatchState_t)(ctxPtr->applyPatchState);

    switch ((ApplyPatchState_t)(ctxPtr->applyPatchState))
    {
        case STATE_READ_HEADER:
        {
            if (sizeof(imgdiff_header_t) != length)
            {
                LE_ERROR("Bad data length, expected: %zu, received: %u",
                         sizeof(imgdiff_header_t),
                         length);
                return LE_FAULT;
            }
            imgdiff_header_t* hdrPtr = &(ctxPtr->hdr);
            utils_CopyAndIncrPtr(&dataPtr, hdrPtr->magic, sizeof(hdrPtr->magic));

            if (0 != memcmp(hdrPtr->magic, "IMGDIFF2", 8))
            {
                LE_ERROR("Corrupt patch file header (magic number): %s", hdrPtr->magic);
                return LE_FAULT;
            }

            hdrPtr->src_img_len = Read4(&dataPtr);
            LE_DEBUG("src_img_len: %d\n", hdrPtr->src_img_len);
            utils_CopyAndIncrPtr(&dataPtr, hdrPtr->src_sha256, sizeof(hdrPtr->src_sha256));


            hdrPtr->tgt_img_len = Read4(&dataPtr);
            LE_DEBUG("tgt_img_len: %d\n", hdrPtr->tgt_img_len);
            utils_CopyAndIncrPtr(&dataPtr, hdrPtr->tgt_sha256, sizeof(hdrPtr->tgt_sha256));
            hdrPtr->patch_count = Read4(&dataPtr);
            LE_DEBUG("patch_count: %d\n", hdrPtr->patch_count);
            applyPatchState = STATE_READ_TYPE;
        }
            break;
        case STATE_READ_TYPE:
            if (sizeof(uint32_t) != length)
            {
                LE_ERROR("Bad data length, expected: %zu, received: %u",
                         sizeof(uint32_t),
                         length);
                return LE_FAULT;
            }
            ctxPtr->metaHdr.chunkType = Read4(&dataPtr);
            LE_DEBUG("ChunkType: %d", ctxPtr->metaHdr.chunkType);
            applyPatchState = STATE_READ_META;
            break;
        case STATE_READ_META:
        {
            applyPatch_Meta_t* metaPtr = &(ctxPtr->metaHdr);
            // Set all meta field to zero
            memset(&(metaPtr->imgpatchMeta), 0, sizeof(metaPtr->imgpatchMeta));
            switch (metaPtr->chunkType)
            {
                case CHUNK_NORMAL:
                    if (sizeof(imgdiff_chunk_normal_meta_t) != length)
                    {
                        LE_ERROR("Bad data length, expected: %zu, received: %u",
                                 sizeof(imgdiff_chunk_normal_meta_t),
                                 length);
                        return LE_FAULT;
                    }
                    metaPtr->imgpatchMeta.normMeta.src_start = Read4(&dataPtr);
                    metaPtr->imgpatchMeta.normMeta.src_len = Read4(&dataPtr);
                    metaPtr->imgpatchMeta.normMeta.patch_len = Read4(&dataPtr);
                    LE_INFO("Normal Chunk. src_start: %u, src_len: %u, patch_len: %u",
                            metaPtr->imgpatchMeta.normMeta.src_start,
                            metaPtr->imgpatchMeta.normMeta.src_len,
                            metaPtr->imgpatchMeta.normMeta.patch_len);
                    applyPatchState = STATE_READ_PATCH;
                    break;
                case CHUNK_RAW:
                    if (sizeof(imgdiff_chunk_raw_meta_t) != length)
                    {
                        LE_ERROR("Bad data length, expected: %zu, received: %u",
                                 sizeof(imgdiff_chunk_raw_meta_t),
                                 length);
                        return LE_FAULT;
                    }
                    metaPtr->imgpatchMeta.rawMeta.tgt_len = Read4(&dataPtr);
                    LE_INFO("RAW Chunk patch_len: %d", metaPtr->imgpatchMeta.rawMeta.tgt_len);
                    applyPatchState = STATE_READ_PATCH;
                    break;
                case CHUNK_DEFLATE:
                    if (sizeof(imgdiff_chunk_deflate_meta_t) != length)
                    {
                        LE_ERROR("Bad data length, expected: %zu, received: %u",
                                 sizeof(imgdiff_chunk_deflate_meta_t),
                                 length);
                        return LE_FAULT;
                    }
                    metaPtr->imgpatchMeta.deflMeta.src_start = Read4(&dataPtr);
                    metaPtr->imgpatchMeta.deflMeta.src_len = Read4(&dataPtr);
                    metaPtr->imgpatchMeta.deflMeta.src_expand_len = Read4(&dataPtr);
                    metaPtr->imgpatchMeta.deflMeta.tgt_expand_len = Read4(&dataPtr);
                    metaPtr->imgpatchMeta.deflMeta.gzip_level = Read4(&dataPtr);
                    metaPtr->imgpatchMeta.deflMeta.gzip_method = Read4(&dataPtr);
                    metaPtr->imgpatchMeta.deflMeta.gzip_windowBits = Read4(&dataPtr);
                    metaPtr->imgpatchMeta.deflMeta.gzip_memlevel = Read4(&dataPtr);
                    metaPtr->imgpatchMeta.deflMeta.gzip_strategy = Read4(&dataPtr);
                    metaPtr->imgpatchMeta.deflMeta.patch_len = Read4(&dataPtr);
                    LE_INFO("Deflate Chunk. src_start: %u, src_len: %u, src_expanded_len: %u "
                            "tgt_expanded_len: %u, gzip_level: %d, gzip_method: %d, "
                            "windowsBit: %d, memlevel: %d, strategy: %d, patch_len: %u",
                            metaPtr->imgpatchMeta.deflMeta.src_start,
                            metaPtr->imgpatchMeta.deflMeta.src_len,
                            metaPtr->imgpatchMeta.deflMeta.src_expand_len,
                            metaPtr->imgpatchMeta.deflMeta.tgt_expand_len,
                            metaPtr->imgpatchMeta.deflMeta.gzip_level,
                            metaPtr->imgpatchMeta.deflMeta.gzip_method,
                            metaPtr->imgpatchMeta.deflMeta.gzip_windowBits,
                            metaPtr->imgpatchMeta.deflMeta.gzip_memlevel,
                            metaPtr->imgpatchMeta.deflMeta.gzip_strategy,
                            metaPtr->imgpatchMeta.deflMeta.patch_len
                            );
                    applyPatchState = STATE_READ_PATCH;
                    break;
                case CHUNK_COPY:
                    if (sizeof(imgdiff_chunk_copy_meta_t) != length)
                    {
                        LE_ERROR("Bad data length, expected: %zu, received: %u",
                                 sizeof(imgdiff_chunk_copy_meta_t),
                                 length);
                        return LE_FAULT;
                    }
                    metaPtr->imgpatchMeta.cpMeta.src_start = Read4(&dataPtr);
                    metaPtr->imgpatchMeta.cpMeta.src_len = Read4(&dataPtr);
                    LE_INFO("Copy Chunk. src_start: %d, src_len: %d",
                            metaPtr->imgpatchMeta.cpMeta.src_start,
                            metaPtr->imgpatchMeta.cpMeta.src_len);
                    applyPatchState = STATE_APPLY_PATCH;
                    break;
                default:
                    LE_CRIT("Bad chunk type: %d", metaPtr->chunkType);
                    return LE_FAULT;
            }

        }
            break;
        case STATE_READ_PATCH:
        case STATE_APPLY_PATCH:
            LE_CRIT("Error: Asking to loading context on wrong state: %u",
                    ctxPtr->applyPatchState);
            return LE_FAULT;
        default:
            LE_CRIT("Bad applyPatchState: %d", ctxPtr->applyPatchState);
            return LE_FAULT;

    }

    LE_DEBUG("state changed from: %u to %u", ctxPtr->applyPatchState,
            (uint32_t)applyPatchState);
    ctxPtr->applyPatchState = (uint32_t)applyPatchState;

    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * This function returns the index of the currently processing patch
 *
 * @return
 *      - Index of currently processing patch
 *      - -1 on error or no patch is processing
 */
//--------------------------------------------------------------------------------------------------
int applyPatch_GetCurrentPatchIndex
(
    applyPatch_Ctx_t* ctxPtr
)
{
    if (!ctxPtr)
    {
        LE_ERROR("Bad input parameter. ctxPtr: %p", ctxPtr);
        return -1;
    }

    return ctxPtr->curIndex;
}

//--------------------------------------------------------------------------------------------------
/**
 * This function checks whether the currently processing patch is the first patch or not
 *
 * @return
 *      - LE_OK if some patch processing is going on
 *      - LE_FAULT if no patch is processing
 */
//--------------------------------------------------------------------------------------------------
le_result_t applyPatch_IsFirstPatch
(
        applyPatch_Ctx_t* ctxPtr,
        bool *isFirstPatch
)
{
    if (!ctxPtr || !isFirstPatch)
    {
        LE_ERROR("Bad input parameter. ctxPtr: %p, isFirstPatch: %p", ctxPtr, isFirstPatch);
        return LE_FAULT;
    }

    *isFirstPatch = ctxPtr->curIndex == 0 ? true : false;

    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * This function checks whether the currently processing patch is the last patch or not
 *
 * @return
 *      - LE_OK if some patch processing is going on
 *      - LE_FAULT if no patch is processing
 */
//--------------------------------------------------------------------------------------------------
le_result_t applyPatch_IsLastPatch
(
        applyPatch_Ctx_t* ctxPtr,
        bool *isLastPatch
)
{
    if (!ctxPtr || !isLastPatch)
    {
        LE_ERROR("Bad input parameter. ctxPtr: %p, isFirstPatch: %p", ctxPtr, isLastPatch);
        return LE_FAULT;
    }

    *isLastPatch = ctxPtr->curIndex == ctxPtr->hdr.patch_count ? true : false;

    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * This function returns total patch count
 *
 * @return
 *      - total patch count
 *      - -1 on error
 */
//--------------------------------------------------------------------------------------------------
int applyPatch_GetTotalPatchCount
(
    applyPatch_Ctx_t* ctxPtr
)
{
    if (!ctxPtr)
    {
        LE_ERROR("Bad input parameter. ctxPtr: %p", ctxPtr);
        return -1;
    }

    return ctxPtr->hdr.patch_count;
}

//--------------------------------------------------------------------------------------------------
/**
 * This function is used by the Legato SW Update component to check whether more metadata should be
 * loaded or not
 *
 * @return
 *      - LE_OK            The request was accepted
 *      - LE_FAULT         If an error occurs
 */
//--------------------------------------------------------------------------------------------------
le_result_t applyPatch_ShouldLoadContext
(
    applyPatch_Ctx_t *ctxPtr,             ///< [IN] Apply patch context
    bool *shouldLoad                      ///< [OUT] False if loading patch context is complete.
                                          ///<       True otherwise.
)
{
    if ((NULL == ctxPtr) || (NULL == shouldLoad))
    {
        LE_CRIT("Bad input applyPatchCtx: %p, shouldLoad: %p", ctxPtr, shouldLoad);
        return LE_FAULT;
    }

    LE_DEBUG("applyPatchState: %u", ctxPtr->applyPatchState);

    switch ((ApplyPatchState_t)(ctxPtr->applyPatchState))
    {
        case STATE_READ_HEADER:
        case STATE_READ_TYPE:
        case STATE_READ_META:
            // Context loading not done, need to load more
            *shouldLoad = true;
            break;

        case STATE_READ_PATCH:
        case STATE_APPLY_PATCH:
            // State switched to reading patch, so no need to load the meta
            *shouldLoad = false;
            break;
        default:
            LE_CRIT("Bad applyPatchState: %d", ctxPtr->applyPatchState);
            *shouldLoad = false;
            return LE_FAULT;
    }

    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Apply patch to a partition
 *
 * @return
 *      - LE_OK            on success
 *      - LE_FAULT         on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t applyPatch_ApplyImgPatch
(
    applyPatch_Ctx_t *ctxPtr,          ///< [IN] Delta update context
    const char* patchFilePtr,          ///< [IN] input data
    pa_flash_Desc_t srcDesc,           ///< [IN] Force close of device and resources
    partition_Ctx_t* destPartPtr,      ///< [IN] Source and destination partion context
    size_t* wrLenToFlash               ///< [OUT] Amount of data written to target flash
)
{
    if (!ctxPtr || !destPartPtr || !srcDesc)
    {
        LE_CRIT("Bad input applyPatchCtx: %p, destPartPtr: %p srcDesc: %p",
                ctxPtr,
                destPartPtr,
                srcDesc);
        return LE_FAULT;
    }
    ApplyPatchState_t applyPatchState = (ApplyPatchState_t)(ctxPtr->applyPatchState);

    // State must be higher than or equal READ_PATCH
    if (applyPatchState < STATE_READ_PATCH)
    {
        LE_ERROR("Bad state :%d, To apply patch, state must be: %d or higher",
                 (uint32_t)applyPatchState,
                 (uint32_t)STATE_READ_PATCH);
        return LE_FAULT;
    }

    // Now read call imgpatch to get the output on temp file
    if(LE_OK != imgpatch_ApplyImgPatch(&(ctxPtr->metaHdr), srcDesc, patchFilePtr,
                                       destPartPtr, wrLenToFlash))
    {
        LE_ERROR("Failed to apply imgpatch");
        return LE_FAULT;
    }

    // Increase the patch count and change the state machine
    ctxPtr->curIndex++;

    if (ctxPtr->curIndex < ctxPtr->hdr.patch_count)
    {
        applyPatchState = STATE_READ_TYPE;
    }
    else
    {
        // Reading of all patches finished, change state to READ_HEADER
        applyPatchState = STATE_READ_HEADER;
    }

    ctxPtr->applyPatchState = (uint32_t)applyPatchState;

    LE_INFO("cur patchIdx: %u, total patch: %u, applyPatchState:%u",
            ctxPtr->curIndex,
            ctxPtr->hdr.patch_count,
            ctxPtr->applyPatchState);

    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * This function returns the expected length of to read according to the patch progress
 *
 * @return
 *      - the length to read
 *      -  0 when when reading of all patches finished
 *      - -1 on error
 */
//--------------------------------------------------------------------------------------------------
ssize_t applyPatch_GetPatchLengthToRead
(
    applyPatch_Ctx_t* ctxPtr,           ///< [IN] Delta update imgdiff context
    size_t chunkLength,                 ///< [IN] chunk length
    bool isImageToBeRead                ///< [IN] Boolean to know if data concerns header or
                                        ///<      component image
)
{
    ssize_t readCount = 0;

    if (!ctxPtr)
    {
        return -1;
    }

    ApplyPatchState_t applyPatchState = (ApplyPatchState_t)(ctxPtr->applyPatchState);

    switch (applyPatchState)
    {
        case STATE_READ_HEADER:
            readCount = sizeof(imgdiff_header_t);
            break;

        case STATE_READ_TYPE:
            readCount = sizeof(uint32_t);
            break;

        case STATE_READ_META:
            {
                int chunkType = ctxPtr->metaHdr.chunkType;

                switch (chunkType)
                {
                    case CHUNK_NORMAL:
                        readCount = sizeof(imgdiff_chunk_normal_meta_t);
                        break;
                    case CHUNK_COPY:
                        readCount = sizeof(imgdiff_chunk_copy_meta_t);
                        break;
                    case CHUNK_DEFLATE:
                        readCount = sizeof(imgdiff_chunk_deflate_meta_t);
                        break;
                    case CHUNK_RAW:
                        readCount = sizeof(imgdiff_chunk_raw_meta_t);
                        break;
                    default:
                        LE_CRIT("Bad chunk type: %d", chunkType);
                        readCount = -1;
                        break;
                }

            }
            break;

        case STATE_READ_PATCH:
            {
                int chunkType = ctxPtr->metaHdr.chunkType;

                switch (chunkType)
                {
                    case CHUNK_NORMAL:
                        readCount = ctxPtr->metaHdr.imgpatchMeta.normMeta.patch_len;
                        break;
                    case CHUNK_COPY:
                        // No patch is there. Only copy needed.
                        readCount = 0;
                        break;
                    case CHUNK_DEFLATE:
                        readCount = ctxPtr->metaHdr.imgpatchMeta.deflMeta.patch_len;
                        break;
                    case CHUNK_RAW:
                        readCount = ctxPtr->metaHdr.imgpatchMeta.rawMeta.tgt_len;
                        break;
                    default:
                        LE_CRIT("Bad chunk type: %d", chunkType);
                        readCount = -1;
                        break;
                }
            }
            break;

        case STATE_APPLY_PATCH:
            LE_INFO("Nothing to read on APPLY_PATCH state");
            break;
    }

    LE_INFO("current state: %u, readCount: %zd", ctxPtr->applyPatchState, readCount);

    return readCount;
}
