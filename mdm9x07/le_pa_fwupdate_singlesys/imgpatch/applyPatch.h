/**
 * @file applyPatch.h
 *
 * Header file containing function related to imgpatch.
 *
 * Copyright (C) Sierra Wireless Inc.
 *
 */

#ifndef LEGATO_IMGPATCH_APPLYPATCH_INCLUDE_GUARD
#define LEGATO_IMGPATCH_APPLYPATCH_INCLUDE_GUARD

#include "legato.h"
#include "imgdiff.h"
#include "pa_flash.h"
#include "partition_local.h"

//--------------------------------------------------------------------------------------------------
/**
 * Imgdiff meta data header
 * Note: Use uint32_t type for all 32-bits fields
 */
//--------------------------------------------------------------------------------------------------
typedef union
{
    imgdiff_chunk_normal_meta_t normMeta;
    imgdiff_chunk_deflate_meta_t deflMeta;
    imgdiff_chunk_raw_meta_t rawMeta;
    imgdiff_chunk_copy_meta_t cpMeta;
}
imgpatch_meta_t;


//--------------------------------------------------------------------------------------------------
/**
 * ApplyPatch meta data header
 * Note: Use uint32_t type for all 32-bits fields
 */
//--------------------------------------------------------------------------------------------------
typedef struct
{
    uint32_t chunkType;               ///< imgdiff chunk type (RAW, DEFLATE, NORMAL etc)
    imgpatch_meta_t imgpatchMeta;     ///< meta data for patch
}
applyPatch_Meta_t;


//--------------------------------------------------------------------------------------------------
/**
 * Delta update context for imgdiff
 */
//--------------------------------------------------------------------------------------------------
typedef struct
{
    imgdiff_header_t hdr;                    ///< Image diff header
    uint32_t curIndex;                       ///< Index of current patch
    applyPatch_Meta_t metaHdr;               ///< Meta data of current patch
    uint32_t applyPatchState;
}
applyPatch_Ctx_t;

//--------------------------------------------------------------------------------------------------
/**
 * This function is used to initialize a Patch Context
 * NOTE: Must provide a valid parameter otherwise program will exit
 */
//--------------------------------------------------------------------------------------------------
void applyPatch_Init
(
    applyPatch_Ctx_t *ctxPtr              ///< [INOUT] Apply patch context
);

//--------------------------------------------------------------------------------------------------
/**
 * This function is used by the Legato SW Update component to read a Patch Context
 *
 * @return
 *      - LE_OK            The request was accepted
 *      - LE_BAD_PARAMETER The parameter is invalid
 *      - LE_FAULT         If an error occurs
 */
//--------------------------------------------------------------------------------------------------
le_result_t applyPatch_LoadPatchContext
(
    const uint8_t* startPtr,             ///< [IN] start address of the Patch header to be read
    uint32_t length,                     ///< [IN] Length of supplied data
    applyPatch_Ctx_t *ctxPtr             ///< [INOUT] Apply patch context
);

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
    bool* shouldLoad                      ///< [OUT] False if loading patch context is complete.
                                          ///<       True otherwise.
);

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
);

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
);

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
);

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
);

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
);

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
);

#endif  // LEGATO_IMGPATCH_APPLYPATCH_INCLUDE_GUARD
