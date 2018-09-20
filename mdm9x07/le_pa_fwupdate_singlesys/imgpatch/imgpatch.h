/**
 * @file imgpatch.h
 *
 * Api for applying imgpatch
 *
 * Copyright (C) Sierra Wireless Inc.
 *
 */



#ifndef LEGATO_IMGPATCH_LOCAL_INCLUDE_GUARD
#define LEGATO_IMGPATCH_LOCAL_INCLUDE_GUARD

#include "legato.h"
#include "pa_flash.h"
#include "partition_local.h"
#include "applyPatch.h"

//--------------------------------------------------------------------------------------------------
/**
 * Apply patch on source chunk, create the target chunk and write to target partition
 *
 * @return
 *      - LE_OK            On success.
 *      - LE_FAULT         On failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t imgpatch_ApplyImgPatch
(
    const applyPatch_Meta_t* patchMetaHdrPtr,        ///< [IN] Meta data of provided patch
    pa_flash_Desc_t srcDesc,                        ///< [IN] Source chunk
    const char* patchFilePtr,                       ///< [IN] File containing patch
    partition_Ctx_t* partCtxPtr,                    ///< [OUT] File containing patched data
    size_t* wrLenToFlash                            ///< [OUT] Amount of data written to target flash
);

//--------------------------------------------------------------------------------------------------
/**
 * Write a chunk directly to target partition
 *
 * @return
 *      - LE_OK            On success.
 *      - LE_FAULT         On failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t imgpatch_WriteChunk
(
    const char* patchFilePtr,              ///< [IN] File containing patch
    uint32_t offset,                       ///< [IN] Offset in partition
    uint32_t len,                          ///< [IN] Length of data
    partition_Ctx_t* destPartPtr           ///< [IN] Partition where data should be written buffer
);

//--------------------------------------------------------------------------------------------------
/**
 * Clean imgpatch context
 */
//--------------------------------------------------------------------------------------------------
void imgpatch_clean
(
   void
);

#endif // LEGATO_IMGPATCH_LOCAL_INCLUDE_GUARD
