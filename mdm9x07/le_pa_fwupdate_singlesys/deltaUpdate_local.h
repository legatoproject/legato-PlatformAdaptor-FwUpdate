/**
 * @file deltaUpdate_local.h
 *
 * delta update header file
 *
 * Copyright (C) Sierra Wireless Inc.
 *
 */

#ifndef LEGATO_DELTAUPDATE_INCLUDE_GUARD
#define LEGATO_DELTAUPDATE_INCLUDE_GUARD

#include "legato.h"
#include "cwe_local.h"
#include "partition_local.h"

//--------------------------------------------------------------------------------------------------
/**
 * Delta patch Meta header (one for each image. May be split into several slices)
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
deltaUpdate_PatchMetaHdr_t;

#define PATCH_META_HEADER_SIZE sizeof(deltaUpdate_PatchMetaHdr_t)

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
deltaUpdate_PatchHdr_t;

#define PATCH_HEADER_SIZE sizeof(deltaUpdate_PatchHdr_t)

//--------------------------------------------------------------------------------------------------
/**
 * Delta update context
 */
//--------------------------------------------------------------------------------------------------
typedef struct
{
    const cwe_Header_t *cweHdrPtr;          ///< Component image header
    deltaUpdate_PatchHdr_t *hdrPtr;         ///< Patch header
    deltaUpdate_PatchMetaHdr_t *metaHdrPtr; ///< Patch meta header
    size_t patchRemLen;                     ///< Expected remaining length of the patch when a patch
                                            ///< is crossing a chunk
    le_mem_PoolRef_t *poolPtr;              ///< Memory pool to use
}
deltaUpdate_Ctx_t;

//--------------------------------------------------------------------------------------------------
/**
 * This function is used by the Legato FW Update component to read a Patch Meta header
 *
 * @return
 *      - LE_OK            The request was accepted
 *      - LE_BAD_PARAMETER The parameter is invalid
 *      - LE_FAULT         If an error occurs
 */
//--------------------------------------------------------------------------------------------------
le_result_t deltaUpdate_LoadPatchMetaHeader
(
    const uint8_t* startPtr,             ///< [IN] start address of the Patch Meta header to be read
    deltaUpdate_PatchMetaHdr_t* hdpPtr   ///< [OUT] pointer to a Patch Meta header structure
);

//--------------------------------------------------------------------------------------------------
/**
 * This function is used by the Legato FW Update component to read a Patch header
 *
 * @return
 *      - LE_OK            The request was accepted
 *      - LE_BAD_PARAMETER The parameter is invalid
 *      - LE_FAULT         If an error occurs
 */
//--------------------------------------------------------------------------------------------------
le_result_t deltaUpdate_LoadPatchHeader
(
    const uint8_t* startPtr,             ///< [IN] start address of the Patch header to be read
    deltaUpdate_Ctx_t *ctxPtr            ///< [IN] Delta update context
);

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
le_result_t deltaUpdate_ApplyPatch
(
    deltaUpdate_Ctx_t *ctxPtr,          ///< [IN] Delta update context
    size_t length,                      ///< [IN] Input data length
    size_t offset,                      ///< [IN] Data offset in the package
    const uint8_t* dataPtr,             ///< [IN] input data
    partition_Ctx_t* partitionCtxPtr,   ///< [IN] Partition context
    size_t* lengthPtr,                  ///< [IN][OUT] Length to be read/written
    size_t* wrLenPtr,                   ///< [OUT] Length really written
    bool forceClose,                    ///< [IN] Force close of device and resources
    bool *isFlashedPtr                  ///< [OUT] true if flash write was done
);

//--------------------------------------------------------------------------------------------------
/**
 * This function returns the expected length of to read according to the patch progress
 *
 * @return
 *      - the length to read
 *      - -1 on error
 */
//--------------------------------------------------------------------------------------------------
ssize_t deltaUpdate_GetPatchLengthToRead
(
    const deltaUpdate_Ctx_t *ctxPtr,    ///< [IN] Delta update context
    size_t chunkLength,                 ///< [IN] chunk length
    bool isImageToBeRead                ///< [IN] Boolean to know if data concerns header or
                                        ///<      component image
);

#endif /* LEGATO_DELTAUPDATE_INCLUDE_GUARD */

