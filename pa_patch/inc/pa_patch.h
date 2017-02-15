/**
 * @file pa_patch.h
 *
 * Copyright (C) Sierra Wireless Inc.
 *
 */

#ifndef LEGATO_PA_PATCH_INCLUDE_GUARD
#define LEGATO_PA_PATCH_INCLUDE_GUARD

#include "legato.h"

//--------------------------------------------------------------------------------------------------
/**
 * Define the maximum size of a patch segment
 */
//--------------------------------------------------------------------------------------------------
#define PA_PATCH_MAX_SEGMENTSIZE (1024U * 1024U)

//--------------------------------------------------------------------------------------------------
/**
 * Define the open mode options and type for pa_patch
 * Open mode: Read-Only (No write allowed)
 *            Write-Only (No read allowed)
 *            Read-and-write (read or/and write allowed)
 */
//--------------------------------------------------------------------------------------------------
typedef enum
{
    PA_PATCH_IMAGE_RAWFLASH = 0,     ///< RAW flash
    PA_PATCH_IMAGE_UBIFLASH,         ///< UBI data info RAW flash
    PA_PATCH_IMAGE_MAX      = PA_PATCH_IMAGE_UBIFLASH,
}
pa_patch_Image_t;

//--------------------------------------------------------------------------------------------------
/**
 * Define the value of an invalid UBI volume ID
 */
//--------------------------------------------------------------------------------------------------
#define PA_PATCH_INVALID_UBI_VOL_ID  0xFFFFFFFFU

//--------------------------------------------------------------------------------------------------
/**
 * Image description. An union with fields and structures depending of the image type
 */
//--------------------------------------------------------------------------------------------------
typedef union
{
    struct
    {
        int mtdNum;         ///< MTD number for RAW flash
        uint32_t ubiVolId;  ///< UBI volumr ID for UBI data into RAW flash
        bool isLogical;     ///< MTD is "logical"
        bool isDual;        ///< "Dual partition" of the "logical" MTD
    }
    flash;
}
pa_patch_ImageDesc_t;

//--------------------------------------------------------------------------------------------------
/**
 * Context for the patch
 */
//--------------------------------------------------------------------------------------------------
typedef struct
{
    size_t               segmentSize;    ///< Size of the patch segment
    off_t                patchOffset;    ///< Offset of this segment
    pa_patch_Image_t     origImage;      ///< Type of image for origin
    size_t               origImageSize;  ///< Full size of the image for origin
    uint32_t             origImageCrc32; ///< CRC32 of the image for origin
    pa_patch_ImageDesc_t origImageDesc;  ///< Device description for origin
    pa_patch_Image_t     destImage;      ///< Type of image for destination
    size_t               destImageSize;  ///< Full size of the image for destination
    uint32_t             destImageCrc32; ///< CRC32 of the image for destination
    pa_patch_ImageDesc_t destImageDesc;  ///< Device description for destination
}
pa_patch_Context_t;

//--------------------------------------------------------------------------------------------------
/**
 * Opaque patch descriptor for patch access functions
 */
//--------------------------------------------------------------------------------------------------
typedef void *pa_patch_Desc_t;

//--------------------------------------------------------------------------------------------------
/**
 * Public functions for PATCH access
 */
//--------------------------------------------------------------------------------------------------

//--------------------------------------------------------------------------------------------------
/**
 * Open a patch context and return a patch descriptor
 *
 * @return
 *      - LE_OK            On success
 *      - LE_BAD_PARAMETER If desc is NULL or if mode is not correct
 *      - LE_OUT_OF_RANGE  The segment size is not compatible with the flash
 *      - LE_FAULT         On failure
 *      - LE_UNSUPPORTED   If the flash device cannot be opened
 *      - others           Depending of the image type and PA device used
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_patch_Open
(
    pa_patch_Context_t *ctx,  ///< [IN] Context of the patch to be open
    pa_patch_Desc_t *desc,    ///< [OUT] Private patch descriptor
    uint8_t **origDataPtr,    ///< [OUT] Pointer to the orig data buffer
    uint8_t **destDataPtr     ///< [OUT] Pointer to the dest data buffer
);

//--------------------------------------------------------------------------------------------------
/**
 * Close a patch descriptor
 *
 * @return
 *      - LE_OK            On success
 *      - LE_BAD_PARAMETER If desc is NULL or not a valid patch descriptor
 *      - others           Depending of the image type and PA device used
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_patch_Close
(
    pa_patch_Desc_t desc,     ///< [IN] Private patch descriptor
    bool            update,   ///< [IN] Update the destination size
    size_t          destSize  ///< [IN] Final size of the destination
);

//--------------------------------------------------------------------------------------------------
/**
 * Read data starting the given block. If a Bad block is detected,
 * the error LE_IO_ERROR is returned and operation is aborted.
 * Note that the length should not be greater than eraseSize
 *
 * @return
 *      - LE_OK            On success
 *      - LE_BAD_PARAMETER If desc is NULL or dataPtr is NULL or dataSizePtr is NULL
 *      - LE_FAULT         On failure
 *      - LE_OUT_OF_RANGE  If the block is outside the partition
 *      - others           Depending of the image type and PA device used
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_patch_ReadSegment
(
    pa_patch_Desc_t desc,     ///< [IN] Private patch descriptor
    off_t offset,             ///< [IN] Offset of the data to read
    uint8_t *dataPtr,         ///< [IN] Pointer to data to be read
    size_t *dataSizePtr       ///< [OUT] Pointer to real amount of data read
);

//--------------------------------------------------------------------------------------------------
/**
 * Write data starting the given block. If a Bad block is detected,
 * the error LE_IO_ERROR is returned and operation is aborted.
 * Note that the block should be erased before the first write (pa_patch_EraseAtBlock)
 * Note that the length should be a multiple of writeSize and should not be greater than eraseSize
 *
 * @return
 *      - LE_OK            On success
 *      - LE_BAD_PARAMETER If desc is NULL or dataPtr is NULL
 *      - LE_FAULT         On failure
 *      - LE_OUT_OF_RANGE  If the block is outside the partition
 *      - others           Depending of the image type and PA device used
 */
//--------------------------------------------------------------------------------------------------
le_result_t pa_patch_WriteSegment
(
    pa_patch_Desc_t desc,     ///< [IN] Private patch descriptor
    off_t offset,             ///< [IN] Offset of the data to be written
    uint8_t *dataPtr,         ///< [IN] Pointer to data to be written
    size_t dataSize           ///< [IN] Size of data to write
);

#endif // LEGATO_PA_PATCH_INCLUDE_GUARD
