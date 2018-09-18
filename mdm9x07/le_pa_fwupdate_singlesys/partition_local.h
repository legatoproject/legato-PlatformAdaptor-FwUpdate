/**
 * @file partition_local.h
 *
 * partition management header file
 *
 * Copyright (C) Sierra Wireless Inc.
 *
 */

#ifndef LEGATO_PARTITONLOCAL_INCLUDE_GUARD
#define LEGATO_PARTITONLOCAL_INCLUDE_GUARD

#include "legato.h"
#include "cwe_local.h"
#include "pa_fwupdate.h"


//--------------------------------------------------------------------------------------------------
/**
 * Partition context
 */
//--------------------------------------------------------------------------------------------------
typedef struct
{
    const cwe_Header_t *cweHdrPtr;          ///< Component image header
    le_mem_PoolRef_t *flashPoolPtr;         ///< Memory pool to use for flash operations
    uint32_t fullImageCrc;                  ///< Full image CRC
    ssize_t fullImageSize;                  ///< Full image size
    uint32_t logicalBlock;                  ///< Logical start block number to store image
    uint32_t phyBlock;                      ///< Physical start block number to store image
}
partition_Ctx_t;


//--------------------------------------------------------------------------------------------------
/**
 * Partition name indexed by CWE identifier. If NULL, no partition matches
 */
//--------------------------------------------------------------------------------------------------
typedef struct
{
    char                  *namePtr;
}
partition_Identifier_t;


//--------------------------------------------------------------------------------------------------
/**
 * Partition Name, Sub System ID and Image Type matrix
 */
//--------------------------------------------------------------------------------------------------
extern partition_Identifier_t Partition_Identifier[ CWE_IMAGE_TYPE_COUNT ];

//--------------------------------------------------------------------------------------------------
/**
 * Get the MTD number and partition name belonging to a image type.
 * The MTD name and the write size of the partition are also returned as output parameters.
 *
 * @return
 *      - The MTD number belonging the image type for the boot system (dual or initial)
 *      - -1 in case of failure
 */
//--------------------------------------------------------------------------------------------------
int partition_GetMtdFromImageTypeOrName
(
    cwe_ImageType_t partName,        ///< [IN] Partition enumerate to get
    char*  partNamePtr,
    char** mtdNamePtr                ///< [OUT] Pointer to the real MTD partition name
);

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
le_result_t partition_CheckIfMounted
(
    int mtdNum
);

//--------------------------------------------------------------------------------------------------
/**
 * This function checks if the partition related to the given MTD is currently an UBI container. If
 * yes, returns the UBI Identifier and the number of volumes detected.
 *
 * @return
 *      - LE_OK            The partition is an UBI container
 *      - LE_BAD_PARAMETER The MTD number is negative, or the other parameters are NULL
 *      - LE_FORMAT_ERROR  The partition is not an UBI container
 *      - LE_FAULT         If an error occurs
 */
//--------------------------------------------------------------------------------------------------
le_result_t partition_CheckIfUbiAndGetUbiVolumes
(
    int mtdNum,             ///< [IN]  MTD to check as UBI container
    int* ubiIdPtr,          ///< [OUT] UBI identifier in case of UBI container
    int* nbUbiVolumesPtr    ///< [OUT] Number of UBI volumes detected
);

//--------------------------------------------------------------------------------------------------
/**
 * Calculate how much real data is stored in the buffer
 *
 * This function calculates how much "real data" is stored in a buffer and returns the "real data"
 * length. Continuous 0xFF bytes at the end * of the buffer are not considered as "real data".
 *
 * @return
 *      - LE_OK            If success and the "real data" length is valid
 *      - LE_BAD_PARAMETER If dataPtr is NULL or dataSize is 0
 */
//--------------------------------------------------------------------------------------------------
le_result_t partition_CalculateDataLength
(
    uint8_t* dataPtr,
    size_t *dataSize
);

//--------------------------------------------------------------------------------------------------
/**
 * Check if data flashed into a partition are correctly written
 *
 * @return
 *      - LE_OK on success
 *      - LE_FAULT on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t partition_CheckData
(
    int mtdNum,                        ///< [IN] Minor of the MTD device to check
    size_t sizeToCheck,                ///< [IN] Size to be used to compute the CRC
    off_t atOffset,                    ///< [IN] Force offset to start from
    uint32_t crc32ToCheck,             ///< [IN] Expected CRC 32
    le_mem_PoolRef_t flashImgPool,     ///< [IN] Memory pool
    bool isEccChecked                  ///< [IN] Whether need to check ecc status in the partition
);

//--------------------------------------------------------------------------------------------------
/**
 * Check if data flashed into a partition are correctly written
 *
 * @return
 *      - LE_OK       on success
 *      - LE_FAULT    on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t partition_CheckUbiVolumeData
(
    int mtdNum,                        ///< [IN] Minor of the MTD device to check
    size_t sizeToCheck,                ///< [IN] Size to be used to compute the CRC
    uint32_t ubiVolId,                 ///< [IN] UBI volume ID to be checked
    uint32_t crc32ToCheck,             ///< [IN] Expected CRC 32
    le_mem_PoolRef_t flashImgPool,     ///< [IN] Memory pool
    bool isEccChecked                  ///< [IN] Whether need to check ecc status in the partition
);

//--------------------------------------------------------------------------------------------------
/**
 * Get absolute current data offset in SWIFOTA partition
 *
 * @return
 *      - LE_OK on success
 *      - LE_FAULT on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t partition_GetSwifotaOffsetPartition
(
    off_t* offsetPtr                  ///< [OUT] Data offset in the partition
);

//--------------------------------------------------------------------------------------------------
/**
 * Set absolute current data offset in SWIFOTA partition
 *
 * @return
 *      - LE_OK on success
 *      - LE_FAULT on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t partition_SetSwifotaOffsetPartition
(
    off_t offset                      ///< [IN] Data offset in the partition
);

//--------------------------------------------------------------------------------------------------
/**
 * Open the SWIFOTA partition for writing
 *
 * @return
 *      - LE_OK on success
 *      - LE_BUSY if the partition is already opened
 *      - LE_FAULT on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t partition_OpenSwifotaPartition
(
    partition_Ctx_t *ctxPtr,          ///< [INOUT] Context
    size_t offset                     ///< [IN] Data offset in the package
);

//--------------------------------------------------------------------------------------------------
/**
 * Close the SWIFOTA partition. When closed, the flush of remaining data is forced.
 *
 * @return
 *      - LE_OK on success
 *      - LE_FAULT on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t partition_CloseSwifotaPartition
(
    partition_Ctx_t *ctxPtr,          ///< [INOUT] Context
    size_t offset,                    ///< [IN] Data offset in the package
    bool forceClose,                  ///< [IN] Force close of device and resources
    bool *isFlashedPtr                ///< [OUT] True if flash write was done
);

//--------------------------------------------------------------------------------------------------
/**
 * Compute the CRC32 of the DATA in UPDATE partitions
 *
 * @return
 *      - LE_OK on success
 *      - LE_FAULT on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t partition_ComputeDataCrc32SwifotaPartition
(
    partition_Ctx_t *ctxPtr,          ///< [INOUT] Context
    off_t inOffset,                   ///< [IN] Current offset in SWIFOTA to start CRC32 computation
    uint32_t size,                    ///< [IN] Size of the data
    uint32_t* crc32Ptr                ///< [OUT] CRC32 computed on the data
);

//--------------------------------------------------------------------------------------------------
/**
 * Write data in UPDATE partitions
 *
 * @return
 *      - LE_OK on success
 *      - LE_FAULT on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t partition_WriteSwifotaPartition
(
    partition_Ctx_t *ctxPtr,          ///< [INOUT] Context
    size_t* lengthPtr,                ///< [INOUT] Data length pointer
    size_t offset,                    ///< [IN] Data offset in the package
    const uint8_t* dataPtr,           ///< [IN] Input data
    bool forceClose,                  ///< [IN] Force close of device and resources
    bool *isFlashedPtr                ///< [OUT] True if flash write was done
);

//--------------------------------------------------------------------------------------------------
/**
 * Open UBI partiton in UPDATE partitions
 *
 * @return
 *      - LE_OK on success
 *      - LE_FAULT on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t partition_OpenUbiSwifotaPartition
(
    partition_Ctx_t *ctxPtr,          ///< [INOUT] Context
    bool forceCreate,                 ///< [IN] Force creation of new UBI partition
    bool *isFlashedPtr                ///< [OUT] True if flash write was done
);

//--------------------------------------------------------------------------------------------------
/**
 * Close UBI partiton in UPDATE partitions
 *
 * @return
 *      - LE_OK on success
 *      - LE_FAULT on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t partition_CloseUbiSwifotaPartition
(
    partition_Ctx_t *ctxPtr,          ///< [INOUT] Context
    bool forceClose,                  ///< [IN] Force close of device and resources
    bool *isFlashedPtr                ///< [OUT] True if flash write was done
);

//--------------------------------------------------------------------------------------------------
/**
 * Compute the CRC32 of the UBI partiton in UPDATE partitions
 *
 * @return
 *      - LE_OK on success
 *      - LE_FAULT on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t partition_ComputeUbiCrc32SwifotaPartition
(
    partition_Ctx_t *ctxPtr,          ///< [INOUT] Context
    uint32_t* sizePtr,                ///< [OUT] Size of the whole UBI partition
    uint32_t* crc32Ptr                ///< [OUT] CRC32 computed on the whole UBI partition
);

//--------------------------------------------------------------------------------------------------
/**
 * Open UBI volume in UPDATE partitions
 *
 * @return
 *      - LE_OK on success
 *      - LE_FAULT on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t partition_OpenUbiVolumeSwifotaPartition
(
    partition_Ctx_t *ctxPtr,          ///< [INOUT] Context
    uint32_t ubiVolId,                ///< [IN] UBI volume ID
    uint32_t ubiVolType,              ///< [IN] UBI volume type
    uint32_t ubiVolSize,              ///< [IN] UBI volume size
    char* ubiVolName,                 ///< [IN] UBI volume name
    bool createVol                    ///< [IN] true if volume needs to be created
);

//--------------------------------------------------------------------------------------------------
/**
 * Close UBI volume in UPDATE partitions
 *
 * @return
 *      - LE_OK on success
 *      - LE_FAULT on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t partition_CloseUbiVolumeSwifotaPartition
(
    partition_Ctx_t *ctxPtr,          ///< [INOUT] Context
    uint32_t ubiVolSize,              ///< [IN] UBI volume size
    bool forceClose,                  ///< [IN] Force close of device and resources
    bool *isFlashedPtr                ///< [OUT] True if flash write was done
);

//--------------------------------------------------------------------------------------------------
/**
 * Write data inside UBI volume in UPDATE partitions
 *
 * @return
 *      - LE_OK on success
 *      - LE_FAULT on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t partition_WriteUbiSwifotaPartition
(
    partition_Ctx_t *ctxPtr,          ///< [INOUT] Context
    size_t* lengthPtr,                ///< [INOUT] Data length pointer
    size_t offset,                    ///< [IN] Data offset in the package
    const uint8_t* dataPtr,           ///< [IN] Input data
    bool forceClose,                  ///< [IN] Force close of device and resources
    bool *isFlashedPtr                ///< [OUT] True if flash write was done
);

//--------------------------------------------------------------------------------------------------
/**
 * Compute the CRC32 of the UBI volume in UPDATE partitions
 *
 * @return
 *      - LE_OK on success
 *      - LE_FAULT on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t partition_ComputeUbiVolumeCrc32SwifotaPartition
(
    partition_Ctx_t *ctxPtr,          ///< [INOUT] Context
    uint32_t ubiVolId,                ///< [IN] UBI volume ID
    size_t* sizePtr,                  ///< [OUT] UBI volume size
    uint32_t* crc32Ptr,               ///< [OUT] CRC32 computed on the UBI volume
    size_t* fullSizePtr,              ///< [OUT] UBI volume size with padded data to the end of PEB
    uint32_t* fullCrc32Ptr            ///< [OUT] CRC32 computed on the data padded to the end of PEB
);

//--------------------------------------------------------------------------------------------------
/**
 * Write data in meta data
 *
 * @return
 *      - LE_OK on success
 *      - LE_FAULT on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t partition_WriteMetaData
(
    const partition_Ctx_t *ctxPtr,    ///< [IN] Context
    size_t length,                    ///< [IN] Input data length
    size_t offset,                    ///< [IN] Data offset in the package
    const uint8_t* dataPtr,           ///< [IN] Input data
    bool forceClose                   ///< [IN] Force close of device and resources
);

#endif /* LEGATO_PARTITONLOCAL_INCLUDE_GUARD */

