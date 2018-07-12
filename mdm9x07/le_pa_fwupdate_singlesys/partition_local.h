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
                                       ///<      RPM2), false in case of lower partition
    size_t sizeToCheck,                ///< [IN] Size to be used to compute the CRC
    off_t atOffset,                    ///< [IN] Force offset to start from
    uint32_t crc32ToCheck,             ///< [IN] Expected CRC 32
    le_mem_PoolRef_t flashImgPool,     ///< [IN] Memory pool
    bool isEccChecked                  ///< [IN] Whether need to check ecc status in the partition
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

