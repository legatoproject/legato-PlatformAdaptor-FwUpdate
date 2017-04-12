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


//--------------------------------------------------------------------------------------------------
/**
 * Partition context
 */
//--------------------------------------------------------------------------------------------------
typedef struct
{
    const cwe_Header_t *cweHdrPtr;          ///< Component image header
    le_mem_PoolRef_t *flashPoolPtr;         ///< Memory pool to use for flash operations
    le_mem_PoolRef_t  sblPool;              ///< Memory pool to use for SBL operations
}
partition_Ctx_t;


//--------------------------------------------------------------------------------------------------
/**
 * Get the initial boot system using the mtd used for rootfs (ubi0). If the rootfs partition is
 * "system", initial boot system is 1, if it is "system2", initial boot system is 2.
 *
 * @return
 *      - 0 if initial boot system is 1,
 *      - 1 if initial boot system is 2,
 *      - -1 in case of failure
 */
//--------------------------------------------------------------------------------------------------
int partition_GetInitialBootSystem
(
    void
);

//--------------------------------------------------------------------------------------------------
/**
 * Get the MTD number and partition name belonging to a image type. If the inDual parameter is true,
 * the MTD is looked into the passive partition matrix. If inDual is false, it is looked into the
 * active (initial boot) partition matrix.
 * The MTD name and the write size of the partition are also returned as output parameters.
 *
 * @return
 *      - The MTD number belonging the image type for the boot system (dual or initial)
 *      - 1 if initial boot system is 2,
 *      - -1 in case of failure
 */
//--------------------------------------------------------------------------------------------------
int partition_GetMtdFromImageType
(
    cwe_ImageType_t partName,         ///< [IN] Partition enumerate to get
    bool inDual,                      ///< [IN] true for the dual partition, false for the active
    char** mtdNamePtr,                ///< [OUT] Pointer to the real MTD partition name
    bool *isLogical,                  ///< [OUT] true if the partition is logical (TZ or RPM)
    bool *isDual                      ///< [OUT] true if the upper partition is concerned (TZ2 or
                                      ///<       RPM2), false in case of lower partition
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
    bool isLogical,                    ///< [IN] true if the partition is logical (TZ or RPM)
    bool isDual,                       ///< [IN] true if the upper partition is concerned (TZ2 or
                                       ///<      RPM2), false in case of lower partition
    size_t sizeToCheck,                ///< [IN] Size to be used to compute the CRC
    off_t atOffset,                    ///< [IN] Force offset to start from
    uint32_t crc32ToCheck,             ///< [IN] Expected CRC 32
    le_mem_PoolRef_t flashImgPool      ///< [IN] memory pool
);

//--------------------------------------------------------------------------------------------------
/**
 * Write data into SBL (SBL scrub)
 *
 * @return
 *      - LE_OK on success
 *      - LE_FAULT on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t partition_WriteDataSBL
(
    const partition_Ctx_t *ctxPtr,    ///< [IN] context
    size_t length,                    ///< [IN] Input data length
    size_t offset,                    ///< [IN] Data offset in the package
    const uint8_t* dataPtr,           ///< [IN] input data
    bool forceClose,                  ///< [IN] Force close of device and resources
    bool *isFlashedPtr                ///< [OUT] true if flash write was done
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
le_result_t partition_WriteUpdatePartition
(
    const partition_Ctx_t *ctxPtr,    ///< [IN] context
    size_t length,                    ///< [IN] Input data length
    size_t offset,                    ///< [IN] Data offset in the package
    const uint8_t* dataPtr,           ///< [IN] input data
    bool forceClose,                  ///< [IN] Force close of device and resources
    bool *isFlashedPtr                ///< [OUT] true if flash write was done
);


#endif /* LEGATO_PARTITONLOCAL_INCLUDE_GUARD */

