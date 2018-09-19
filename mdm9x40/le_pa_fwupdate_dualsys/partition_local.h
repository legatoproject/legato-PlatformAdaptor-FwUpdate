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
    le_mem_PoolRef_t  sblPool;              ///< Memory pool to use for SBL operations
}
partition_Ctx_t;


//--------------------------------------------------------------------------------------------------
/**
 * Partition active and dual name and sub system ID containing these partitions
 */
//--------------------------------------------------------------------------------------------------
typedef struct
{
    char                  *namePtr[2];       // Name of partition in system 1 and 2
    pa_fwupdate_SubSysId_t subSysId;         // Sub system containing these partitions
    uint64_t               badImageMask[2];  // Bitmask for partitions in bad image flag
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
 * Get the initial boot system using the mtd used for rootfs (ubi0) and modem (ubi1). Read the
 * ssdata to detect the LK boot system. The returned value is an array of three uint8_t as follow:
 *     [0] = modem (tz/rpm/modem)
 *     [1] = lk (aboot)
 *     [2] = linux (boot/system/lefwkro)
 *
 * @return
 *      - LE_OK on success
 *      - LE_FAULT for any other errors
 */
//--------------------------------------------------------------------------------------------------
le_result_t partition_GetInitialBootSystem
(
    uint8_t* initBootSysPtr ///< [OUT] System array for "modem/lk/linux" partition groups
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
 * Get an UBI partition's block valid data length
 *
 * @return
 *      - LE_OK       on success
 *      - LE_FAULT    on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t partition_GetUbiBlockValidDataLen
(
    uint32_t* dataLenPtr,                ///< [OUT] valid data length
    int pgSize,                          ///< [IN] page size
    uint8_t* flashBlockPtr               ///< [IN] flash data pointer
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
    le_mem_PoolRef_t flashImgPool,     ///< [IN] memory pool
    bool isEccChecked,                 ///< [IN] whether need to check ecc status in the partition
    bool onlyChkValidUbiData           ///< [IN] whether only check valid data or not
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

//--------------------------------------------------------------------------------------------------
/**
 * Set bad image flag preventing concurrent partition access
 *
 * @return
 *      - LE_OK            The request was accepted
 *      - LE_BAD_PARAMETER The parameter is invalid
 *      - LE_FAULT         If an error occurs
 */
//--------------------------------------------------------------------------------------------------
le_result_t partition_SetBadImage
(
    cwe_ImageType_t imageType,        ///< [IN] CWE image type to set/clear bad image flag for
    bool isBad                        ///< [IN] True to set bad image flag, false to clear it
);

#endif /* LEGATO_PARTITONLOCAL_INCLUDE_GUARD */

