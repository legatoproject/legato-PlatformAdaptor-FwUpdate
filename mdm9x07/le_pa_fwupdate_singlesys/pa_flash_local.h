/**
 * @file pa_flash_local.h
 *
 * Internal flash descriptor for MTD device and UBI data
 *
 * Copyright (C) Sierra Wireless Inc.
 *
 */

#include "flash-ubi.h"

#ifndef LEGATO_LEPAFLASHLOCAL_INCLUDE_GUARD
#define LEGATO_LEPAFLASHLOCAL_INCLUDE_GUARD

//--------------------------------------------------------------------------------------------------
/**
 * Internal flash MTD descriptor. To be valid, the magic should be its own address
 */
//--------------------------------------------------------------------------------------------------
typedef struct
{
    pa_flash_Desc_t magic;   ///< Pointer to itself for checking validity
    int mtdNum;              ///< MTD number open
    int fd;                  ///< File descriptor for MTD access
    pa_flash_Info_t mtdInfo; ///< MTD information
    bool scanDone;           ///< The scan is done, use LEB translation for PEB access
    bool markBad;            ///< Mark bad block and use next to read/write...
    uint32_t lebToPeb[PA_FLASH_MAX_LEB]; ///< LEB to PEB translstion array (if scanDone)
    uint32_t ubiLebToPeb[PA_FLASH_MAX_LEB]; ///< LEB to PEB translstion array (if scanDone)
    uint32_t ubiVolumeId;    ///< UBI volume ID if UBI, 0xFFFFFFFFU otherwise
    uint32_t ubiVolumeSize;  ///< UBI volume Size if UBI and static volume, 0xFFFFFFFFU otherwise
    off_t ubiDataOffset;     ///< Offset of UBI data in the PEB
    struct ubi_vtbl_record vtbl[UBI_MAX_VOLUMES];     ///< Pointer to VTBL if UBI
    struct ubi_vtbl_record *vtblPtr; ///< Pointer to VTBL if UBI
    uint32_t vtblPeb[2];     ///< PEB containing the VTBL if UBI
    uint32_t ubiBadBlkCnt;   ///< counter of bad blocks
    off_t ubiAbsOffset;      ///< Absolute offset for UBI
    off_t ubiOffsetInPeb;    ///< Offset in block for UBI
    uint32_t ubiBasePeb;     ///< Base PEB for UBI
}
pa_flash_MtdDesc_t;

//--------------------------------------------------------------------------------------------------
/**
 * Get the current logical or physical block and position and the absolute offset in the flash
 *
 * @return
 *      - LE_OK            On success
 *      - LE_BAD_PARAMETER If desc is NULL
 *      - LE_FAULT         On failure
 *      - LE_OUT_OF_RANGE  If the block is outside the partition
 *      - LE_NOT_PERMITTED If the LEB is not linked to a PEB
 *      - LE_IO_ERROR      If a flash IO error occurs
 */
//--------------------------------------------------------------------------------------------------
LE_SHARED le_result_t pa_flash_Tell
(
    pa_flash_Desc_t desc,     ///< [IN] Private flash descriptor
    uint32_t* blockIndexPtr,  ///< [OUT] Current Physical or Logical block
    off_t* offsetPtr,         ///< [OUT] Current Physical or Logical offset
    off_t* absOffsetPtr       ///< [OUT] Current absolute offset
);

//--------------------------------------------------------------------------------------------------
/**
 * Set the current pointer of the flash to the given offset
 *
 * @return
 *      - LE_OK            On success
 *      - LE_BAD_PARAMETER If desc is NULL
 *      - LE_FAULT         On failure
 *      - LE_OUT_OF_RANGE  If the block is outside the partition
 *      - LE_NOT_PERMITTED If the LEB is not linked to a PEB
 *      - LE_IO_ERROR      If a flash IO error occurs
 */
//--------------------------------------------------------------------------------------------------
LE_SHARED le_result_t pa_flash_SeekAtAbsOffset
(
    pa_flash_Desc_t desc,
    off_t offset
);

//--------------------------------------------------------------------------------------------------
/**
 * Get UBI offset
 *
 * @return
 *      - LE_OK            On success
 *      - LE_BAD_PARAMETER If desc is NULL or is not a valid descriptor
 *      - LE_FORMAT_ERROR  If the flash is not in UBI format
 */
//--------------------------------------------------------------------------------------------------
LE_SHARED le_result_t pa_flash_GetUbiOffset
(
    pa_flash_Desc_t desc,         ///< [IN] Private flash descriptor
    off_t*          ubiOffsetPtr  ///< [OUT] Offset where the UBI starts
);

//--------------------------------------------------------------------------------------------------
/**
 * Get UBI volume type and name
 *
 * @return
 *      - LE_OK            On success
 *      - LE_BAD_PARAMETER If desc is NULL or is not a valid descriptor
 *      - LE_FORMAT_ERROR  If the flash is not in UBI format
 */
//--------------------------------------------------------------------------------------------------
LE_SHARED le_result_t pa_flash_GetUbiTypeAndName
(
    pa_flash_Desc_t desc,         ///< [IN] Private flash descriptor
    uint32_t*       volTypePtr,   ///< [OUT] Type of the volume
    char            volName[PA_FLASH_UBI_MAX_VOLUMES]
                                  ///< [OUT] Name of the volume
);

//--------------------------------------------------------------------------------------------------
/**
 * Scan an UBI partition for the volumes number and volumes name
 * volume ID.
 *
 * @return
 *      - LE_OK            On success
 *      - LE_BAD_PARAMETER If desc is NULL or is not a valid descriptor
 *      - LE_FAULT         On failure
 *      - LE_BUSY          If a scan was already run on an UBI volume
 *      - LE_IO_ERROR      If a flash IO error occurs
 *      - LE_FORMAT_ERROR  If the flash is not in UBI format
 */
//--------------------------------------------------------------------------------------------------
LE_SHARED le_result_t pa_flash_ScanUbiForVolumesAtOffset
(
    pa_flash_Desc_t desc,            ///< [IN]  Private flash descriptor
    off_t           offset,          ///< [IN]  Base offset for the UBI
    uint32_t*       ubiVolNumberPtr, ///< [OUT] UBI volume number found
    char            ubiVolName[PA_FLASH_UBI_MAX_VOLUMES][PA_FLASH_UBI_MAX_VOLUMES]
                                     ///< [OUT] UBI volume name array
);

//--------------------------------------------------------------------------------------------------
/**
 * Scan a partition for the UBI volume ID given. Update the LebToPeb array field with LEB for this
 * volume ID.
 *
 * @return
 *      - LE_OK            On success
 *      - LE_BAD_PARAMETER If desc is NULL or is not a valid descriptor
 *      - LE_FAULT         On failure
 *      - LE_OUT_OF_RANGE  If the UBI volume ID is over its permitted values
 *      - LE_IO_ERROR      If a flash IO error occurs
 *      - LE_FORMAT_ERROR  If the flash is not in UBI format
 */
//--------------------------------------------------------------------------------------------------
LE_SHARED le_result_t pa_flash_ScanUbiAtOffset
(
    pa_flash_Desc_t desc,     ///< [IN] Private flash descriptor
    off_t           offset,   ///< [IN]  Base offset for the UBI
    uint32_t        ubiVolId  ///< [IN] UBI volume ID
);

//--------------------------------------------------------------------------------------------------
/**
 * Create UBI partition
 *
 * @return
 *      - LE_OK            On success
 *      - LE_BAD_PARAMETER If desc is NULL or is not a valid descriptor
 *      - LE_BUSY          If desc refers to an UBI volume or an UBI partition
 *      - LE_IO_ERROR      If a flash IO error occurs
 */
//--------------------------------------------------------------------------------------------------
LE_SHARED le_result_t pa_flash_CreateUbiAtOffset
(
    pa_flash_Desc_t desc,           ///< [IN] Private flash descriptor
    off_t           offset,         ///< [IN] Base offset for the UBI
    bool            isForcedCreate  ///< [IN] If set to true the UBI partition is overwriten and the
                                    ///<      previous content is lost
);

//--------------------------------------------------------------------------------------------------
/**
 * Read data from an UBI volume starting at a given offset and up to a given number of bytes.
 *
 * @return
 *      - LE_OK            On success.
 *      - LE_BAD_PARAMETER If desc is NULL or dataPtr or dataSizePtr is NULL
 *      - LE_FAULT         On failure
 *      - LE_OUT_OF_RANGE  If the offset or length are outside the partition range
 *      - LE_IO_ERROR      If a flash IO error occurs
 *      - LE_FORMAT_ERROR  If the flash is not in UBI format
 */
//--------------------------------------------------------------------------------------------------
LE_SHARED le_result_t pa_flash_ReadUbiAtOffset
(
    pa_flash_Desc_t desc,        ///< [IN] Private flash descriptor
    off_t           dataOffset,  ///< [IN] Offset from where read should be done
    uint8_t*        dataPtr,     ///< [IN] Pointer to data to be read
    size_t*         dataSizePtr  ///< [IN][OUT] Data size to be read/data size really read
);

#endif // LEGATO_LEPAFLASHLOCAL_INCLUDE_GUARD
