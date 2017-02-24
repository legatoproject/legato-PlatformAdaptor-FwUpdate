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
    pa_flash_Desc_t magic;   ///< itself for checking validity
    int mtdNum;              ///< MTD number open
    int fd;                  ///< File descriptor for MTD access
    pa_flash_Info_t mtdInfo; ///< MTD information
    bool scanDone;           ///< The scan is done, use LEB translation for PEB access
    bool markBad;            ///< Mark bad block and use next to read/write...
    uint32_t lebToPeb[PA_FLASH_MAX_LEB]; ///< LEB to PEB translstion array (if scanDone)
    uint32_t ubiVolumeId;    ///< UBI volume ID if UBI, 0xFFFFFFFFU else
    off_t ubiOffset;         ///< Offset of UBI data in the PEB
    struct ubi_vtbl_record vtbl[UBI_MAX_VOLUMES];     ///< Pointer to VTBL is UBI
    struct ubi_vtbl_record *vtblPtr;     ///< Pointer to VTBL is UBI
    uint32_t vtblPeb[2];     ///< PEB containing the VTBL if UBI
}
pa_flash_MtdDesc_t;

#endif // LEGATO_LEPAFLASHLOCAL_INCLUDE_GUARD
