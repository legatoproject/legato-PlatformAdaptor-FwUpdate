/**
 * @file fwupdate_stubs.h
 *
 * Structure definitions for fwupdate_stubs.c file.
 *
 * Copyright (C) Sierra Wireless Inc.
 */

#include "legato.h"

//--------------------------------------------------------------------------------------------------
/**
 * Maximum number of volume ID (from 0 to 127)
 */
//--------------------------------------------------------------------------------------------------
#define UBI_MAX_VOLUMES 128


//--------------------------------------------------------------------------------------------------
/**
 * Flash descriptor for flash operation access
 */
//--------------------------------------------------------------------------------------------------
// Opaque structure for internal usage
typedef void *pa_flash_Desc_t;

struct __attribute__ ((packed)) ubi_vtbl_record {
        uint32_t  reserved_pebs;
        uint32_t  alignment;
        uint32_t  data_pad;
        uint8_t    vol_type;
        uint8_t    upd_marker;
        uint16_t  name_len;
        uint8_t    name[UBI_MAX_VOLUMES];
        uint8_t    flags;
        uint8_t    padding[23];
        uint32_t  crc;
};

//--------------------------------------------------------------------------------------------------
/**
 * Internal flash MTD descriptor. To be valid, the magic should be its own address
 */
//--------------------------------------------------------------------------------------------------
typedef struct
{
    pa_flash_Desc_t magic;                        ///< itself for checking validity
    int mtdNum;                                   ///< MTD number open
    int fd;                                       ///< File descriptor for MTD access
    pa_flash_Info_t mtdInfo;                      ///< MTD information
    bool scanDone;                                ///< The scan is done, use LEB translation for
                                                  ///< PEB access
    bool markBad;                                 ///< Mark bad block and use next to read/write
    uint32_t lebToPeb[PA_FLASH_MAX_LEB];          ///< LEB to PEB translstion array (if scanDone)
    uint32_t ubiVolumeId;                         ///< UBI volume ID if UBI, 0xFFFFFFFFU else
    off_t ubiOffset;                              ///< Offset of UBI data in the PEB
    struct ubi_vtbl_record vtbl[UBI_MAX_VOLUMES]; ///< Pointer to VTBL is UBI
    struct ubi_vtbl_record *vtblPtr;              ///< Pointer to VTBL is UBI
    uint32_t vtblPeb[2];                          ///< PEB containing the VTBL if UBI
    uint32_t ubiBadBlkCnt;                        ///< counter of bad blocks
}
pa_flash_MtdDesc_t;
