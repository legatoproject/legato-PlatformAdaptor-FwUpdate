/**
 * @file pa_fwupdate_local.h
 *
 * Copyright (C) Sierra Wireless Inc.
 *
 */

#ifndef LEGATO_LEFWUPDATELOCAL_INCLUDE_GUARD
#define LEGATO_LEFWUPDATELOCAL_INCLUDE_GUARD

#include "legato.h"

//--------------------------------------------------------------------------------------------------
/**
 * Define the maximum length for a package data chunk
 */
//--------------------------------------------------------------------------------------------------
#define CHUNK_LENGTH 65536

/* constants for image header */
#define HDRSOURCEVERSION    16    ///< Size of source version (in PSB)
#define HDRPSBLEN           8     ///< Size PSB
#define HDRCURVER           3     ///< Current version of the header
#define HVERSTRSIZE         84    ///< Size of download file's version name string
#define HDATESIZE           8     ///< Size of release data string

/* header field offset constants (relative to the first byte of image in flash) */
#define CRC_PROD_BUF_OFST  0x100
#define HDR_REV_NUM_OFST   0x104
#define CRC_INDICATOR_OFST 0x108
#define IMAGE_TYPE_OFST    0x10C
#define STOR_ADDR_OFST     0x180
#define PROG_ADDR_OFST     0x184
#define ENTRY_OFST         0x188
#define HEADER_SIZE        0x190
#define APPSIGN            0x00000001 ///<  Default appl signature


//--------------------------------------------------------------------------------------------------
/**
 * CWE file: Product Specific Buffer (PSB).
 */
//--------------------------------------------------------------------------------------------------
typedef struct
{
    uint8_t descriptorVersion;                  ///< Descriptor version
    uint8_t type;                               ///< Component type
    uint8_t flag;                               ///< Component flag (for extended descriptor enable
                                                ///< /disable)
    uint8_t reserved;                           ///< Reserved for future use
    uint32_t offset;                            ///< offset from start of update package to start
                                                ///< of component
    uint32_t size;                              ///< Size of component (in bytes)
    uint8_t sourceVersion[HDRSOURCEVERSION];    ///< Source version
    uint32_t reserved2;                         ///< Reserved for future use
}
pa_fwupdateCweFilePsb_t;

//--------------------------------------------------------------------------------------------------
/**
 * CWE image header structure
 */
//--------------------------------------------------------------------------------------------------
typedef struct
{
    pa_fwupdateCweFilePsb_t PSB[HDRPSBLEN];   ///< Product specific buffer
    uint32_t crcProdBuf;                      ///< CRC of Product Specific Buffer
    uint32_t hdrRevNum;                       ///< Header revision number
    uint32_t crcIndicator;                    ///< Update Package CRC valid indicator
    uint32_t imageType;                       ///< Image type
    uint32_t prodType;                        ///< Product type
    uint32_t imageSize;                       ///< Update Package size
    uint32_t crc32;                           ///< CRC32 of Update Package image body
    uint8_t  version[HVERSTRSIZE];            ///< Version/Time
    uint8_t  relDate[HDATESIZE];              ///< Release Date string
    uint32_t compat;                          ///< Backward compat field
    uint8_t  miscOpts;                        ///< Misc Options field
    uint8_t  hdrRes[3];                       ///< Header reserved
    uint32_t storAddr;                        ///< Storage address
    uint32_t progAddr;                        ///< Program reloc. Address
    uint32_t entry;                           ///< Entry Point address
    uint32_t signature;                       ///< Application Signature
}
pa_fwupdate_CweHeader_t;

//--------------------------------------------------------------------------------------------------
/**
 * Misc Options Field Bit Map
 */
//--------------------------------------------------------------------------------------------------
#define MISC_OPTS_COMPRESS        0x01  ///< image following header is compressed
#define MISC_OPTS_ENCRYPT         0x02  ///< image following header is encrypyted
#define MISC_OPTS_SIGNED          0x04  ///< image following header is signed
#define MISC_OPTS_DELTAPATCH      0x08  ///< image following header is a delta patch
#define MISC_OPTS_UNUSED3         0x10
#define MISC_OPTS_UNUSED2         0x20
#define MISC_OPTS_UNUSED1         0x40
#define MISC_OPTS_UNUSED0         0x80

//--------------------------------------------------------------------------------------------------
/**
 * Enumerate all supported component image format
 */
//--------------------------------------------------------------------------------------------------
typedef enum pa_fwupdate_imageformat
{
    PA_FWUPDATE_IMAGE_FORMAT_RAW = 0,    ///< Raw image
    PA_FWUPDATE_IMAGE_FORMAT_UBI,        ///< UBI image
    PA_FWUPDATE_IMAGE_FORMAT_COUNT,      ///< Number of entries in list
    PA_FWUPDATE_IMAGE_FORMAT_INVALID     ///< Invalid entry;
}
pa_fwupdate_ImageFormat_t;

//--------------------------------------------------------------------------------------------------
/**
 * Enumerate all supported component image types
 */
//--------------------------------------------------------------------------------------------------
typedef enum pa_fwupdate_imagetype
{
    CWE_IMAGE_TYPE_MIN = 0,
    CWE_IMAGE_TYPE_QPAR = CWE_IMAGE_TYPE_MIN,     ///<  partition
    CWE_IMAGE_TYPE_SBL1,                          ///<  SBL1
    CWE_IMAGE_TYPE_SBL2,                          ///<  SBL2
    CWE_IMAGE_TYPE_DSP1,                          ///<  QDSP1 FW
    CWE_IMAGE_TYPE_DSP2,                          ///<  QDSP2 SW
    CWE_IMAGE_TYPE_DSP3,                          ///<  QDSP3 SW
    CWE_IMAGE_TYPE_QRPM,                          ///<  QCT RPM image
    CWE_IMAGE_TYPE_BOOT,                          ///<  boot composite image
    CWE_IMAGE_TYPE_APPL,                          ///<  appl composite image
    CWE_IMAGE_TYPE_OSBL,                          ///<  OS Second boot loader
    CWE_IMAGE_TYPE_AMSS,                          ///<  amss
    CWE_IMAGE_TYPE_APPS,                          ///<  apps
    CWE_IMAGE_TYPE_APBL,                          ///<  apps bootloader
    CWE_IMAGE_TYPE_NVBF,                          ///<  NV Backup (factory)
    CWE_IMAGE_TYPE_NVBO,                          ///<  NV Backup (oem)
    CWE_IMAGE_TYPE_NVBU,                          ///<  NV Backup (user)
    CWE_IMAGE_TYPE_EXEC,                          ///<  Self-contained executable
    CWE_IMAGE_TYPE_SWOC,                          ///<  Software on card image
    CWE_IMAGE_TYPE_FOTO,                          ///<  FOTO image
    CWE_IMAGE_TYPE_FILE,                          ///<  Generic file
    CWE_IMAGE_TYPE_SPKG,                          ///<  Super package
    CWE_IMAGE_TYPE_MODM,                          ///<  modem composite image
    CWE_IMAGE_TYPE_SYST,                          ///<  image for 0:SYSTEM
    CWE_IMAGE_TYPE_USER,                          ///<  image for 0:USERDATA
    CWE_IMAGE_TYPE_HDAT,                          ///<  image for 0:HDATA
    CWE_IMAGE_TYPE_NVBC,                          ///<  Cache NV Backup
    CWE_IMAGE_TYPE_SPLA,                          ///<  Splash screen image file
    CWE_IMAGE_TYPE_NVUP,                          ///<  NV UPdate file
    CWE_IMAGE_TYPE_QMBA,                          ///<  Modem Boot Authenticator
    CWE_IMAGE_TYPE_TZON,                          ///<  QCT Trust-Zone Image
    CWE_IMAGE_TYPE_QSDI,                          ///<  QCT System Debug Image
    CWE_IMAGE_TYPE_ARCH,                          ///<  Archive
    CWE_IMAGE_TYPE_UAPP,                          ///<  USER APP Image
    CWE_IMAGE_TYPE_MAX  = CWE_IMAGE_TYPE_UAPP,    ///<  End of list
    CWE_IMAGE_TYPE_COUNT,                         ///<  Number of entries in list
    CWE_IMAGE_TYPE_ANY = 0xFE,                    ///<  any image type
    CWE_IMAGE_TYPE_INVALID = 0xFF,                ///<  invalid image type
}
pa_fwupdate_ImageType_t;

//--------------------------------------------------------------------------------------------------
/**
 * Delta patch DIFF magic signature
 */
//--------------------------------------------------------------------------------------------------
#define DIFF_MAGIC   "BSDIFF40\0\0\0\0\0\0\0\0"

//--------------------------------------------------------------------------------------------------
/**
 * Delta patch Meta header (one for each image. May be splitted into several slices)
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
pa_fwupdate_PatchMetaHdr_t;

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
pa_fwupdate_PatchHdr_t;

//--------------------------------------------------------------------------------------------------
/**
 * This function writes provided data in corresponding flash partition
 *
 * @return
 *      - Written data length
 *      - 0 in case of failure
 */
//--------------------------------------------------------------------------------------------------
LE_SHARED size_t pa_fwupdate_ImageData
(
    pa_fwupdate_CweHeader_t *cweHeader, ///<[IN] CWE header linked to image data
    uint8_t* chunk,                     ///< [IN]Data to be written in flash partition
    size_t length                       ///< [IN]Data length to be written in flash partition
);

//--------------------------------------------------------------------------------------------------
/**
 * Update some variables in SSDATA to indicate that systems are not synchronized
 *
 * @return
 *      - LE_OK on success
 *      - LE_FAULT on failure
 */
//--------------------------------------------------------------------------------------------------
LE_SHARED le_result_t pa_fwupdate_SetUnsyncState
(
    void
);

//--------------------------------------------------------------------------------------------------
/**
 * Update some variables in SSDATA to indicate that systems are synchronized
 *
 * @return
 *      - LE_OK on success
 *      - LE_FAULT on failure
 */
//--------------------------------------------------------------------------------------------------
LE_SHARED le_result_t pa_fwupdate_SetSyncState
(
    void
);

//--------------------------------------------------------------------------------------------------
/**
 * Function which indicates if Active and Update systems are synchronized
 *
 * @return
 *      - LE_OK            On success
 *      - LE_UNSUPPORTED   The feature is not supported
 */
//--------------------------------------------------------------------------------------------------
LE_SHARED le_result_t pa_fwupdate_GetSyncState
(
    bool *isSync ///< [OUT] true if both systems are synchronized, false otherwise
);

//--------------------------------------------------------------------------------------------------
/**
 * Function which read the initial sub system id
 *
 * @return
 *      - LE_OK            On success
 *      - LE_FAULT         On failure
 */
//--------------------------------------------------------------------------------------------------
LE_SHARED le_result_t pa_fwupdate_GetInitialSubSystemId
(
    uint8_t *initialSSId ///< [OUT] if LE_OK, the current boot system
);

#endif /* LEGATO_LESWUPDATELOCAL_INCLUDE_GUARD */

