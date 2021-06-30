/**
 * @file cwe.h
 *
 * cwe header file
 *
 * Copyright (C) Sierra Wireless Inc.
 *
 */

#ifndef LEGATO_CWE_INCLUDE_GUARD
#define LEGATO_CWE_INCLUDE_GUARD

#include "legato.h"

// constants for image header
#define CWE_HDRSOURCEVERSION    16    ///< Size of source version (in PSB)
#define CWE_HDRPSBLEN           8     ///< Size PSB
#define CWE_HDRCURVER           3     ///< Current version of the header
#define CWE_HVERSTRSIZE         84    ///< Size of download file's version name string
#define CWE_HDATESIZE           8     ///< Size of release data string

// header field offset constants (relative to the first byte of image in flash)
#define CWE_CRC_PROD_BUF_OFST  0x100
#define CWE_HDR_REV_NUM_OFST   0x104
#define CWE_CRC_INDICATOR_OFST 0x108
#define CWE_IMAGE_TYPE_OFST    0x10C
#define CWE_STOR_ADDR_OFST     0x180
#define CWE_PROG_ADDR_OFST     0x184
#define CWE_ENTRY_OFST         0x188
#define CWE_APPSIGN            0x00000001 ///< Default appl signature

// Misc Options Field Bit Map/
#define CWE_MISC_OPTS_COMPRESS      0x01  ///< image following header is compressed
#define CWE_MISC_OPTS_ENCRYPT       0x02  ///< image following header is encrypted
#define CWE_MISC_OPTS_SIGNED        0x04  ///< image following header is signed
#define CWE_MISC_OPTS_DELTAPATCH    0x08  ///< image following header is a delta patch
#define CWE_MISC_OPTS_UNUSED3       0x10
#define CWE_MISC_OPTS_UNUSED2       0x20
#define CWE_MISC_OPTS_UNUSED1       0x40
#define CWE_MISC_OPTS_UNUSED0       0x80

//--------------------------------------------------------------------------------------------------
/**
 * Enumerate all supported component image types
 */
//--------------------------------------------------------------------------------------------------
typedef enum
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
    CWE_IMAGE_TYPE_LRAM,                          ///<  Linux RAM image
    CWE_IMAGE_TYPE_CUS0,                          ///<  User image image 0 or 1, for customer0
                                                  ///<  partition
    CWE_IMAGE_TYPE_CUS1,                          ///<  User image image 0 or 1, for customer1
                                                  ///<  partition
    CWE_IMAGE_TYPE_CUS2,                          ///<  User image image 2, for customer2 partition
    CWE_IMAGE_TYPE_HASH,                          ///<  Hash
    CWE_IMAGE_TYPE_META,                          ///<  Meta CWE header for delta update
    CWE_IMAGE_TYPE_CUSG,                          ///<  User image generic for customer security
    CWE_IMAGE_TYPE_KEYS,                          ///<  OEM keystore file
    CWE_IMAGE_TYPE_DCFG,                          ///<  Device Config Image
    CWE_IMAGE_TYPE_TAOP,                          ///<  Trustzone, security and power management related images
    CWE_IMAGE_TYPE_MAX  = CWE_IMAGE_TYPE_TAOP,    ///<  End of list
    CWE_IMAGE_TYPE_COUNT,                         ///<  Number of entries in list
}
cwe_ImageType_t;

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
    uint8_t sourceVersion[CWE_HDRSOURCEVERSION];///< Source version
    uint32_t reserved2;                         ///< Reserved for future use
}
cwe_FilePsb_t;

//--------------------------------------------------------------------------------------------------
/**
 * CWE image header structure
 */
//--------------------------------------------------------------------------------------------------
typedef struct
{
    cwe_FilePsb_t PSB[CWE_HDRPSBLEN];         ///< Product specific buffer
    uint32_t crcProdBuf;                      ///< CRC of Product Specific Buffer
    uint32_t hdrRevNum;                       ///< Header revision number
    uint32_t crcIndicator;                    ///< Update Package CRC valid indicator
    uint32_t imageType;                       ///< Image type
    uint32_t prodType;                        ///< Product type
    uint32_t imageSize;                       ///< Update Package size
    uint32_t crc32;                           ///< CRC32 of Update Package image body
    uint8_t  version[CWE_HVERSTRSIZE];        ///< Version/Time
    uint8_t  relDate[CWE_HDATESIZE];          ///< Release Date string
    uint32_t compat;                          ///< Backward compat field
    uint8_t  miscOpts;                        ///< Misc Options field
    uint8_t  hdrRes[3];                       ///< Header reserved
    uint32_t storAddr;                        ///< Storage address
    uint32_t progAddr;                        ///< Program reloc. Address
    uint32_t entry;                           ///< Entry Point address
    uint32_t signature;                       ///< Application Signature
}
cwe_Header_t;

#define CWE_HEADER_SIZE    sizeof(cwe_Header_t)

//--------------------------------------------------------------------------------------------------
/**
 * This function reads a CWE header
 *
 * @return
 *      - LE_OK            The request was accepted
 *      - LE_BAD_PARAMETER The parameter is invalid
 *      - LE_FAULT         If an error occurs
 */
//--------------------------------------------------------------------------------------------------
le_result_t cwe_LoadHeader
(
    const uint8_t* startPtr,  ///< [IN] start address of the CWE header to be read
    cwe_Header_t* hdpPtr      ///< [OUT] pointer to a CWE header structure
);


#endif /* LEGATO_CWE_INCLUDE_GUARD */

