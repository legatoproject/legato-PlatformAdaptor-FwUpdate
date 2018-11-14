/**
 * @file cwe.c
 *
 * CWE manipulation functions
 *
 *
 * Copyright (C) Sierra Wireless Inc.
 *
 */

#include "legato.h"
#include "cwe_local.h"
#include "utils_local.h"

//==================================================================================================
//                                       Static variables
//==================================================================================================

//--------------------------------------------------------------------------------------------------
/**
 * Image type characters as filled in a CWE header
 * The order of entries in this table must match the order of the enums in cwe_ImageType_t
 */
//--------------------------------------------------------------------------------------------------
static const char ImageString [CWE_IMAGE_TYPE_COUNT][sizeof(uint32_t)] =
{
    { 'Q', 'P', 'A', 'R' },     ///<  partition
    { 'S', 'B', 'L', '1' },     ///<  SBL1
    { 'S', 'B', 'L', '2' },     ///<  SBL2
    { 'D', 'S', 'P', '1' },     ///<  QDSP1 FW
    { 'D', 'S', 'P', '2' },     ///<  QDSP2 SW
    { 'D', 'S', 'P', '3' },     ///<  QDSP3 SW
    { 'Q', 'R', 'P', 'M' },     ///<  QCT RPM image
    { 'B', 'O', 'O', 'T' },     ///<  boot composite image
    { 'A', 'P', 'P', 'L' },     ///<  appl composite image
    { 'O', 'S', 'B', 'L' },     ///<  OS Second boot loader
    { 'A', 'M', 'S', 'S' },     ///<  amss
    { 'A', 'P', 'P', 'S' },     ///<  apps
    { 'A', 'P', 'B', 'L' },     ///<  apps bootloader
    { 'N', 'V', 'B', 'F' },     ///<  NV Backup (factory)
    { 'N', 'V', 'B', 'O' },     ///<  NV Backup (oem)
    { 'N', 'V', 'B', 'U' },     ///<  NV Backup (user)
    { 'E', 'X', 'E', 'C' },     ///<  Self-contained executable
    { 'S', 'W', 'O', 'C' },     ///<  Software on card image
    { 'F', 'O', 'T', 'O' },     ///<  FOTO image
    { 'F', 'I', 'L', 'E' },     ///<  Generic file
    { 'S', 'P', 'K', 'G' },     ///<  Super package
    { 'M', 'O', 'D', 'M' },     ///<  modem composite image
    { 'S', 'Y', 'S', 'T' },     ///<  image for 0:SYSTEM
    { 'U', 'S', 'E', 'R' },     ///<  image for 0:USERDATA
    { 'H', 'D', 'A', 'T' },     ///<  image for 0:HDATA
    { 'N', 'V', 'B', 'C' },     ///<  Cache NV Backup
    { 'S', 'P', 'L', 'A' },     ///<  Splash screen image file
    { 'N', 'V', 'U', 'P' },     ///<  NV UPdate file
    { 'Q', 'M', 'B', 'A' },     ///<  Modem Boot Authenticator
    { 'T', 'Z', 'O', 'N' },     ///<  QCT Trust-Zone Image
    { 'Q', 'S', 'D', 'I' },     ///<  QCT System Debug Image
    { 'A', 'R', 'C', 'H' },     ///<  Archive
    { 'U', 'A', 'P', 'P' },     ///<  USER APP image
    { 'L', 'R', 'A', 'M' },     ///<  Linux RAM image
    { 'C', 'U', 'S', '0' },     ///<  Customer 0 or 1 image in dual system
    { 'C', 'U', 'S', '1' },     ///<  Customer 0 or 1 image in dual system
    { 'C', 'U', 'S', '2' },     ///<  Customer 2 image
    { 'H', 'A', 'S', 'H' },     ///<  Hash
    { 'M', 'E', 'T', 'A' },     ///<  Meta CWE header for delta update
    { 'C', 'U', 'S', 'G' },     ///<  Customer generic image
};

//--------------------------------------------------------------------------------------------------
/**
 * List of accepted product IDs. Note that some targets have a single product ID while other may
 * have multiples product IDs.
 */
//--------------------------------------------------------------------------------------------------
static uint32_t ProductIdList[] =
{
#ifdef PA_FWUPDATE_PRODUCT_ID
    PA_FWUPDATE_PRODUCT_ID,
#endif

#ifdef PA_FWUPDATE_APP_PRODUCT_ID
    PA_FWUPDATE_APP_PRODUCT_ID,
#endif

#ifdef PA_FWUPDATE_ALT_APP_PRODUCT_ID
    PA_FWUPDATE_ALT_APP_PRODUCT_ID,
#endif

#ifdef PA_FWUPDATE_USR_PRODUCT_ID
    PA_FWUPDATE_USR_PRODUCT_ID,
#endif

#ifdef PA_FWUPDATE_ALT_USR_PRODUCT_ID
    PA_FWUPDATE_ALT_USR_PRODUCT_ID,
#endif
};

//==================================================================================================
//                                       Private Functions
//==================================================================================================

//--------------------------------------------------------------------------------------------------
/**
 * This function returns an integer value for the specified CWE image type
 *
 * @return
 *      - uint32_t  integer value for a valid image type or CWE_IMAGE_TYPE_COUNT
 *                  if image type is invalid
 */
//--------------------------------------------------------------------------------------------------
static uint32_t GetImageValue
(
    cwe_ImageType_t imageType   ///< [IN] CWE Image Type to convert
)
{
    uint32_t imageVal = CWE_IMAGE_TYPE_COUNT;

    if (imageType < CWE_IMAGE_TYPE_COUNT)
    {
        imageVal = (ImageString[imageType][0] << 24) |
                   (ImageString[imageType][1] << 16) |
                   (ImageString[imageType][2] <<  8) |
                   (ImageString[imageType][3]);
            }

    return imageVal;
}

//--------------------------------------------------------------------------------------------------
/**
 * This function checks if a product ID exists in the allowed list of product IDs
 *
 * @return
 *      - true  if the identifier is valid
 *      - false otherwise
 */
//--------------------------------------------------------------------------------------------------
static bool IsValidProductId
(
    uint32_t identifier   ///< [IN] Product Identifier
)
{
    int i;
    for (i=0; i< NUM_ARRAY_MEMBERS(ProductIdList); i++)
    {
        if (ProductIdList[i] == identifier)
        {
            return true;
        }
    }

    return false;
}

//--------------------------------------------------------------------------------------------------
/**
 * This function validates the image type against supported values
 *
 * @note
 *      enumvalue = CWE_IMAGE_TYPE_COUNT if imagetype is not valid
 *
 * @return
 *      - true      if image type is one of the supported values
 *      - false     otherwise
 */
//--------------------------------------------------------------------------------------------------
static bool ValidateImageType
(
    uint32_t imageType,             ///< [IN] image type for validation
    cwe_ImageType_t* enumValuePtr   ///< [OUT] enum value for image type
)
{
    bool retVal = true;
    cwe_ImageType_t idx;
    uint32_t imageVal;

    LE_DEBUG ("imagetype 0x%x", imageType);

    for (idx = CWE_IMAGE_TYPE_MIN; idx < CWE_IMAGE_TYPE_COUNT; idx++)
    {
        imageVal = GetImageValue(idx);
        if (imageVal == imageType)
        {
            break;
        }
    }

    /* save found index */
    *enumValuePtr = idx;

    if (CWE_IMAGE_TYPE_COUNT == idx)
    {
        /* imagetype not found */
        retVal = false;
    }

    LE_DEBUG ("retVal %d --> image type %d", retVal, *enumValuePtr);

    return retVal;
}

//==================================================================================================
//  PUBLIC API FUNCTIONS
//==================================================================================================

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
)
{
    le_result_t result;

    if ((NULL == startPtr) || (NULL == hdpPtr))
    {
        result = LE_BAD_PARAMETER;
    }
    else
    {
        uint8_t* bufPtr;
        cwe_ImageType_t imagetype;

        /* init the buf pointer */
        bufPtr = (uint8_t*)startPtr;

        /* read in the required number of bytes from product specific buffer */
        utils_CopyAndIncrPtr (&bufPtr, (uint8_t*) hdpPtr->PSB, sizeof(hdpPtr->PSB));

        /* Get the Header Version: Set our pointer to the header revision number first */
        bufPtr = (uint8_t*)startPtr + CWE_HDR_REV_NUM_OFST;

        /* Read the header version number */
        hdpPtr->hdrRevNum = utils_TranslateNetworkByteOrder(&bufPtr);
        LE_DEBUG ("hdpPtr->hdrRevNum %d", hdpPtr->hdrRevNum);

        /* Continue reading the buffer from the Image Type Offset field */
        bufPtr = (uint8_t*)startPtr + CWE_IMAGE_TYPE_OFST;

        /* get the image type */
        hdpPtr->imageType = utils_TranslateNetworkByteOrder(&bufPtr);
        LE_DEBUG ("ImageType 0x%x", hdpPtr->imageType);

        if (hdpPtr->hdrRevNum >= CWE_HDRCURVER)
        {
            /* validate image type */
            if (ValidateImageType(hdpPtr->imageType, &imagetype))
            {
                hdpPtr->imageType = imagetype;
                LE_DEBUG ("ImageType %d", hdpPtr->imageType);
                /* get product type */
                hdpPtr->prodType = utils_TranslateNetworkByteOrder(&bufPtr);
                LE_DEBUG ("ProdType 0x%x", hdpPtr->prodType);

                /* get application image size */
                hdpPtr->imageSize = utils_TranslateNetworkByteOrder(&bufPtr);
                LE_DEBUG ("ImageSize %d 0x%x", hdpPtr->imageSize, hdpPtr->imageSize);

                /* get CRC32 of application */
                hdpPtr->crc32 = utils_TranslateNetworkByteOrder(&bufPtr);
                LE_DEBUG ("CRC32 0x%x", hdpPtr->crc32);

                /* get version string */
                utils_CopyAndIncrPtr(&bufPtr, hdpPtr->version, CWE_HVERSTRSIZE);
                LE_DEBUG ("Version %s", hdpPtr->version);
                /* get date string */
                utils_CopyAndIncrPtr(&bufPtr, hdpPtr->relDate, CWE_HDATESIZE);

                /* get backwards compatibilty field */
                hdpPtr->compat = utils_TranslateNetworkByteOrder(&bufPtr);

                /* get the misc options */
                hdpPtr->miscOpts = *bufPtr;
                LE_DEBUG ("hdpPtr->miscOpts %d", hdpPtr->miscOpts);

                /* get the load address and entry point based upon the header version. */
                bufPtr=(uint8_t*)startPtr+CWE_STOR_ADDR_OFST;
                hdpPtr->storAddr = utils_TranslateNetworkByteOrder(&bufPtr);

                bufPtr=(uint8_t*)startPtr+CWE_PROG_ADDR_OFST;
                hdpPtr->progAddr = utils_TranslateNetworkByteOrder(&bufPtr);

                bufPtr=(uint8_t*)startPtr+CWE_ENTRY_OFST;
                hdpPtr->entry = utils_TranslateNetworkByteOrder(&bufPtr);

                /* get signature */
                hdpPtr->signature = utils_TranslateNetworkByteOrder(&bufPtr);

                /* get product specific buffer CRC value */
                bufPtr = (uint8_t*)startPtr + CWE_CRC_PROD_BUF_OFST;
                hdpPtr->crcProdBuf = utils_TranslateNetworkByteOrder(&bufPtr);

                /* get CRC valid indicator value */
                bufPtr = (uint8_t*)startPtr + CWE_CRC_INDICATOR_OFST;
                hdpPtr->crcIndicator = utils_TranslateNetworkByteOrder(&bufPtr);

                /* Only check the signature field for application imagetypes (not for
                 * bootloader) since we always want to return false for bootloader
                 * imagetypes. */
                if (CWE_IMAGE_TYPE_APPL == imagetype)
                {
                    /* check application signature */
                    if (hdpPtr->signature != CWE_APPSIGN)
                    {
                        /* application not found */
                        result = LE_FAULT;
                    }
                    else
                    {
                        result = LE_OK;
                    }
                }
                else
                {
                    result = LE_OK;
                }
            }
            else
            {
                LE_ERROR ("Image Type in CWE header is not supported %d", imagetype);
                result = LE_FAULT;
            }
        }
        else
        {
            LE_ERROR ("bad header version %d", hdpPtr->hdrRevNum);
            result = LE_FAULT;
        }

        /* The CWE header was well loaded.
         * Now make some checks
         */
        if (LE_OK == result)
        {
            /* The image type was already checked in LoadCweHeader */

            /* Validate product ID */
            if (!IsValidProductId(hdpPtr->prodType))
            {
                LE_ERROR ("Bad Product Id in the header %x", hdpPtr->prodType);
                result = LE_FAULT;
            }

            /* Check that the image is not a compressed one:
             * not supported on this platform
             */
            if ((hdpPtr->miscOpts & CWE_MISC_OPTS_COMPRESS) == CWE_MISC_OPTS_COMPRESS)
            {
                LE_ERROR( "Compressed image is not supported");
                result = LE_FAULT;
            }

            /* validate PSB CRC */
            if (le_crc_Crc32((uint8_t*)startPtr, CWE_CRC_PROD_BUF_OFST, LE_CRC_START_CRC32) !=
                hdpPtr->crcProdBuf)
            {
                LE_ERROR( "error PSB CRC32");
                result = LE_FAULT;
            }

            /* The image CRC will be checked when all data are retrieved */
            if (result != LE_OK)
            {
                LE_ERROR ("Error when validate the header");
            }
        }
    }
    LE_DEBUG ("result %d", result);
    return result;
}
