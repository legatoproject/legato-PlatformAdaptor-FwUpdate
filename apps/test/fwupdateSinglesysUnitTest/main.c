 /**
  * This module implements the pa_fwupdate_dualsys unit tests.
  *
  * Copyright (C) Sierra Wireless Inc.
  *
  */

#include "legato.h"
#include <pthread.h>
#include "interfaces.h"
#include "pa_fwupdate.h"
#include "cwe_local.h"
#include "log.h"
#include "sys_flash.h"
#include <endian.h>

#define FILE_PATH      "/fwupdate/dwl_status.nfo"
#define TEST_FILE      "/tmp/test_file.txt"
#define KEYSTORE_CWE   "../data/keystore.cwe"
#define LS_CWE         "../data/ls.cwe"
#define CP_CWE         "../data/cp.cwe"
#define LS2CP_CWE      "../data/ls2cp.cwe"
#define CP2LS_CWE      "../data/cp2ls.cwe"
#define LS_UBI_CWE     "../data/ls_ubi.cwe"
#define CP_UBI_CWE     "../data/cp_ubi.cwe"
#define LS2CP_UBI_CWE  "../data/ls2cp_ubi.cwe"
#define CP2LS_UBI_CWE  "../data/cp2ls_ubi.cwe"

//--------------------------------------------------------------------------------------------------
/**
 * Meta data structure
 */
//--------------------------------------------------------------------------------------------------
typedef struct __attribute__((__packed__))
{
    uint8_t   cweHeaderRaw[CWE_HEADER_SIZE];  ///< Raw CWE header copied from image
    uint32_t  magicBegin;                     ///< Magic number
    uint32_t  version;                        ///< Version of the structure
    uint32_t  offset;                         ///< Offset of partition to store image
    uint32_t  logicalBlock;                   ///< Logical start block number to store image
    uint32_t  phyBlock;                       ///< Physical start block number to store image
    uint32_t  imageSize;                      ///< Size of the image including CWE header
    uint32_t  dldSource;                      ///< Image download source, local or FOTA
    uint32_t  nbComponents;                   ///< Number of component images in slot
    uint8_t   reserved[108];                  ///< Reserved for future use
    uint32_t  magicEnd;                       ///< Magic number
    uint32_t  crc32;                          ///< CRC of the structure
}
Metadata_t;

//==================================================================================================
//                                       Private Functions
//==================================================================================================

//--------------------------------------------------------------------------------------------------
/**
 * This function copies the CWE body image from SWIFOTA to BOOT partition (Single systems).
 *
 */
//--------------------------------------------------------------------------------------------------
static void ApplySwifotaToBootPartition
(
    void
)
{
    FILE* fdPtr;
    uint32_t eraseSize, nbBlk;
    int rc;
    int fdSwifota, fdDest;
    int mtdSwifota = -1, mtdBoot = -1, mtdLefwkro = -1, mtdDest;
    char line[256];
    off_t offset;

    fdPtr = fopen("/sys/class/mtd/mtd0/erasesize", "r");
    LE_TEST_ASSERT(fdPtr, "");
    rc = fscanf(fdPtr, "%u", &eraseSize);
    LE_TEST_ASSERT(rc == 1, "");
    fclose(fdPtr);

    fdPtr = fopen("/proc/mtd", "r");
    LE_TEST_ASSERT(fdPtr, "");
    while( fgets(line, sizeof(line)-1, fdPtr) )
    {
        line[sizeof(line)-1] = '\0';
        if( strstr( line, "\"swifota\"" ))
        {
            rc = sscanf( line, "mtd%d", &mtdSwifota );
            LE_TEST_ASSERT(rc == 1, "");
        }
        else if( strstr( line, "\"boot\"" ))
        {
            rc = sscanf( line, "mtd%d", &mtdBoot );
            LE_TEST_ASSERT(rc == 1, "");
        }
        else if( strstr( line, "\"lefwkro\"" ))
        {
            rc = sscanf( line, "mtd%d", &mtdLefwkro );
            LE_TEST_ASSERT(rc == 1, "");
        }
        else
        {
        }
    }
    fclose(fdPtr);
    LE_TEST_ASSERT((mtdSwifota != -1) && (mtdBoot != -1), "");

    Metadata_t md;
    uint8_t buffer[eraseSize];
    snprintf(line, sizeof(line), "/dev/mtd%d", mtdSwifota);
    fdSwifota = open(line, O_RDONLY);
    LE_TEST_ASSERT(fdSwifota != -1, "");

    rc = sys_flashReadSkipBadBlock(fdSwifota, &md, sizeof(md));
    LE_TEST_ASSERT(rc == sizeof(md), "");

    offset = lseek(fdSwifota, 0, SEEK_CUR);
    LE_TEST_ASSERT(-1 != offset, "");
    LE_TEST_INFO("Meta Data: phyBlock %u logicalBlock %u", md.phyBlock, md.logicalBlock);

    offset = md.phyBlock * eraseSize;
    rc = lseek(fdSwifota, offset, SEEK_SET);
    LE_TEST_ASSERT(rc == offset, "");

    // Use read() as we really want to check that we are pointing to the real block
    rc = read(fdSwifota, buffer, 2 * CWE_HEADER_SIZE);
    LE_TEST_ASSERT(rc == (2 * CWE_HEADER_SIZE), "");

    LE_TEST_ASSERT(0 == memcmp(&md, buffer, CWE_HEADER_SIZE), "");

    // Skip the first header;
    cwe_Header_t* cwePtr = (cwe_Header_t*)(buffer + CWE_HEADER_SIZE);
    uint32_t cweType = (cwePtr->imageType);
    uint32_t cweSize = be32toh(cwePtr->imageSize);
    uint32_t size = 0;

    if( memcmp(&cweType, "APPS", 4) == 0 )
    {
        mtdDest = mtdBoot;
    }
    else if( memcmp(&cweType, "USER", 4) == 0 )
    {
        mtdDest = mtdLefwkro;
    }
    else
    {
        LE_ERROR("Unsupported partition");
        LE_TEST_ASSERT(0, "");
    }

    snprintf(line, sizeof(line), "/dev/mtd%d", mtdDest);
    fdDest = open(line, O_WRONLY);
    LE_TEST_ASSERT(fdDest != -1, "");
    while( size < cweSize )
    {
        int rdsz;
        rdsz = sys_flashReadSkipBadBlock(fdSwifota, buffer, eraseSize);
        LE_TEST_ASSERT(rdsz > 0, "");
        rc = write(fdDest, buffer, rdsz);
        LE_TEST_ASSERT(rc == rdsz, "");
        size += rdsz;
    }
    close(fdSwifota);

    // Erase all remaining blocks in destination partition
    snprintf(line, sizeof(line), "/sys/class/mtd/mtd%d/size", mtdDest);
    fdPtr = fopen(line, "r");
    LE_TEST_ASSERT(fdPtr, "");
    rc = fscanf(fdPtr, "%u", &nbBlk);
    nbBlk /= eraseSize;
    LE_TEST_ASSERT(rc == 1, "");
    fclose(fdPtr);

    lseek( fdDest, ((cweSize + eraseSize - 1) / eraseSize) * eraseSize, SEEK_SET);
    memset(buffer, 0xFF, sizeof(buffer));
    uint32_t nb = ((cweSize + eraseSize - 1) / eraseSize);
    lseek( fdDest, nb * eraseSize, SEEK_SET);
    for( ; nb < nbBlk; nb++ )
    {
        write(fdDest, &buffer, sizeof(buffer));
    }
    close(fdDest);
    LE_TEST_INFO("SWIFOTA applied");
}

//--------------------------------------------------------------------------------------------------
/**
 * This test gets the pa_fwupdate_InitDownload API
 *
 * API Tested:
 *  pa_fwupdate_InitDownload().
 */
//--------------------------------------------------------------------------------------------------
static void Testpa_fwupdate_InitDownload
(
    void
)
{
    LE_TEST_INFO ("======== Test: pa_fwupdate_InitDownload ========");
    pa_fwupdateSimu_SetReturnVal(LE_OK);
    LE_TEST(LE_OK == pa_fwupdate_InitDownload());
}

//--------------------------------------------------------------------------------------------------
/**
 * This test gets the pa_fwupdate_Download API
 *
 * API Tested:
 *  pa_fwupdate_Download().
 */
//--------------------------------------------------------------------------------------------------
static void Testpa_fwupdate_Download
(
    void
)
{
    int fd;

    LE_TEST_INFO ("======== Test: pa_fwupdate_Download ========");

    fd = -1;
    LE_TEST(LE_BAD_PARAMETER == pa_fwupdate_Download(fd));

    if ((-1 == unlink(TEST_FILE)) && (ENOENT != errno))
    {
        LE_TEST_FATAL("unlink failed: %m");
    }

    fd = open(TEST_FILE, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    LE_TEST(LE_CLOSED == pa_fwupdate_Download(fd));
    close(fd);
}

//--------------------------------------------------------------------------------------------------
/**
 * This test gets the pa_fwupdate_Download API
 *
 * API Tested:
 *  pa_fwupdate_Download().
 */
//--------------------------------------------------------------------------------------------------
static void Testpa_fwupdate_DownloadDelta
(
    void
)
{
    int fd;

    LE_TEST_INFO ("======== Test: pa_fwupdate_DownloadDelta ========");

    LE_TEST_INFO ("======== Test: Donwload LS ========");
    fd = open(LS_CWE, O_RDONLY);
    LE_TEST_ASSERT(fd >= 0, "");
    LE_TEST(LE_OK == pa_fwupdate_Download(fd));
    close(fd);
    (void)pa_fwupdate_Install(true);
    ApplySwifotaToBootPartition();

    LE_TEST_INFO ("======== Test: Patch LS to CP ========");
    fd = open(LS2CP_CWE, O_RDONLY);
    LE_TEST_ASSERT(fd >= 0, "");
    LE_TEST(LE_OK == pa_fwupdate_Download(fd));
    close(fd);
    (void)pa_fwupdate_Install(true);
    ApplySwifotaToBootPartition();

    LE_TEST_INFO ("======== Test: Patch LS to CP ========");
    fd = open(LS2CP_CWE, O_RDONLY);
    LE_TEST_ASSERT(fd >= 0, "");
    // Apply same patch to another image should be rejected/
    LE_TEST(LE_FAULT == pa_fwupdate_Download(fd));
    close(fd);

    LE_TEST_INFO ("======== Test: Patch CP to LS ========");
    LE_TEST(LE_OK == pa_fwupdate_InitDownload());
    fd = open(CP2LS_CWE, O_RDONLY);
    LE_TEST_ASSERT(fd >= 0, "");
    LE_TEST(LE_OK == pa_fwupdate_Download(fd));
    close(fd);
    (void)pa_fwupdate_Install(true);
    ApplySwifotaToBootPartition();

    LE_TEST_INFO ("======== Test: Donwload CP_UBI ========");

    fd = open(CP_UBI_CWE, O_RDONLY);
    LE_TEST_ASSERT(fd >= 0, "");
    LE_TEST(LE_OK == pa_fwupdate_Download(fd));
    close(fd);
    (void)pa_fwupdate_Install(true);
    ApplySwifotaToBootPartition();

    LE_TEST_INFO ("======== Test: Patch CP_UBI to LS_UBI ========");
    fd = open(CP2LS_UBI_CWE, O_RDONLY);
    LE_TEST_ASSERT(fd >= 0, "");
    LE_TEST(LE_OK == pa_fwupdate_Download(fd));
    close(fd);
    (void)pa_fwupdate_Install(true);
    ApplySwifotaToBootPartition();

    LE_TEST_INFO ("======== Test: Patch LS_UBI to CP_UBI ========");
    LE_TEST(LE_OK == pa_fwupdate_InitDownload());
    fd = open(LS2CP_UBI_CWE, O_RDONLY);
    LE_TEST_ASSERT(fd >= 0, "");
    LE_TEST(LE_OK == pa_fwupdate_Download(fd));
    close(fd);
    (void)pa_fwupdate_Install(true);
    ApplySwifotaToBootPartition();

    LE_TEST_INFO ("======== Test: Donwload KEYSTORE ========");
    fd = open(KEYSTORE_CWE, O_RDONLY);
    LE_TEST_ASSERT(fd >= 0, "");
    LE_TEST(LE_OK == pa_fwupdate_Download(fd));
    close(fd);
}

//--------------------------------------------------------------------------------------------------
/**
 * This test gets the pa_fwupdate_GetResumePosition API
 *
 * API Tested:
 *  pa_fwupdate_GetResumePosition().
 */
//--------------------------------------------------------------------------------------------------
static void Testpa_fwupdate_GetResumePosition
(
    void
)
{
    LE_TEST_INFO ("======== Test: pa_fwupdate_GetResumePosition ========");

    size_t position;
    LE_TEST(LE_BAD_PARAMETER == pa_fwupdate_GetResumePosition(NULL));
    LE_TEST(LE_OK == pa_fwupdate_GetResumePosition(&position));
}

//--------------------------------------------------------------------------------------------------
/**
 * This test gets the pa_fwupdate_Install API
 *
 * API Tested:
 *  pa_fwupdate_Install().
 */
//--------------------------------------------------------------------------------------------------
static void Testpa_fwupdate_Install
(
    void
)
{
    LE_TEST_INFO ("======== Test: pa_fwupdate_Install ========");

    LE_TEST(LE_FAULT == pa_fwupdate_Install(true));
}

//--------------------------------------------------------------------------------------------------
/**
 * This test gets the pa_fwupdate_GetUpdateStatus API
 *
 * API Tested:
 *  pa_fwupdate_GetUpdateStatus().
 */
//--------------------------------------------------------------------------------------------------
static void Testpa_fwupdate_GetUpdateStatus
(
    void
)
{
    pa_fwupdate_UpdateStatus_t statusPtr;
    char statusLabel[50]= {0};
    size_t statusLabelLength = 1;

    LE_TEST_INFO ("======== Test: pa_fwupdate_GetUpdateStatus ========");

    LE_TEST(LE_BAD_PARAMETER == pa_fwupdate_GetUpdateStatus(NULL, statusLabel,
                                                              statusLabelLength));
    LE_TEST(LE_OK == pa_fwupdate_GetUpdateStatus(&statusPtr, statusLabel, statusLabelLength));
    LE_TEST(LE_OK == pa_fwupdate_GetUpdateStatus(&statusPtr, statusLabel, 50));
}

//--------------------------------------------------------------------------------------------------
/**
 * Component init of the unit test
 */
//--------------------------------------------------------------------------------------------------
COMPONENT_INIT
{
    le_fs_FileRef_t fileRef;
    char thisPath[PATH_MAX], *ptr;

    LE_TEST_PLAN(LE_TEST_NO_PLAN);

    snprintf(thisPath, sizeof(thisPath), "/proc/%d/cmdline", getpid());
    FILE* fdPtr = fopen( thisPath, "r" );
    memset(thisPath, 0, sizeof(thisPath));
    fscanf(fdPtr, "%s", thisPath);
    fclose(fdPtr);
    ptr = strrchr(thisPath, '/');
    if( ptr )
    {
        *ptr = '\0';
    }
    LE_TEST_INFO("cwd: %s", thisPath);
    chdir(thisPath);

    int bbMaskIdx = 0;
    unsigned long long bbMask = 0;
    unsigned long long bbMaskTab[] =
    {
        // This is the bad blocks mask:
        //     if bit 1<<n is set to 1, the block "n" will be seen as "bad"
        // Bad blocks will be "raised" while erasing flash,
        0ULL,
        0x11182ULL | (1ULL << 59),
        0xFF0ULL,
        -1ULL,
    };

    char *bbPtr = getenv("BAD_BLOCK_SWIFOTA");
    if( bbPtr && *bbPtr )
    {
        if ((sscanf( bbPtr, "%llx", &bbMask )) != 1)
        {
            LE_TEST_INFO("Error reading bad block mask from %s", bbPtr);
        }
        LE_TEST_INFO("Bad block string \"%s\", mask %llx", bbPtr, bbMask);
        sys_flash_SetBadBlockErase( "swifota", bbMask );
    }

    do
    {
        if ((-1 == unlink(FILE_PATH)) && (ENOENT != errno))
        {
            LE_TEST_FATAL("unlink failed: %m");
        }

        LE_TEST(LE_OK == le_fs_Open(FILE_PATH, LE_FS_CREAT | LE_FS_RDWR, &fileRef));

        LE_TEST_INFO("======== Start UnitTest of FW Update Singlesys"
                     " [Bad block mask 0x%llx] ========", bbMask);

        sys_flash_ResetBadBlock( "swifota" );
        sys_flash_SetBadBlockErase( "swifota", bbMask );

        Testpa_fwupdate_InitDownload();
        Testpa_fwupdate_Download();
        Testpa_fwupdate_GetResumePosition();
        Testpa_fwupdate_Install();
        Testpa_fwupdate_GetUpdateStatus();
        Testpa_fwupdate_InitDownload();
        Testpa_fwupdate_DownloadDelta();

        bbMask = bbMaskTab[bbMaskIdx];
        bbMaskIdx++;
    }
    while( bbMask != (-1ULL) );

    LE_TEST_INFO("======== FW Update Singlesys tests end ========");
    LE_TEST_EXIT;
}
