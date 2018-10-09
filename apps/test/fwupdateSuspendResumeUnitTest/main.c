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
    int mtdSwifota = -1, mtdBoot = -1, mtdLefwkro = -1, mtdModem = -1, mtdSystem = -1, mtdDest;
    char line[256];

    fdPtr = fopen("/sys/class/mtd/mtd0/erasesize", "r");
    LE_ASSERT(fdPtr);
    rc = fscanf(fdPtr, "%u", &eraseSize);
    LE_ASSERT(rc == 1);
    fclose(fdPtr);

    fdPtr = fopen("/proc/mtd", "r");
    LE_ASSERT(fdPtr);
    while( fgets(line, sizeof(line)-1, fdPtr) )
    {
        line[sizeof(line)-1] = '\0';
        if( strstr( line, "\"swifota\"" ))
        {
            rc = sscanf( line, "mtd%d", &mtdSwifota );
            LE_ASSERT(rc == 1);
        }
        else if( strstr( line, "\"modem\"" ))
        {
            rc = sscanf( line, "mtd%d", &mtdModem );
            LE_ASSERT(rc == 1);
        }
        else if( strstr( line, "\"boot\"" ))
        {
            rc = sscanf( line, "mtd%d", &mtdBoot );
            LE_ASSERT(rc == 1);
        }
        else if( strstr( line, "\"system\"" ))
        {
            rc = sscanf( line, "mtd%d", &mtdSystem );
            LE_ASSERT(rc == 1);
        }
        else if( strstr( line, "\"lefwkro\"" ))
        {
            rc = sscanf( line, "mtd%d", &mtdLefwkro );
            LE_ASSERT(rc == 1);
        }
        else
        {
        }
    }
    fclose(fdPtr);
    LE_ASSERT(mtdSwifota != -1);

    uint8_t buffer[eraseSize];
    snprintf(line, sizeof(line), "/dev/mtd%d", mtdSwifota);
    fdSwifota = open(line, O_RDONLY);
    LE_ASSERT(fdSwifota != -1);

    // Skip the 2 first erase blocks.
    // Skip the first header;
    LE_ASSERT(2*eraseSize + CWE_HEADER_SIZE == lseek(fdSwifota,
                                                     2*eraseSize + CWE_HEADER_SIZE,
                                                     SEEK_SET));
    rc = read(fdSwifota, buffer, eraseSize);
    LE_ASSERT(rc == eraseSize);

    cwe_Header_t* cwePtr = (cwe_Header_t*)buffer;
    uint32_t cweType = (cwePtr->imageType);
    uint32_t cweSize = be32toh(cwePtr->imageSize);
    uint32_t size = 0;

    if( memcmp(&cweType, "MODM", 4) == 0 )
    {
        mtdDest = mtdModem;
    }
    else if( memcmp(&cweType, "APPS", 4) == 0 )
    {
        mtdDest = mtdBoot;
    }
    else if( memcmp(&cweType, "SYST", 4) == 0 )
    {
        mtdDest = mtdSystem;
    }
    else if( memcmp(&cweType, "USER", 4) == 0 )
    {
        mtdDest = mtdLefwkro;
    }
    else
    {
        LE_ERROR("Unsupported partition");
        LE_ASSERT(0);
    }

    snprintf(line, sizeof(line), "/dev/mtd%d", mtdDest);
    fdDest = open(line, O_WRONLY);
    LE_ASSERT(fdDest != -1);
    // Skip the 2 first erase blocks.
    // Skip the 2 first headers;
    LE_ASSERT(2*(eraseSize + CWE_HEADER_SIZE) == lseek(fdSwifota,
                                                       2*(eraseSize + CWE_HEADER_SIZE),
                                                       SEEK_SET));
    while( size < cweSize )
    {
        int rdsz;
        rdsz = read(fdSwifota, buffer, eraseSize);
        LE_ASSERT(rdsz > 0);
        rc = write(fdDest, buffer, rdsz);
        LE_ASSERT(rc == rdsz);
        size += rdsz;
    }
    close(fdSwifota);

    // Erase all remaining blocks in destination partition
    snprintf(line, sizeof(line), "/sys/class/mtd/mtd%d/size", mtdDest);
    fdPtr = fopen(line, "r");
    LE_ASSERT(fdPtr);
    rc = fscanf(fdPtr, "%u", &nbBlk);
    nbBlk /= eraseSize;
    LE_ASSERT(rc == 1);
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
    LE_INFO("SWIFOTA applied");
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
    int pip[2];
    const char* imagePtr;
    const char* patchPtr;
    uint32_t imageLen, patchLen;
    pid_t pid;
    int status;

    LE_INFO ("======== Test: pa_fwupdate_DownloadDelta ========");

    if( le_arg_NumArgs() < 4 )
    {
        // At least 4 arguments are required to launch the test, else the test exits successfully.
        // test <image.cwe> <offset-to-stop|0> <image-patch.cwe> <offset-to-stop|0>
        // if offset-to-stop is not 0, the test stops abruptly the download after offset-to-stop
        // and restart a resume from the requested position.
        // if 0, the download is performed in one shot.
        return;
    }

    imagePtr = le_arg_GetArg( 0 );
    sscanf(le_arg_GetArg( 1 ), "%u", &imageLen);
    patchPtr = le_arg_GetArg( 2 );
    sscanf(le_arg_GetArg( 3 ), "%u", &patchLen);

    LE_TEST(LE_OK == pa_fwupdate_InitDownload());

    LE_INFO ("======== Test: Donwload %s ========", imagePtr);

    LE_ASSERT(-1 != pipe(pip));
    pid = fork();
    LE_ASSERT(-1 != pid);
    if( 0 == pid )
    {
        int fd;
        uint8_t buff[65536];
        int rcr, rcw;
        int rdLen = 0;

        close(pip[0]);
        fd = open(imagePtr, O_RDONLY);
        LE_ASSERT(fd >= 0);
        for( ; ; )
        {
            rcr = read(fd, buff, sizeof(buff));
            if( 0 >= rcr )
            {
                break;
            }
            rdLen += rcr;
            rcw = write(pip[1], buff, rcr);
            if( 0 >= rcw )
            {
                break;
            }
            if( imageLen && (rdLen >= imageLen) )
            {
                LE_INFO("Max size for read reached (%d %u)", rdLen, imageLen);
                break;
            }
        }
        close(pip[1]);
        close(fd);
        exit(0);
    }

    close(pip[1]);
    LE_TEST(LE_OK == pa_fwupdate_Download(pip[0]));
    close(pip[0]);
    waitpid(pid, &status, 0);
    ApplySwifotaToBootPartition();

    LE_INFO ("======== Test: Patch %s to %s ========", imagePtr, patchPtr);

    LE_TEST(LE_OK == pa_fwupdate_InitDownload());

    LE_ASSERT(-1 != pipe(pip));
    pid = fork();
    LE_ASSERT(-1 != pid);
    if( 0 == pid )
    {
        int fd;
        uint8_t buff[65536];
        int rcr, rcw;
        int rdLen = 0;

        close(pip[0]);
        fd = open(patchPtr, O_RDONLY);
        LE_ASSERT(fd >= 0);
        for( ; ; )
        {
            rcr = read(fd, buff, sizeof(buff));
            if( 0 >= rcr )
            {
                break;
            }
            rdLen += rcr;
            rcw = write(pip[1], buff, rcr);
            if( 0 >= rcw )
            {
                break;
            }
            if( patchLen && (rdLen >= patchLen) )
            {
                LE_INFO("Max size for read reached (%d %u)", rdLen, patchLen);
                break;
            }
        }
        close(pip[1]);
        close(fd);
        exit(0);
    }

    close(pip[1]);
    LE_TEST(LE_OK == pa_fwupdate_Download(pip[0]));
    close(pip[0]);
    waitpid(pid, &status, 0);
    ApplySwifotaToBootPartition();
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
    LE_INFO("cwd: %s", thisPath);
    chdir(thisPath);

    if ((-1 == unlink(FILE_PATH)) && (ENOENT != errno))
    {
        LE_TEST_FATAL("unlink failed: %m");
    }

    LE_TEST(LE_OK == le_fs_Open(FILE_PATH, LE_FS_CREAT | LE_FS_RDWR, &fileRef));

    LE_INFO("======== Start UnitTest of FW Update Singlesys ========");

    Testpa_fwupdate_DownloadDelta();

    LE_INFO("======== FW Update Singlesys tests SUCCESS ========");
    LE_TEST_EXIT;
}
