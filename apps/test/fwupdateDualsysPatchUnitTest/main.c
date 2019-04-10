/**
* Unit test for Firmware update (Dual systems)
*
* Here, some examples on how to run the test:
*
* "./fwupdateDualsystemPatchUnitTest legato.cwe 1500000": Download a legato with suspend/resume
*   at the defined offset
*
* "./fwupdateDualsystemPatchUnitTest legato.cwe 1500000 delta.cwe 300000": Download a legato with
*  suspend/resume, then download the delta with also a suspend/resume at the defined offsets
*
* If the input offset is zero, then the download won't perform a suspend/resume. Instead, it will
* perform a complete download in one shot.
*
* Copyright (C) Sierra Wireless Inc.
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
static void ApplySwap
(
    void
)
{
    FILE* fdPtr;
    uint32_t eraseSize, nbBlk;
    int rc;
    int mtdAboot[2], mtdBoot[2], mtdSystem[2], mtdLefwkro[2], mtdModem[2];
    int fdDest;
    char line[256];
    char line2[256];

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
        if( strstr( line, "\"aboot\"" ))
        {
            rc = sscanf( line, "mtd%d", &mtdAboot[0] );
            LE_TEST_ASSERT(rc == 1, "");
        }
        else if( strstr( line, "\"aboot2\"" ))
        {
            rc = sscanf( line, "mtd%d", &mtdAboot[1] );
            LE_TEST_ASSERT(rc == 1, "");
        }
        else if( strstr( line, "\"boot\"" ))
        {
            rc = sscanf( line, "mtd%d", &mtdBoot[0] );
            LE_TEST_ASSERT(rc == 1, "");
        }
        else if( strstr( line, "\"boot2\"" ))
        {
            rc = sscanf( line, "mtd%d", &mtdBoot[1] );
            LE_TEST_ASSERT(rc == 1, "");
        }
        else if( strstr( line, "\"system\"" ))
        {
            rc = sscanf( line, "mtd%d", &mtdSystem[0] );
            LE_TEST_ASSERT(rc == 1, "");
        }
        else if( strstr( line, "\"system2\"" ))
        {
            rc = sscanf( line, "mtd%d", &mtdSystem[1] );
            LE_TEST_ASSERT(rc == 1, "");
        }
        else if( strstr( line, "\"lefwkro\"" ))
        {
            rc = sscanf( line, "mtd%d", &mtdLefwkro[0] );
            LE_TEST_ASSERT(rc == 1, "");
        }
        else if( strstr( line, "\"lefwkro2\"" ))
        {
            rc = sscanf( line, "mtd%d", &mtdLefwkro[1] );
            LE_TEST_ASSERT(rc == 1, "");
        }
        else if( strstr( line, "\"modem\"" ))
        {
            rc = sscanf( line, "mtd%d", &mtdModem[0] );
            LE_TEST_ASSERT(rc == 1, "");
        }
        else if( strstr( line, "\"modem2\"" ))
        {
            rc = sscanf( line, "mtd%d", &mtdModem[1] );
            LE_TEST_ASSERT(rc == 1, "");
        }
        else
        {
        }
    }
    fclose(fdPtr);

    snprintf(line, sizeof(line), "/dev/mtd%d_tmp", mtdAboot[0]);
    snprintf(line2, sizeof(line), "/dev/mtd%d", mtdAboot[0]);
    rc = rename(line2, line);
    snprintf(line, sizeof(line), "/dev/mtd%d", mtdAboot[0]);
    snprintf(line2, sizeof(line), "/dev/mtd%d", mtdAboot[1]);
    rc = rename(line2, line);
    snprintf(line, sizeof(line), "/dev/mtd%d", mtdAboot[1]);
    snprintf(line2, sizeof(line), "/dev/mtd%d_tmp", mtdAboot[0]);
    rc = rename(line2, line);
    LE_TEST_ASSERT(rc != -1, "");

    snprintf(line, sizeof(line), "/dev/mtd%d_tmp", mtdBoot[0]);
    snprintf(line2, sizeof(line), "/dev/mtd%d", mtdBoot[0]);
    rc = rename(line2, line);
    snprintf(line, sizeof(line), "/dev/mtd%d", mtdBoot[0]);
    snprintf(line2, sizeof(line), "/dev/mtd%d", mtdBoot[1]);
    rc = rename(line2, line);
    snprintf(line, sizeof(line), "/dev/mtd%d", mtdBoot[1]);
    snprintf(line2, sizeof(line), "/dev/mtd%d_tmp", mtdBoot[0]);
    rc = rename(line2, line);
    LE_TEST_ASSERT(rc != -1, "");

    snprintf(line, sizeof(line), "/dev/mtd%d_tmp", mtdSystem[0]);
    snprintf(line2, sizeof(line), "/dev/mtd%d", mtdSystem[0]);
    rc = rename(line2, line);
    snprintf(line, sizeof(line), "/dev/mtd%d", mtdSystem[0]);
    snprintf(line2, sizeof(line), "/dev/mtd%d", mtdSystem[1]);
    rc = rename(line2, line);
    snprintf(line, sizeof(line), "/dev/mtd%d", mtdSystem[1]);
    snprintf(line2, sizeof(line), "/dev/mtd%d_tmp", mtdSystem[0]);
    rc = rename(line2, line);
    LE_TEST_ASSERT(rc != -1, "");

    snprintf(line, sizeof(line), "/dev/mtd%d_tmp", mtdLefwkro[0]);
    snprintf(line2, sizeof(line), "/dev/mtd%d", mtdLefwkro[0]);
    rc = rename(line2, line);
    snprintf(line, sizeof(line), "/dev/mtd%d", mtdLefwkro[0]);
    snprintf(line2, sizeof(line), "/dev/mtd%d", mtdLefwkro[1]);
    rc = rename(line2, line);
    snprintf(line, sizeof(line), "/dev/mtd%d", mtdLefwkro[1]);
    snprintf(line2, sizeof(line), "/dev/mtd%d_tmp", mtdLefwkro[0]);
    rc = rename(line2, line);
    LE_TEST_ASSERT(rc != -1, "");

    snprintf(line, sizeof(line), "/dev/mtd%d_tmp", mtdModem[0]);
    snprintf(line2, sizeof(line), "/dev/mtd%d", mtdModem[0]);
    rc = rename(line2, line);
    LE_TEST_ASSERT(rc != -1, "");
    snprintf(line, sizeof(line), "/dev/mtd%d", mtdModem[0]);
    snprintf(line2, sizeof(line), "/dev/mtd%d", mtdModem[1]);
    rc = rename(line2, line);
    LE_TEST_ASSERT(rc != -1, "");
    snprintf(line, sizeof(line), "/dev/mtd%d", mtdModem[1]);
    snprintf(line2, sizeof(line), "/dev/mtd%d_tmp", mtdModem[0]);
    rc = rename(line2, line);
    LE_TEST_ASSERT(rc != -1, "");
    LE_TEST_INFO("SWAP complete");

    // Erase all remaining blocks in destination partition
    snprintf(line, sizeof(line), "/sys/class/mtd/mtd%d/size", mtdLefwkro[0]);
    fdPtr = fopen(line, "r");
    LE_TEST_ASSERT(fdPtr, "");
    rc = fscanf(fdPtr, "%u", &nbBlk);
    nbBlk /= eraseSize;
    LE_TEST_ASSERT(rc == 1, "");
    fclose(fdPtr);

    uint8_t ubiEc[64] =
            {
                0x55,0x42,0x49,0x23,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x10,0x00,0x00,0x00,0x20,0x00,0x12,0x34,0x56,0x78,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xef,0xe4,0x7f,0xad,
            };
    uint8_t ubiBuff[64];
    uint8_t buffer[eraseSize];

    snprintf(line, sizeof(line), "/dev/mtd%d", mtdLefwkro[0]);
    fdDest = open(line, O_RDWR);
    LE_TEST_ASSERT(-1 != fdDest, "");
    lseek( fdDest, 0, SEEK_SET);
    memset(buffer, 0xFF, sizeof(buffer));
    memcpy(buffer, ubiEc, sizeof(ubiEc));

    sys_flash_SwapBadBlock( "lefwkro2", "lefwkro" );

    int nb;
    for( nb = 0; nb < nbBlk; nb++ )
    {
        lseek(fdDest, nb * eraseSize, SEEK_SET);
        rc = read(fdDest, &ubiBuff, sizeof(ubiBuff));
        if( (rc != sizeof(ubiBuff)) || memcmp(ubiBuff, ubiEc, 4) )
        {
            lseek(fdDest, nb * eraseSize, SEEK_SET);
            write(fdDest, &buffer, sizeof(buffer));
        }
    }
    close(fdDest);
    LE_TEST_INFO("SWAP applied");
}

//--------------------------------------------------------------------------------------------------
/**
 * This test performs a full package download with suspend/resume feature at any particular position
 *
 * API Tested:
 *  pa_fwupdate_Download()
 *  pa_fwupdate_InitDownload()
 *  pa_fwupdate_GetResumePosition()
 */
//--------------------------------------------------------------------------------------------------
static void Testpa_fwupdate_Download
(
    const char* imagePtr,      ///< [IN] Image to be downloaded
    uint32_t suspendAtOffset   ///< [IN] Perform a suspend/resume when reaching the offset
)
{
    int pip[2];
    size_t position = 0;
    pid_t pid;
    int status;
    le_result_t result;

    // Initialize download
    LE_TEST_INFO ("Test: Download %s", imagePtr);
    LE_TEST(LE_OK == pa_fwupdate_InitDownload());

    // Check if the suspend offset is within the image
    struct stat st;
    LE_TEST_ASSERT(0 == stat(imagePtr, &st), "");
    LE_TEST_ASSERT(st.st_size > suspendAtOffset, "");

    // Fork the program and send the image content using a pipe
    LE_TEST_ASSERT(-1 != pipe(pip), "");
    pid = fork();
    LE_TEST_ASSERT(-1 != pid, "");
    if( 0 == pid )
    {
        int fd;
        uint8_t buff[65536];
        int rcr, rcw;
        int rdLen = 0;

        close(pip[0]);
        fd = open(imagePtr, O_RDONLY);
        LE_TEST_ASSERT(fd >= 0, "");
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
            if( suspendAtOffset && (rdLen >= suspendAtOffset) )
            {
                LE_TEST_INFO("Max size for read reached (%d %u)", rdLen, suspendAtOffset);
                break;
            }
        }
        close(pip[1]);
        close(fd);
        exit(0);
    }
    close(pip[1]);

    if (suspendAtOffset == 0)
    {
        LE_TEST_ASSERT(LE_OK == pa_fwupdate_Download(pip[0]), "");
    }
    else
    {
        LE_TEST_ASSERT(LE_OK != pa_fwupdate_Download(pip[0]), "");
    }

    close(pip[0]);
    waitpid(pid, &status, 0);
    // Perform the swap and request a mark good
    if (suspendAtOffset == 0)
    {
        ApplySwap();
        pa_fwupdate_MarkGood();
    }

    // Resume the previous download if it has been suspended
    if (suspendAtOffset != 0)
    {
        // Check if we need to resume or not
        result = pa_fwupdate_GetResumePosition(&position);
        if ((result == LE_OK) && (position != 0))
        {
            LE_TEST_INFO("resume download at position %zd", position);
        }
        else
        {
            LE_ERROR("Can't resume");
            LE_TEST_ASSERT(0, "");
        }

        // Fork the program and send the remaining image content using a pipe
        LE_TEST_ASSERT(-1 != pipe(pip), "");
        pid = fork();
        LE_TEST_ASSERT(-1 != pid, "");
        if( 0 == pid )
        {
            int fd;
            uint8_t buff[65536];
            int rcr, rcw;

            close(pip[0]);
            fd = open(imagePtr, O_RDONLY);
            LE_TEST_ASSERT(fd >= 0, "");
            if (lseek(fd,position,SEEK_SET) < 0)
            {
                LE_ERROR("Unable to seek to the correct position");
            }

            for( ; ; )
            {
                rcr = read(fd, buff, sizeof(buff));
                if( 0 >= rcr )
                {
                    break;
                }
                rcw = write(pip[1], buff, rcr);
                if( 0 >= rcw )
                {
                    break;
                }
            }
            close(pip[1]);
            close(fd);
            exit(0);
        }

        close(pip[1]);
        LE_TEST_ASSERT(LE_OK == pa_fwupdate_Download(pip[0]), "");
        close(pip[0]);
        waitpid(pid, &status, 0);
    }

    // Perform the swap
    ApplySwap();
    pa_fwupdate_MarkGood();
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
    const char* imagePtr;
    uint32_t suspendAtOffset;

    LE_TEST_PLAN(LE_TEST_NO_PLAN);

    // Get command line arguments
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
    chdir(thisPath);

    int bbMaskIdx = 0;
    unsigned long long bbMask = 0;
    unsigned long long bbMaskTab[][3] =
    {
        // These are the bad blocks masks:
        //     if bit 1<<n is set to 1, the block "n" will be seen as "bad"
        // 3 values for the 3 kinds of bad blocks simulated by sys_flash:
        //     [0] = bad blocks while erasing flash,
        //     [1] = bad blocks while writing,
        //     [2] = bad blocks already marked [Not used]
        { 0ULL, 0ULL, 0ULL },
        { 0x11182ULL | (1ULL << 59), 0x24228ULL, 0ULL, },
        { 0xFF0ULL, 0x000333ULL, 0ULL, },
        { -1ULL, },
    };

    char *bbPtr = getenv("BAD_BLOCK_LEFWKRO2");
    if( bbPtr && *bbPtr )
    {
        sscanf( bbPtr, "%llx", &bbMask );
        LE_TEST_INFO("Bad block string \"%s\", mask %llx", bbPtr, bbMask);
        sys_flash_SetBadBlockErase( "lefwkro2", bbMask );
    }

    do
    {
        // Create file to store the download last status
        if ((-1 == unlink(FILE_PATH)) && (ENOENT != errno))
        {
            LE_TEST_FATAL("unlink failed: %m");
        }
        LE_TEST(LE_OK == le_fs_Open(FILE_PATH, LE_FS_CREAT | LE_FS_RDWR, &fileRef));

        LE_TEST_INFO("======== Start UnitTest of FW Update Dualsys"
                     " [Bad block mask 0x%llx] ========", bbMask);

        sys_flash_SetBadBlockErase( "lefwkro2", bbMask );
        sys_flash_SetBadBlockWrite( "lefwkro2", bbMaskTab[bbMaskIdx][1] );

        if (le_arg_NumArgs() >= 2)
        {
            LE_TEST_INFO ("=========== Download the initial package ==========");
            imagePtr = le_arg_GetArg( 0 );
            if (strcmp(imagePtr, "-"))
            {
                sscanf(le_arg_GetArg( 1 ), "%u", &suspendAtOffset);
                Testpa_fwupdate_Download(imagePtr, suspendAtOffset);
            }
        }

        if (le_arg_NumArgs() >= 4)
        {
            LE_TEST_INFO ("=========== Download the delta package ==========");
            imagePtr = le_arg_GetArg( 2 );
            if (strcmp(imagePtr, "-"))
            {
                sscanf(le_arg_GetArg( 3 ), "%u", &suspendAtOffset);
                Testpa_fwupdate_Download(imagePtr, suspendAtOffset);
            }
        }

        bbMask = bbMaskTab[bbMaskIdx][0];
        bbMaskIdx++;
    }
    while( bbMask != (-1ULL) );

    sys_flash_ResetBadBlock( "lefwkro" );
    sys_flash_ResetBadBlock( "lefwkro2" );

    // Create file to store the download last status
    if ((-1 == unlink(FILE_PATH)) && (ENOENT != errno))
    {
        LE_TEST_FATAL("unlink failed: %m");
    }
    LE_TEST(LE_OK == le_fs_Open(FILE_PATH, LE_FS_CREAT | LE_FS_RDWR, &fileRef));

    LE_TEST_INFO("======== Start UnitTest of FW Update Dualsys"
                 " [Bad block mask 0x%llx] ========", bbMask);

    if (le_arg_NumArgs() >= 2)
    {
        struct stat st;

        LE_TEST_INFO ("=========== Download the initial package ==========");
        imagePtr = le_arg_GetArg( 0 );
        if (strcmp(imagePtr, "-"))
        {
            LE_TEST_ASSERT(0 == stat(imagePtr, &st), "");
            sscanf(le_arg_GetArg( 1 ), "%u", &suspendAtOffset);
            sys_flash_SetSizeInByte( "lefwkro", st.st_size, 2 );
            sys_flash_SetSizeInByte( "lefwkro2", st.st_size, 2 );
            Testpa_fwupdate_Download(imagePtr, suspendAtOffset);
        }
    }

    if (le_arg_NumArgs() >= 4)
    {
        sys_flash_SetBadBlockErase( "lefwkro2", 0ULL );
        sys_flash_SetBadBlockWrite( "lefwkro2", 0x81ULL );

        LE_TEST_INFO ("=========== Download the delta package ==========");
        if (strcmp(imagePtr, "-"))
        {
            imagePtr = le_arg_GetArg( 2 );
            sscanf(le_arg_GetArg( 3 ), "%u", &suspendAtOffset);
            Testpa_fwupdate_Download(imagePtr, suspendAtOffset);
        }
    }

    LE_TEST_INFO("======== Start UnitTest of FW Update Dualsys for SBL"
                 " [Bad blocks 1,3] ========");
    if (le_arg_NumArgs() >= 5)
    {
        sys_flash_SetBadBlockErase( "sbl", 0ULL );
        sys_flash_SetBadBlockWrite( "sbl", 0ULL );
        sys_flash_SetBadBlockMarked( "sbl", 0xAULL /* blocks 1 and 3 */ );

        LE_TEST_INFO ("=========== Download the boot (SBL) package ==========");
        imagePtr = le_arg_GetArg( 4 );
        suspendAtOffset = 0;
        Testpa_fwupdate_Download(imagePtr, suspendAtOffset);
    }

    LE_TEST_INFO("======== FW Update tests end ========");
    LE_TEST_EXIT;
}
