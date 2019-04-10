/**
* Unit test for Firmware update (Single system)
*
* Here, some examples on how to run the test:
*
* "./fwupdateSuspendResumeUnitTest legato.cwe 1500000": Download a legato with suspend/resume
*   at the defined offset
*
* "./fwupdateSuspendResumeUnitTest legato.cwe 1500000 delta.cwe 300000": Download a legato with
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

//--------------------------------------------------------------------------------------------------
/**
 * File hosting the last download status
 */
//--------------------------------------------------------------------------------------------------
#define FILE_PATH      "/fwupdate/dwl_status.nfo"

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
 * This function copies the CWE body image from SWIFOTA to BOOT partition (Single system).
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
    int mtdBoot = -1, mtdLefwkro = -1, mtdModem = -1, mtdSystem = -1, mtdABoot = -1,
        mtdSwifota = -1, mtdDest;
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
        else if( strstr( line, "\"modem\"" ))
        {
            rc = sscanf( line, "mtd%d", &mtdModem );
            LE_TEST_ASSERT(rc == 1, "");
        }
        else if( strstr( line, "\"aboot\"" ))
        {
            rc = sscanf( line, "mtd%d", &mtdABoot );
            LE_TEST_ASSERT(rc == 1, "");
        }
        else if( strstr( line, "\"boot\"" ))
        {
            rc = sscanf( line, "mtd%d", &mtdBoot );
            LE_TEST_ASSERT(rc == 1, "");
        }
        else if( strstr( line, "\"system\"" ))
        {
            rc = sscanf( line, "mtd%d", &mtdSystem );
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
    LE_TEST_ASSERT(mtdSwifota != -1, "");

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

    uint32_t cweType;
    uint32_t cweSize;

    offset = md.phyBlock * eraseSize;
    rc = lseek(fdSwifota, offset, SEEK_SET);
    LE_TEST_ASSERT(rc == offset, "");
    for( ; ; )
    {
        rc = sys_flashReadSkipBadBlock(fdSwifota, buffer, CWE_HEADER_SIZE);
        LE_TEST_ASSERT(rc == CWE_HEADER_SIZE, "");

        cwe_Header_t* cwePtr = (cwe_Header_t*)buffer;
        cweType = (cwePtr->imageType);
        cweSize = be32toh(cwePtr->imageSize);
        uint32_t size = 0;

        LE_TEST_INFO("CWE TYPE %c%c%c%c (%08x)",
                cweType & 0xFF,
                (cweType >>  8) & 0xFF,
                (cweType >> 16) & 0xFF,
                (cweType >> 24) & 0xFF,
                htobe32(cweType));
        if( cweType == 0xFFFFFFFF )
        {
            break;
        }
        if( memcmp(&cweType, "DSP2", 4) == 0 )
        {
            mtdDest = mtdModem;
        }
        else if( memcmp(&cweType, "APBL", 4) == 0 )
        {
            mtdDest = mtdABoot;
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
            if( memcmp(&cweType, "APPL", 4) == 0 ||
                memcmp(&cweType, "MODM", 4) == 0 ||
                memcmp(&cweType, "SPKG", 4) == 0 ||
                memcmp(&cweType, "BOOT", 4) == 0)
            {
                continue;
            }
            else
            {
                while( size < cweSize )
                {
                    int rdsz = (cweSize - size);
                    if( rdsz > eraseSize )
                    {
                        rdsz = eraseSize;
                    }
                    rdsz = sys_flashReadSkipBadBlock(fdSwifota, buffer, rdsz);
                    LE_TEST_ASSERT(rdsz > 0, "");
                    size += rdsz;
                }
                continue;
            }
        }

        snprintf(line, sizeof(line), "/dev/mtd%d", mtdDest);
        fdDest = open(line, O_WRONLY);
        LE_TEST_ASSERT(fdDest != -1, "");

        while( size < cweSize )
        {
            int rdsz = (cweSize - size);
            if( rdsz > eraseSize )
            {
                rdsz = eraseSize;
            }
            rdsz = sys_flashReadSkipBadBlock(fdSwifota, buffer, rdsz);
            LE_TEST_ASSERT(rdsz > 0, "");
            rc = write(fdDest, buffer, rdsz);
            LE_TEST_ASSERT(rc == rdsz, "");
            size += rdsz;
        }

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
    }
    close(fdSwifota);

    LE_TEST_INFO("SWIFOTA applied");
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

    // Apply meta data
    (void)pa_fwupdate_Install(true);
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
        sscanf( bbPtr, "%llx", &bbMask );
        LE_TEST_INFO("Bad block string \"%s\", mask %llx", bbPtr, bbMask);
        sys_flash_SetBadBlockErase( "swifota", bbMask );
    }

    do
    {
        LE_TEST_INFO("======== Start UnitTest of FW Update Singlesys"
                     " [Bad block mask 0x%llx] ========", bbMask);

        sys_flash_ResetBadBlock( "swifota" );
        sys_flash_SetBadBlockErase( "swifota", bbMask );

        // Create file to store the download last status
        if ((-1 == unlink(FILE_PATH)) && (ENOENT != errno))
        {
            LE_TEST_FATAL("unlink failed: %m");
        }
        LE_TEST(LE_OK == le_fs_Open(FILE_PATH, LE_FS_CREAT | LE_FS_RDWR, &fileRef));

        if (le_arg_NumArgs() >= 2)
        {
            LE_TEST_INFO ("=========== Download the initial package ==========");
            imagePtr = le_arg_GetArg( 0 );
            sscanf(le_arg_GetArg( 1 ), "%u", &suspendAtOffset);
            Testpa_fwupdate_Download(imagePtr, suspendAtOffset);
        }

        if (le_arg_NumArgs() >= 4)
        {
            LE_TEST_INFO ("=========== Download the delta package ==========");
            imagePtr = le_arg_GetArg( 2 );
            sscanf(le_arg_GetArg( 3 ), "%u", &suspendAtOffset);
            Testpa_fwupdate_Download(imagePtr, suspendAtOffset);
        }

        bbMask = bbMaskTab[bbMaskIdx];
        bbMaskIdx++;
    }
    while( bbMask != (-1ULL) );

    LE_TEST_INFO("======== FW Update Singlesys tests end ========");
    LE_TEST_EXIT;
}
