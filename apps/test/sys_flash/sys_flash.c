/**
 * @file main.c
 *
 * It emulates a MTD flash layer for unitary tests
 *
 * Copyright (C) Sierra Wireless Inc.
 */

#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/ioctl.h>
#include <mtd/mtd-user.h>
#include <sys/types.h>
#include <memory.h>
#include <fcntl.h>
#include <dirent.h>
#include "legato.h"

//--------------------------------------------------------------------------------------------------
/**
 * Absolute names for devices, proc and sys entries related to flash MTD and UBI.
 */
//--------------------------------------------------------------------------------------------------
#define SYS_CLASS_UBI_PATH     "/sys/class/ubi"
#define SYS_CLASS_MTD_PATH     "/sys/class/mtd"
#define PROC_MTD_PATH          "/proc/mtd"
#define DEV_MTD_PATH           "/dev/mtd"
#define SYS_FLASH_PREFIX       "/tmp/sys_flash"

//--------------------------------------------------------------------------------------------------
/**
 * Flash geometry: PEB erase size and write/page size
 */
//--------------------------------------------------------------------------------------------------
#ifndef SYS_FLASH_ERASESIZE
#define SYS_FLASH_ERASESIZE    32768
#endif
#ifndef SYS_FLASH_WRITESIZE
#define SYS_FLASH_WRITESIZE     1024
#endif

//--------------------------------------------------------------------------------------------------
/**
 * Absolute names for le_fs directory
 */
//--------------------------------------------------------------------------------------------------
#define LE_FS_FWUPDATE_PATH    "/tmp/data/le_fs/fwupdate"

//==================================================================================================
//                                       Static variables
//==================================================================================================

//--------------------------------------------------------------------------------------------------
/**
 * Partition table: for both DUAL and SINGLE system
 */
//--------------------------------------------------------------------------------------------------
static struct
{
    char *name;
    uint32_t nbPeb;
    int ubi;
    char *ubiVolNames[3];
}
SysFlashMtd[] =
{
    { "sbl",          8, -1, {    NULL, }, },
    { "tz",           6, -1, {    NULL, }, },
    { "rpm",          8, -1, {    NULL, }, },
    { "modem",       10,  1, { "modem", NULL, }, },
    { "modem2",      10, -1, { "modem", NULL, }, }, // Dual system
    { "swifota",     60, -1, {    NULL, }, }, // Single system
    { "aboot",        4, -1, { NULL, }, },
    { "boot",         8, -1, { NULL, }, },
    { "system",      20,  0, { "rootfs", NULL, }, }, // Dual system
    { "lefwkro",     10,  2, { "legato", NULL, }, }, // Dual system
    { "customer0",   10, -1, { NULL, }, },
    { "aboot2",       4, -1, { NULL, }, },
    { "boot2",        8, -1, { NULL, }, },
    { "system2",     20, -1, { "rootfs", NULL, }, }, // Dual system
    { "lefwkro2",    10, -1, { "legato", NULL, }, }, // Dual system
    { "customer1",   10, -1, { NULL, }, },
};

//--------------------------------------------------------------------------------------------------
/**
 * ECC state: Set to true ifunrecoverable errors. This may changed by sys_flash_SetEccState().
 */
//--------------------------------------------------------------------------------------------------
static bool IsEccStateFailed = false;

//--------------------------------------------------------------------------------------------------
/**
 * Build the "real" absolute pathname according to the given one. If the given path refers to entry
 * related to flash MTD or UBI, add the SYS_FLASH_PREFIX behind. Else, do nothing
 * THIS SERVICE IS NOT REENTRANT AND MUST NOT BE CALLED WHILE MULTITHREADED
 *
 * @return
 *      - The new path
 */
//--------------------------------------------------------------------------------------------------
static char *sys_FlashBuildPathName
(
    const char *pathname
)
{
    static char SysFlashPathname[PATH_MAX];

    if( strncmp(SYS_CLASS_UBI_PATH, pathname, 14) == 0 ||
        strncmp(SYS_CLASS_MTD_PATH, pathname, 14) == 0 ||
        strcmp(PROC_MTD_PATH, pathname) == 0 ||
        strncmp(DEV_MTD_PATH, pathname, 8) == 0 )
    {
        snprintf(SysFlashPathname, sizeof(SysFlashPathname), SYS_FLASH_PREFIX "%s", pathname);
    }
    else
    {
        snprintf(SysFlashPathname, sizeof(SysFlashPathname), "%s", pathname);
    }
    return SysFlashPathname;
}

//--------------------------------------------------------------------------------------------------
/**
 * Erase a block. Set 0xFF on the whole PEBs (erasesize) at starting at given offset.
 *
 * @return   (errno)
 *      - 0            On success
 *      - -1  EINVAL   If the start does not belong to a PEB boundary
 *      - -1           The write(2) has failed (errno set by write(2))
 */
//--------------------------------------------------------------------------------------------------
static int sys_flashErase
(
    int fd,
    void *arg
)
{
    struct erase_info_user *eraseMePtr = (struct erase_info_user *)arg;

    if(eraseMePtr->start & (SYS_FLASH_ERASESIZE - 1))
    {
        errno = EINVAL;
        return -1;
    }

    if( eraseMePtr->start != lseek(fd, eraseMePtr->start, SEEK_SET))
    {
        return -1;
    }
    int nb;
    char erased[SYS_FLASH_ERASESIZE];
    memset(erased, 0xFF, sizeof(erased));
    for(nb = 0; nb < eraseMePtr->length; nb += sizeof(erased))
    {
        if(sizeof(erased) != write(fd, erased, sizeof(erased)))
        {
            errno = EIO;
            return -1;
        }
    }
    return 0;
}

//--------------------------------------------------------------------------------------------------
/**
 * Check if the PEB at given offset is a bad block.
 *
 * @return   (errno)
 *      - 0            On success and the PEB is good
 *      - 1            On success and the PEB is bad
 *      - -1  EINVAL   If the offset does not belong to a PEB boundary
 */
//--------------------------------------------------------------------------------------------------
static int sys_flashGetBadBlock
(
    int fd,
    void *arg
)
{
    loff_t offset = *(loff_t*)arg;

    if(offset & (SYS_FLASH_ERASESIZE - 1))
    {
        errno = EINVAL;
        return -1;
    }

    return 0;
}

//--------------------------------------------------------------------------------------------------
/**
 * Mark the PEB at given offset as bad.
 *
 * @return   (errno)
 *      - 0            On success
 *      - -1  EINVAL   If the offset does not belong to a PEB boundary
 */
//--------------------------------------------------------------------------------------------------
static int sys_flashSetBadBlock
(
    int fd,
    void *arg
)
{
    loff_t offset = *(loff_t*)arg;

    if(offset & (SYS_FLASH_ERASESIZE - 1))
    {
        errno = EINVAL;
        return -1;
    }

    return 0;
}

//--------------------------------------------------------------------------------------------------
/**
 * Get the ECC statistics for a MTD partition
 *
 * @return   (errno)
 *      - 0            On success
 */
//--------------------------------------------------------------------------------------------------
static int sys_flashEccGetStats
(
    int fd,
    void *arg
)
{
    struct mtd_ecc_stats *eccStatsPtr = (struct mtd_ecc_stats *)arg;

    memset(eccStatsPtr, 0, sizeof(struct mtd_ecc_stats));

    eccStatsPtr->corrected = 1;

    if (true == IsEccStateFailed)
    {
        eccStatsPtr->failed = 1;
    }
    else
    {
        eccStatsPtr->failed = 0;
    }

    eccStatsPtr->badblocks = 0;

    return 0;
}

//--------------------------------------------------------------------------------------------------
/**
 * Open a partition or a file for stdio(3) services.
 *
 * @return   (errno)
 *      - 0            On success
 *      - -1           The fopen(3) has failed (errno set by fopen(3))
 */
//--------------------------------------------------------------------------------------------------
FILE* sys_flashFOpen
(
    const char *pathname,
    const char *mode
)
{
    return fopen(sys_FlashBuildPathName(pathname), mode);
}

//--------------------------------------------------------------------------------------------------
/**
 * Open a partition or a file.
 *
 * @return   (errno)
 *      - 0            On success
 *      - -1           The open(2) has failed (errno set by open(2))
 */
//--------------------------------------------------------------------------------------------------
int sys_flashOpen
(
    const char *pathname,
    int flags,
    ...
)
{
    int mode;
    va_list ap;

    va_start (ap, flags);
    mode = va_arg (ap, int);
    va_end(ap);

    return open(sys_FlashBuildPathName(pathname), flags, mode);
}

//--------------------------------------------------------------------------------------------------
/**
 * Write to a partition or to a file.
 *
 * @return   (errno)
 *      - >= 0         On success
 *      - -1           The write(2) has failed (errno set by write(2))
 */
//--------------------------------------------------------------------------------------------------
int sys_flashWrite
(
    int fd,
    const void* buf,
    size_t count
)
{
    off_t here = lseek(fd, 0, SEEK_CUR);
    char path[PATH_MAX];
    char link[PATH_MAX];

    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    if(-1 == readlink( path, link, sizeof(link) ))
    {
        return -1;
    }
    if(memcmp(link, SYS_FLASH_PREFIX DEV_MTD_PATH, strlen(SYS_FLASH_PREFIX DEV_MTD_PATH)))
    {
        return write(fd, buf, count);
    }

    if((here & (SYS_FLASH_WRITESIZE - 1)) || (count & (SYS_FLASH_WRITESIZE - 1)))
    {
        errno = EINVAL;
        return -1;
    }
    return write(fd, buf, count);
}

//--------------------------------------------------------------------------------------------------
/**
 * Perform an ioctl.
 *
 * @return   (errno)
 *      - >= 0         On success
 *      - -1           The ioctl(2) has failed (errno set by ioctl(2))
 */
//--------------------------------------------------------------------------------------------------
int sys_flashIoctl
(
    int fd,
    unsigned long request,
    ...
)
{
    void *arg;
    va_list ap;

    va_start (ap, request);
    arg = va_arg (ap, void *);

    switch(request)
    {
        case MEMERASE:
            return sys_flashErase(fd, arg);
            break;
        case MEMGETBADBLOCK:
            return sys_flashGetBadBlock(fd, arg);
            break;
        case MEMSETBADBLOCK:
            return sys_flashSetBadBlock(fd, arg);
            break;
        case ECCGETSTATS:
            return sys_flashEccGetStats(fd, arg);
            break;
    }

    return ioctl(fd, request, ap);
}

//--------------------------------------------------------------------------------------------------
/**
 * Open a directory
 */
//--------------------------------------------------------------------------------------------------
DIR *sys_flashOpendir
(
    const char *name
)
{
    return opendir(sys_FlashBuildPathName(name));
}

//--------------------------------------------------------------------------------------------------
/**
 * Delete an entry from a directory
 */
//--------------------------------------------------------------------------------------------------
int sys_flashUnlink
(
    const char *name
)
{
    return unlink(sys_FlashBuildPathName(name));
}

//--------------------------------------------------------------------------------------------------
/**
 * Rename an entry
 */
//--------------------------------------------------------------------------------------------------
int sys_flashRename
(
    const char *oldname,
    const char *newname
)
{
    char oldpath[PATH_MAX];
    snprintf(oldpath, sizeof(oldpath), "%s", sys_FlashBuildPathName(oldname));
    return rename(oldpath, sys_FlashBuildPathName(newname));
}

//--------------------------------------------------------------------------------------------------
/**
 * Perform a shell command execution with system(3)
 */
//--------------------------------------------------------------------------------------------------
int sys_flashSystem
(
    const char *command
)
{
    if (0 == strncmp(command, "/sbin/reboot", 12))
    {
        errno = EPERM;
        return -1;
    }
    else if (0 == strncmp(command, "/home/root/bspatch", 18))
    {
        return system(command);
    }
    return 0x6400;
}

//--------------------------------------------------------------------------------------------------
/**
 * Main of the test.
 */
//--------------------------------------------------------------------------------------------------
COMPONENT_INIT
{
    FILE* flashFdPtr;
    FILE* mtdFdPtr;
    int iMtd, iPeb, iVol;
    char ubiPath[PATH_MAX];
    char mtdPath[PATH_MAX];
    uint8_t peb[SYS_FLASH_ERASESIZE];

    memset( peb, 0xFF, sizeof(peb) );

    int rc = system("rm -rf " SYS_FLASH_PREFIX);
    if( WEXITSTATUS(rc) )
    {
        LE_ERROR("system() failed: %d", rc);
        exit(EXIT_FAILURE);
    }

    // Create directories for /sys/class/mtd entries
    rc = system("mkdir -p " SYS_FLASH_PREFIX SYS_CLASS_MTD_PATH);
    if( WEXITSTATUS(rc) )
    {
        LE_ERROR("system() failed: %d", rc);
        exit(EXIT_FAILURE);
    }

    // Create directories for /sys/class/ubi entries
    rc = system("mkdir -p " SYS_FLASH_PREFIX SYS_CLASS_UBI_PATH);
    if( WEXITSTATUS(rc) )
    {
        LE_ERROR("system() failed: %d", rc);
        exit(EXIT_FAILURE);
    }

    // Create directories for /dev and /proc entries
    rc = system("mkdir -p " SYS_FLASH_PREFIX "/dev " SYS_FLASH_PREFIX "/proc");
    if( WEXITSTATUS(rc) )
    {
        LE_ERROR("system() failed: %d", rc);
        exit(EXIT_FAILURE);
    }

    // Create /proc/mtd file
    LE_ASSERT((NULL != (mtdFdPtr = fopen(SYS_FLASH_PREFIX PROC_MTD_PATH, "w"))));
    LE_ASSERT(0 < fprintf(mtdFdPtr, "dev:    size   erasesize  name\n"));

    for (iMtd = 0; iMtd < sizeof(SysFlashMtd)/sizeof(SysFlashMtd[0]); iMtd++)
    {
        LE_ASSERT(0 < fprintf(mtdFdPtr, "mtd%u: %08x %08x \"%s\"\n",
                              iMtd, SysFlashMtd[iMtd].nbPeb * SYS_FLASH_ERASESIZE,
                              SYS_FLASH_ERASESIZE, SysFlashMtd[iMtd].name));

        // Create /sys/class/mtd/mtdN
        snprintf(mtdPath, sizeof(mtdPath), SYS_FLASH_PREFIX SYS_CLASS_MTD_PATH "/mtd%d", iMtd);
        if (-1 == mkdir(mtdPath, 0777))
        {
            LE_ERROR("mkdir %s failed: %m", mtdPath);
            exit(EXIT_FAILURE);
        }

        // Creates entries erasesize writesize size and name used by pa_flash
        snprintf(mtdPath, sizeof(mtdPath),
                 SYS_FLASH_PREFIX SYS_CLASS_MTD_PATH "/mtd%d/erasesize", iMtd);
        LE_ASSERT((NULL != (flashFdPtr = fopen(mtdPath, "w"))));
        LE_ASSERT(0 < fprintf(flashFdPtr, "%u\n", SYS_FLASH_ERASESIZE ));
        LE_ASSERT(0 == fclose(flashFdPtr));

        snprintf(mtdPath, sizeof(mtdPath),
                 SYS_FLASH_PREFIX SYS_CLASS_MTD_PATH "/mtd%d/size", iMtd);
        LE_ASSERT((NULL != (flashFdPtr = fopen(mtdPath, "w"))));
        LE_ASSERT(0 < fprintf(flashFdPtr, "%u\n", SysFlashMtd[iMtd].nbPeb * SYS_FLASH_ERASESIZE));
        LE_ASSERT(0 == fclose(flashFdPtr));

        snprintf(mtdPath, sizeof(mtdPath),
                 SYS_FLASH_PREFIX SYS_CLASS_MTD_PATH "/mtd%d/writesize", iMtd);
        LE_ASSERT((NULL != (flashFdPtr = fopen(mtdPath, "w"))));
        LE_ASSERT(0 < fprintf(flashFdPtr, "%u\n", SYS_FLASH_WRITESIZE ));
        LE_ASSERT(0 == fclose(flashFdPtr));

        snprintf(mtdPath, sizeof(mtdPath),
                 SYS_FLASH_PREFIX SYS_CLASS_MTD_PATH "/mtd%d/name", iMtd);
        LE_ASSERT((NULL != (flashFdPtr = fopen(mtdPath, "w"))));
        LE_ASSERT(0 < fprintf(flashFdPtr, "%s\n", SysFlashMtd[iMtd].name));
        LE_ASSERT(0 == fclose(flashFdPtr));

        // Create the /dev/mtdN and fill this file with all PEB to 0xFF
        snprintf(mtdPath, sizeof(mtdPath), SYS_FLASH_PREFIX DEV_MTD_PATH "%d", iMtd);
        LE_ASSERT((NULL != (flashFdPtr = fopen(mtdPath, "w"))));

        for (iPeb = 0; iPeb < SysFlashMtd[iMtd].nbPeb; iPeb++)
        {
            LE_ASSERT(1 == fwrite(peb, sizeof(peb), 1, flashFdPtr));
        }
        LE_ASSERT(0 == fclose(flashFdPtr));

        if (SysFlashMtd[iMtd].ubi != -1)
        {
            // This partition is expected to be an UBI container. Create the /sys/class/ubi/ubiN
            snprintf(ubiPath, sizeof(mtdPath),
                     SYS_FLASH_PREFIX SYS_CLASS_UBI_PATH "/ubi%d", SysFlashMtd[iMtd].ubi);
            if( -1 == mkdir(ubiPath, 0777) )
            {
                LE_ERROR("mkdir %s failed: %m", ubiPath);
                exit(EXIT_FAILURE);
            }

            // Create entries mtd_num and volumes_count
            snprintf(ubiPath, sizeof(ubiPath),
                     SYS_FLASH_PREFIX SYS_CLASS_UBI_PATH "/ubi%d/mtd_num", SysFlashMtd[iMtd].ubi);
            LE_ASSERT((NULL != (flashFdPtr = fopen(ubiPath, "w"))));
            LE_ASSERT(0 < fprintf(flashFdPtr, "%d\n", iMtd));
            LE_ASSERT(0 == fclose(flashFdPtr));

            for( iVol = 0; (iVol < 3) && SysFlashMtd[iMtd].ubiVolNames[iVol]; iVol++ )
            {
                // Volumes expected inside this UBI container. Create the /sys/class/ubi/ubiN_V
                snprintf(ubiPath, sizeof(mtdPath),
                         SYS_FLASH_PREFIX SYS_CLASS_UBI_PATH "/ubi%d_%d",
                         SysFlashMtd[iMtd].ubi, iVol);
                if( -1 == mkdir(ubiPath, 0777) )
                {
                    LE_ERROR("mkdir %s failed: %m", ubiPath);
                    exit(EXIT_FAILURE);
                }

                // Create the entries /sys/class/ubi/ubiN/ubiN_V/name
                snprintf(ubiPath, sizeof(ubiPath),
                         SYS_FLASH_PREFIX SYS_CLASS_UBI_PATH "/ubi%d_%d/name",
                         SysFlashMtd[iMtd].ubi, iVol);
                LE_ASSERT((NULL != (flashFdPtr = fopen(ubiPath, "w"))));
                LE_ASSERT(0 < fprintf(flashFdPtr, "%s\n", SysFlashMtd[iMtd].ubiVolNames[iVol]));
                LE_ASSERT(0 == fclose(flashFdPtr));
            }

            // Update the volume count
            snprintf(ubiPath, sizeof(ubiPath),
                     SYS_FLASH_PREFIX SYS_CLASS_UBI_PATH "/ubi%d/volumes_count",
                     SysFlashMtd[iMtd].ubi);
            LE_ASSERT((NULL != (flashFdPtr = fopen(ubiPath, "w"))));
            LE_ASSERT(0 < fprintf(flashFdPtr, "%d\n", iVol));
            LE_ASSERT(0 == fclose(flashFdPtr));
        }
    }
    LE_ASSERT(0 == fclose(mtdFdPtr));
    LE_INFO("MTD and UBI hierarchy is created successfully.");

    // Remove all /data/le_fs/fwupdate hierachy to prevent disturbance from any tests previously
    // launched
    rc = system("\\rm -rf " LE_FS_FWUPDATE_PATH "; \\mkdir -p " LE_FS_FWUPDATE_PATH);
    if( WEXITSTATUS(rc) )
    {
        LE_ERROR("system() failed: %d", rc);
        exit(EXIT_FAILURE);
    }
    LE_INFO(LE_FS_FWUPDATE_PATH " tree cleaned up");
}

//--------------------------------------------------------------------------------------------------
/**
 * Set the ECC failed state for pa_flash_GetEccStats API
 *
 * @return None
 */
//--------------------------------------------------------------------------------------------------
void sys_flash_SetEccState
(
    bool eccState
)
{
    IsEccStateFailed = eccState;
}
