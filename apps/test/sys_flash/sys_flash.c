/**
 * @file main.c
 *
 * It emulates a MTD flash layer for unitary tests
 *
 * Copyright (C) Sierra Wireless Inc.
 */

// Undefine all services provided by this module, if compiled with -Dopen=sys_flashOpen.
// This will prevent unexpected recursion and insure that the system call is really called.
#undef fopen
#undef open
#undef write
#undef read
#undef ioctl
#undef opendir
#undef unlink
#undef rename
#undef system
#undef access

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
#define LEGATO_PATH            "/legato"

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
    unsigned long long badBlockErase;
    unsigned long long badBlockWrite;
    unsigned long long badBlockMarked;
    int ubi;
    char *ubiVolNames[3];
    uint32_t origNbPeb;
}
SysFlashMtd[] =
{
#ifdef SYS_FLASH_REAL_FLASH
    { "sbl",         10, 0, 0, 0, -1, {    NULL, }, },
    { "tz",           6, 0, 0, 0, -1, {    NULL, }, },
    { "rpm",          6, 0, 0, 0, -1, {    NULL, }, },
    { "modem",      128, 0, 0, 0,  1, { "modem", NULL, }, },
#ifdef SYS_FLASH_DUALSYS
    { "modem2",     128, 0, 0, 0, -1, { "modem", NULL, }, }, // Dual system
#else
    { "swifota",    300, 0, 0, 0, -1, {    NULL, }, }, // Single system
#endif
    { "aboot",        4, 0, 0, 0, -1, { NULL, }, },
    { "boot",        60, 0, 0, 0, -1, { NULL, }, },
    { "system",     120, 0, 0, 0,  0, { "rootfs", NULL, }, }, // Dual system
#ifdef SYS_FLASH_DUALSYS
    { "lefwkro",    252, 0, 0, 0,  2, { "legato", NULL, }, }, // Dual system
    { "customer0",   10, 0, 0, 0, -1, { NULL, }, },
    { "aboot2",       4, 0, 0, 0, -1, { NULL, }, },
    { "boot2",       60, 0, 0, 0, -1, { NULL, }, },
    { "system2",    120, 0, 0, 0, -1, { "rootfs", NULL, }, }, // Dual system
    { "lefwkro2",   252, 0, 0, 0, -1, { "legato", NULL, }, }, // Dual system
    { "customer1",   10, 0, 0, 0, -1, { NULL, }, },
#else
    { "lefwkro",     35, 0, 0, 0,  2, { "legato", NULL, }, }, // Dual system
#endif
#else
    { "sbl",          8, 0, 0, 0, -1, {    NULL, }, },
    { "tz",           6, 0, 0, 0, -1, {    NULL, }, },
    { "rpm",          8, 0, 0, 0, -1, {    NULL, }, },
    { "modem",       10, 0, 0, 0,  1, { "modem", NULL, }, },
    { "modem2",      10, 0, 0, 0, -1, { "modem", NULL, }, }, // Dual system
    { "swifota",     60, 0, 0, 0, -1, {    NULL, }, }, // Single system
    { "aboot",        4, 0, 0, 0, -1, { NULL, }, },
    { "boot",         8, 0, 0, 0, -1, { NULL, }, },
    { "system",      20, 0, 0, 0,  0, { "rootfs", NULL, }, }, // Dual system
    { "lefwkro",     10, 0, 0, 0,  2, { "legato", NULL, }, }, // Dual system
    { "customer0",   10, 0, 0, 0, -1, { NULL, }, },
    { "aboot2",       4, 0, 0, 0, -1, { NULL, }, },
    { "boot2",        8, 0, 0, 0, -1, { NULL, }, },
    { "system2",     20, 0, 0, 0, -1, { "rootfs", NULL, }, }, // Dual system
    { "lefwkro2",    10, 0, 0, 0, -1, { "legato", NULL, }, }, // Dual system
    { "customer1",   10, 0, 0, 0, -1, { NULL, }, },
#endif
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
        strncmp(LEGATO_PATH, pathname, 7) == 0 ||
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
 * Get the mtd number.
 *
 * @return
 *      - The mtd number or -1 in case of error (errno is set accordingly)
 */
//--------------------------------------------------------------------------------------------------
static int sys_FlashGetMtdNum
(
    int fd
)
{
    char path[PATH_MAX];
    char link[PATH_MAX];
    int mtdNum;

    memset(link, 0, sizeof(link));
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    if(-1 == readlink( path, link, sizeof(link) ))
    {
        // errno from readlink(2)
        return -1;
    }

    if(memcmp(link, SYS_FLASH_PREFIX DEV_MTD_PATH, strlen(SYS_FLASH_PREFIX DEV_MTD_PATH)))
    {
        errno = ENOTTY;
        return -1;
    }

    if( (1 != sscanf(link, SYS_FLASH_PREFIX DEV_MTD_PATH "%d", &mtdNum)) ||
        (mtdNum >= (sizeof(SysFlashMtd)/sizeof(SysFlashMtd[0]))) )
    {
        errno = EBADF;
        return -1;
    }

    return mtdNum;
}

//--------------------------------------------------------------------------------------------------
/**
 * Erase a block. Set 0xFF on the whole PEBs (erasesize) at starting at given offset.
 *
 * @return   (errno)
 *      - 0            On success
 *      - -1  EINVAL   If the start does not belong to a PEB boundary
 */
//--------------------------------------------------------------------------------------------------
static int sys_flashErase
(
    int fd,
    void *arg
)
{
    struct erase_info_user *eraseMePtr = (struct erase_info_user *)arg;
    int mtdNum = sys_FlashGetMtdNum( fd );

    if( -1 == mtdNum )
    {
        return -1;
    }

    if( eraseMePtr->start & (SYS_FLASH_ERASESIZE - 1) )
    {
        errno = EINVAL;
        return -1;
    }

    if( eraseMePtr->start != lseek(fd, eraseMePtr->start, SEEK_SET))
    {
        return -1;
    }

    int nb;
    int peb;
    char erased[SYS_FLASH_ERASESIZE];

    memset(erased, 0xFF, sizeof(erased));
    for(nb = 0; nb < eraseMePtr->length; nb += sizeof(erased))
    {
        peb = (eraseMePtr->start / SYS_FLASH_ERASESIZE);
        if( (peb < 64) && ((1ULL << peb) & SysFlashMtd[mtdNum].badBlockErase) )
        {
            errno = EIO;
            return -1;
        }
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
    int mtdNum = sys_FlashGetMtdNum( fd );
    int peb = offset / SYS_FLASH_ERASESIZE;

    if( -1 == mtdNum )
    {
        return -1;
    }

    if(offset & (SYS_FLASH_ERASESIZE - 1))
    {
        errno = EINVAL;
        return -1;
    }

    int rc = (peb < 64) && (SysFlashMtd[mtdNum].badBlockMarked & (1ULL << peb)) ? 1 : 0;
    if( rc == 1 )
    {
        fprintf(stderr, "MTD %d : Bad block peb %d\n", mtdNum, peb);
    }
    return rc;
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
    int mtdNum;
    int peb = offset / SYS_FLASH_ERASESIZE;

    mtdNum = sys_FlashGetMtdNum( fd );
    if( -1 == mtdNum )
    {
        return -1;
    }

    if(offset & (SYS_FLASH_ERASESIZE - 1))
    {
        errno = EINVAL;
        return -1;
    }

    if( peb < 64 )
    {
        SysFlashMtd[mtdNum].badBlockMarked |= (1ULL << peb);
    }
    else
    {
        fprintf(stderr, "MTD %d : Cannot mark bad block peb %d\n", mtdNum, peb);
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
 * Create and initialize the /proc/mtd entries file
 */
//--------------------------------------------------------------------------------------------------
static void sys_flashInitProcMtd
(
    void
)
{
    FILE* mtdFdPtr;
    int iMtd;

    // Create /proc/mtd file
    LE_ASSERT((NULL != (mtdFdPtr = fopen(SYS_FLASH_PREFIX PROC_MTD_PATH, "w"))));
    LE_ASSERT(0 < fprintf(mtdFdPtr, "dev:    size   erasesize  name\n"));

    for (iMtd = 0; iMtd < sizeof(SysFlashMtd)/sizeof(SysFlashMtd[0]); iMtd++)
    {
        LE_ASSERT(0 < fprintf(mtdFdPtr, "mtd%u: %08x %08x \"%s\"\n",
                              iMtd, SysFlashMtd[iMtd].nbPeb * SYS_FLASH_ERASESIZE,
                              SYS_FLASH_ERASESIZE, SysFlashMtd[iMtd].name));
    }

    LE_ASSERT(0 == fclose(mtdFdPtr));
}

//--------------------------------------------------------------------------------------------------
/**
 * Create and initialize the /dev/mtdN, /sys/class/mtd/mtdN and /sys/class/ubi/ubiN files and trees
 */
//--------------------------------------------------------------------------------------------------
static void sys_flashInitPartition
(
    int mtdNum
)
{
    FILE* flashFdPtr;
    int iPeb, iVol;
    char ubiPath[PATH_MAX];
    char mtdPath[PATH_MAX];
    uint8_t peb[SYS_FLASH_ERASESIZE];

    memset( peb, 0xFF, sizeof(peb) );

    // Create /sys/class/mtd/mtdN
    snprintf(mtdPath, sizeof(mtdPath), SYS_FLASH_PREFIX SYS_CLASS_MTD_PATH "/mtd%d", mtdNum);
    if ((-1 == mkdir(mtdPath, 0777)) && (EEXIST != errno))
    {
        LE_ERROR("mkdir %s failed: %m", mtdPath);
        exit(EXIT_FAILURE);
    }

    // Creates entries erasesize writesize size and name used by pa_flash
    snprintf(mtdPath, sizeof(mtdPath),
             SYS_FLASH_PREFIX SYS_CLASS_MTD_PATH "/mtd%d/erasesize", mtdNum);
    flashFdPtr = fopen(mtdPath, "w");
    LE_ASSERT(NULL != flashFdPtr);
    LE_ASSERT(0 < fprintf(flashFdPtr, "%u\n", SYS_FLASH_ERASESIZE ));
    LE_ASSERT(0 == fclose(flashFdPtr));

    snprintf(mtdPath, sizeof(mtdPath),
             SYS_FLASH_PREFIX SYS_CLASS_MTD_PATH "/mtd%d/size", mtdNum);
    flashFdPtr = fopen(mtdPath, "w");
    LE_ASSERT(NULL != flashFdPtr);
    LE_ASSERT(0 < fprintf(flashFdPtr, "%u\n", SysFlashMtd[mtdNum].nbPeb * SYS_FLASH_ERASESIZE));
    LE_ASSERT(0 == fclose(flashFdPtr));

    snprintf(mtdPath, sizeof(mtdPath),
             SYS_FLASH_PREFIX SYS_CLASS_MTD_PATH "/mtd%d/writesize", mtdNum);
    flashFdPtr = fopen(mtdPath, "w");
    LE_ASSERT(NULL != flashFdPtr);
    LE_ASSERT(0 < fprintf(flashFdPtr, "%u\n", SYS_FLASH_WRITESIZE ));
    LE_ASSERT(0 == fclose(flashFdPtr));

    snprintf(mtdPath, sizeof(mtdPath),
             SYS_FLASH_PREFIX SYS_CLASS_MTD_PATH "/mtd%d/name", mtdNum);
    flashFdPtr = fopen(mtdPath, "w");
    LE_ASSERT(NULL != flashFdPtr);
    LE_ASSERT(0 < fprintf(flashFdPtr, "%s\n", SysFlashMtd[mtdNum].name));
    LE_ASSERT(0 == fclose(flashFdPtr));

    // Create the /dev/mtdN and fill this file with all PEB to 0xFF
    snprintf(mtdPath, sizeof(mtdPath), SYS_FLASH_PREFIX DEV_MTD_PATH "%d", mtdNum);
    flashFdPtr = fopen(mtdPath, "w");
    LE_ASSERT(NULL != flashFdPtr);

    for (iPeb = 0; iPeb < SysFlashMtd[mtdNum].nbPeb; iPeb++)
    {
        LE_ASSERT(1 == fwrite(peb, sizeof(peb), 1, flashFdPtr));
    }
    LE_ASSERT(0 == fclose(flashFdPtr));

    if (SysFlashMtd[mtdNum].ubi != -1)
    {
        // This partition is expected to be an UBI container. Create the /sys/class/ubi/ubiN
        snprintf(ubiPath, sizeof(mtdPath),
                 SYS_FLASH_PREFIX SYS_CLASS_UBI_PATH "/ubi%d", SysFlashMtd[mtdNum].ubi);
        if( (-1 == mkdir(ubiPath, 0777)) && (EEXIST != errno) )
        {
            LE_ERROR("mkdir %s failed: %m", ubiPath);
            exit(EXIT_FAILURE);
        }

        // Create entries mtd_num and volumes_count
        snprintf(ubiPath, sizeof(ubiPath),
                 SYS_FLASH_PREFIX SYS_CLASS_UBI_PATH "/ubi%d/mtd_num", SysFlashMtd[mtdNum].ubi);
        flashFdPtr = fopen(ubiPath, "w");
        LE_ASSERT(NULL != flashFdPtr);
        LE_ASSERT(0 < fprintf(flashFdPtr, "%d\n", mtdNum));
        LE_ASSERT(0 == fclose(flashFdPtr));

        for( iVol = 0; (iVol < 3) && SysFlashMtd[mtdNum].ubiVolNames[iVol]; iVol++ )
        {
            // Volumes expected inside this UBI container. Create the /sys/class/ubi/ubiN_V
            snprintf(ubiPath, sizeof(mtdPath),
                     SYS_FLASH_PREFIX SYS_CLASS_UBI_PATH "/ubi%d_%d",
                     SysFlashMtd[mtdNum].ubi, iVol);
            if( (-1 == mkdir(ubiPath, 0777)) && (EEXIST != errno) )
            {
                LE_ERROR("mkdir %s failed: %m", ubiPath);
                exit(EXIT_FAILURE);
            }

            // Create the entries /sys/class/ubi/ubiN/ubiN_V/name
            snprintf(ubiPath, sizeof(ubiPath),
                     SYS_FLASH_PREFIX SYS_CLASS_UBI_PATH "/ubi%d_%d/name",
                     SysFlashMtd[mtdNum].ubi, iVol);
            flashFdPtr = fopen(ubiPath, "w");
            LE_ASSERT(NULL != flashFdPtr);
            LE_ASSERT(0 < fprintf(flashFdPtr, "%s\n", SysFlashMtd[mtdNum].ubiVolNames[iVol]));
            LE_ASSERT(0 == fclose(flashFdPtr));
        }

        // Update the volume count
        snprintf(ubiPath, sizeof(ubiPath),
                 SYS_FLASH_PREFIX SYS_CLASS_UBI_PATH "/ubi%d/volumes_count",
                 SysFlashMtd[mtdNum].ubi);
        flashFdPtr = fopen(ubiPath, "w");
        LE_ASSERT(NULL != flashFdPtr);
        LE_ASSERT(0 < fprintf(flashFdPtr, "%d\n", iVol));
        LE_ASSERT(0 == fclose(flashFdPtr));
    }
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
 * Check the existence of an entry
 *
 * @return   (errno)
 *      - >= 0         On success
 *      - -1           The access(2) has failed (errno set by write(2))
 */
//--------------------------------------------------------------------------------------------------
int sys_flashAccess
(
    const char *namePtr,
    int mode
)
{
    return access(sys_FlashBuildPathName(namePtr), mode);
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
    int mtdNum = sys_FlashGetMtdNum( fd );
    int peb;

    if( -1 == mtdNum )
    {
        return ENOTTY == errno ? write(fd, buf, count) : -1;
    }

    if( -1 == here )
    {
        return -1;
    }

    if((here & (SYS_FLASH_WRITESIZE - 1)) || (count & (SYS_FLASH_WRITESIZE - 1)))
    {
        errno = EINVAL;
        return -1;
    }

    peb = here / SYS_FLASH_ERASESIZE;
    if( (peb < 64) && ((1ULL << peb) & SysFlashMtd[mtdNum].badBlockWrite) )
    {
        SysFlashMtd[mtdNum].badBlockErase |= (1ULL << peb);
        SysFlashMtd[mtdNum].badBlockWrite &= ~(1ULL << peb);
        errno = EIO;
        return -1;
    }
    return write(fd, buf, count);
}

//--------------------------------------------------------------------------------------------------
/**
 * Read from a partition or from a file. If a read is performed on a bad block, the errno EIO is set
 * and -1 is returned.
 *
 * @return   (errno)
 *      - >= 0         On success
 *      - -1           The read(2) has failed (errno set by read(2))
 */
//--------------------------------------------------------------------------------------------------
int sys_flashRead
(
    int fd,
    void* buf,
    size_t count
)
{
    off_t here = lseek(fd, 0, SEEK_CUR);
    int mtdNum = sys_FlashGetMtdNum( fd );

    if( -1 == mtdNum )
    {
        return ENOTTY == errno ? read(fd, buf, count) : -1;
    }

    if( -1 == here )
    {
        return -1;
    }

    int rdCount = 0;
    int rd = SYS_FLASH_ERASESIZE - (here & (SYS_FLASH_ERASESIZE - 1));
    int rc;
    int nbPeb = (here + count - 1) / SYS_FLASH_ERASESIZE;
    int peb = here / SYS_FLASH_ERASESIZE;

    if( count < rd )
    {
        rd = count;
    }
    nbPeb = nbPeb - peb + 1;
    for( ; (rd > 0) && (nbPeb > 0); )
    {
        if( (peb < 64) && ((1ULL << peb) & SysFlashMtd[mtdNum].badBlockMarked) )
        {
            fprintf(stderr, "MTD %d : Reading from bad block peb %d\n", mtdNum, peb);
            errno = EIO;
            rc = -1;
            break;
        }
        else
        {
            fprintf(stderr, "MTD %d : Read peb %d, offset %lx, rd %d, rdCount %d count %zu\n",
                    mtdNum, peb, here, rd, rdCount, count);
            rc = read(fd, buf + rdCount, rd);
            if( -1 == rc )
            {
                // errno from read(2)
                break;
            }
            rdCount += rc;
            rc = rdCount;
            rd = count - rdCount > SYS_FLASH_ERASESIZE ? SYS_FLASH_ERASESIZE : count - rdCount;
            nbPeb--;
            peb++;
        }
    }

    return rc;
}

//--------------------------------------------------------------------------------------------------
/**
 * Read from a partition and skip the bad block. If a read is performed on a bad block, the next
 * good block is used.
 *
 * @return   (errno)
 *      - >= 0         On success
 *      - -1           The read(2) has failed (errno set by read(2))
 */
//--------------------------------------------------------------------------------------------------
int sys_flashReadSkipBadBlock
(
    int fd,
    void* buf,
    size_t count
)
{
    off_t here = lseek(fd, 0, SEEK_CUR);
    int mtdNum = sys_FlashGetMtdNum( fd );

    if( -1 == mtdNum )
    {
        return ENOTTY == errno ? read(fd, buf, count) : -1;
    }

    if( -1 == here )
    {
        return -1;
    }

    int rdCount = 0;
    int rd = SYS_FLASH_ERASESIZE - (here & (SYS_FLASH_ERASESIZE - 1));
    int rc;
    int nbPeb = (here + count - 1) / SYS_FLASH_ERASESIZE;
    int peb = here / SYS_FLASH_ERASESIZE;

    if( count < rd )
    {
        rd = count;
    }
    nbPeb = nbPeb - peb + 1;
    for( ; (rd > 0) && (nbPeb > 0); )
    {
        if( (peb < 64) && ((1ULL << peb) & SysFlashMtd[mtdNum].badBlockMarked) )
        {
            fprintf(stderr, "MTD %d : Skipping bad block peb %d\n", mtdNum, peb);
            here = lseek(fd, SYS_FLASH_ERASESIZE, SEEK_CUR);
            if( -1 == here )
            {
                return -1;
            }
            peb++;
            fprintf(stderr, "MTD %d : Next block peb %d, set to offset %lx\n", mtdNum, peb, here);
            errno = EIO;
            rc = -1;
        }
        else
        {
            here = lseek(fd, 0, SEEK_CUR);
            fprintf(stderr, "MTD %d : Read peb %d, here %lx, rd %d, rdCount %d count %zu\n",
                    mtdNum, peb, here, rd, rdCount, count);
            rc = read(fd, buf + rdCount, rd);
            if( -1 == rc )
            {
                return rc;
            }
            rdCount += rc;
            rc = rdCount;
            rd = count - rdCount > SYS_FLASH_ERASESIZE ? SYS_FLASH_ERASESIZE : count - rdCount;
            nbPeb--;
            peb++;
        }
    }

    return rc;
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
    va_end(ap);

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
    else if (0 == strncmp(command, "bspatch", 6))
    {
        return system(command);
    }
    else if (0 == strncmp(command, "/legato/systems/current/bin/cus_sec.sh", 38))
    {
        LE_INFO("Result: %s", command);
        return 0;
    }
    return 0x6400;
}

//--------------------------------------------------------------------------------------------------
/**
 * Initialize the simulated flash layer
 */
//--------------------------------------------------------------------------------------------------
#ifdef SYS_FLASH_INIT
void sys_flashInit
(
    void
)
#else
COMPONENT_INIT
#endif
{
    int iMtd;

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

    // Create directories for /legato entries
    rc = system("mkdir -p " SYS_FLASH_PREFIX LEGATO_PATH);
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

    sys_flashInitProcMtd();

    for (iMtd = 0; iMtd < sizeof(SysFlashMtd)/sizeof(SysFlashMtd[0]); iMtd++)
    {
        SysFlashMtd[iMtd].origNbPeb = SysFlashMtd[iMtd].nbPeb;

        sys_flashInitPartition(iMtd);
    }
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

//--------------------------------------------------------------------------------------------------
/**
 * Reset the bad block for a partition
 *
 * @return None
 */
//--------------------------------------------------------------------------------------------------
void sys_flash_ResetBadBlock
(
    char *partNamePtr
)
{
    int iMtd;

    for (iMtd = 0; iMtd < sizeof(SysFlashMtd)/sizeof(SysFlashMtd[0]); iMtd++)
    {
        if( 0 == strcmp(SysFlashMtd[iMtd].name, partNamePtr) )
        {
            LE_INFO("Reset bad blocks for partition \"%s\"", SysFlashMtd[iMtd].name);
            SysFlashMtd[iMtd].badBlockErase = 0;
            SysFlashMtd[iMtd].badBlockWrite = 0;
            SysFlashMtd[iMtd].badBlockMarked = 0;
        }
    }
}

//--------------------------------------------------------------------------------------------------
/**
 * Mark the current bad blocks for a partition
 *
 * @return None
 */
//--------------------------------------------------------------------------------------------------
void sys_flash_SetBadBlockMarked
(
    char *partNamePtr,
    unsigned long long badBlockMask
)
{
    int iMtd;

    for (iMtd = 0; iMtd < sizeof(SysFlashMtd)/sizeof(SysFlashMtd[0]); iMtd++)
    {
        if( 0 == strcmp(SysFlashMtd[iMtd].name, partNamePtr) )
        {
            LE_INFO("Set bad blocks mask %llx for partition \"%s\"",
                    badBlockMask, SysFlashMtd[iMtd].name);
            SysFlashMtd[iMtd].badBlockMarked = badBlockMask;
        }
    }
}

//--------------------------------------------------------------------------------------------------
/**
 * Mark the blocks to become bad while writing (EIO) for a partition
 *
 * @return None
 */
//--------------------------------------------------------------------------------------------------
void sys_flash_SetBadBlockWrite
(
    char *partNamePtr,
    unsigned long long badBlockMask
)
{
    int iMtd;

    for (iMtd = 0; iMtd < sizeof(SysFlashMtd)/sizeof(SysFlashMtd[0]); iMtd++)
    {
        if( 0 == strcmp(SysFlashMtd[iMtd].name, partNamePtr) )
        {
            LE_INFO("Set bad blocks while writing mask %llx for partition \"%s\"",
                    badBlockMask, SysFlashMtd[iMtd].name);
            SysFlashMtd[iMtd].badBlockWrite = badBlockMask;
        }
    }
}

//--------------------------------------------------------------------------------------------------
/**
 * Mark the blocks to become bad while erasing (EIO) for a partition
 *
 * @return None
 */
//--------------------------------------------------------------------------------------------------
void sys_flash_SetBadBlockErase
(
    char *partNamePtr,
    unsigned long long badBlockMask
)
{
    int iMtd;

    for (iMtd = 0; iMtd < sizeof(SysFlashMtd)/sizeof(SysFlashMtd[0]); iMtd++)
    {
        if( 0 == strcmp(SysFlashMtd[iMtd].name, partNamePtr) )
        {
            LE_INFO("Set bad blocks while erasing mask %llx for partition \"%s\"",
                    badBlockMask, SysFlashMtd[iMtd].name);
            SysFlashMtd[iMtd].badBlockErase = badBlockMask;
        }
    }
}

//--------------------------------------------------------------------------------------------------
/**
 * Swap the bad blocks (Marked, Write and Erase) between two partitions
 *
 * @return None
 */
//--------------------------------------------------------------------------------------------------
void sys_flash_SwapBadBlock
(
    char *srcPartNamePtr,
    char *dstPartNamePtr
)
{
    int iMtd, sMtd = -1, dMtd = -1;

    for (iMtd = 0; iMtd < sizeof(SysFlashMtd)/sizeof(SysFlashMtd[0]); iMtd++)
    {
        if( 0 == strcmp(SysFlashMtd[iMtd].name, srcPartNamePtr) )
        {
            sMtd = iMtd;
        }
        if( 0 == strcmp(SysFlashMtd[iMtd].name, dstPartNamePtr) )
        {
            dMtd = iMtd;
        }
    }

    if( -1 == dMtd || -1 == sMtd )
    {
        fprintf(stderr, "Unable to find partition \"%s\" (%d) or \"%s\" (%d)\n",
                srcPartNamePtr, sMtd, dstPartNamePtr, dMtd);
    }
    else
    {
        unsigned long long tmp;

        tmp = SysFlashMtd[sMtd].badBlockMarked;
        SysFlashMtd[sMtd].badBlockMarked = SysFlashMtd[dMtd].badBlockMarked;
        SysFlashMtd[dMtd].badBlockMarked = tmp;
        tmp = SysFlashMtd[sMtd].badBlockWrite;
        SysFlashMtd[sMtd].badBlockWrite = SysFlashMtd[dMtd].badBlockWrite;
        SysFlashMtd[dMtd].badBlockWrite = tmp;
        tmp = SysFlashMtd[sMtd].badBlockErase;
        SysFlashMtd[sMtd].badBlockErase = SysFlashMtd[dMtd].badBlockErase;
        SysFlashMtd[dMtd].badBlockErase = tmp;
    }
}

//--------------------------------------------------------------------------------------------------
/**
 * Set the partition size in bytes and will be aligned up to a multiple of PEB. An optional number
 * number of PEB can be added to the given size
 *
 * @return None
 */
//--------------------------------------------------------------------------------------------------
void sys_flash_SetSizeInByte
(
    char *partNamePtr,
    uint32_t size,
    uint32_t addedPeb
)
{
    int iMtd;
    uint32_t peb = addedPeb + (size + (SYS_FLASH_ERASESIZE - 1)) / SYS_FLASH_ERASESIZE;

    for (iMtd = 0; iMtd < sizeof(SysFlashMtd)/sizeof(SysFlashMtd[0]); iMtd++)
    {
        if( 0 == strcmp(SysFlashMtd[iMtd].name, partNamePtr) )
        {
            LE_INFO("Set size to %u (%u PEB) for partition \"%s\"",
                    size, peb, SysFlashMtd[iMtd].name);
            SysFlashMtd[iMtd].nbPeb = peb;
            sys_flashInitProcMtd();
            sys_flashInitPartition(iMtd);
            break;
        }
    }
}

//--------------------------------------------------------------------------------------------------
/**
 * Set the partition size in PEB
 *
 * @return None
 */
//--------------------------------------------------------------------------------------------------
void sys_flash_SetSizeInPeb
(
    char *partNamePtr,
    uint32_t nbPeb
)
{
    int iMtd;

    for (iMtd = 0; iMtd < sizeof(SysFlashMtd)/sizeof(SysFlashMtd[0]); iMtd++)
    {
        if( 0 == strcmp(SysFlashMtd[iMtd].name, partNamePtr) )
        {
            LE_INFO("Set size to %u (%u PEB) for partition \"%s\"",
                    nbPeb * SYS_FLASH_ERASESIZE, nbPeb, SysFlashMtd[iMtd].name);
            SysFlashMtd[iMtd].nbPeb = nbPeb;
            sys_flashInitProcMtd();
            sys_flashInitPartition(iMtd);
            break;
        }
    }
}

//--------------------------------------------------------------------------------------------------
/**
 * Reset the partition size and PEB to its original size
 *
 * @return None
 */
//--------------------------------------------------------------------------------------------------
void sys_flash_ResetSize
(
    char *partNamePtr
)
{
    int iMtd;

    for (iMtd = 0; iMtd < sizeof(SysFlashMtd)/sizeof(SysFlashMtd[0]); iMtd++)
    {
        if( 0 == strcmp(SysFlashMtd[iMtd].name, partNamePtr) )
        {
            LE_INFO("Reset size to %u (%u PEB) for partition \"%s\"",
                    SysFlashMtd[iMtd].origNbPeb * SYS_FLASH_ERASESIZE, SysFlashMtd[iMtd].origNbPeb,
                    SysFlashMtd[iMtd].name);
            SysFlashMtd[iMtd].nbPeb = SysFlashMtd[iMtd].origNbPeb;
            sys_flashInitProcMtd();
            sys_flashInitPartition(iMtd);
            break;
        }
    }
}
