/**
 * @file main.c
 *
 * It will create ubi files required for fwupdate dualsys unit test cases.
 *
 * Copyright (C) Sierra Wireless Inc.
 */

#include "legato.h"

//--------------------------------------------------------------------------------------------------
/**
 * Macro definations for fwupdate file name.
 */
//--------------------------------------------------------------------------------------------------
#define SYS_CLASS_UBI_PATH     "/tmp"
#define MTD_PATH               "/tmp/mtd"
#define RESUME_CTX_FILENAME0   "/tmp/data/le_fs/fwupdate_ResumeCtx_0"
#define RESUME_CTX_FILENAME1   "/tmp/data/le_fs/fwupdate_ResumeCtx_1"


//--------------------------------------------------------------------------------------------------
/**
 * Delta patch Meta header (one for each image. May be split into several slices)
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
deltaUpdate_PatchMetaHdr_t;

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
deltaUpdate_PatchHdr_t;

//--------------------------------------------------------------------------------------------------
/**
 * Resume context to save structure definition
 */
//--------------------------------------------------------------------------------------------------
typedef struct
{
    uint32_t ctxCounter;            ///< Context counter, incremented each time the context is
                                    ///< updated
    uint32_t imageType;             ///< Image type
    uint32_t imageSize;             ///< Image size
    uint32_t imageCrc;              ///< Image CRC
    uint32_t currentImageCrc;       ///< current image CRC
    uint32_t globalCrc;             ///< CRC of all the package (crc in first cwe header)
    uint32_t currentGlobalCrc;      ///< current global CRC
    size_t   totalRead;             ///< total read from the beginning to the end of the latest cwe
                                    ///< header read
    uint32_t currentOffset;         ///< offset in the current partition (must be a block erase
                                    ///< limit)
    ssize_t  fullImageLength;       ///< total size of the package (read from the first CWE header)
    uint8_t  miscOpts;              ///< Misc Options field from CWE header
    bool     isFirstNvupDownloaded; ///< Boolean to know if a NVUP file(s) has been downloaded
    bool     isModemDownloaded;     ///< Boolean to know if a modem partition has been downloaded
    bool     isImageToBeRead;       ///< Boolean to know if data concerns header or component image
    deltaUpdate_PatchMetaHdr_t patchMetaHdr;    ///< Patch Meta Header
    deltaUpdate_PatchHdr_t     patchHdr;        ///< Patch Header
    uint32_t ctxCrc;                ///< context CRC, Computed on all previous fields of this struct
}
ResumeCtxSave_t;

//--------------------------------------------------------------------------------------------------
/**
 * Set resume context save.
 */
//--------------------------------------------------------------------------------------------------
static ResumeCtxSave_t ResumeCtxsave;


//--------------------------------------------------------------------------------------------------
/**
 * Main of the test.
 */
//--------------------------------------------------------------------------------------------------
COMPONENT_INIT
{
    FILE* flashFdPtr;
    int iUbi;
    char ubiPath[PATH_MAX];
    char mtdPath[PATH_MAX];
    int data[2] = {0,1};
    char mtdFetchName[2][16] = {"system2","modem"};
    le_fs_FileRef_t fd[2];
    le_result_t resultFs;
    size_t writeSize;

    LE_ASSERT(-1 != system("mkdir -p /tmp/ubi0"));
    LE_ASSERT(-1 != system("mkdir -p /tmp/ubi1"));
    LE_ASSERT(-1 != system("mkdir -p /tmp/mtd0"));
    LE_ASSERT(-1 != system("mkdir -p /tmp/mtd1"));

    if ((-1 == unlink("/tmp/ubi0/mtd_num")) && (ENOENT != errno))
    {
        LE_ERROR("unlink failed: %m");
        exit(EXIT_FAILURE);
    }

    if ((-1 == unlink("/tmp/ubi1/mtd_num")) && (ENOENT != errno))
    {
        LE_ERROR("unlink failed: %m");
        exit(EXIT_FAILURE);
    }

    if ((-1 == unlink("/tmp/mtd0/name")) && (ENOENT != errno))
    {
        LE_ERROR("unlink failed: %m");
        exit(EXIT_FAILURE);
    }

    if ((-1 == unlink("/tmp/mtd1/name")) && (ENOENT != errno))
    {
        LE_ERROR("unlink failed: %m");
        exit(EXIT_FAILURE);
    }

    if ((-1 == unlink("/tmp/mtd")) && (ENOENT != errno))
    {
        LE_ERROR("unlink failed: %m");
        exit(EXIT_FAILURE);
    }

    if ((-1 == unlink(RESUME_CTX_FILENAME0)) && (ENOENT != errno))
    {
        LE_ERROR("unlink failed: %m");
        exit(EXIT_FAILURE);
    }

    if ((-1 == unlink(RESUME_CTX_FILENAME1)) && (ENOENT != errno))
    {
        LE_ERROR("unlink failed: %m");
        exit(EXIT_FAILURE);
    }

    for (iUbi = 0; iUbi <= 1; iUbi++)
    {
        snprintf(ubiPath, sizeof(ubiPath), SYS_CLASS_UBI_PATH "/ubi%d/mtd_num", iUbi);

        // Try to open the MTD belonging to ubi0
        LE_ASSERT((NULL != (flashFdPtr = fopen(ubiPath, "w+"))));

        LE_ASSERT(0 < fprintf(flashFdPtr, "%d", data[iUbi]));
        fseek(flashFdPtr, 0L, SEEK_SET);

        LE_ASSERT(0 == fclose(flashFdPtr));

        snprintf(mtdPath, sizeof(mtdPath), SYS_CLASS_UBI_PATH "/mtd%d/name", iUbi);
        LE_ASSERT((NULL != (flashFdPtr = fopen(mtdPath, "w+"))));
        LE_ASSERT(0 < fprintf(flashFdPtr, "%s", mtdFetchName[iUbi]));
        fseek(flashFdPtr, 0L, SEEK_SET);

        LE_ASSERT(0 == fclose(flashFdPtr));
    }

    LE_INFO("Ubi files are created successfully.");

    LE_ASSERT((NULL != (flashFdPtr = fopen(MTD_PATH, "w+"))));
    LE_ASSERT(0 < fprintf(flashFdPtr, "dev:    size   erasesize  name\n"));
    LE_ASSERT(0 < fprintf(flashFdPtr, "mtd0: 00280000 00040000 \"sbl\"\n"));
    LE_ASSERT(0 < fprintf(flashFdPtr, "mtd1: 00d80000 00040000 \"backup\"\n"));
    LE_ASSERT(0 < fprintf(flashFdPtr, "mtd2: 00200000 00040000 \"ssdata\"\n"));
    LE_ASSERT(0 < fprintf(flashFdPtr, "mtd3: 00300000 00040000 \"tz\"\n"));
    LE_ASSERT(0 < fprintf(flashFdPtr, "mtd4: 00280000 00040000 \"rpm\"\n"));
    LE_ASSERT(0 < fprintf(flashFdPtr, "mtd5: 02800000 00040000 \"modem\"\n"));
    LE_ASSERT(0 < fprintf(flashFdPtr, "mtd6: 02800000 00040000 \"modem2\"\n"));
    LE_ASSERT(0 < fprintf(flashFdPtr, "mtd7: 00200000 00040000 \"aboot\"\n"));
    LE_ASSERT(0 < fprintf(flashFdPtr, "mtd8: 01000000 00040000 \"boot\"\n"));
    LE_ASSERT(0 < fprintf(flashFdPtr, "mtd9: 01e00000 00040000 \"system\"\n"));
    LE_ASSERT(0 < fprintf(flashFdPtr, "mtd10: 03f00000 00040000 \"lefwkro\"\n"));
    LE_ASSERT(0 < fprintf(flashFdPtr, "mtd11: 03600000 00040000 \"customer0\"\n"));
    LE_ASSERT(0 < fprintf(flashFdPtr, "mtd12: 00200000 00040000 \"aboot2\"\n"));
    LE_ASSERT(0 < fprintf(flashFdPtr, "mtd13: 01000000 00040000 \"boot2\"\n"));
    LE_ASSERT(0 < fprintf(flashFdPtr, "mtd14: 01e00000 00040000 \"system2\"\n"));
    LE_ASSERT(0 < fprintf(flashFdPtr, "mtd15: 03f00000 00040000 \"lefwkro2\"\n"));
    LE_ASSERT(0 < fprintf(flashFdPtr, "mtd16: 03600000 00040000 \"customer1\"\n"));
    LE_ASSERT(0 < fprintf(flashFdPtr, "mtd17: 03800000 00040000 \"customer2\"\n"));
    LE_ASSERT(0 == fclose(flashFdPtr));

    LE_INFO("MTD file is created successfully.");

    writeSize = sizeof(ResumeCtxsave);

    // Write dummy content in fwupdate_ResumeCtx_x file.
    LE_ASSERT_OK(le_fs_Open(RESUME_CTX_FILENAME0, LE_FS_CREAT | LE_FS_WRONLY, &fd[0]));

    memset(&ResumeCtxsave, 0, writeSize);
    ResumeCtxsave.imageType = 1;
    ResumeCtxsave.ctxCrc = 0x21d80272;
    resultFs = le_fs_Write(fd[0], (uint8_t*)&ResumeCtxsave, writeSize);
    if (LE_OK != resultFs)
    {
        LE_ERROR("Error while writing fd[0]!");
    }

    le_fs_Close(fd[0]);

    LE_ASSERT_OK(le_fs_Open(RESUME_CTX_FILENAME1, LE_FS_CREAT | LE_FS_WRONLY, &fd[1]));
    resultFs = le_fs_Write(fd[1], (uint8_t*)&ResumeCtxsave, writeSize);
    if (LE_OK != resultFs)
    {
        LE_ERROR("Error while writing fd[1]!");
    }

    le_fs_Close(fd[1]);

    LE_INFO("Resume context files are created successfully.");
}
