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

    LE_TEST_INIT;

    LE_TEST(-1 != system("mkdir -p /tmp/ubi0"));
    LE_TEST(-1 != system("mkdir -p /tmp/ubi1"));
    LE_TEST(-1 != system("mkdir -p /tmp/mtd0"));
    LE_TEST(-1 != system("mkdir -p /tmp/mtd1"));

    if ((-1 == unlink("/tmp/ubi0/mtd_num")) && (ENOENT != errno))
    {
        LE_TEST_FATAL("unlink failed: %m");
    }

    if ((-1 == unlink("/tmp/ubi1/mtd_num")) && (ENOENT != errno))
    {
        LE_TEST_FATAL("unlink failed: %m");
    }

    if ((-1 == unlink("/tmp/mtd0/name")) && (ENOENT != errno))
    {
        LE_TEST_FATAL("unlink failed: %m");
    }

    if ((-1 == unlink("/tmp/mtd1/name")) && (ENOENT != errno))
    {
        LE_TEST_FATAL("unlink failed: %m");
    }

    if ((-1 == unlink("/tmp/mtd")) && (ENOENT != errno))
    {
        LE_TEST_FATAL("unlink failed: %m");
    }

    if ((-1 == unlink(RESUME_CTX_FILENAME0)) && (ENOENT != errno))
    {
        LE_TEST_FATAL("unlink failed: %m");
    }

    if ((-1 == unlink(RESUME_CTX_FILENAME1)) && (ENOENT != errno))
    {
        LE_TEST_FATAL("unlink failed: %m");
    }

    for (iUbi = 0; iUbi <= 1; iUbi++)
    {
        snprintf(ubiPath, sizeof(ubiPath), SYS_CLASS_UBI_PATH "/ubi%d/mtd_num", iUbi);

        // Try to open the MTD belonging to ubi0
        LE_TEST(NULL != (flashFdPtr = fopen(ubiPath, "w")));

        fprintf(flashFdPtr, "%d", data[iUbi]);
        fseek(flashFdPtr, 0L, SEEK_SET);

        LE_TEST(0 == fclose(flashFdPtr));

        snprintf(mtdPath, sizeof(mtdPath), SYS_CLASS_UBI_PATH "/mtd%d/name", iUbi);
        LE_TEST((NULL != (flashFdPtr = fopen(mtdPath, "w"))));
        fprintf(flashFdPtr, "%s", mtdFetchName[iUbi]);
        fseek(flashFdPtr, 0L, SEEK_SET);

        LE_TEST(0 == fclose(flashFdPtr));
    }

    LE_INFO("Ubi files are created successfully");

    LE_TEST((NULL != (flashFdPtr = fopen(MTD_PATH, "w+"))));
    LE_TEST(0 < fprintf(flashFdPtr, "dev:    size   erasesize  name\n"));
    LE_TEST(0 < fprintf(flashFdPtr, "mtd0: 00280000 00040000 \"sbl\"\n"));
    LE_TEST(0 < fprintf(flashFdPtr, "mtd1: 00280000 00040000 \"mibib\"\n"));
    LE_TEST(0 < fprintf(flashFdPtr, "mtd2: 00680000 00040000 \"backup\"\n"));
    LE_TEST(0 < fprintf(flashFdPtr, "mtd3: 00100000 00040000 \"security\"\n"));
    LE_TEST(0 < fprintf(flashFdPtr, "mtd4: 00200000 00040000 \"persist\"\n"));
    LE_TEST(0 < fprintf(flashFdPtr, "mtd5: 01180000 00040000 \"efs2\"\n"));
    LE_TEST(0 < fprintf(flashFdPtr, "mtd6: 04f40000 00040000 \"swifota\"\n"));
    LE_TEST(0 < fprintf(flashFdPtr, "mtd7: 00180000 00040000 \"tz\"\n"));
    LE_TEST(0 < fprintf(flashFdPtr, "mtd8: 000c0000 00040000 \"devcfg\"\n"));
    LE_TEST(0 < fprintf(flashFdPtr, "mtd9: 000c0000 00040000 \"rpm\"\n"));
    LE_TEST(0 < fprintf(flashFdPtr, "mtd10: 02000000 00040000 \"modem\"\n"));
    LE_TEST(0 < fprintf(flashFdPtr, "mtd11: 00100000 00040000 \"aboot\"\n"));
    LE_TEST(0 < fprintf(flashFdPtr, "mtd12: 00f00000 00040000 \"boot\"\n"));
    LE_TEST(0 < fprintf(flashFdPtr, "mtd13: 01e00000 00040000 \"system\"\n"));
    LE_TEST(0 < fprintf(flashFdPtr, "mtd14: 008c0000 00040000 \"lefwkro\"\n"));
    LE_TEST(0 < fprintf(flashFdPtr, "mtd15: 01900000 00040000 \"swirw\"\n"));
    LE_TEST(0 < fprintf(flashFdPtr, "mtd16: 08300000 00040000 \"userapp\"\n"));
    LE_TEST(0 < fprintf(flashFdPtr, "mtd17: 03680000 00040000 \"reserved\"\n"));
    LE_TEST(0 < fprintf(flashFdPtr, "mtd18: 02180000 00040000 \"slot_2\"\n"));
    LE_TEST(0 < fprintf(flashFdPtr, "mtd19: 02180000 00040000 \"slot_1\"\n"));
    LE_TEST(0 < fprintf(flashFdPtr, "mtd20: 02180000 00040000 \"slot_0\"\n"));
    LE_TEST(0 == fclose(flashFdPtr));

    LE_INFO("MTD file is created successfully.");

    writeSize = sizeof(ResumeCtxsave);

    // Write dummy content in fwupdate_ResumeCtx_x file.
    LE_TEST(LE_OK == le_fs_Open(RESUME_CTX_FILENAME0, LE_FS_CREAT | LE_FS_WRONLY, &fd[0]));

    memset(&ResumeCtxsave, 0, writeSize);
    ResumeCtxsave.imageType = 1;
    ResumeCtxsave.ctxCrc = 0x21d80272;
    resultFs = le_fs_Write(fd[0], (uint8_t*)&ResumeCtxsave, writeSize);
    if (LE_OK != resultFs)
    {
        LE_ERROR("Error while writing fd[0]!");
    }

    le_fs_Close(fd[0]);

    LE_TEST(LE_OK == le_fs_Open(RESUME_CTX_FILENAME1, LE_FS_CREAT | LE_FS_WRONLY, &fd[1]));
    resultFs = le_fs_Write(fd[1], (uint8_t*)&ResumeCtxsave, writeSize);
    if (LE_OK != resultFs)
    {
        LE_ERROR("Error while writing fd[1]!");
    }

    le_fs_Close(fd[1]);

    LE_INFO("Resume context files are created successfully.");
}
