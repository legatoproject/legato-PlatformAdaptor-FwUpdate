/**
 * @file main.c
 *
 * It will create ubi files required for fwupdate dualsys unit test cases.
 *
 * Copyright (C) Sierra Wireless Inc.
 */

#include "legato.h"
#include "pa_flash.h"

//--------------------------------------------------------------------------------------------------
/**
 * Macro definations for fwupdate file name.
 */
//--------------------------------------------------------------------------------------------------
#define SYS_CLASS_UBI_PATH     "/tmp/sys_flash/sys/class/ubi/"
#define RESUME_CTX_FILENAME0   "/fwupdate/fwupdate_ResumeCtx_0"
#define RESUME_CTX_FILENAME1   "/fwupdate/fwupdate_ResumeCtx_1"

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
    le_fs_FileRef_t fd[2];
    le_result_t resultFs;
    size_t writeSize;

    LE_TEST_INIT;

    resultFs = le_fs_Delete(RESUME_CTX_FILENAME0);
    if ((LE_OK != resultFs) && (LE_NOT_FOUND != resultFs))
    {
        LE_TEST_FATAL("unlink failed: %m");
    }

    resultFs = le_fs_Delete(RESUME_CTX_FILENAME1);
    if ((LE_OK != resultFs) && (LE_NOT_FOUND != resultFs))
    {
        LE_TEST_FATAL("unlink failed: %m");
    }

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

    int iUbi;

    // Loop only on UBI 0 (rootfs) 1 (modem) and 2 (lefwkro)
    for( iUbi = 0; iUbi < 3; iUbi++ )
    {
        FILE *ubiFd;
        char ubiPath[PATH_MAX];
        char ubiVolName[PA_FLASH_UBI_MAX_VOLUMES];
        int mtdNum;
        pa_flash_Desc_t desc;
        pa_flash_Info_t *mtdInfoPtr;
        int iblk;

        snprintf(ubiPath, sizeof(ubiPath), SYS_CLASS_UBI_PATH "/ubi%d/mtd_num", iUbi);
        LE_ASSERT(NULL != (ubiFd = fopen(ubiPath, "r")));
        fscanf(ubiFd, "%d", &mtdNum);
        fclose(ubiFd);
        snprintf(ubiPath, sizeof(ubiPath), SYS_CLASS_UBI_PATH "/ubi%d_0/name", iUbi);
        LE_ASSERT(NULL != (ubiFd = fopen(ubiPath, "r")));
        fscanf(ubiFd, "%s", ubiVolName);
        fclose(ubiFd);
        LE_ASSERT_OK(pa_flash_Open(mtdNum, PA_FLASH_OPENMODE_READWRITE, &desc, &mtdInfoPtr));
        LE_ASSERT_OK(pa_flash_CreateUbi(desc, true));

        uint8_t squashfs[mtdInfoPtr->eraseSize - 2 * mtdInfoPtr->writeSize];

        LE_ASSERT_OK(pa_flash_CreateUbiVolume(desc, 0, ubiVolName, PA_FLASH_VOLUME_STATIC,
                                              2 *sizeof(squashfs)));
        LE_ASSERT_OK(pa_flash_ScanUbi(desc, 0));
        memset(squashfs, 0xA0 | iUbi, sizeof(squashfs));
        for( iblk = 0; iblk < 2; iblk++ )
        {
            LE_ASSERT_OK(pa_flash_WriteUbiAtBlock(desc, iblk, squashfs, sizeof(squashfs), true));
        }
        LE_ASSERT_OK(pa_flash_AdjustUbiSize(desc, 2 * sizeof(squashfs)));
        LE_ASSERT_OK(pa_flash_Close(desc));
    }
}
