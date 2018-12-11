 /**
  * This module implements the pa_fwupdate_dualsys unit tests.
  *
  * Copyright (C) Sierra Wireless Inc.
  *
  */

#include "legato.h"
#include <pthread.h>
#include "cwe_local.h"
#include "pa_fwupdate.h"
#include "partition_local.h"
#include "pa_flash.h"
#include "log.h"
#include "sys_flash.h"

//==================================================================================================
//                                       Static variables
//==================================================================================================

//--------------------------------------------------------------------------------------------------
/**
 * Memory Pool for flash temporary image blocks
 */
//--------------------------------------------------------------------------------------------------
static le_mem_PoolRef_t   FlashImgPool;

//--------------------------------------------------------------------------------------------------
/**
 * Crc and full crc to check with resume test
 */
//--------------------------------------------------------------------------------------------------
static uint32_t CweCrc = LE_CRC_START_CRC32;
static uint32_t CweFullCrc = LE_CRC_START_CRC32;
static uint32_t DeltaCweCrc = LE_CRC_START_CRC32;
static uint32_t DeltaCweFullCrc = LE_CRC_START_CRC32;

//==================================================================================================
//                                       Private Functions
//==================================================================================================

// Size of the block we read/write
#define CHUNK_SIZE 20000

//--------------------------------------------------------------------------------------------------
/**
 * This test tries to write a full image to SWIFOTA
 *
 */
//--------------------------------------------------------------------------------------------------
static void Test_pa_flash_WriteCwe
(
    void
)
{
    le_result_t res;
    partition_Ctx_t ctx;
    uint8_t body[8*CHUNK_SIZE + 2*sizeof(cwe_Header_t)];
    cwe_Header_t *cweFullHdrPtr = (cwe_Header_t *)body;
    cwe_Header_t *cweHdrPtr = (cwe_Header_t *)&body[sizeof(cwe_Header_t)];
    uint8_t *bodyPtr = &body[2*sizeof(cwe_Header_t)];
    bool iswr;
    size_t sz, wrOff = 0;
    uint32_t crc = LE_CRC_START_CRC32;
    int nb;

    memset(cweFullHdrPtr, 0xCE, sizeof(cwe_Header_t));
    memset(cweHdrPtr, 0xEC, sizeof(cwe_Header_t));
    memset(&bodyPtr[0], 0x07, CHUNK_SIZE);
    memset(&bodyPtr[CHUNK_SIZE], 0x17, CHUNK_SIZE);
    memset(&bodyPtr[2*CHUNK_SIZE], 0x27, CHUNK_SIZE);
    memset(&bodyPtr[3*CHUNK_SIZE], 0x37, CHUNK_SIZE);
    memset(&bodyPtr[4*CHUNK_SIZE], 0x47, CHUNK_SIZE);
    memset(&bodyPtr[5*CHUNK_SIZE], 0x57, CHUNK_SIZE);
    memset(&bodyPtr[6*CHUNK_SIZE], 0x67, CHUNK_SIZE);
    memset(&bodyPtr[7*CHUNK_SIZE], 0x77, CHUNK_SIZE);
    crc = le_crc_Crc32(bodyPtr, 8 * CHUNK_SIZE, LE_CRC_START_CRC32);

    cweHdrPtr->imageType = CWE_IMAGE_TYPE_USER;
    cweHdrPtr->imageSize = 8 * CHUNK_SIZE;
    cweHdrPtr->crc32 = crc;
    crc = le_crc_Crc32((uint8_t*)cweHdrPtr,
                       sizeof(cwe_Header_t) + 8 * CHUNK_SIZE, LE_CRC_START_CRC32);

    cweFullHdrPtr->imageType = CWE_IMAGE_TYPE_APPL;
    cweFullHdrPtr->imageSize = 8 * CHUNK_SIZE + sizeof(cwe_Header_t);
    cweFullHdrPtr->crc32 = crc;

    LE_TEST_INFO ("======== Test: pa_flash_WriteCwe ========");
    ctx.fullImageSize = sizeof(body);
    ctx.fullImageCrc = crc;
    ctx.flashPoolPtr = &FlashImgPool;
    ctx.cweHdrPtr = cweFullHdrPtr;
    res = partition_OpenSwifotaPartition(&ctx, wrOff);
    LE_TEST(LE_OK == res);

    sz = sizeof(cwe_Header_t);
    res = partition_WriteSwifotaPartition(&ctx, &sz, (uint8_t*)cweFullHdrPtr, false, &iswr);
    LE_TEST(LE_OK == res);
    wrOff += sz;

    ctx.cweHdrPtr = cweHdrPtr;
    sz = sizeof(cwe_Header_t);
    res = partition_WriteSwifotaPartition(&ctx, &sz, (uint8_t*)cweHdrPtr, false, &iswr);
    LE_TEST(LE_OK == res);
    wrOff += sz;

    for( nb = 0; nb < 8 * CHUNK_SIZE; nb += sz)
    {
        sz = 8 * CHUNK_SIZE - nb;
        res = partition_WriteSwifotaPartition(&ctx, &sz, &bodyPtr[nb], false, &iswr);
        LE_TEST(LE_OK == res);
        wrOff += sz;
    }

    ctx.cweHdrPtr = cweFullHdrPtr;
    res = partition_ComputeDataCrc32SwifotaPartition(&ctx, sizeof(cwe_Header_t),
                                                     8 * CHUNK_SIZE + sizeof(cwe_Header_t), &crc);
    LE_TEST(LE_OK == res);
    LE_TEST(crc == cweFullHdrPtr->crc32);

    res = partition_CloseSwifotaPartition(&ctx, wrOff, false, NULL);
    LE_TEST(LE_OK == res);

    res = partition_ComputeDataCrc32SwifotaPartition(&ctx, sizeof(cwe_Header_t),
                                                     8 * CHUNK_SIZE + sizeof(cwe_Header_t), &crc);
    LE_TEST(LE_OK == res);
    LE_TEST(crc == cweFullHdrPtr->crc32);
    CweCrc = crc;
    res = partition_ComputeDataCrc32SwifotaPartition(&ctx, 0,
                                                     8 * CHUNK_SIZE + 2 * sizeof(cwe_Header_t),
                                                     &crc);
    LE_TEST(LE_OK == res);
    CweFullCrc = crc;
}

//--------------------------------------------------------------------------------------------------
/**
 * This test tries to write a delta image to SWIFOTA
 *
 */
//--------------------------------------------------------------------------------------------------
static void Test_pa_flash_WriteDeltaCwe
(
    void
)
{
    le_result_t res;
    partition_Ctx_t ctx;
    uint8_t body[17 * CHUNK_SIZE + 4*sizeof(cwe_Header_t)];
    cwe_Header_t *cweFullHdrPtr = (cwe_Header_t *)body;
    cwe_Header_t *cweHdrAPtr = (cwe_Header_t *)&body[sizeof(cwe_Header_t)];
    uint8_t *bodyAPtr = &body[2*sizeof(cwe_Header_t)];
    cwe_Header_t *cweHdrBPtr = (cwe_Header_t *)&body[8*CHUNK_SIZE + 2*sizeof(cwe_Header_t)];
    uint8_t *bodyBPtr = &body[8 * CHUNK_SIZE + 3*sizeof(cwe_Header_t)];
    cwe_Header_t *cweHdrCPtr = (cwe_Header_t *)&body[12*CHUNK_SIZE + 3*sizeof(cwe_Header_t)];
    uint8_t *bodyCPtr = &body[12 * CHUNK_SIZE + 4*sizeof(cwe_Header_t)];
    bool iswr;
    size_t sz, wrOff = 0, fullSz;
    uint32_t crc = LE_CRC_START_CRC32, fullCrc;
    off_t start, end;

    memset(cweFullHdrPtr, 0xEE, sizeof(cwe_Header_t));
    memset(cweHdrAPtr, 0xDA, sizeof(cwe_Header_t));
    memset(&bodyAPtr[0], 0x0A, CHUNK_SIZE);
    memset(&bodyAPtr[CHUNK_SIZE], 0x1A, CHUNK_SIZE);
    memset(&bodyAPtr[2*CHUNK_SIZE], 0x2A, CHUNK_SIZE);
    memset(&bodyAPtr[3*CHUNK_SIZE], 0x3A, CHUNK_SIZE);
    memset(&bodyAPtr[4*CHUNK_SIZE], 0x4A, CHUNK_SIZE);
    memset(&bodyAPtr[5*CHUNK_SIZE], 0x5A, CHUNK_SIZE);
    memset(&bodyAPtr[6*CHUNK_SIZE], 0x6A, CHUNK_SIZE);
    memset(&bodyAPtr[7*CHUNK_SIZE], 0x7A, CHUNK_SIZE);
    crc = le_crc_Crc32(bodyAPtr, 8 * CHUNK_SIZE, LE_CRC_START_CRC32);

    cweHdrAPtr->imageType = CWE_IMAGE_TYPE_BOOT;
    cweHdrAPtr->imageSize = 8 * CHUNK_SIZE;
    cweHdrAPtr->crc32 = crc;

    memset(cweHdrBPtr, 0xDB, sizeof(cwe_Header_t));
    memset(&bodyBPtr[0], 0x0B, CHUNK_SIZE);
    memset(&bodyBPtr[CHUNK_SIZE], 0x1B, CHUNK_SIZE);
    memset(&bodyBPtr[2*CHUNK_SIZE], 0x2B, CHUNK_SIZE);
    memset(&bodyBPtr[3*CHUNK_SIZE], 0x3B, CHUNK_SIZE);
    crc = le_crc_Crc32(bodyBPtr, 4 * CHUNK_SIZE, LE_CRC_START_CRC32);

    cweHdrBPtr->imageType = CWE_IMAGE_TYPE_SYST;
    cweHdrBPtr->imageSize = 4 * CHUNK_SIZE;
    cweHdrBPtr->crc32 = crc;

    memset(cweHdrCPtr, 0xDC, sizeof(cwe_Header_t));
    memset(&bodyCPtr[0], 0x0C, CHUNK_SIZE);
    memset(&bodyCPtr[CHUNK_SIZE], 0x1C, CHUNK_SIZE);
    memset(&bodyCPtr[2*CHUNK_SIZE], 0x2C, CHUNK_SIZE);
    memset(&bodyCPtr[3*CHUNK_SIZE], 0x3C, CHUNK_SIZE);
    memset(&bodyCPtr[4*CHUNK_SIZE], 0x4C, CHUNK_SIZE);
    crc = le_crc_Crc32(bodyCPtr, 5 * CHUNK_SIZE, LE_CRC_START_CRC32);

    cweHdrCPtr->imageType = CWE_IMAGE_TYPE_USER;
    cweHdrCPtr->imageSize = 5 * CHUNK_SIZE;
    cweHdrCPtr->crc32 = crc;

    crc = le_crc_Crc32((uint8_t*)cweHdrAPtr,
                       2*sizeof(cwe_Header_t) + 17 * CHUNK_SIZE,
                       LE_CRC_START_CRC32);
    cweFullHdrPtr->imageType = CWE_IMAGE_TYPE_APPL;
    cweFullHdrPtr->imageSize = 17 * CHUNK_SIZE + 3*sizeof(cwe_Header_t);
    cweFullHdrPtr->crc32 = crc;

    LE_TEST_INFO ("======== Test: pa_flash_WriteDeltaCwe ========");
    ctx.fullImageSize = sizeof(body);
    ctx.fullImageCrc = crc;
    ctx.flashPoolPtr = &FlashImgPool;
    ctx.cweHdrPtr = cweFullHdrPtr;
    res = partition_OpenSwifotaPartition(&ctx, wrOff);
    LE_TEST(LE_OK == res);

    sz = sizeof(cwe_Header_t);
    res = partition_WriteSwifotaPartition(&ctx, &sz, (uint8_t*)cweFullHdrPtr, false, &iswr);
    LE_TEST(LE_OK == res);
    wrOff += sz;
    res = partition_GetSwifotaOffsetPartition(&start);
    LE_TEST(LE_OK == res);
    LE_TEST_INFO("Swifota start %lx", (unsigned long)start);

    ctx.cweHdrPtr = cweHdrAPtr;
    sz = sizeof(cwe_Header_t);
    res = partition_WriteSwifotaPartition(&ctx, &sz, (uint8_t*)cweHdrAPtr, false, &iswr);
    LE_TEST(LE_OK == res);
    wrOff += sz;

    int nb;
    for( nb = 0; nb < 8 * CHUNK_SIZE; nb += sz)
    {
        sz = 8 * CHUNK_SIZE - nb;
        res = partition_WriteSwifotaPartition(&ctx, &sz, &bodyAPtr[nb], false, &iswr);
        LE_TEST(LE_OK == res);
        wrOff += sz;
    }

    ctx.cweHdrPtr = cweHdrBPtr;
    sz = sizeof(cwe_Header_t);
    res = partition_WriteSwifotaPartition(&ctx, &sz, (uint8_t*)cweHdrBPtr, false, &iswr);
    LE_TEST(LE_OK == res);
    wrOff += sz;

    res = partition_OpenUbiSwifotaPartition(&ctx, 0xABCD0001, true, true, &iswr);
    LE_TEST(LE_OK == res);

    res = partition_OpenUbiVolumeSwifotaPartition(&ctx, 0, PA_FLASH_VOLUME_STATIC,
                                                  4 * CHUNK_SIZE, 0, "volume0", true);
    LE_TEST(LE_OK == res);

    for( nb = 0; nb < 4 * CHUNK_SIZE; nb += sz)
    {
        sz = 4 * CHUNK_SIZE - nb;
        res = partition_WriteUbiSwifotaPartition(&ctx, &sz, wrOff, &bodyBPtr[nb], false, &iswr);
        LE_TEST(LE_OK == res);
        wrOff += sz;
    }

    crc = 0;
    sz = 0;
    res = partition_CloseUbiVolumeSwifotaPartition(&ctx, 4 * CHUNK_SIZE, false, &iswr);
    LE_TEST(LE_OK == res);
    res = partition_ComputeUbiVolumeCrc32SwifotaPartition(&ctx, 0, &sz, &crc, &fullSz, &fullCrc);
    LE_TEST(LE_OK == res);
    LE_TEST_INFO("SZ %u CSZ %zu CFSZ %zu CRC %08x CCRC %08x CFCRC %08x",
            cweHdrBPtr->imageSize, sz, fullSz, cweHdrBPtr->crc32, crc, fullCrc);
    res = partition_ComputeUbiCrc32SwifotaPartition(&ctx, (uint32_t*)&sz, &crc);
    LE_TEST(LE_OK == res);
    LE_TEST_INFO("SZ %zu CRC %08x", sz, crc);
    res = partition_CloseUbiSwifotaPartition(&ctx, false, &iswr);
    LE_TEST(LE_OK == res);

    ctx.cweHdrPtr = cweHdrCPtr;
    sz = sizeof(cwe_Header_t);
    res = partition_WriteSwifotaPartition(&ctx, &sz, (uint8_t*)cweHdrCPtr, false, &iswr);
    LE_TEST(LE_OK == res);
    wrOff += sz;

    res = partition_OpenUbiSwifotaPartition(&ctx, 0xABCD0002, true, true, &iswr);
    LE_TEST(LE_OK == res);

    res = partition_OpenUbiVolumeSwifotaPartition(&ctx, 1, PA_FLASH_VOLUME_DYNAMIC,
                                                  -1, 1, "volume1", true);
    LE_TEST(LE_OK == res);

    for( nb = 0; nb < 5 * CHUNK_SIZE; nb += sz)
    {
        sz = 5 * CHUNK_SIZE - nb;
        res = partition_WriteUbiSwifotaPartition(&ctx, &sz, wrOff, &bodyCPtr[nb], false, &iswr);
        LE_TEST(LE_OK == res);
        wrOff += sz;
    }

    crc = 0;
    sz = 0;
    res = partition_CloseUbiVolumeSwifotaPartition(&ctx, -1, false, &iswr);
    LE_TEST(LE_OK == res);
    res = partition_ComputeUbiVolumeCrc32SwifotaPartition(&ctx, 1, &sz, &crc, &fullSz, &fullCrc);
    LE_TEST(LE_OK == res);
    LE_TEST_INFO("SZ %u CSZ %zu CFSZ %zu CRC %08x CCRC %08x CFCRC %08x",
            cweHdrBPtr->imageSize, sz, fullSz, cweHdrBPtr->crc32, crc, fullCrc);
    res = partition_ComputeUbiCrc32SwifotaPartition(&ctx, (uint32_t*)&sz, &crc);
    LE_TEST(LE_OK == res);
    LE_TEST_INFO("SZ %zu CRC %08x", sz, crc);
    res = partition_CloseUbiSwifotaPartition(&ctx, false, &iswr);
    LE_TEST(LE_OK == res);
    sz = 0;
    res = partition_GetSwifotaOffsetPartition(&end);
    LE_TEST(LE_OK == res);
    LE_TEST_INFO("Swifota end %lx: length %lx", (unsigned long)end, (unsigned long)(end - start));

    res = partition_ComputeDataCrc32SwifotaPartition(&ctx, sizeof(cwe_Header_t),
                                                     (end - start), &crc);
    LE_TEST(LE_OK == res);
    res = partition_ComputeDataCrc32SwifotaPartition(&ctx, 0,
                                                     (end - start + sizeof(cwe_Header_t)), &crc);
    LE_TEST(LE_OK == res);
    ctx.fullImageCrc = crc;
    res = partition_WriteSwifotaPartition(&ctx, &sz, body, false, &iswr);
    LE_TEST_INFO("RES = %d", res);
    res = partition_ComputeDataCrc32SwifotaPartition(&ctx, sizeof(cwe_Header_t),
                                                     (end - start), &crc);
    LE_TEST(LE_OK == res);
    LE_TEST_INFO("FCRC %08x CRC %08x", ctx.fullImageCrc, crc);
    DeltaCweCrc = crc;
    res = partition_ComputeDataCrc32SwifotaPartition(&ctx, 0,
                                                     (end - start) + sizeof(cwe_Header_t), &crc);
    LE_TEST(LE_OK == res);
    DeltaCweFullCrc = crc;

    res = partition_CloseSwifotaPartition(&ctx, wrOff, false, NULL);
    LE_TEST(LE_OK == res);
}

//--------------------------------------------------------------------------------------------------
/**
 * This test tries to write and resume a full image to SWIFOTA
 *
 */
//--------------------------------------------------------------------------------------------------
static void Test_pa_flash_ResumeWriteCwe
(
    void
)
{
    le_result_t res;
    partition_Ctx_t ctx;
    uint8_t body[8*CHUNK_SIZE + 2*sizeof(cwe_Header_t)];
    cwe_Header_t *cweFullHdrPtr = (cwe_Header_t *)body;
    cwe_Header_t *cweHdrPtr = (cwe_Header_t *)&body[sizeof(cwe_Header_t)];
    uint8_t *bodyPtr = &body[2*sizeof(cwe_Header_t)];
    bool iswr;
    size_t sz, wrOff = 0;
    uint32_t crc = LE_CRC_START_CRC32, fullCrc;
    int nb;
    void* partPtr;
    size_t partSize;

    memset(cweFullHdrPtr, 0xCE, sizeof(cwe_Header_t));
    memset(cweHdrPtr, 0xEC, sizeof(cwe_Header_t));
    memset(&bodyPtr[0], 0x07, CHUNK_SIZE);
    memset(&bodyPtr[CHUNK_SIZE], 0x17, CHUNK_SIZE);
    memset(&bodyPtr[2*CHUNK_SIZE], 0x27, CHUNK_SIZE);
    memset(&bodyPtr[3*CHUNK_SIZE], 0x37, CHUNK_SIZE);
    memset(&bodyPtr[4*CHUNK_SIZE], 0x47, CHUNK_SIZE);
    memset(&bodyPtr[5*CHUNK_SIZE], 0x57, CHUNK_SIZE);
    memset(&bodyPtr[6*CHUNK_SIZE], 0x67, CHUNK_SIZE);
    memset(&bodyPtr[7*CHUNK_SIZE], 0x77, CHUNK_SIZE);
    crc = le_crc_Crc32(bodyPtr, 8 * CHUNK_SIZE, LE_CRC_START_CRC32);

    cweHdrPtr->imageType = CWE_IMAGE_TYPE_USER;
    cweHdrPtr->imageSize = 8 * CHUNK_SIZE;
    cweHdrPtr->crc32 = crc;
    crc = le_crc_Crc32((uint8_t*)cweHdrPtr,
                       sizeof(cwe_Header_t) + 8 * CHUNK_SIZE, LE_CRC_START_CRC32);

    cweFullHdrPtr->imageType = CWE_IMAGE_TYPE_APPL;
    cweFullHdrPtr->imageSize = 8 * CHUNK_SIZE + sizeof(cwe_Header_t);
    cweFullHdrPtr->crc32 = crc;

    LE_TEST_INFO ("======== Test: pa_flash_ResumeWriteCwe ========");
    ctx.fullImageSize = sizeof(body);
    ctx.fullImageCrc = crc;
    ctx.flashPoolPtr = &FlashImgPool;
    ctx.cweHdrPtr = cweFullHdrPtr;
    res = partition_OpenSwifotaPartition(&ctx, wrOff);
    LE_TEST(LE_OK == res);

    sz = sizeof(cwe_Header_t);
    res = partition_WriteSwifotaPartition(&ctx, &sz, (uint8_t*)cweFullHdrPtr, false, &iswr);
    LE_TEST(LE_OK == res);
    wrOff += sz;

    res = partition_GetPartitionInternals(&partPtr, &partSize);
    LE_TEST(LE_OK == res);

    char part[partSize];
    memcpy(part, partPtr, partSize);

    ctx.cweHdrPtr = cweHdrPtr;
    sz = sizeof(cwe_Header_t);
    res = partition_WriteSwifotaPartition(&ctx, &sz, (uint8_t*)cweHdrPtr, false, &iswr);
    LE_TEST(LE_OK == res);
    wrOff += sz;

    for( nb = 0; nb < 3 * CHUNK_SIZE; nb += sz)
    {
        sz = 8 * CHUNK_SIZE - nb;
        res = partition_WriteSwifotaPartition(&ctx, &sz, &bodyPtr[nb], false, &iswr);
        LE_TEST(LE_OK == res);
        wrOff += sz;
        memcpy(part, partPtr, partSize);
    }

    (void)partition_CloseSwifotaPartition(&ctx, wrOff, false, NULL);

    res = partition_OpenSwifotaPartition(&ctx, wrOff);
    LE_TEST(LE_OK == res);
    LE_TEST_ASSERT(LE_OK == res, "");
    res = partition_SetPartitionInternals((void*)part);
    LE_TEST(LE_OK == res);
    LE_TEST_ASSERT(LE_OK == res, "");

    for( ; nb < 8 * CHUNK_SIZE; nb += sz)
    {
        sz = 8 * CHUNK_SIZE - nb;
        res = partition_WriteSwifotaPartition(&ctx, &sz, &bodyPtr[nb], false, &iswr);
        LE_TEST(LE_OK == res);
        wrOff += sz;
        memcpy(part, partPtr, partSize);
    }

    ctx.cweHdrPtr = cweFullHdrPtr;
    res = partition_ComputeDataCrc32SwifotaPartition(&ctx, sizeof(cwe_Header_t),
                                                     8 * CHUNK_SIZE + sizeof(cwe_Header_t), &crc);
    LE_TEST(LE_OK == res);
    LE_TEST(crc == cweFullHdrPtr->crc32);

    res = partition_CloseSwifotaPartition(&ctx, wrOff, false, NULL);
    LE_TEST(LE_OK == res);

    res = partition_ComputeDataCrc32SwifotaPartition(&ctx, sizeof(cwe_Header_t),
                                                     8 * CHUNK_SIZE + sizeof(cwe_Header_t), &crc);
    LE_TEST(LE_OK == res);
    LE_TEST(crc == cweFullHdrPtr->crc32);
    res = partition_ComputeDataCrc32SwifotaPartition(&ctx, 0,
                                                     8 * CHUNK_SIZE + 2 * sizeof(cwe_Header_t),
                                                     &fullCrc);
    LE_TEST(LE_OK == res);

    LE_TEST_INFO("Expected CRC %08x %08x = Computed CRC %08x %08x", CweCrc, CweFullCrc, crc, fullCrc);
    LE_TEST_ASSERT(CweCrc == crc, "");
    LE_TEST_ASSERT(CweFullCrc == fullCrc, "");
}

//--------------------------------------------------------------------------------------------------
/**
 * This test tries to write and resume a delta image to SWIFOTA
 *
 */
//--------------------------------------------------------------------------------------------------
static void Test_pa_flash_ResumeWriteDeltaCwe
(
    void
)
{
    le_result_t res;
    partition_Ctx_t ctx;
    uint8_t body[17 * CHUNK_SIZE + 4*sizeof(cwe_Header_t)];
    cwe_Header_t *cweFullHdrPtr = (cwe_Header_t *)body;
    cwe_Header_t *cweHdrAPtr = (cwe_Header_t *)&body[sizeof(cwe_Header_t)];
    uint8_t *bodyAPtr = &body[2*sizeof(cwe_Header_t)];
    cwe_Header_t *cweHdrBPtr = (cwe_Header_t *)&body[8*CHUNK_SIZE + 2*sizeof(cwe_Header_t)];
    uint8_t *bodyBPtr = &body[8 * CHUNK_SIZE + 3*sizeof(cwe_Header_t)];
    cwe_Header_t *cweHdrCPtr = (cwe_Header_t *)&body[12*CHUNK_SIZE + 3*sizeof(cwe_Header_t)];
    uint8_t *bodyCPtr = &body[12 * CHUNK_SIZE + 4*sizeof(cwe_Header_t)];
    bool iswr;
    size_t sz, wrOff = 0, fullSz;
    uint32_t crc = LE_CRC_START_CRC32, fullCrc;
    off_t start, end;
    void* partPtr;
    size_t partSize;

    memset(cweFullHdrPtr, 0xEE, sizeof(cwe_Header_t));
    memset(cweHdrAPtr, 0xDA, sizeof(cwe_Header_t));
    memset(&bodyAPtr[0], 0x0A, CHUNK_SIZE);
    memset(&bodyAPtr[CHUNK_SIZE], 0x1A, CHUNK_SIZE);
    memset(&bodyAPtr[2*CHUNK_SIZE], 0x2A, CHUNK_SIZE);
    memset(&bodyAPtr[3*CHUNK_SIZE], 0x3A, CHUNK_SIZE);
    memset(&bodyAPtr[4*CHUNK_SIZE], 0x4A, CHUNK_SIZE);
    memset(&bodyAPtr[5*CHUNK_SIZE], 0x5A, CHUNK_SIZE);
    memset(&bodyAPtr[6*CHUNK_SIZE], 0x6A, CHUNK_SIZE);
    memset(&bodyAPtr[7*CHUNK_SIZE], 0x7A, CHUNK_SIZE);
    crc = le_crc_Crc32(bodyAPtr, 8 * CHUNK_SIZE, LE_CRC_START_CRC32);

    cweHdrAPtr->imageType = CWE_IMAGE_TYPE_BOOT;
    cweHdrAPtr->imageSize = 8 * CHUNK_SIZE;
    cweHdrAPtr->crc32 = crc;

    memset(cweHdrBPtr, 0xDB, sizeof(cwe_Header_t));
    memset(&bodyBPtr[0], 0x0B, CHUNK_SIZE);
    memset(&bodyBPtr[CHUNK_SIZE], 0x1B, CHUNK_SIZE);
    memset(&bodyBPtr[2*CHUNK_SIZE], 0x2B, CHUNK_SIZE);
    memset(&bodyBPtr[3*CHUNK_SIZE], 0x3B, CHUNK_SIZE);
    crc = le_crc_Crc32(bodyBPtr, 4 * CHUNK_SIZE, LE_CRC_START_CRC32);

    cweHdrBPtr->imageType = CWE_IMAGE_TYPE_SYST;
    cweHdrBPtr->imageSize = 4 * CHUNK_SIZE;
    cweHdrBPtr->crc32 = crc;

    memset(cweHdrCPtr, 0xDC, sizeof(cwe_Header_t));
    memset(&bodyCPtr[0], 0x0C, CHUNK_SIZE);
    memset(&bodyCPtr[CHUNK_SIZE], 0x1C, CHUNK_SIZE);
    memset(&bodyCPtr[2*CHUNK_SIZE], 0x2C, CHUNK_SIZE);
    memset(&bodyCPtr[3*CHUNK_SIZE], 0x3C, CHUNK_SIZE);
    memset(&bodyCPtr[4*CHUNK_SIZE], 0x4C, CHUNK_SIZE);
    crc = le_crc_Crc32(bodyCPtr, 5 * CHUNK_SIZE, LE_CRC_START_CRC32);

    cweHdrCPtr->imageType = CWE_IMAGE_TYPE_USER;
    cweHdrCPtr->imageSize = 5 * CHUNK_SIZE;
    cweHdrCPtr->crc32 = crc;

    crc = le_crc_Crc32((uint8_t*)cweHdrAPtr,
                       2*sizeof(cwe_Header_t) + 17 * CHUNK_SIZE,
                       LE_CRC_START_CRC32);
    cweFullHdrPtr->imageType = CWE_IMAGE_TYPE_APPL;
    cweFullHdrPtr->imageSize = 17 * CHUNK_SIZE + 3*sizeof(cwe_Header_t);
    cweFullHdrPtr->crc32 = crc;

    LE_TEST_INFO ("======== Test: pa_flash_ResumeWriteDeltaCwe ========");
    ctx.fullImageSize = sizeof(body);
    ctx.fullImageCrc = crc;
    ctx.flashPoolPtr = &FlashImgPool;
    ctx.cweHdrPtr = cweFullHdrPtr;
    res = partition_OpenSwifotaPartition(&ctx, wrOff);
    LE_TEST(LE_OK == res);

    sz = sizeof(cwe_Header_t);
    res = partition_WriteSwifotaPartition(&ctx, &sz, (uint8_t*)cweFullHdrPtr, false, &iswr);
    LE_TEST(LE_OK == res);
    wrOff += sz;
    res = partition_GetSwifotaOffsetPartition(&start);
    LE_TEST(LE_OK == res);
    LE_TEST_INFO("Swifota start %lx", (unsigned long)start);

    res = partition_GetPartitionInternals(&partPtr, &partSize);
    LE_TEST(LE_OK == res);

    char part[partSize];
    memcpy(part, partPtr, partSize);

    ctx.cweHdrPtr = cweHdrAPtr;
    sz = sizeof(cwe_Header_t);
    res = partition_WriteSwifotaPartition(&ctx, &sz, (uint8_t*)cweHdrAPtr, false, &iswr);
    LE_TEST(LE_OK == res);
    wrOff += sz;

    int nb;
    for( nb = 0; nb < 3 * CHUNK_SIZE; nb += sz)
    {
        sz = 8 * CHUNK_SIZE - nb;
        res = partition_WriteSwifotaPartition(&ctx, &sz, &bodyAPtr[nb], false, &iswr);
        LE_TEST(LE_OK == res);
        wrOff += sz;
        memcpy(part, partPtr, partSize);
    }

    (void)partition_CloseSwifotaPartition(&ctx, wrOff, false, NULL);

    res = partition_OpenSwifotaPartition(&ctx, wrOff);
    LE_TEST(LE_OK == res);
    LE_TEST_ASSERT(LE_OK == res, "");
    res = partition_SetPartitionInternals((void*)part);
    LE_TEST(LE_OK == res);
    LE_TEST_ASSERT(LE_OK == res, "");

    for( ; nb < 8 * CHUNK_SIZE; nb += sz)
    {
        sz = 8 * CHUNK_SIZE - nb;
        res = partition_WriteSwifotaPartition(&ctx, &sz, &bodyAPtr[nb], false, &iswr);
        LE_TEST(LE_OK == res);
        wrOff += sz;
        memcpy(part, partPtr, partSize);
    }

    ctx.cweHdrPtr = cweHdrBPtr;
    sz = sizeof(cwe_Header_t);
    res = partition_WriteSwifotaPartition(&ctx, &sz, (uint8_t*)cweHdrBPtr, false, &iswr);
    LE_TEST(LE_OK == res);
    wrOff += sz;
    memcpy(part, partPtr, partSize);

    res = partition_OpenUbiSwifotaPartition(&ctx, 0xABCD0001, true, true, &iswr);
    LE_TEST(LE_OK == res);

    res = partition_OpenUbiVolumeSwifotaPartition(&ctx, 0, PA_FLASH_VOLUME_STATIC,
                                                  4 * CHUNK_SIZE, 0, "volume0", true);
    LE_TEST(LE_OK == res);

    for( nb = 0; nb < 4 * CHUNK_SIZE; nb += sz)
    {
        sz = 4 * CHUNK_SIZE - nb;
        res = partition_WriteUbiSwifotaPartition(&ctx, &sz, wrOff, &bodyBPtr[nb], false, &iswr);
        LE_TEST(LE_OK == res);
        wrOff += sz;
        memcpy(part, partPtr, partSize);
    }

    crc = 0;
    sz = 0;
    res = partition_CloseUbiVolumeSwifotaPartition(&ctx, 4 * CHUNK_SIZE, false, &iswr);
    LE_TEST(LE_OK == res);
    memcpy(part, partPtr, partSize);
    res = partition_ComputeUbiVolumeCrc32SwifotaPartition(&ctx, 0, &sz, &crc, &fullSz, &fullCrc);
    LE_TEST(LE_OK == res);
    LE_TEST_INFO("SZ %u CSZ %zu CFSZ %zu CRC %08x CCRC %08x CFCRC %08x",
            cweHdrBPtr->imageSize, sz, fullSz, cweHdrBPtr->crc32, crc, fullCrc);
    res = partition_ComputeUbiCrc32SwifotaPartition(&ctx, (uint32_t*)&sz, &crc);
    LE_TEST(LE_OK == res);
    LE_TEST_INFO("SZ %zu CRC %08x", sz, crc);
    res = partition_CloseUbiSwifotaPartition(&ctx, false, &iswr);
    LE_TEST(LE_OK == res);

    ctx.cweHdrPtr = cweHdrCPtr;
    sz = sizeof(cwe_Header_t);
    res = partition_WriteSwifotaPartition(&ctx, &sz, (uint8_t*)cweHdrCPtr, false, &iswr);
    LE_TEST(LE_OK == res);
    wrOff += sz;
    memcpy(part, partPtr, partSize);

    res = partition_OpenUbiSwifotaPartition(&ctx, 0xABCD0002, true, true, &iswr);
    LE_TEST(LE_OK == res);

    res = partition_OpenUbiVolumeSwifotaPartition(&ctx, 1, PA_FLASH_VOLUME_DYNAMIC,
                                                  -1, 1, "volume1", true);
    LE_TEST(LE_OK == res);

    off_t swiOff;
    for( nb = 0; nb < 2 * CHUNK_SIZE; nb += sz)
    {
        sz = 5 * CHUNK_SIZE - nb;
        res = partition_WriteUbiSwifotaPartition(&ctx, &sz, wrOff, &bodyCPtr[nb], false, &iswr);
        LE_TEST(LE_OK == res);
        wrOff += sz;
        memcpy(part, partPtr, partSize);
        res = partition_GetSwifotaOffsetPartition(&swiOff);
    }

    (void)partition_CloseSwifotaPartition(&ctx, wrOff, true, NULL);

    res = partition_OpenSwifotaPartition(&ctx, swiOff);
    LE_TEST(LE_OK == res);
    LE_TEST_ASSERT(LE_OK == res, "");
    res = partition_SetPartitionInternals((void*)part);
    LE_TEST(LE_OK == res);
    LE_TEST_ASSERT(LE_OK == res, "");
    res = partition_OpenUbiSwifotaPartition(&ctx, 0, false, false, &iswr);
    LE_TEST(LE_OK == res);
    LE_TEST_ASSERT(LE_OK == res, "");
    res = partition_OpenUbiVolumeSwifotaPartition(&ctx, 1, PA_FLASH_VOLUME_DYNAMIC,
                                                  -1, 1, "volume1", false);
    LE_TEST(LE_OK == res);
    LE_TEST_ASSERT(LE_OK == res, "");

    for( ; nb < 5 * CHUNK_SIZE; nb += sz)
    {
        sz = 5 * CHUNK_SIZE - nb;
        res = partition_WriteUbiSwifotaPartition(&ctx, &sz, wrOff, &bodyCPtr[nb], false, &iswr);
        LE_TEST(LE_OK == res);
        wrOff += sz;
    }

    crc = 0;
    sz = 0;
    res = partition_CloseUbiVolumeSwifotaPartition(&ctx, -1, false, &iswr);
    LE_TEST(LE_OK == res);
    res = partition_ComputeUbiVolumeCrc32SwifotaPartition(&ctx, 1, &sz, &crc, &fullSz, &fullCrc);
    LE_TEST(LE_OK == res);
    LE_TEST_INFO("SZ %u CSZ %zu CFSZ %zu CRC %08x CCRC %08x CFCRC %08x",
            cweHdrBPtr->imageSize, sz, fullSz, cweHdrBPtr->crc32, crc, fullCrc);
    res = partition_ComputeUbiCrc32SwifotaPartition(&ctx, (uint32_t*)&sz, &crc);
    LE_TEST(LE_OK == res);
    LE_TEST_INFO("SZ %zu CRC %08x", sz, crc);
    res = partition_CloseUbiSwifotaPartition(&ctx, false, &iswr);
    LE_TEST(LE_OK == res);
    sz = 0;
    res = partition_GetSwifotaOffsetPartition(&end);
    LE_TEST(LE_OK == res);
    LE_TEST_INFO("Swifota end %lx: length %lx", (unsigned long)end, (unsigned long)(end - start));

    res = partition_ComputeDataCrc32SwifotaPartition(&ctx, sizeof(cwe_Header_t),
                                                     (end - start), &crc);
    LE_TEST(LE_OK == res);
    res = partition_ComputeDataCrc32SwifotaPartition(&ctx, 0,
                                                     (end - start + sizeof(cwe_Header_t)), &crc);
    LE_TEST(LE_OK == res);
    ctx.fullImageCrc = crc;
    res = partition_WriteSwifotaPartition(&ctx, &sz, body, false, &iswr);
    LE_TEST_INFO("RES = %d", res);
    res = partition_ComputeDataCrc32SwifotaPartition(&ctx, sizeof(cwe_Header_t),
                                                     (end - start), &crc);
    LE_TEST(LE_OK == res);
    LE_TEST_INFO("FCRC %08x CRC %08x", ctx.fullImageCrc, crc);

    res = partition_ComputeDataCrc32SwifotaPartition(&ctx, 0,
                                                     (end - start) + sizeof(cwe_Header_t),
                                                     &fullCrc);
    LE_TEST(LE_OK == res);
    res = partition_CloseSwifotaPartition(&ctx, wrOff, false, NULL);
    LE_TEST(LE_OK == res);

    LE_TEST_INFO("Expected CRC %08x %08x = Computed CRC %08x %08x",
            DeltaCweCrc, DeltaCweFullCrc, crc, fullCrc);
    LE_TEST_ASSERT(DeltaCweCrc == crc, "");
    LE_TEST_ASSERT(DeltaCweFullCrc == fullCrc, "");
}

//--------------------------------------------------------------------------------------------------
/**
 * Main of the test.
 */
//--------------------------------------------------------------------------------------------------
COMPONENT_INIT
{
    int mtdNum;
    pa_flash_Info_t flashInfo;

    LE_TEST_PLAN(LE_TEST_NO_PLAN);

    // Get MTD information from SWIFOTA partition. This is will be used to set the
    // pool object size and compute the max object size
    mtdNum = partition_GetMtdFromImageTypeOrName( 0, "swifota", NULL );
    if (-1 == mtdNum)
    {
        LE_TEST_FATAL("Unable to find a valid MTD for \"swifota\"");
    }

    if (LE_OK != pa_flash_GetInfo( mtdNum, &flashInfo, false, false ))
    {
        LE_TEST_FATAL("Unable to get MTD informations for \"swifota\"");
    }

    // Allocate a pool for the blocks to be flashed and checked
    FlashImgPool = le_mem_CreatePool("FlashImagePool", flashInfo.eraseSize);
    // Request 3 blocks: 1 for flash, 1 spare, 1 for check
    le_mem_ExpandPool(FlashImgPool, 3);

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

    partition_Initialize();

    char *bbPtr = getenv("BAD_BLOCK_SWIFOTA");
    if( bbPtr && *bbPtr )
    {
        sscanf( bbPtr, "%llx", &bbMask );
        LE_TEST_INFO("Bad block string \"%s\", mask %llx", bbPtr, bbMask);
        sys_flash_SetBadBlockErase( "swifota", bbMask );
    }

    do
    {
        LE_TEST_INFO("======== Start UnitTest of FW PA FLASH [Bad block mask 0x%llx] ========",
                bbMask);

        sys_flash_ResetBadBlock( "swifota" );
        sys_flash_SetBadBlockErase( "swifota", bbMask );

        Test_pa_flash_WriteCwe();
        Test_pa_flash_WriteDeltaCwe();
        Test_pa_flash_ResumeWriteCwe();
        Test_pa_flash_ResumeWriteDeltaCwe();

        bbMask = bbMaskTab[bbMaskIdx];
        bbMaskIdx++;
    }
    while( bbMask != (-1ULL) );

    LE_TEST_INFO ("======== FW PA FLASH end ========");
    LE_TEST_EXIT;
}
