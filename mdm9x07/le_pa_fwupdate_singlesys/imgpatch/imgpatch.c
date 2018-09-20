/*
 * Copyright (C) 2009 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "imgpatch.h"
#include "imgdiff.h"
#include "applyPatch.h"
#include "zlib.h"
#include <openssl/sha.h>
#include "imgpatch_utils.h"
#include "legato.h"

#define MAX_CHUNK_LEN           1024*1024
#define BUFFER_SIZE             32768

#define COMMAND_SIZE            4096
#define BSPATCH                 "bspatch"

#define IMGDIFF_TEST_TMP_DIR    "/tmp/"

// zlib default windowBits
#define ZLIB_WINDOWS_BITS       15

#define TMP_SRC_CHUNK           IMGDIFF_TEST_TMP_DIR"imgdiff-src-chunk"
#define TMP_PATCHED_CHUNK       IMGDIFF_TEST_TMP_DIR"imgdiff-patched-chunk"
#define TMP_INFLATE_CHUNK       IMGDIFF_TEST_TMP_DIR"imgdiff-tgt-chunk-inflate"

//--------------------------------------------------------------------------------------------------
/**
 * Chunk to store src chunk
 */
//--------------------------------------------------------------------------------------------------
static uint8_t ChunkBuffer[MAX_CHUNK_LEN];


static le_result_t ReadFile
(
    const char* filePtr,      ///< [IN] File to read
    uint8_t* outBufPtr,       ///< [OUT] Output buffer to store file data
    size_t  *fileLenPtr       ///< [OUT] Length of data read from file
)
{
    struct stat st;
    if (stat(filePtr, &st) < 0)
    {
        LE_ERROR("Failed to state file '%s' (%m)", filePtr);
        return LE_FAULT;
    }

    size_t fileLen = st.st_size;

    FILE* file = fopen(filePtr, "r");
    if (NULL == file)
    {
        LE_ERROR("Failed to read file: %s", filePtr);
        return LE_FAULT;
    }

    if (fileLen > MAX_CHUNK_LEN)
    {
        LE_ERROR("Chunk file too large. Max allowed: %d, Length: %zu", MAX_CHUNK_LEN, fileLen);
        fclose(file);
        return LE_FAULT;
    }

    if (fread(outBufPtr, 1, fileLen, file) < fileLen)
    {
        LE_ERROR("Failed to read full file '%s'", filePtr);
        fclose(file);
        return LE_FAULT;
    }

    fclose(file);
    *fileLenPtr = fileLen;

    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Write a patch chunk directly to target partition
 *
 * @return
 *      - LE_OK            On success.
 *      - LE_FAULT         On failure
 */
//--------------------------------------------------------------------------------------------------
static le_result_t WritePatchToPartition
(
    const char* patchFilePtr,              ///< [IN] File containing patch
    uint32_t offset,                       ///< [IN] Offset in partition
    uint32_t len,                          ///< [IN] Length of data
    partition_Ctx_t* destPartPtr           ///< [IN] Partition where data should be written buffer
)
{
    size_t fileLen = 0;
    memset(ChunkBuffer, 0, sizeof(ChunkBuffer));
    if (LE_OK != ReadFile(patchFilePtr, ChunkBuffer, &fileLen))
    {
       LE_ERROR("Error while reading file: %s", patchFilePtr);
       return LE_FAULT;
    }

    if (len != fileLen)
    {
        LE_ERROR("Patch length (%u) and input file length (%zu) mismatch",
                 len, fileLen);
        return LE_FAULT;
    }

    if (LE_OK != WriteChunk(ChunkBuffer, 0, len, destPartPtr))
    {
       LE_ERROR("Failed to write chunk on target partition");
       return LE_FAULT;
    }

    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Write a chunk directly to target partition
 *
 * @return
 *      - LE_OK            On success.
 *      - LE_FAULT         On failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t imgpatch_WriteChunk
(
    const char* patchFilePtr,              ///< [IN] File containing patch
    uint32_t offset,                       ///< [IN] Offset in partition
    uint32_t len,                          ///< [IN] Length of data
    partition_Ctx_t* destPartPtr           ///< [IN] Partition where data should be written buffer
)
{
    if ((NULL == patchFilePtr) || (NULL == destPartPtr))
    {
        LE_CRIT("Bad input. patchFilePtr: %p  destPartPtr: %p",
                patchFilePtr,
                destPartPtr);
        return LE_FAULT;
    }
    return WritePatchToPartition(patchFilePtr, offset, len, destPartPtr);
}

//--------------------------------------------------------------------------------------------------
/**
 * Apply patch on source chunk and create the target chunk
 *
 * @return
 *      - LE_OK            On success.
 *      - LE_FAULT         On failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t imgpatch_ApplyImgPatch
(
    const applyPatch_Meta_t* patchMetaHdrPtr,       ///< [IN] Meta data of provided patch
    pa_flash_Desc_t srcDesc,                        ///< [IN] Source chunk
    const char* patchFilePtr,                       ///< [IN] File containing patch
    partition_Ctx_t* partCtxPtr,                    ///< [OUT] File containing patched data
    size_t* wrLenToFlash                            ///< [OUT] Amount of data written to target flash
)
{

    if ( (NULL == patchMetaHdrPtr) ||
         (NULL == srcDesc)       ||
         (NULL == patchFilePtr)     ||
         (NULL == partCtxPtr)
       )
    {
        LE_CRIT("Bad input. patchMetaHdrPtr: %p srcDesc: %p, patchChkPtr: %p, partCtxPtr: %p",
                patchMetaHdrPtr,
                srcDesc,
                patchFilePtr,
                partCtxPtr);
        return LE_FAULT;
    }
    int type = patchMetaHdrPtr->chunkType;
    imgpatch_meta_t imgpatchMeta = patchMetaHdrPtr->imgpatchMeta;

    if (CHUNK_NORMAL == type)
    {

        LE_DEBUG("PatchMetaPtr: %p", patchMetaHdrPtr);
        size_t srcStart = imgpatchMeta.normMeta.src_start;
        size_t srcLen = imgpatchMeta.normMeta.src_len;

        memset(ChunkBuffer, 0, sizeof(ChunkBuffer));
        if ( LE_OK != ReadChunk(srcDesc, srcStart, srcLen, ChunkBuffer))
        {
            LE_ERROR("Failed to read source chunk");
            return LE_FAULT;
        }

        FILE* srcChunkFile = fopen(TMP_SRC_CHUNK, "w");
        if (NULL == srcChunkFile)
        {
            LE_ERROR("Imgpatch failed to create a temporary file: %s", TMP_SRC_CHUNK);
            return LE_FAULT;
        }
        int result = fwrite(ChunkBuffer, 1, srcLen, srcChunkFile);
        if (result < srcLen)
        {
            LE_ERROR("Imgpatch failed to write on temporary file: %s", TMP_SRC_CHUNK);
            fclose(srcChunkFile);
            return LE_FAULT;
        }
        fclose(srcChunkFile);

        char bspatchCmd[COMMAND_SIZE] = "";
        snprintf(bspatchCmd, sizeof(bspatchCmd), BSPATCH" %s %s %s",
                 TMP_SRC_CHUNK, TMP_PATCHED_CHUNK, patchFilePtr);
        // TODO: Use library that will be given by toolchain
        LE_DEBUG("bspatch cmd: '%s'", bspatchCmd);
        if (system(bspatchCmd) < 0)
        {
            LE_CRIT("Failed: '%s'", bspatchCmd);
            return LE_FAULT;
        }

        size_t patchedLen = 0;

        if (LE_OK != ReadFile(TMP_PATCHED_CHUNK, ChunkBuffer, &patchedLen))
        {
            LE_ERROR("Error while reading file "TMP_PATCHED_CHUNK);
            return LE_FAULT;
        }

        if (LE_OK != WriteChunk(ChunkBuffer, 0, patchedLen, partCtxPtr))
        {
            LE_ERROR("Failed to write chunk on target partition");
            return LE_FAULT;
        }

        if (wrLenToFlash)
        {
            *wrLenToFlash = patchedLen;
        }
        unlink(TMP_SRC_CHUNK);
        unlink(TMP_PATCHED_CHUNK);
    }
    else if (CHUNK_RAW == type)
    {
        size_t patchLen = imgpatchMeta.rawMeta.tgt_len;
        LE_INFO("Raw chunk. len: %u", (uint32_t)patchLen);
        if (LE_OK != WritePatchToPartition(patchFilePtr, 0, patchLen, partCtxPtr))
        {
           LE_ERROR("Failed to write chunk on target partition");
           return LE_FAULT;
        }

        if (wrLenToFlash)
        {
            *wrLenToFlash = patchLen;
        }
    }
    else if (CHUNK_COPY == type)
    {
        size_t srcStart = imgpatchMeta.cpMeta.src_start;
        size_t srcLen = imgpatchMeta.cpMeta.src_len;
        LE_DEBUG("Copy chunk.src_start: %zu len: %zu", srcStart, srcLen);
        memset(ChunkBuffer, 0, sizeof(ChunkBuffer));
        if ( LE_OK != ReadChunk(srcDesc, srcStart, srcLen, ChunkBuffer))
        {
            LE_ERROR("Failed to read source chunk");
            return LE_FAULT;
        }

        if (LE_OK != WriteChunk(ChunkBuffer, 0, srcLen, partCtxPtr))
        {
           LE_ERROR("Failed to write chunk on target partition");
           return LE_FAULT;
        }

        if (wrLenToFlash)
        {
            *wrLenToFlash = srcLen;
        }
    }
    else if (CHUNK_DEFLATE == type)
    {
        LE_INFO("Deflate chunk. PatchMetaPtr: %p", patchMetaHdrPtr);
        size_t srcStart = imgpatchMeta.deflMeta.src_start;
        size_t srcLen = imgpatchMeta.deflMeta.src_len;
        size_t srcExpandedLen = imgpatchMeta.deflMeta.src_expand_len;
        size_t tgtExpandedLen = imgpatchMeta.deflMeta.tgt_expand_len;
        int level = imgpatchMeta.deflMeta.gzip_level;
        int method = imgpatchMeta.deflMeta.gzip_method;
        int windowBits = imgpatchMeta.deflMeta.gzip_windowBits;
        int memLevel = imgpatchMeta.deflMeta.gzip_memlevel;
        int strategy = imgpatchMeta.deflMeta.gzip_strategy;
        unsigned char* expandedSource = NULL;
        unsigned char* inflatedTgtData = NULL;
        unsigned char* tempData = NULL;
        le_result_t result = LE_OK;
        int sourceReuse = 0;

        // Decompress the source data; the chunk header tells us exactly
        // how big we expect it to be when decompressed.

        memset(ChunkBuffer, 0, sizeof(ChunkBuffer));
        if ( LE_OK != ReadChunk(srcDesc, srcStart, srcLen, ChunkBuffer))
        {
            LE_ERROR("Failed to read source chunk");
            return LE_FAULT;
        }

        expandedSource = malloc(srcExpandedLen);
        if (NULL == expandedSource)
        {
            LE_ERROR("failed to allocate %zu bytes for expanded_source",
                   srcExpandedLen);
            return LE_FAULT;
        }

        z_stream strm;
        strm.zalloc = Z_NULL;
        strm.zfree = Z_NULL;
        strm.opaque = Z_NULL;
        strm.avail_in = srcLen;
        strm.next_in = (unsigned char*)(ChunkBuffer);
        strm.avail_out = srcExpandedLen;
        strm.next_out = expandedSource;

        int ret;
        ret = inflateInit2(&strm, ZLIB_WINDOWS_BITS);
        if (ret != Z_OK)
        {
            LE_ERROR("failed to init source inflation: %d", ret);
            result = LE_FAULT;
            goto error;
        }

        // Because we've provided enough room to accommodate the output
        // data, we expect one call to inflate() to suffice.
        ret = inflate(&strm, Z_SYNC_FLUSH);
        if (ret != Z_STREAM_END) {
            LE_ERROR("source inflation returned %d", ret);
            result = LE_FAULT;
            goto error;
        }

        inflateEnd(&strm);

        FILE* srcChunkFile = fopen(TMP_SRC_CHUNK, "w");
        if (NULL == srcChunkFile)
        {
            LE_ERROR("Imgpatch failed to create a temporary file: %s", TMP_SRC_CHUNK);
            result = LE_FAULT;
            goto error;
        }
        int len = fwrite(expandedSource, 1, srcExpandedLen, srcChunkFile);
        if (len < srcExpandedLen)
        {
            LE_ERROR("Imgpatch failed to write temporary file: %s", TMP_SRC_CHUNK);
            result = LE_FAULT;
            fclose(srcChunkFile);
            goto error;
        }
        fclose(srcChunkFile);

        char bspatchCmd[COMMAND_SIZE] = "";
        snprintf(bspatchCmd, sizeof(bspatchCmd), BSPATCH" %s %s %s",
                 TMP_SRC_CHUNK, TMP_INFLATE_CHUNK, patchFilePtr);
        LE_DEBUG("bspatch cmd: '%s'", bspatchCmd);
        // TODO: Use library that will be given by toolchain
        int rc = system(bspatchCmd);
        if (rc != 0)
        {
            LE_ERROR("Failed: '%s', rc: %d", bspatchCmd, rc);
            result = LE_FAULT;
            //exit(1);
            goto error;
        }

        struct stat stTgtInflate;
        if (stat(TMP_INFLATE_CHUNK, &stTgtInflate) != 0)
        {
          LE_ERROR("Failed to stat '%s'. %m", TMP_INFLATE_CHUNK);
          result = LE_FAULT;
          goto error;
        }

        size_t inflatedTgtSize = stTgtInflate.st_size;
        if (inflatedTgtSize != tgtExpandedLen)
        {
            LE_ERROR("Error: target chunk expanded length mismatch. Expected: %zu, original: %zu",
                   tgtExpandedLen,
                   inflatedTgtSize);
            result = LE_FAULT;
            goto error;
        }

        inflatedTgtData = malloc(inflatedTgtSize);
        if (NULL == inflatedTgtData)
        {
            LE_CRIT("malloc() failed");
            result = LE_FAULT;
            goto error;
        }

        FILE *tgtInflatedFile = fopen(TMP_INFLATE_CHUNK, "rb");

        if (NULL == tgtInflatedFile)
        {
            LE_ERROR("Imgpatch failed to open a temporary file: "TMP_INFLATE_CHUNK);
            result = LE_FAULT;
            goto error;
        }

        len = fread(inflatedTgtData, 1, inflatedTgtSize, tgtInflatedFile);
        if (len < inflatedTgtSize)
        {
            LE_ERROR("Imgpatch failed to read temporary file: %s", TMP_INFLATE_CHUNK);
            result = LE_FAULT;
            fclose(tgtInflatedFile);
            goto error;
        }

        fclose(tgtInflatedFile);

        // Now compress the target data and append it to the output.
        // we're done with the expanded_source data buffer, so we'll
        // reuse that memory to receive the output of deflate.
        tempData = expandedSource;
        sourceReuse = 1;
        ssize_t tempSize = srcExpandedLen;
        if (tempSize < BUFFER_SIZE)
        {
            // unless the buffer is too small, in which case we'll
            // allocate a fresh one.
            free(tempData);
            tempData = malloc(BUFFER_SIZE);

            if (NULL == tempData)
            {
                LE_CRIT("malloc() failed");
                result = LE_FAULT;
                goto error;
            }

            tempSize = BUFFER_SIZE;
        }

        FILE *tgtFile = fopen(TMP_PATCHED_CHUNK, "wb");
        if (NULL == tgtFile)
        {
            LE_ERROR("Fail to open tgt file: %s", TMP_PATCHED_CHUNK);
            result = LE_FAULT;
            goto error;
        }

        // now the deflate stream
        strm.zalloc = Z_NULL;
        strm.zfree = Z_NULL;
        strm.opaque = Z_NULL;
        strm.avail_in = inflatedTgtSize;
        strm.next_in = inflatedTgtData;
        ret = deflateInit2(&strm, level, method, windowBits, memLevel, strategy);
        do
        {
            strm.avail_out = tempSize;
            strm.next_out = tempData;
            ret = deflate(&strm, Z_FINISH);

            if (Z_STREAM_ERROR == ret)
            {
                LE_CRIT("Deflate() failed.");
                result = LE_FAULT;
                deflateEnd(&strm);
                fclose(tgtFile);
                goto error;
            }

            ssize_t have = tempSize - strm.avail_out;
            len = fwrite(tempData, 1, have, tgtFile);
            if (len < have)
            {
                LE_ERROR("Failed to write file: %s", TMP_PATCHED_CHUNK);
                result = LE_FAULT;
                deflateEnd(&strm);
                fclose(tgtFile);
                goto error;
            }
        }
        while (ret != Z_STREAM_END);
        deflateEnd(&strm);
        fclose(tgtFile);

        // Now write the patched chunk to swifota partition
        size_t patchedLen = 0;

        if (LE_OK != ReadFile(TMP_PATCHED_CHUNK, ChunkBuffer, &patchedLen))
        {
            LE_ERROR("Error while reading file "TMP_PATCHED_CHUNK);
            result = LE_FAULT;
            goto error;
        }

        if (LE_OK != WriteChunk(ChunkBuffer, 0, patchedLen, partCtxPtr))
        {
            LE_ERROR("Failed to write chunk on target partition");
            result = LE_FAULT;
            goto error;
        }

        if (wrLenToFlash)
        {
            *wrLenToFlash = patchedLen;
        }
error:
        if (!sourceReuse)
        {
            free(expandedSource);
        }
        if (NULL != tempData)
        {
            free(tempData);
        }
        if (NULL != inflatedTgtData)
        {
            free(inflatedTgtData);
        }
        unlink(TMP_SRC_CHUNK);
        unlink(TMP_PATCHED_CHUNK);
        unlink(TMP_INFLATE_CHUNK);
        return result;
    }
    else
    {
        LE_CRIT("Error: unknown chunk type %d", type);
        return LE_FAULT;
    }


    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * Clean imgpatch context
 */
//--------------------------------------------------------------------------------------------------
void imgpatch_clean
(
    void
)
{
    unlink(TMP_SRC_CHUNK);
    unlink(TMP_PATCHED_CHUNK);
    unlink(TMP_INFLATE_CHUNK);
}
