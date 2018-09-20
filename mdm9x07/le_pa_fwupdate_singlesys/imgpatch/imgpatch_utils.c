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

#include "imgpatch_utils.h"
#include "pa_flash_local.h"


//--------------------------------------------------------------------------------------------------
/**
 * This function is used to get a 32 bit value from an input buffer and increment the input buffer
 * pointer beyond the extracted field
 *
 * @return
 *          the translated value
 */
//--------------------------------------------------------------------------------------------------
int32_t Read4
(
    uint8_t** bufPtr ///< [INOUT] memory location of the pointer to input buffer
)
{
    if (NULL == bufPtr)
    {
        LE_CRIT("Bad input bufPtr: %p", bufPtr);
        return LE_FAULT;
    }

    uint8_t* packetPtr;

    packetPtr = *bufPtr;

    uint8_t p[4] = {0};
    memcpy(p, packetPtr, 4);
    int val = (int)(((unsigned int)p[3] << 24) |
                 ((unsigned int)p[2] << 16) |
                 ((unsigned int)p[1] << 8) |
                 (unsigned int)p[0]);
    packetPtr += 4;

    LE_DEBUG("packet=0x%x, val=0x%x", *packetPtr, le32toh(val));
    *bufPtr = packetPtr;

    return le32toh(val);
}

//--------------------------------------------------------------------------------------------------
/**
 * This function is used to read a chunk from source partition
 *
 * @return
 *      - LE_OK on success
 *      - LE_FAULT on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t ReadChunk
(
    pa_flash_Desc_t srcDesc,         ///< [IN] Source partition from where data should be read
    uint32_t offset,                 ///< [IN] Offset in the partition
    uint32_t len,                    ///< [IN] Length of the chunk
    uint8_t* outBufPtr               ///< [OUT] Buffer to store chunk
)
{
    if (NULL == outBufPtr)
    {
        LE_CRIT("Bad input outBufPtr: %p", outBufPtr);
        return LE_FAULT;
    }
    size_t readLen = len;
    LE_INFO("Reading chunk, offset: %u len: %u", offset, len);
    if (LE_OK != pa_flash_ReadUbiAtOffset(srcDesc, offset, outBufPtr, &readLen))
    {
        LE_ERROR("Failed to read from source flash partition");
        return LE_FAULT;
    }

    if (len != readLen)
    {
        LE_ERROR("Read less data than expect. Expected: %u, Read: %zu", len, readLen);
        return LE_FAULT;
    }

    return LE_OK;
}

//--------------------------------------------------------------------------------------------------
/**
 * This function is used to write a chunk to destination partition
 *
 * @return
 *      - LE_OK on success
 *      - LE_FAULT on failure
 */
//--------------------------------------------------------------------------------------------------
le_result_t WriteChunk
(
    const uint8_t* outBufPtr,              ///< [IN] Buffer to write in partition
    uint32_t offset,                       ///< [IN] Offset in partition
    uint32_t len,                          ///< [IN] Length of data
    partition_Ctx_t* destPartPtr           ///< [IN] Partition where data should be written buffer
)
{
    if ((NULL == outBufPtr) || (NULL == destPartPtr))
    {
        LE_CRIT("Bad input outBufPtr: %p, destPartPtr: %p", outBufPtr, destPartPtr);
        return LE_FAULT;
    }
    size_t writeLen;
    size_t fullLen = 0;
    while( fullLen < len )
    {
        writeLen = len - fullLen;
        LE_INFO("Writing chunk to swifota, offset: %u len: %u, full %zu write %zu",
                offset, len, fullLen, writeLen);
        if (LE_OK != partition_WriteUbiSwifotaPartition(destPartPtr, &writeLen, offset,
                                                        outBufPtr + fullLen, false, NULL))
        {
            LE_ERROR("Failed to write on target partition");
            return LE_FAULT;
        }
        fullLen += writeLen;
    }

    return LE_OK;
}
