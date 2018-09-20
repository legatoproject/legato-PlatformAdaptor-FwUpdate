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

#ifndef _BUILD_TOOLS_APPLYPATCH_UTILS_H
#define _BUILD_TOOLS_APPLYPATCH_UTILS_H

#include "legato.h"
#include "pa_flash.h"
#include "partition_local.h"

//--------------------------------------------------------------------------------------------------
/**
 * This function is used to get a 32 bit value from an input buffer and increment the input buffer
 * pointer beyond the extracted field
 *
 * @return
 *          the translated value
 */
//--------------------------------------------------------------------------------------------------
int Read4
(
    uint8_t **bufPtr
);

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
);

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
);

#endif //  _BUILD_TOOLS_APPLYPATCH_UTILS_H
