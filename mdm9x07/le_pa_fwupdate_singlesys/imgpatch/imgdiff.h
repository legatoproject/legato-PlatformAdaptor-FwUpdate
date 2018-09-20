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
#ifndef IMGDIFF_INCLUDE_GUARD
#define IMGDIFF_INCLUDE_GUARD

#include <openssl/sha.h>
#include <stdint.h>

// Image patch chunk types
#define CHUNK_NORMAL   0
#define CHUNK_COPY     1   // This option is added when block has to be copied.
#define CHUNK_DEFLATE  2   // version 2 only
#define CHUNK_RAW      3   // version 2 only

// The gzip header size is actually variable, but we currently don't
// support gzipped data with any of the optional fields, so for now it
// will always be ten bytes.  See RFC 1952 for the definition of the
// gzip format.
#define GZIP_HEADER_LEN   10

// The gzip footer size really is fixed.
#define GZIP_FOOTER_LEN   8

// Imgdiff magic len
#define IMGDIFF_MAGIC_LEN   8


//--------------------------------------------------------------------------------------------------
/**
 * Imgdiff: Imgdiff header and magic
 */
//--------------------------------------------------------------------------------------------------
typedef struct
{
    uint8_t magic[IMGDIFF_MAGIC_LEN];           ///< Imgdiff magic and version
    uint32_t src_img_len;                       ///< Source image length
    uint8_t src_sha256[SHA256_DIGEST_LENGTH];   ///< source image sha256 value
    uint32_t tgt_img_len;                       ///< Target image length
    uint8_t tgt_sha256[SHA256_DIGEST_LENGTH];   ///< Target image sha256 value
    uint32_t patch_count;                       ///< Number of target patches                                                ///< /disable)
}
imgdiff_header_t;


//--------------------------------------------------------------------------------------------------
/**
 * Imgdiff: Imgdiff normal chunk meta data
 */
//--------------------------------------------------------------------------------------------------
typedef struct
{
    uint32_t src_start;                         ///< Start address of source chunk
    uint32_t src_len;                           ///< Source chunk length
    uint32_t patch_len;                         ///< Patch length
}
imgdiff_chunk_normal_meta_t;


//--------------------------------------------------------------------------------------------------
/**
 * Imgdiff: Imgdiff deflate chunk meta data
 */
//--------------------------------------------------------------------------------------------------
typedef struct
{
    uint32_t src_start;                         ///< Start address of source chunk
    uint32_t src_len;                           ///< Source chunk length
    uint32_t src_expand_len;                    ///< Source chunk decompressed length
    uint32_t tgt_expand_len;                    ///< Target chunk decompressed length
    int32_t gzip_level;                         ///< Gzip compression level
    int32_t gzip_method;                        ///< Gzip compression method
    int32_t gzip_windowBits;                    ///< Gzip compression windowbits
    int32_t gzip_memlevel;                      ///< Gzip memory consumption level
    int32_t gzip_strategy;                      ///< Gzip compression strategy
    uint32_t patch_len;                         ///< Patch length
}
imgdiff_chunk_deflate_meta_t;


//--------------------------------------------------------------------------------------------------
/**
 * Imgdiff: Imgdiff raw chunk meta data
 */
//--------------------------------------------------------------------------------------------------
typedef struct
{
    uint32_t tgt_len;                         ///< Target chunk len ( = patch len)
}
imgdiff_chunk_raw_meta_t;


//--------------------------------------------------------------------------------------------------
/**
 * Imgdiff: Imgdiff copy chunk meta data
 */
//--------------------------------------------------------------------------------------------------
typedef struct
{
    uint32_t src_start;                       ///< Source chunk start address
    uint32_t src_len;                         ///< Source chunk len
}
imgdiff_chunk_copy_meta_t;

#endif  // IMGDIFF_INCLUDE_GUARD
