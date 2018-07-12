/**
 * @file utils_local.h
 *
 * Utility functions header file
 *
 * Copyright (C) Sierra Wireless Inc.
 *
 */

#ifndef LEGATO_UTILSLOCAL_INCLUDE_GUARD
#define LEGATO_UTILSLOCAL_INCLUDE_GUARD

#include "legato.h"
#include "cwe_local.h"

//--------------------------------------------------------------------------------------------------
/**
 * This function is used to get a 32 bit value from a packet in network byte order and increment the
 * packet pointer beyond the extracted field
 *
 * @return
 *          the translated value
 */
//--------------------------------------------------------------------------------------------------
uint32_t utils_TranslateNetworkByteOrder
(
    uint8_t** packetPtrPtr ///< [INOUT] memory location of the pointer to the packet from which the
                           ///<         32 bits value will be read
);

//--------------------------------------------------------------------------------------------------
/**
 * This function is used to get a string of 8-bit fields from a packet and increment the packet
 * pointer beyond the last read 8-bit field
 */
//--------------------------------------------------------------------------------------------------
void utils_CopyAndIncrPtr
(
    uint8_t** packetPtrPtr, ///< [INOUT] memory location of a pointer to a packet from which the
                            ///<         string of 8-bit fields is to be read
    uint8_t* bufferPtr,     ///< [OUT] pointer to a buffer into which the 8-bit fields are to be
                            ///<       copied
    size_t numfields        ///< [IN] number of 8-bit fields to be copied
);

#endif /* LEGATO_UTILSLOCAL_INCLUDE_GUARD */