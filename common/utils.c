/**
 * @file utils.c
 *
 * Utility functions
 *
 *
 * Copyright (C) Sierra Wireless Inc.
 *
 */

#include "legato.h"

//==================================================================================================
//  PUBLIC API FUNCTIONS
//==================================================================================================

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
)
{
    uint32_t field;
    uint8_t* packetPtr;

    packetPtr = *packetPtrPtr;

    field = be32toh(*(uint32_t*)packetPtr);
    LE_DEBUG("packet=0x%x, field=0x%x", *packetPtr, field);
    packetPtr += sizeof(field);

    *packetPtrPtr = packetPtr;

    return field;
}

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
)
{
    uint8_t* packetPtr;

    packetPtr = *packetPtrPtr;

    memcpy(bufferPtr, packetPtr, numfields);
    packetPtr += numfields;

    *packetPtrPtr = packetPtr;
}

