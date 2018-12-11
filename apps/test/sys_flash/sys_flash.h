/**
 * @file main.c
 *
 * It emulates a MTD flash layer for unitary tests
 *
 * Copyright (C) Sierra Wireless Inc.
 */

//--------------------------------------------------------------------------------------------------
/**
 * Set the ECC failed state for pa_flash_GetEccStats API
 *
 * @return None
 */
//--------------------------------------------------------------------------------------------------
void sys_flash_SetEccState
(
    bool eccState
);

//--------------------------------------------------------------------------------------------------
/**
 * Read from a partition and skip the bad block. If a read is performed on a bad block, the next
 * good block is used.
 *
 * @return   (errno)
 *      - >= 0         On success
 *      - -1           The write(2) has failed (errno set by write(2))
 */
//--------------------------------------------------------------------------------------------------
int sys_flashReadSkipBadBlock
(
    int fd,
    void* buf,
    size_t count
);

//--------------------------------------------------------------------------------------------------
/**
 * Reset the bad block for a partition
 *
 * @return None
 */
//--------------------------------------------------------------------------------------------------
void sys_flash_ResetBadBlock
(
    char *partNamePtr
);

//--------------------------------------------------------------------------------------------------
/**
 * Mark the current bad blocks for a partition
 *
 * @return None
 */
//--------------------------------------------------------------------------------------------------
void sys_flash_SetBadBlockMarked
(
    char *partNamePtr,
    unsigned long long badBlockMask
);

//--------------------------------------------------------------------------------------------------
/**
 * Mark the blocks to become bad while writing (EIO) for a partition
 *
 * @return None
 */
//--------------------------------------------------------------------------------------------------
void sys_flash_SetBadBlockWrite
(
    char *partNamePtr,
    unsigned long long badBlockMask
);

//--------------------------------------------------------------------------------------------------
/**
 * Mark the blocks to become bad while erasing (EIO) for a partition
 *
 * @return None
 */
//--------------------------------------------------------------------------------------------------
void sys_flash_SetBadBlockErase
(
    char *partNamePtr,
    unsigned long long badBlockMask
);

//--------------------------------------------------------------------------------------------------
/**
 * Swap the bad blocks (Marked, Write and Erase) between two partitions
 *
 * @return None
 */
//--------------------------------------------------------------------------------------------------
void sys_flash_SwapBadBlock
(
    char *srcPartNamePtr,
    char *dstPartNamePtr
);

//--------------------------------------------------------------------------------------------------
/**
 * Set the partition size in bytes and will be aligned up to a multiple of PEB. An optional number
 * number of PEB can be added to the given size
 *
 * @return None
 */
//--------------------------------------------------------------------------------------------------
void sys_flash_SetSizeInByte
(
    char *partNamePtr,
    uint32_t size,
    uint32_t addedPeb
);

//--------------------------------------------------------------------------------------------------
/**
 * Set the partition size in PEB
 *
 * @return None
 */
//--------------------------------------------------------------------------------------------------
void sys_flash_SetSizeInPeb
(
    char *partNamePtr,
    uint32_t nbPeb
);

//--------------------------------------------------------------------------------------------------
/**
 * Reset the partition size and PEB to its original size
 *
 * @return None
 */
//--------------------------------------------------------------------------------------------------
void sys_flash_ResetSize
(
    char *partNamePtr
);

//--------------------------------------------------------------------------------------------------
/**
 * Initialize the emulated flash layer
 */
//--------------------------------------------------------------------------------------------------
#ifdef SYS_FLASH_INIT
void sys_flashInit
(
    void
);
#endif
