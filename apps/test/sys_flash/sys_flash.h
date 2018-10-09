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
 * Initialize the emulated flash layer
 */
//--------------------------------------------------------------------------------------------------
#ifdef SYS_FLASH_INIT
void sys_flashInit
(
    void
);
#endif
