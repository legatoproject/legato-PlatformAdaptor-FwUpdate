/**
 * @file interfaces.c
 *
 * Simulation function prototype declaration.
 *
 * Copyright (C) Sierra Wireless Inc.
 */

#include "le_fwupdate_interface.h"
#include "cwe_local.h"
#include "partition_local.h"
#include "pa_fwupdate_dualsys.h"

#undef LE_KILL_CLIENT
#define LE_KILL_CLIENT LE_WARN

//--------------------------------------------------------------------------------------------------
/**
 * Set the stub synchronization state
 *
 * @return None
 */
//--------------------------------------------------------------------------------------------------
void pa_fwupdateSimu_SetSystemState
(
    bool isSync
);

//--------------------------------------------------------------------------------------------------
/**
 * Set the return state for pa_fwupdate_GetSystemState API
 *
 * @return None
 */
//--------------------------------------------------------------------------------------------------
void pa_fwupdateSimu_SetReturnVal
(
    le_result_t result
);

//--------------------------------------------------------------------------------------------------
/**
 * Set the ECC failed state for pa_flash_GetEccStats API
 *
 * @return None
 */
//--------------------------------------------------------------------------------------------------
void pa_flashSimu_SetEccStatsFailed
(
   bool state
);
