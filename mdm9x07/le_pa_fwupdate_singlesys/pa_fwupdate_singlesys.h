/**
 * @file pa_fwupdate_singlesys.h
 *
 * This file is used for communication between PA FWUPDATE QMI and PA FWUPDATE SINGLE SYSTEM only
 *
 * Copyright (C) Sierra Wireless Inc.
 *
 */

#ifndef LEGATO_PAFWUPDATESINGLESYS_INCLUDE_GUARD
#define LEGATO_PAFWUPDATESINGLESYS_INCLUDE_GUARD

#include "legato.h"

//--------------------------------------------------------------------------------------------------
/**
 * Internal update status
 */
//--------------------------------------------------------------------------------------------------
typedef enum pa_fwupdate_InternalStatus
{
    PA_FWUPDATE_INTERNAL_STATUS_OK,               ///< Last update succeeded
    PA_FWUPDATE_INTERNAL_STATUS_SWIFOTA,          ///< SWIFOTA partition is corrupted
    PA_FWUPDATE_INTERNAL_UPDATE_STATUS_UA,        ///< Update agent failed to install the package
    PA_FWUPDATE_INTERNAL_UPDATE_STATUS_BL,        ///< Bootloader error
    PA_FWUPDATE_INTERNAL_STATUS_DWL_ONGOING,      ///< Downloading in progress
    PA_FWUPDATE_INTERNAL_STATUS_DWL_FAILED,       ///< Last downloading failed
    PA_FWUPDATE_INTERNAL_STATUS_DWL_TIMEOUT,      ///< Last downloading stopped due to timeout
    PA_FWUPDATE_INTERNAL_STATUS_INST_ONGOING,     ///< Ongoing installation
    PA_FWUPDATE_INTERNAL_STATUS_UNKNOWN           ///< Unknown status. It has to be the last one.
}
pa_fwupdate_InternalStatus_t;

//--------------------------------------------------------------------------------------------------
/**
 * Open SWIFOTA partition
 *
 * @return
 *      - LE_OK             on success
 *      - LE_UNSUPPORTED    the feature is not supported
 *      - LE_DUPLICATE      parition is already opened
 *      - LE_FAULT          on failure
 */
//--------------------------------------------------------------------------------------------------
LE_SHARED le_result_t pa_fwupdate_OpenSwifota
(
    void
);

//--------------------------------------------------------------------------------------------------
/**
 * Close SWIFOTA partition
 *
 * @return
 *      - LE_OK             on success
 *      - LE_UNSUPPORTED    the feature is not supported
 *      - LE_FAULT          on failure
 */
//--------------------------------------------------------------------------------------------------
LE_SHARED le_result_t pa_fwupdate_CloseSwifota
(
    void
);

//--------------------------------------------------------------------------------------------------
/**
 * Return the last internal update status.
 *
 * @return
 *      - LE_OK            on success
 *      - LE_UNSUPPORTED   the feature is not supported
 *      - LE_FAULT         on failure
 */
//--------------------------------------------------------------------------------------------------
LE_SHARED le_result_t pa_fwupdate_GetInternalUpdateStatus
(
    pa_fwupdate_InternalStatus_t *statusPtr  ///< [OUT] Returned update status
);

#endif /* LEGATO_PASWUPDATESINGLESYS_INCLUDE_GUARD */