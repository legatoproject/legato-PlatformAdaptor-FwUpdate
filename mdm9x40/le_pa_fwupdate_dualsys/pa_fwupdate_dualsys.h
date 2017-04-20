/**
 * @file pa_fwupdate_dualsys.h
 *
 * This file is used for communication between PA FWUPDATE QMI and PA FWUPDATE DUALSYS only
 *
 * Copyright (C) Sierra Wireless Inc.
 *
 */

#ifndef LEGATO_PAFWUPDATEDUALSYS_INCLUDE_GUARD
#define LEGATO_PAFWUPDATEDUALSYS_INCLUDE_GUARD

#include "legato.h"

//--------------------------------------------------------------------------------------------------
/**
 * Internal update status
 */
//--------------------------------------------------------------------------------------------------
typedef enum pa_fwupdate_InternalStatus
{
    PA_FWUPDATE_INTERNAL_STATUS_OK,              ///< Last update succeeded
    PA_FWUPDATE_INTERNAL_STATUS_SBL,             ///< SBL partition is corrupted
    PA_FWUPDATE_INTERNAL_STATUS_MIBIB,           ///< MIBIB partition is corrupted
    PA_FWUPDATE_INTERNAL_STATUS_RESERVED1,       ///< RESERVED1 partition is corrupted
    PA_FWUPDATE_INTERNAL_STATUS_SEDB,            ///< SEDB partition is corrupted
    PA_FWUPDATE_INTERNAL_STATUS_RESERVED2,       ///< RESERVED2 partition is corrupted
    PA_FWUPDATE_INTERNAL_STATUS_TZ1,             ///< TZ1 partition is corrupted
    PA_FWUPDATE_INTERNAL_STATUS_TZ2,             ///< TZ2 partition is corrupted
    PA_FWUPDATE_INTERNAL_STATUS_RPM1,            ///< RPM1 partition is corrupted
    PA_FWUPDATE_INTERNAL_STATUS_RPM2,            ///< RPM2 partition is corrupted
    PA_FWUPDATE_INTERNAL_STATUS_MODEM1,          ///< MODEM1 partition is corrupted
    PA_FWUPDATE_INTERNAL_STATUS_MODEM2,          ///< MODEM2 partition is corrupted
    PA_FWUPDATE_INTERNAL_STATUS_LK1,             ///< LK1 partition is corrupted
    PA_FWUPDATE_INTERNAL_STATUS_LK2,             ///< LK2 partition is corrupted
    PA_FWUPDATE_INTERNAL_STATUS_KERNEL1,         ///< KERNEL1 partition is corrupted
    PA_FWUPDATE_INTERNAL_STATUS_KERNEL2,         ///< KERNEL2 partition is corrupted
    PA_FWUPDATE_INTERNAL_STATUS_ROOT_FS1,        ///< ROOT_FS1 partition is corrupted
    PA_FWUPDATE_INTERNAL_STATUS_ROOT_FS2,        ///< ROOT_FS2 partition is corrupted
    PA_FWUPDATE_INTERNAL_STATUS_USER_DATA1,      ///< USER_DATA1 partition is corrupted
    PA_FWUPDATE_INTERNAL_STATUS_USER_DATA2,      ///< USER_DATA2 partition is corrupted
    PA_FWUPDATE_INTERNAL_STATUS_CUST_APP1,       ///< CUST_APP1 partition is corrupted
    PA_FWUPDATE_INTERNAL_STATUS_CUST_APP2,       ///< CUST_APP2 partition is corrupted
    PA_FWUPDATE_INTERNAL_STATUS_DWL_ONGOING,     ///< Downloading in progress
    PA_FWUPDATE_INTERNAL_STATUS_DWL_FAILED,      ///< Last downloading failed
    PA_FWUPDATE_INTERNAL_STATUS_DWL_TIMEOUT,     ///< Last downloading stopped due to timeout
    PA_FWUPDATE_INTERNAL_STATUS_UNKNOWN          ///< Unknown status. It has to be the last one.
} pa_fwupdate_InternalStatus_t;

//--------------------------------------------------------------------------------------------------
/**
 * Get the internal firmware update status label
 *
 * @return
 *      - The address of the internal FW update status description matching the given status.
 *      - NULL if the given status is invalid.
 */
//--------------------------------------------------------------------------------------------------
LE_SHARED const char *pa_fwupdate_GetUpdateStatusLabel
(
    pa_fwupdate_InternalStatus_t status    ///< [IN] Firmware update status
);

//--------------------------------------------------------------------------------------------------
/**
 * Return the last internal update status.
 *
 * @return
 *      - LE_OK on success
 *      - LE_BAD_PARAMETER Invalid parameter
 *      - LE_FAULT on failure
 *      - LE_UNSUPPORTED not supported
 */
//--------------------------------------------------------------------------------------------------
LE_SHARED le_result_t pa_fwupdate_GetInternalUpdateStatus
(
    pa_fwupdate_InternalStatus_t *statusPtr, ///< [OUT] Returned update status
    char *statusLabelPtr,                    ///< [OUT] String matching the status
    size_t statusLabelLength                 ///< [IN] Maximum length of the status description
);

//--------------------------------------------------------------------------------------------------
/**
 * Update some variables in SSDATA to indicate that systems are not synchronized
 *
 * @return
 *      - LE_OK on success
 *      - LE_FAULT on failure
 */
//--------------------------------------------------------------------------------------------------
LE_SHARED le_result_t pa_fwupdate_SetUnsyncState
(
    void
);

//--------------------------------------------------------------------------------------------------
/**
 * Update some variables in SSDATA to indicate that systems are synchronized
 *
 * @return
 *      - LE_OK on success
 *      - LE_FAULT on failure
 */
//--------------------------------------------------------------------------------------------------
LE_SHARED le_result_t pa_fwupdate_SetSyncState
(
    void
);

//--------------------------------------------------------------------------------------------------
/**
 * Function which read the initial sub system id
 *
 * @return
 *      - LE_OK            On success
 *      - LE_FAULT         On failure
 */
//--------------------------------------------------------------------------------------------------
LE_SHARED le_result_t pa_fwupdate_GetInitialSubSystemId
(
    uint8_t *initialSSId ///< [OUT] if LE_OK, the current boot system
);

//--------------------------------------------------------------------------------------------------
/**
 * Program a swap between active and update systems
 *
 * @return
 *      - LE_OK             on success
 *      - LE_UNSUPPORTED    the feature is not supported
 *      - LE_FAULT          on failure
 */
//--------------------------------------------------------------------------------------------------
LE_SHARED le_result_t pa_fwupdate_Swap
(
    bool isSyncReq      ///< [IN] Indicate if a synchronization is requested after the swap
);

//--------------------------------------------------------------------------------------------------
/**
 * Request the flash access for a SW update
 *
 * @return
 *      - LE_OK            on success
 *      - LE_UNAVAILABLE   the flash access is not granted for SW update
 *      - LE_FAULT         on failure
 */
//--------------------------------------------------------------------------------------------------
LE_SHARED le_result_t pa_fwupdate_RequestUpdate
(
    void
);

//--------------------------------------------------------------------------------------------------
/**
 * Release the flash access after a SW update
 *
 * @return
 *      - LE_OK           on success
 *      - LE_FAULT        on failure
 */
//--------------------------------------------------------------------------------------------------
LE_SHARED le_result_t pa_fwupdate_CompleteUpdate
(
    void
);

#endif /* LEGATO_PASWUPDATEDUALSYS_INCLUDE_GUARD */

