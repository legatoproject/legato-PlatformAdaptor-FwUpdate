 /**
  * This module implements the pa_fwupdate_dualsys unit tests.
  *
  * Copyright (C) Sierra Wireless Inc.
  *
  */

#include "legato.h"
#include <pthread.h>
#include "interfaces.h"
#include "pa_fwupdate.h"
#include "log.h"
#include "sys_flash.h"

#define FILE_PATH "/fwupdate/dwl_status.nfo"
#define TEST_FILE "/tmp/test_file.txt"


//--------------------------------------------------------------------------------------------------
/**
 * This test gets the pa_fwupdate_InitDownload API
 *
 * API Tested:
 *  pa_fwupdate_InitDownload().
 */
//--------------------------------------------------------------------------------------------------
static void Testpa_fwupdate_InitDownload
(
    void
)
{
    LE_TEST_INFO ("======== Test: pa_fwupdate_InitDownload ========");

    pa_fwupdateSimu_SetSystemState(false);
    pa_fwupdateSimu_SetReturnVal(LE_FAULT);
    LE_TEST_ASSERT(LE_FAULT == pa_fwupdate_InitDownload(), "");

    pa_fwupdateSimu_SetSystemState(true);
    pa_fwupdateSimu_SetReturnVal(LE_OK);
    LE_TEST_ASSERT(LE_OK == pa_fwupdate_InitDownload(), "");

    pa_fwupdateSimu_SetSystemState(false);
    pa_fwupdateSimu_SetReturnVal(LE_OK);
    LE_TEST_ASSERT(LE_OK == pa_fwupdate_InitDownload(), "");
}

//--------------------------------------------------------------------------------------------------
/**
 * This test gets the pa_fwupdate_Download API
 *
 * API Tested:
 *  pa_fwupdate_Download().
 */
//--------------------------------------------------------------------------------------------------
static void Testpa_fwupdate_Download
(
    void
)
{
    int fd;

    LE_TEST_INFO ("======== Test: pa_fwupdate_Download ========");

    fd = -1;
    LE_TEST_ASSERT(LE_BAD_PARAMETER == pa_fwupdate_Download(fd), "");

    fd = 0;
    pa_fwupdateSimu_SetSystemState(false);
    pa_fwupdate_DisableSyncBeforeUpdate(false);
    LE_TEST_ASSERT(LE_NOT_PERMITTED == pa_fwupdate_Download(fd), "");

    if ((-1 == unlink(TEST_FILE)) && (ENOENT != errno))
    {
        LE_ERROR("unlink failed: %m");
        exit(EXIT_FAILURE);
    }

    fd = open(TEST_FILE, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    pa_fwupdateSimu_SetSystemState(true);
    pa_fwupdate_DisableSyncBeforeUpdate(true);
    LE_TEST_ASSERT(LE_CLOSED == pa_fwupdate_Download(fd), "");
}

//--------------------------------------------------------------------------------------------------
/**
 * This test gets the pa_fwupdate_MarkGood API
 *
 * API Tested:
 *  pa_fwupdate_MarkGood().
 */
//--------------------------------------------------------------------------------------------------
static void Testpa_fwupdate_MarkGood
(
    void
)
{
    LE_TEST_INFO ("======== Test: pa_fwupdate_MarkGood ========");

    LE_TEST_ASSERT(LE_OK == pa_fwupdate_MarkGood(), "");

    pa_fwupdateSimu_SetReturnVal(LE_FAULT);
    LE_TEST_ASSERT(LE_FAULT == pa_fwupdate_MarkGood(), "");

    sys_flash_SetEccState(true);
    LE_TEST_ASSERT(LE_IO_ERROR == pa_fwupdate_MarkGood(), "");
    sys_flash_SetEccState(false);
}

//--------------------------------------------------------------------------------------------------
/**
 * This test gets the pa_fwupdate_GetResumePosition API
 *
 * API Tested:
 *  pa_fwupdate_GetResumePosition().
 */
//--------------------------------------------------------------------------------------------------
static void Testpa_fwupdate_GetResumePosition
(
    void
)
{
    LE_TEST_INFO ("======== Test: pa_fwupdate_GetResumePosition ========");

    size_t position;
    LE_TEST_ASSERT(LE_BAD_PARAMETER == pa_fwupdate_GetResumePosition(NULL), "");
    LE_TEST_ASSERT(LE_OK == pa_fwupdate_GetResumePosition(&position), "");
}

//--------------------------------------------------------------------------------------------------
/**
 * This test gets the pa_fwupdate_GetSystem API
 *
 * API Tested:
 *  pa_fwupdate_GetSystem().
 */
//--------------------------------------------------------------------------------------------------
static void Testpa_fwupdate_GetSystem
(
    void
)
{
    LE_TEST_INFO ("======== Test: pa_fwupdate_GetSystem ========");

    pa_fwupdate_System_t systemArray[PA_FWUPDATE_SUBSYSID_MAX];

    LE_TEST_ASSERT(LE_FAULT == pa_fwupdate_GetSystem(NULL), "");
    LE_TEST_ASSERT(LE_OK == pa_fwupdate_GetSystem(systemArray), "");
}

//--------------------------------------------------------------------------------------------------
/**
 * This test gets the pa_fwupdate_SetSystem API
 *
 * API Tested:
 *  pa_fwupdate_SetSystem().
 */
//--------------------------------------------------------------------------------------------------
static void Testpa_fwupdate_SetSystem
(
    void
)
{
    LE_TEST_INFO ("======== Test: pa_fwupdate_SetSystem ========");

    pa_fwupdate_System_t systemArray[PA_FWUPDATE_SUBSYSID_MAX];
    LE_TEST_ASSERT(LE_FAULT == pa_fwupdate_SetSystem(systemArray), "");
}

//--------------------------------------------------------------------------------------------------
/**
 * This test gets the pa_fwupdate_Install API
 *
 * API Tested:
 *  pa_fwupdate_Install().
 */
//--------------------------------------------------------------------------------------------------
static void Testpa_fwupdate_Install
(
    void
)
{
    pa_fwupdate_UpdateStatus_t status;
    char statusLabel[LE_FWUPDATE_STATUS_LABEL_LENGTH_MAX];
    size_t statusLabelLength = LE_FWUPDATE_STATUS_LABEL_LENGTH_MAX;

    LE_TEST_INFO ("======== Test: pa_fwupdate_Install ========");

    LE_TEST_ASSERT(LE_FAULT == pa_fwupdate_Install(true), "");
    LE_TEST_ASSERT(LE_OK == pa_fwupdate_GetUpdateStatus(&status, statusLabel, statusLabelLength),
                   "");
    LE_TEST_ASSERT(PA_FWUPDATE_UPDATE_STATUS_UNKNOWN == status, "");
    LE_TEST_ASSERT(0 == strncmp(statusLabel, "Swap and mark good ongoing", statusLabelLength), "");

    LE_TEST_ASSERT(LE_FAULT == pa_fwupdate_Install(false), "");
    LE_TEST_ASSERT(LE_OK == pa_fwupdate_GetUpdateStatus(&status, statusLabel, statusLabelLength),
                   "");
    LE_TEST_ASSERT(PA_FWUPDATE_UPDATE_STATUS_UNKNOWN == status, "");
    LE_TEST_ASSERT(0 == strncmp(statusLabel, "Swap ongoing", statusLabelLength), "");
}

//--------------------------------------------------------------------------------------------------
/**
 * This test gets the pa_fwupdate_GetUpdateStatus API
 *
 * API Tested:
 *  pa_fwupdate_GetUpdateStatus().
 */
//--------------------------------------------------------------------------------------------------
static void Testpa_fwupdate_GetUpdateStatus
(
    void
)
{
    pa_fwupdate_UpdateStatus_t status;
    char statusLabel;
    size_t statusLabelLength = 1;

    LE_TEST_INFO ("======== Test: pa_fwupdate_GetUpdateStatus ========");

    LE_TEST_ASSERT(LE_BAD_PARAMETER == pa_fwupdate_GetUpdateStatus(NULL, &statusLabel,
                                                              statusLabelLength), "");
    LE_TEST_ASSERT(LE_OK == pa_fwupdate_GetUpdateStatus(&status, &statusLabel, statusLabelLength),
                   "");
}

//--------------------------------------------------------------------------------------------------
/**
 * Main of the test.
 */
//--------------------------------------------------------------------------------------------------
COMPONENT_INIT
{
    le_fs_FileRef_t fileRef;

    LE_TEST_PLAN(LE_TEST_NO_PLAN);

    if ((-1 == unlink(FILE_PATH)) && (ENOENT != errno))
    {
        LE_ERROR("unlink failed: %m");
        exit(EXIT_FAILURE);
    }

    LE_TEST_ASSERT(LE_OK == le_fs_Open(FILE_PATH, LE_FS_CREAT | LE_FS_RDWR, &fileRef), "");

    LE_TEST_INFO("======== Start UnitTest of FW Update Dualsys ========");

    Testpa_fwupdate_InitDownload();
    Testpa_fwupdate_Download();
    Testpa_fwupdate_MarkGood();
    Testpa_fwupdate_GetResumePosition();
    Testpa_fwupdate_GetSystem();
    Testpa_fwupdate_SetSystem();
    Testpa_fwupdate_Install();
    Testpa_fwupdate_GetUpdateStatus();

    LE_TEST_INFO ("======== FW Update Dualsys tests end ========");
    LE_TEST_EXIT;
}
