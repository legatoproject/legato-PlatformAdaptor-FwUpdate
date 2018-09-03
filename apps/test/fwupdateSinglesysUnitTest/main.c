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
    LE_INFO ("======== Test: pa_fwupdate_InitDownload ========");
    pa_fwupdateSimu_SetReturnVal(LE_OK);
    LE_TEST(LE_OK == pa_fwupdate_InitDownload());
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

    LE_INFO ("======== Test: pa_fwupdate_Download ========");

    fd = -1;
    LE_TEST(LE_BAD_PARAMETER == pa_fwupdate_Download(fd));

    if ((-1 == unlink(TEST_FILE)) && (ENOENT != errno))
    {
        LE_TEST_FATAL("unlink failed: %m");
    }

    fd = open(TEST_FILE, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    LE_TEST(LE_CLOSED == pa_fwupdate_Download(fd));
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
    LE_INFO ("======== Test: pa_fwupdate_GetResumePosition ========");

    size_t position;
    LE_TEST(LE_BAD_PARAMETER == pa_fwupdate_GetResumePosition(NULL));
    LE_TEST(LE_OK == pa_fwupdate_GetResumePosition(&position));
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
    LE_INFO ("======== Test: pa_fwupdate_Install ========");

    LE_TEST(LE_FAULT == pa_fwupdate_Install(true));
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
    pa_fwupdate_UpdateStatus_t statusPtr;
    char statusLabel[50]= {0};
    size_t statusLabelLength = 1;

    LE_INFO ("======== Test: pa_fwupdate_GetUpdateStatus ========");

    LE_TEST(LE_BAD_PARAMETER == pa_fwupdate_GetUpdateStatus(NULL, statusLabel,
                                                              statusLabelLength));
    LE_TEST(LE_OK == pa_fwupdate_GetUpdateStatus(&statusPtr, statusLabel, statusLabelLength));
    LE_TEST(LE_OK == pa_fwupdate_GetUpdateStatus(&statusPtr, statusLabel, 50));
}

//--------------------------------------------------------------------------------------------------
/**
 * Component init of the unit test
 */
//--------------------------------------------------------------------------------------------------
COMPONENT_INIT
{
    le_fs_FileRef_t fileRef;

    if ((-1 == unlink(FILE_PATH)) && (ENOENT != errno))
    {
        LE_TEST_FATAL("unlink failed: %m");
    }

    LE_TEST(LE_OK == le_fs_Open(FILE_PATH, LE_FS_CREAT | LE_FS_RDWR, &fileRef));

    LE_INFO("======== Start UnitTest of FW Update Singlesys ========");

    Testpa_fwupdate_InitDownload();
    Testpa_fwupdate_Download();
    Testpa_fwupdate_GetResumePosition();
    Testpa_fwupdate_Install();
    Testpa_fwupdate_GetUpdateStatus();

    LE_INFO("======== FW Update Singlesys tests SUCCESS ========");
    LE_TEST_EXIT;
}
