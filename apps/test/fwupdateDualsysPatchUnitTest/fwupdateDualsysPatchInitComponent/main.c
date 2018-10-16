/**
 * @file main.c
 *
 * It will initialize the emulated flash layer.
 *
 * Copyright (C) Sierra Wireless Inc.
 */


#include "legato.h"
#include "sys_flash.h"

//--------------------------------------------------------------------------------------------------
/**
 * Initialize the emulated flash layer.
 */
//--------------------------------------------------------------------------------------------------
COMPONENT_INIT
{
    sys_flashInit();
}
