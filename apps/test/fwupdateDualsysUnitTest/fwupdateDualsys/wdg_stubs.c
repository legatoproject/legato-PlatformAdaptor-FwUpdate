/**
 * @file wdg_stubs.c
 *
 * Stub functions required for watchdog.
 *
 * Copyright (C) Sierra Wireless Inc.
 */

#include "legato.h"

//--------------------------------------------------------------------------------------------------
/**
 * Start watchdogs 0..N-1.  Typically this is used in COMPONENT_INIT to start all watchdogs needed
 * by the process.
 */
//--------------------------------------------------------------------------------------------------
void le_wdogChain_Init
(
    uint32_t wdogCount  ///< Watchdog count
)
{
}

//--------------------------------------------------------------------------------------------------
/**
 * Begin monitoring the event loop on the current thread.
 */
//--------------------------------------------------------------------------------------------------
void le_wdogChain_MonitorEventLoop
(
    uint32_t watchdog,             ///< Watchdog to use for monitoring
    le_clk_Time_t watchdogInterval ///< Interval at which to check event loop is functioning
)
{
}
