/**
 * @file auto_update.h
 * @brief Inert stub for the future server-based auto-update mechanism.
 *
 * This module provides the entry point that the app calls on startup to check
 * for application-level updates (NOT signature database updates — those go
 * through the Python aggregator via update_signature_db()).
 *
 * The current implementation is intentionally inert: it logs once and returns
 * "no update available". This is a placeholder so that the application
 * lifecycle already calls into the auto-update check, and wiring up a real
 * server-side update mechanism later is a matter of replacing the body of
 * auto_update_check() — no call-site changes needed.
 *
 * TODO (future): implement against <your server URL>:
 *   1. Fetch version manifest from a server you control.
 *   2. Compare against the compiled-in APP_VERSION.
 *   3. If newer, prompt the user (or auto-download, depending on policy).
 *   4. Verify signature of the downloaded update package.
 *   5. Apply the update atomically (replace EXE, restart).
 */

#ifndef AUTO_UPDATE_H
#define AUTO_UPDATE_H

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Public API
 * ========================================================================== */

/**
 * @brief Check for an application-level update.
 *
 * Current behavior: logs once and returns 0 (no update).
 *
 * @return 0 if no update is available (or check skipped),
 *         non-zero if an update is available (reserved for future use).
 */
int auto_update_check(void);

/**
 * @brief Initialize the auto-update subsystem.
 *
 * Safe to call multiple times; only the first call has an effect.
 * Called from app_activate() during startup.
 */
void auto_update_init(void);

#ifdef __cplusplus
}
#endif

#endif /* AUTO_UPDATE_H */
