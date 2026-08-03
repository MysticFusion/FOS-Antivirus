/**
 * @file ransomware_signals.h
 * @brief Content-aware ransomware signal tracking (R-05, I-09).
 *
 * Pure, thread-free tracker: the caller (rt_monitor.c) feeds directory
 * change events; the tracker decides whether a corroborated ransomware
 * pattern is active. Built to be unit-testable without filesystem access.
 *
 * Signals (MAP R-05):
 *   RW_SIG_RATE - >10 file create/modify events within 5 s (sliding window)
 *   RW_SIG_EXT  - >5 files renamed to a different extension within 10 s
 *   RW_SIG_SCOPE- the affected path sits in a user document directory
 *                 (Documents/Desktop/Pictures), supplied by the caller
 *
 * Ransomware context is confirmed only when >= 2 of the 3 signals agree.
 * The tracker is NOT internally synchronized; callers must serialize
 * access (rt_monitor.c uses g_rt_lock).
 */

#ifndef RANSOMWARE_SIGNALS_H
#define RANSOMWARE_SIGNALS_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <wchar.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RW_RATE_WINDOW_SEC  5   /**< Sliding window for create/modify rate */
#define RW_RATE_THRESHOLD  10   /**< Events within window to flag a burst */
#define RW_EXT_WINDOW_SEC  10   /**< Sliding window for extension rewriting */
#define RW_EXT_THRESHOLD    5   /**< Distinct extension changes within window */

#define RW_SIG_RATE  0x01       /**< Burst of file creation/modification */
#define RW_SIG_EXT   0x02       /**< Mass extension rewriting (renames) */
#define RW_SIG_SCOPE 0x04       /**< Path is inside a user document folder */

/* Opaque tracker state. */
typedef struct rw_tracker rw_tracker_t;

rw_tracker_t *rw_tracker_create(void);
void rw_tracker_free(rw_tracker_t *t);

/**
 * @brief Record a file create/modify event (FILE_ACTION_ADDED,
 *        FILE_ACTION_MODIFIED, FILE_ACTION_RENAMED_NEW_NAME).
 */
void rw_tracker_on_exec_event(rw_tracker_t *t, time_t now);

/**
 * @brief Record a FILE_ACTION_RENAMED_OLD_NAME event.
 * @param old_ext Extension of the pre-rename name (e.g. L".txt"),
 *                NULL-safe. Ownership not taken.
 */
void rw_tracker_on_rename_old(rw_tracker_t *t, time_t now, uint64_t file_id,
                              const wchar_t *old_ext);

/**
 * @brief Record a FILE_ACTION_RENAMED_NEW_NAME event. Counts an extension
 *        rewrite if it pairs with a matching rename-old entry.
 */
void rw_tracker_on_rename_new(rw_tracker_t *t, time_t now, uint64_t file_id,
                              const wchar_t *new_ext);

/**
 * @brief Compute the currently active signals (pruning stale events).
 * @param in_doc_dir Whether the current event path is inside a user
 *        document directory (Documents/Desktop/Pictures).
 * @return Bitmask of RW_SIG_* flags.
 */
int rw_tracker_signals(const rw_tracker_t *t, time_t now, bool in_doc_dir);

/**
 * @brief R-05 confirmation rule: >= 2 of the 3 signals must agree.
 */
static inline bool rw_signals_confirmed(int signals)
{
    int n = 0;
    if (signals & RW_SIG_RATE)  n++;
    if (signals & RW_SIG_EXT)   n++;
    if (signals & RW_SIG_SCOPE) n++;
    return n >= 2;
}

#ifdef __cplusplus
}
#endif

#endif /* RANSOMWARE_SIGNALS_H */
