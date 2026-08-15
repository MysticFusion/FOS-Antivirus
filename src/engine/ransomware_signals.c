/**
 * @file ransomware_signals.c
 * @brief Content-aware ransomware signal tracking (R-05, I-09; U-07 rework).
 *
 * Sliding-window rate counter, extension-rewrite pair tracker, and the
 * >=2-signals confirmation rule from MAP R-05. Purely in-memory.
 *
 * U-07: the pending-rename and dedup tables no longer use fixed 64-slot
 * arrays (a benign bulk rename storm — git checkout, a compiler, a
 * renormalization script — exhausted them and blinded the tracker to the
 * actual ransomware extension rewrites). Slots now grow geometrically up
 * to a hard, memory-bounded ceiling; expired entries are reclaimed first,
 * and a full table of live entries evicts the oldest entry rather than
 * dropping the new one.
 */

#include "ransomware_signals.h"

#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define RW_RATE_RING   64   /* Must exceed RW_RATE_THRESHOLD with headroom */
#define RW_EXT_RING    64   /* Must exceed RW_EXT_THRESHOLD with headroom */
#define RW_SLOTS_INIT  64   /* Initial per-table slot count (U-07)         */
#define RW_SLOTS_MAX   65536/* Hard ceiling: ~3.7 MB per table, far above  */
                            /* any real burst, but memory-bounded          */

typedef struct {
    uint64_t   id;              /* FILE_ID for pairing old/new names */
    time_t     t;               /* event time */
    wchar_t    ext[16];         /* extension with dot, e.g. L".txt" */
    bool       used;            /* slot occupancy (id==0 also implies free) */
} rename_slot_t;

struct rw_tracker {
    /* Rate events: time-ordered FIFO ring. */
    time_t    rate[RW_RATE_RING];
    int       rate_head;
    int       rate_count;

    /* Extension-rewrite events: time-ordered FIFO ring. */
    time_t    ext[RW_EXT_RING];
    int       ext_head;
    int       ext_count;

    /* Pending rename-old entries awaiting a rename-new pair (U-07: grows). */
    rename_slot_t *rename_old;
    size_t         rename_old_cap;

    /* FileIds already counted as an extension rewrite in the window. */
    rename_slot_t *ext_counted;
    size_t         ext_counted_cap;
};

rw_tracker_t *rw_tracker_create(void)
{
    rw_tracker_t *t = (rw_tracker_t *)calloc(1, sizeof(*t));
    return t;
}

void rw_tracker_free(rw_tracker_t *t)
{
    if (!t) return;
    free(t->rename_old);
    free(t->ext_counted);
    free(t);
}

/* Drop entries in the FIFO ring older than (now - window). */
static void prune_ring(time_t *ring, int *head, int *count, int cap,
                       time_t now, int window_sec)
{
    time_t cutoff = now - (time_t)window_sec;
    while (*count > 0 && ring[*head] < cutoff) {
        *head = (*head + 1) % cap;
        (*count)--;
    }
}

/* Insert into the FIFO ring, pruning stale entries first. */
static void ring_push(time_t *ring, int *head, int *count, int cap,
                      time_t now, int window_sec)
{
    prune_ring(ring, head, count, cap, now, window_sec);
    if (*count >= cap) {
        /* Full of live entries: drop the oldest to keep the window. */
        *head = (*head + 1) % cap;
        (*count)--;
    }
    int idx = (*head + *count) % cap;
    ring[idx] = now;
    (*count)++;
}

/* ---- U-07 growable slot tables -------------------------------------- */

static int slot_find(const rename_slot_t *slots, size_t cap, uint64_t id)
{
    if (!slots) return -1;
    for (size_t i = 0; i < cap; i++) {
        if (slots[i].used && slots[i].id == id) return (int)i;
    }
    return -1;
}

/* Mark expired slots free. */
static void slots_prune(rename_slot_t *slots, size_t cap, time_t cutoff)
{
    if (!slots) return;
    for (size_t i = 0; i < cap; i++) {
        if (slots[i].used && slots[i].t < cutoff) slots[i].used = false;
    }
}

/**
 * @brief Reserve a slot for (id, now): reuses a free/expired slot, grows
 *        the table geometrically (up to RW_SLOTS_MAX), or — when the table
 *        is full of LIVE entries at the ceiling — evicts the oldest entry.
 *
 * @return index of the reserved slot, or -1 on allocation failure.
 */
static int slot_reserve(rw_tracker_t *t, rename_slot_t **arr, size_t *cap,
                        uint64_t id, time_t now, int window_sec)
{
    time_t cutoff = now - (time_t)window_sec;
    slots_prune(*arr, *cap, cutoff);

    /* Free slot? */
    for (size_t i = 0; i < *cap; i++) {
        if (!(*arr)[i].used) {
            memset(&(*arr)[i], 0, sizeof((*arr)[i]));
            (*arr)[i].used = true;
            (*arr)[i].id = id;
            (*arr)[i].t = now;
            return (int)i;
        }
    }

    /* Grow when possible (U-07: no more fixed-capacity blindness). */
    if (*cap < RW_SLOTS_MAX) {
        size_t new_cap = (*cap == 0) ? RW_SLOTS_INIT : *cap * 2;
        if (new_cap > RW_SLOTS_MAX) new_cap = RW_SLOTS_MAX;
        rename_slot_t *grown =
            (rename_slot_t *)realloc(*arr, new_cap * sizeof(rename_slot_t));
        if (grown) {
            memset(grown + *cap, 0, (new_cap - *cap) * sizeof(rename_slot_t));
            *arr = grown;
            size_t idx = *cap;
            *cap = new_cap;
            grown[idx].used = true;
            grown[idx].id = id;
            grown[idx].t = now;
            return (int)idx;
        }
        return -1; /* OOM: drop the event rather than corrupt state */
    }

    /* At the ceiling and full of live entries: evict the oldest. */
    size_t oldest = 0;
    for (size_t i = 1; i < *cap; i++) {
        if ((*arr)[i].t < (*arr)[oldest].t) oldest = i;
    }
    memset(&(*arr)[oldest], 0, sizeof((*arr)[oldest]));
    (*arr)[oldest].used = true;
    (*arr)[oldest].id = id;
    (*arr)[oldest].t = now;
    return (int)oldest;
}

void rw_tracker_on_exec_event(rw_tracker_t *t, time_t now)
{
    if (!t) return;
    ring_push(t->rate, &t->rate_head, &t->rate_count, RW_RATE_RING,
              now, RW_RATE_WINDOW_SEC);
}

static bool same_ext(const wchar_t *a, const wchar_t *b)
{
    if (!a || !b) return false;
    return _wcsicmp(a, b) == 0;
}

void rw_tracker_on_rename_old(rw_tracker_t *t, time_t now, uint64_t file_id,
                              const wchar_t *old_ext)
{
    if (!t) return;
    if (file_id == 0) return; /* no reliable pairing key */

    /* Refresh an existing pending pair (repeated rename). */
    int idx = slot_find(t->rename_old, t->rename_old_cap, file_id);
    if (idx >= 0) {
        t->rename_old[idx].t = now;
        if (old_ext) {
            wcsncpy_s(t->rename_old[idx].ext, 16, old_ext, _TRUNCATE);
        }
        return;
    }

    idx = slot_reserve(t, &t->rename_old, &t->rename_old_cap, file_id, now,
                       RW_EXT_WINDOW_SEC);
    if (idx < 0) return;
    if (old_ext) {
        wcsncpy_s(t->rename_old[idx].ext, 16, old_ext, _TRUNCATE);
    }
}

void rw_tracker_on_rename_new(rw_tracker_t *t, time_t now, uint64_t file_id,
                              const wchar_t *new_ext)
{
    if (!t) return;
    if (file_id == 0 || !new_ext) return;

    time_t cutoff = now - (time_t)RW_EXT_WINDOW_SEC;

    /* Find the matching pending old-name entry. */
    int old_idx = slot_find(t->rename_old, t->rename_old_cap, file_id);
    if (old_idx < 0) return; /* no pair (missed event or pairing key lost) */

    const wchar_t *old_ext = t->rename_old[old_idx].ext;
    t->rename_old[old_idx].used = false; /* consume the pair */

    if (same_ext(old_ext, new_ext)) return; /* not an extension rewrite */

    /* Deduplicate: same file must not count twice within the window. (An
     * expired leftover entry is tolerated — slot_reserve's prune frees it
     * before a new slot is reserved.) */
    int di = slot_find(t->ext_counted, t->ext_counted_cap, file_id);
    if (di >= 0 && t->ext_counted[di].t >= cutoff) {
        return;
    }

    int idx = slot_reserve(t, &t->ext_counted, &t->ext_counted_cap, file_id,
                           now, RW_EXT_WINDOW_SEC);
    if (idx < 0) return;
    wcsncpy_s(t->ext_counted[idx].ext, 16, new_ext, _TRUNCATE);

    ring_push(t->ext, &t->ext_head, &t->ext_count, RW_EXT_RING,
              now, RW_EXT_WINDOW_SEC);
}

int rw_tracker_signals(const rw_tracker_t *t, time_t now, bool in_doc_dir)
{
    if (!t) return 0;

    /* Const-cast: prune is a logical purge of expired state. */
    rw_tracker_t *m = (rw_tracker_t *)t;
    prune_ring(m->rate, &m->rate_head, &m->rate_count, RW_RATE_RING,
               now, RW_RATE_WINDOW_SEC);
    prune_ring(m->ext, &m->ext_head, &m->ext_count, RW_EXT_RING,
               now, RW_EXT_WINDOW_SEC);
    slots_prune(m->rename_old, m->rename_old_cap,
                now - (time_t)RW_EXT_WINDOW_SEC);
    slots_prune(m->ext_counted, m->ext_counted_cap,
                now - (time_t)RW_EXT_WINDOW_SEC);

    int signals = 0;
    if (m->rate_count >= RW_RATE_THRESHOLD) signals |= RW_SIG_RATE;
    if (m->ext_count >= RW_EXT_THRESHOLD)   signals |= RW_SIG_EXT;
    if (in_doc_dir)                          signals |= RW_SIG_SCOPE;
    return signals;
}
