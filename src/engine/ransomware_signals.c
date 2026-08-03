/**
 * @file ransomware_signals.c
 * @brief Content-aware ransomware signal tracking (R-05, I-09).
 *
 * Sliding-window rate counter, extension-rewrite pair tracker, and the
 * >=2-signals confirmation rule from MAP R-05. Purely in-memory.
 */

#include "ransomware_signals.h"

#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define RW_RATE_RING   64   /* Must exceed RW_RATE_THRESHOLD with headroom */
#define RW_EXT_RING    64   /* Must exceed RW_EXT_THRESHOLD with headroom */
#define RW_RENAME_SLOTS 64

typedef struct {
    uint64_t   id;              /* FILE_ID for pairing old/new names */
    time_t     t;               /* event time */
    wchar_t    ext[16];         /* extension with dot, e.g. L".txt" */
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

    /* Pending rename-old entries awaiting a rename-new pair. */
    rename_slot_t rename_old[RW_RENAME_SLOTS];

    /* FileIds already counted as an extension rewrite in the window. */
    rename_slot_t ext_counted[RW_RENAME_SLOTS];
};

rw_tracker_t *rw_tracker_create(void)
{
    rw_tracker_t *t = (rw_tracker_t *)calloc(1, sizeof(*t));
    return t;
}

void rw_tracker_free(rw_tracker_t *t)
{
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

    time_t cutoff = now - (time_t)RW_EXT_WINDOW_SEC;
    int replace = -1;
    time_t oldest_t = (time_t)-1;
    for (int i = 0; i < RW_RENAME_SLOTS; i++) {
        rename_slot_t *s = &t->rename_old[i];
        if (s->id == file_id) {
            /* Refresh an existing pending pair (repeated rename). */
            s->t = now;
            if (old_ext) {
                wcsncpy_s(s->ext, 16, old_ext, _TRUNCATE);
            }
            return;
        }
        if (s->id == 0) { replace = i; break; }             /* empty slot */
        if (s->t < cutoff) { replace = i; break; }          /* expired slot */
        if (s->t < oldest_t) { oldest_t = s->t; replace = i; }
    }
    if (replace < 0) return;
    rename_slot_t *s = &t->rename_old[replace];
    memset(s, 0, sizeof(*s));
    s->id = file_id;
    s->t = now;
    if (old_ext) {
        wcsncpy_s(s->ext, 16, old_ext, _TRUNCATE);
    }
}

void rw_tracker_on_rename_new(rw_tracker_t *t, time_t now, uint64_t file_id,
                              const wchar_t *new_ext)
{
    if (!t) return;
    if (file_id == 0 || !new_ext) return;

    time_t cutoff = now - (time_t)RW_EXT_WINDOW_SEC;

    /* Find the matching pending old-name entry. */
    int old_idx = -1;
    for (int i = 0; i < RW_RENAME_SLOTS; i++) {
        if (t->rename_old[i].id == file_id) { old_idx = i; break; }
    }
    if (old_idx < 0) return; /* no pair (missed event or pairing key lost) */

    const wchar_t *old_ext = t->rename_old[old_idx].ext;
    t->rename_old[old_idx].id = 0; /* consume the pair */

    if (same_ext(old_ext, new_ext)) return; /* not an extension rewrite */

    /* Deduplicate: same file must not count twice within the window. */
    for (int i = 0; i < RW_RENAME_SLOTS; i++) {
        if (t->ext_counted[i].id == file_id && t->ext_counted[i].t >= cutoff) {
            return;
        }
    }

    int replace = -1;
    time_t oldest_t = (time_t)-1;
    for (int i = 0; i < RW_RENAME_SLOTS; i++) {
        rename_slot_t *s = &t->ext_counted[i];
        if (s->id == 0) { replace = i; break; }
        if (s->t < cutoff) { replace = i; break; }
        if (s->t < oldest_t) { oldest_t = s->t; replace = i; }
    }
    if (replace < 0) return;
    rename_slot_t *s = &t->ext_counted[replace];
    memset(s, 0, sizeof(*s));
    s->id = file_id;
    s->t = now;
    if (new_ext) {
        wcsncpy_s(s->ext, 16, new_ext, _TRUNCATE);
    }

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

    int signals = 0;
    if (m->rate_count >= RW_RATE_THRESHOLD) signals |= RW_SIG_RATE;
    if (m->ext_count >= RW_EXT_THRESHOLD)   signals |= RW_SIG_EXT;
    if (in_doc_dir)                          signals |= RW_SIG_SCOPE;
    return signals;
}
