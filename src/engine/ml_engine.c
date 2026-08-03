/**
 * @file ml_engine.c - Hardened ML engine
 */
#include "ml_engine.h"
#include "ed25519_verify.h"
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define FOREST_MAGIC 0x45524F46
#define MAX_TREES 10000
#define MAX_NODES_PER_TREE 1000000
#define EXPECTED_FEATURES 2381
#define MAX_FILE_SIZE (200 * 1024 * 1024) // 200MB max model

/* Public half of the build-time Ed25519 keypair (scripts/sign_model.py).
 * Regenerate with: python scripts/sign_model.py --model assets/models/forest.bin
 * The private key is NOT part of the repository. */
static const uint8_t k_ed25519_pubkey[32] = {
    0x3f, 0x42, 0x14, 0x35, 0x0f, 0xcb, 0x57, 0x1d, 0x0d, 0x32, 0x01, 0xfc,
    0xeb, 0x1d, 0x8c, 0x53, 0x51, 0xee, 0xcb, 0x14, 0x4f, 0x29, 0x24, 0xa2,
    0x94, 0xee, 0x5e, 0x56, 0x0e, 0x5c, 0x8c, 0x0a,
};

#pragma pack(push, 1)
typedef struct { int16_t feature_index; float threshold; int32_t left_child; int32_t right_child; float value; } ForestNode;
typedef struct { uint32_t num_nodes; ForestNode *nodes; } BinaryTree;
typedef struct { uint32_t num_trees; uint32_t num_features; BinaryTree *trees; } BinaryForest;
#pragma pack(pop)

static BinaryForest *g_forest = NULL;
static HANDLE g_init_event = NULL;
static CRITICAL_SECTION g_forest_lock;
static INIT_ONCE g_lock_once = INIT_ONCE_STATIC_INIT;
static BOOL CALLBACK init_lock_cb(PINIT_ONCE o, PVOID p, PVOID *c){ (void)o;(void)p;(void)c; InitializeCriticalSection(&g_forest_lock); return TRUE; }

static float evaluate_tree(const BinaryTree *tree, const float *features)
{
    if (!tree || !tree->nodes || !features) return 0.0f;
    uint32_t curr = 0;
    uint32_t steps = 0;
    while (steps < tree->num_nodes) {
        if (curr >= tree->num_nodes) break;
        int16_t fidx = tree->nodes[curr].feature_index;
        if (fidx == -1) break;
        if (fidx < 0 || fidx >= EXPECTED_FEATURES) break;
        if (features[fidx] <= tree->nodes[curr].threshold) {
            int32_t left = tree->nodes[curr].left_child;
            if (left < 0 || (uint32_t)left >= tree->num_nodes) break;
            curr = (uint32_t)left;
        } else {
            int32_t right = tree->nodes[curr].right_child;
            if (right < 0 || (uint32_t)right >= tree->num_nodes) break;
            curr = (uint32_t)right;
        }
        steps++;
    }
    return tree->nodes[curr].value;
}

void ml_engine_pre_init(void)
{
    InitOnceExecuteOnce(&g_lock_once, init_lock_cb, NULL, NULL);
    if (!g_init_event) g_init_event = CreateEvent(NULL, TRUE, FALSE, NULL);
}

static void ml_log_security_event(const char *msg)
{
    OutputDebugStringA(msg);
    fprintf(stderr, "%s\n", msg);
}

static int read_sig_file(const char *model_path, uint8_t sig[64])
{
    size_t plen = strlen(model_path);
    if (plen + 5 > MAX_PATH) return -1;
    char sig_path[MAX_PATH] = {0};
    memcpy(sig_path, model_path, plen);
    memcpy(sig_path + plen, ".sig", 5);

    FILE *f = NULL;
    if (fopen_s(&f, sig_path, "rb") != 0 || !f) return -1;
    size_t got = fread(sig, 1, 64, f);
    int extra = (int)(fgetc(f) != EOF);
    fclose(f);
    if (got != 64 || extra != 0) return -1;
    return 0;
}

int ml_engine_init(const char *model_path)
{
    InitOnceExecuteOnce(&g_lock_once, init_lock_cb, NULL, NULL);
    const char *path = model_path;
    char bin_path[MAX_PATH] = {0};
    if (!path) {
        GetModuleFileNameA(NULL, bin_path, MAX_PATH);
        char *last = strrchr(bin_path, '\\');
        if (last) *last = '\0';
        strncat_s(bin_path, sizeof(bin_path), "\\ml\\models\\forest.bin", _TRUNCATE);
        path = bin_path;
    }

    FILE *f = NULL;
    if (fopen_s(&f, path, "rb") != 0 || !f) {
        f = NULL;
        /* Fallback: try the model relative to the executable directory */
        char exe_dir[MAX_PATH] = {0};
        GetModuleFileNameA(NULL, exe_dir, MAX_PATH);
        char *last = strrchr(exe_dir, '\\');
        if (last) *last = '\0';
        snprintf(bin_path, sizeof(bin_path), "%s\\ml\\models\\forest.bin", exe_dir);
        if (fopen_s(&f, bin_path, "rb") != 0) f = NULL;
        if (f) path = bin_path;
    }
    if (!f) { ml_log_security_event("ML engine: model file not found; ML layer disabled"); if (g_init_event) SetEvent(g_init_event); return -1; }
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsize <= 0 || fsize > MAX_FILE_SIZE) { fclose(f); ml_log_security_event("ML engine: model size out of bounds; ML layer disabled"); if (g_init_event) SetEvent(g_init_event); return -1; }

    /* Read the whole model into memory so it can be authenticated and parsed. */
    uint8_t *model = (uint8_t *)malloc((size_t)fsize);
    if (!model) { fclose(f); if (g_init_event) SetEvent(g_init_event); return -1; }
    if (fread(model, 1, (size_t)fsize, f) != (size_t)fsize) {
        free(model); fclose(f); if (g_init_event) SetEvent(g_init_event); return -1;
    }
    fclose(f);

    /* R-02: verify the Ed25519 signature before touching the model contents. */
    uint8_t sig[64] = {0};
    if (read_sig_file(path, sig) != 0) {
        free(model);
        ml_log_security_event("ML engine: signature file missing; refusing to load model");
        if (g_init_event) SetEvent(g_init_event);
        return -1;
    }
    if (ed25519_verify(sig, sizeof(sig), model, (size_t)fsize, k_ed25519_pubkey) != 0) {
        free(model);
        ml_log_security_event("ML engine: Ed25519 signature INVALID - model rejected (possible tampering)");
        if (g_init_event) SetEvent(g_init_event);
        return -1;
    }

    /* Parse the authenticated model from memory. */
    size_t off = 0;
    uint32_t magic = 0;
    if (fsize < 4) { free(model); if (g_init_event) SetEvent(g_init_event); return -1; }
    memcpy(&magic, model + off, 4); off += 4;
    if (magic != FOREST_MAGIC) {
        free(model); ml_log_security_event("ML engine: bad FORE magic - model rejected"); if (g_init_event) SetEvent(g_init_event); return -1;
    }

    BinaryForest *forest = (BinaryForest *)calloc(1, sizeof(BinaryForest));
    if (!forest) { free(model); return -1; }

    if (fsize - off < 8) { free(forest); free(model); if (g_init_event) SetEvent(g_init_event); return -1; }
    memcpy(&forest->num_trees, model + off, 4); off += 4;
    memcpy(&forest->num_features, model + off, 4); off += 4;
    if (forest->num_trees == 0 || forest->num_trees > MAX_TREES || forest->num_features != EXPECTED_FEATURES) {
        free(forest); free(model); ml_log_security_event("ML engine: bad tree/feature counts - model rejected"); if (g_init_event) SetEvent(g_init_event); return -1;
    }

    forest->trees = (BinaryTree *)calloc(forest->num_trees, sizeof(BinaryTree));
    if (!forest->trees) { free(forest); free(model); return -1; }

    for (uint32_t i = 0; i < forest->num_trees; i++) {
        uint32_t n_nodes;
        if (fsize - off < 4) goto fail;
        memcpy(&n_nodes, model + off, 4); off += 4;
        if (n_nodes == 0 || n_nodes > MAX_NODES_PER_TREE) goto fail;
        size_t bytes = (size_t)n_nodes * sizeof(ForestNode);
        if (bytes > (size_t)(fsize - off)) goto fail;
        forest->trees[i].num_nodes = n_nodes;
        forest->trees[i].nodes = (ForestNode *)malloc(bytes);
        if (!forest->trees[i].nodes) goto fail;
        memcpy(forest->trees[i].nodes, model + off, bytes); off += bytes;
    }

    free(model);
    EnterCriticalSection(&g_forest_lock);
    g_forest = forest;
    LeaveCriticalSection(&g_forest_lock);
    if (g_init_event) SetEvent(g_init_event);
    return 0;
fail:
    for (uint32_t j = 0; j < forest->num_trees; j++) free(forest->trees[j].nodes);
    free(forest->trees); free(forest); free(model);
    ml_log_security_event("ML engine: malformed model structure - model rejected");
    if (g_init_event) SetEvent(g_init_event);
    return -1;
}

void ml_engine_cleanup(void)
{
    EnterCriticalSection(&g_forest_lock);
    if (!g_forest) { LeaveCriticalSection(&g_forest_lock); return; }
    for (uint32_t i=0;i<g_forest->num_trees;i++) free(g_forest->trees[i].nodes);
    free(g_forest->trees); free(g_forest); g_forest=NULL;
    LeaveCriticalSection(&g_forest_lock);
    if (g_init_event) { CloseHandle(g_init_event); g_init_event=NULL; }
}

double ml_engine_scan(const FileFeatures *features)
{
    if (!g_forest && g_init_event) WaitForSingleObject(g_init_event, 1000);
    EnterCriticalSection(&g_forest_lock);
    BinaryForest *forest = g_forest;
    LeaveCriticalSection(&g_forest_lock);
    if (!forest || !features) return ML_SCORE_ERROR;
    float total = 0.0f;
    for (uint32_t i=0;i<forest->num_trees;i++) total += evaluate_tree(&forest->trees[i], features->vector);
    double log_odds = (double)total;
    return 1.0 / (1.0 + exp(-log_odds));
}
