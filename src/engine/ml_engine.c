/**
 * @file ml_engine.c - Hardened ML engine
 */
#include "ml_engine.h"
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
    if (!f) { if (g_init_event) SetEvent(g_init_event); return -1; }
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsize <= 0 || fsize > MAX_FILE_SIZE) { fclose(f); if (g_init_event) SetEvent(g_init_event); return -1; }

    uint32_t magic = 0;
    if (fread(&magic, 4, 1, f) != 1 || magic != FOREST_MAGIC) {
        fclose(f); if (g_init_event) SetEvent(g_init_event); return -1;
    }

    BinaryForest *forest = (BinaryForest*)calloc(1, sizeof(BinaryForest));
    if (!forest) { fclose(f); return -1; }

    if (fread(&forest->num_trees, 4, 1, f) != 1 || fread(&forest->num_features, 4, 1, f) != 1) {
        free(forest); fclose(f); if (g_init_event) SetEvent(g_init_event); return -1;
    }
    if (forest->num_trees == 0 || forest->num_trees > MAX_TREES || forest->num_features != EXPECTED_FEATURES) {
        free(forest); fclose(f); if (g_init_event) SetEvent(g_init_event); return -1;
    }

    forest->trees = (BinaryTree*)calloc(forest->num_trees, sizeof(BinaryTree));
    if (!forest->trees) { free(forest); fclose(f); return -1; }

    for (uint32_t i=0;i<forest->num_trees;i++) {
        uint32_t n_nodes;
        if (fread(&n_nodes, 4, 1, f) != 1 || n_nodes==0 || n_nodes > MAX_NODES_PER_TREE) goto fail;
        forest->trees[i].num_nodes = n_nodes;
        forest->trees[i].nodes = (ForestNode*)malloc(n_nodes * sizeof(ForestNode));
        if (!forest->trees[i].nodes) goto fail;
        if (fread(forest->trees[i].nodes, sizeof(ForestNode), n_nodes, f) != n_nodes) goto fail;
    }

    fclose(f);
    EnterCriticalSection(&g_forest_lock);
    g_forest = forest;
    LeaveCriticalSection(&g_forest_lock);
    if (g_init_event) SetEvent(g_init_event);
    return 0;
fail:
    for (uint32_t j=0;j<forest->num_trees;j++) free(forest->trees[j].nodes);
    free(forest->trees); free(forest); fclose(f);
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
