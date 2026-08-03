/**
 * @file ml_engine.c
 * @brief Ultra-Lightweight Binary Decision Forest Engine
 */

#include "ml_engine.h"
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define FOREST_MAGIC                                                           \
  0x45524F46 // 'FORE' in little-endian (0x46, 0x4F, 0x52, 0x45)

#pragma pack(push, 1)
typedef struct {
  int16_t feature_index;
  float threshold;
  int32_t left_child;
  int32_t right_child;
  float value;
} ForestNode;

typedef struct {
  uint32_t num_nodes;
  ForestNode *nodes;
} BinaryTree;

typedef struct {
  uint32_t num_trees;
  uint32_t num_features;
  BinaryTree *trees;
} BinaryForest;
#pragma pack(pop)

static BinaryForest *g_forest = NULL;
static HANDLE g_init_event = NULL;

static float evaluate_tree(const BinaryTree *tree, const float *features) {
  uint32_t curr = 0;
  while (tree->nodes[curr].feature_index != -1) {
    int16_t feat_idx = tree->nodes[curr].feature_index;
    if (features[feat_idx] <= tree->nodes[curr].threshold) {
      curr = tree->nodes[curr].left_child;
    } else {
      curr = tree->nodes[curr].right_child;
    }
  }
  return tree->nodes[curr].value;
}

void ml_engine_pre_init(void) {
  if (!g_init_event) {
    g_init_event = CreateEvent(NULL, TRUE, FALSE, NULL);
  }
}

int ml_engine_init(const char *model_path) {
  FILE *f = fopen(model_path, "rb");
  if (!f) {
    // Fallback to searching relative to EXE
    char bin_path[MAX_PATH];
    GetModuleFileNameA(NULL, bin_path, MAX_PATH);
    char *last_slash = strrchr(bin_path, '\\');
    if (last_slash)
      *last_slash = '\0';
    strncat(bin_path, "\\ml\\models\\forest.bin",
            MAX_PATH - strlen(bin_path) - 1);
    f = fopen(bin_path, "rb");
  }

  if (!f) {
    if (g_init_event)
      SetEvent(g_init_event);
    return -1;
  }

  uint32_t magic = 0;
  if (fread(&magic, 4, 1, f) != 1 || magic != FOREST_MAGIC) {
    printf("[ML-ENGINE] INVALID MAGIC: 0x%08X (Expected 0x%08X)\n", magic,
           FOREST_MAGIC);
    fclose(f);
    if (g_init_event)
      SetEvent(g_init_event);
    return -1;
  }

  g_forest = calloc(1, sizeof(BinaryForest));
  if (!g_forest) {
    fclose(f);
    return -1;
  }

  fread(&g_forest->num_trees, 4, 1, f);
  fread(&g_forest->num_features, 4, 1, f);

  g_forest->trees = calloc(g_forest->num_trees, sizeof(BinaryTree));
  for (uint32_t i = 0; i < g_forest->num_trees; i++) {
    uint32_t n_nodes;
    if (fread(&n_nodes, 4, 1, f) != 1)
      break;
    g_forest->trees[i].num_nodes = n_nodes;
    g_forest->trees[i].nodes = malloc(n_nodes * sizeof(ForestNode));
    fread(g_forest->trees[i].nodes, sizeof(ForestNode), n_nodes, f);
  }

  fclose(f);
  printf("[ML-ENGINE] Binary Forest Ready. Trees: %u, Features: %u\n",
         g_forest->num_trees, g_forest->num_features);

  if (g_init_event)
    SetEvent(g_init_event);
  return 0;
}

void ml_engine_cleanup(void) {
  if (!g_forest)
    return;
  for (uint32_t i = 0; i < g_forest->num_trees; i++) {
    if (g_forest->trees[i].nodes)
      free(g_forest->trees[i].nodes);
  }
  free(g_forest->trees);
  free(g_forest);
  g_forest = NULL;
  if (g_init_event) {
    CloseHandle(g_init_event);
    g_init_event = NULL;
  }
}

double ml_engine_scan(const FileFeatures *features) {
  if (!g_forest && g_init_event)
    WaitForSingleObject(g_init_event, 1000);
  if (!g_forest || !features)
    return ML_SCORE_ERROR;

  float total_score = 0.0f;
  for (uint32_t i = 0; i < g_forest->num_trees; i++) {
    total_score += evaluate_tree(&g_forest->trees[i], features->vector);
  }
  /* LightGBM leaf values are raw log-odds.  Average them then apply
     the sigmoid to produce a calibrated [0, 1] malware probability. */
  double log_odds = (double)(total_score / (float)g_forest->num_trees);
  return 1.0 / (1.0 + exp(-log_odds));
}
