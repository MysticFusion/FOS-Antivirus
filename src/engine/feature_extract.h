/**
 * @file feature_extract.h
 * @brief Static File Feature Extraction Interface
 *
 * This module provides the logic for extracting static features from files,
 * which are used by the heuristic and ML engines for threat detection.
 *
 */

#ifndef FEATURE_EXTRACT_H
#define FEATURE_EXTRACT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>
#include "path_utils.h"

/* ============================================================================
 * Scan Reason Definitions
 * ========================================================================== */

/**
 * @brief The context or trigger for the current scan.
 */
typedef enum {
    SCAN_REASON_MANUAL = 0,        /**< User-initiated manual scan */
    SCAN_REASON_RT_CREATE,         /**< Real-time: File created */
    SCAN_REASON_RT_MODIFY,         /**< Real-time: File modified */
    SCAN_REASON_RANSOMWARE_BURST   /**< Dynamic: Burst of rapid file events */
} ScanReason;

/* ============================================================================
 * Feature Vector Structure
 * ========================================================================== */

/**
 * @brief Represents the static feature set extracted from a single file.
 *
 * These features are deterministic and do not require code execution.
 */
typedef struct {
    /* Basic properties */
    bool     exists;          /**< True if file was found and accessible */
    
    /* EMBER-2024 Full 2381-Dimensional Feature Vector */
    float    vector[2381];    /**< The dense float array passed to the LightGBM engine */
    
    /* Legacy / Helpers (Required for Heuristic Engine) */
    bool     is_executable;    /**< True if extension matches known executables */
    bool     is_pe;            /**< True if valid PE header found */
    
    bool     in_temp_dir;      /**< True if inside a system Temp folder */
    bool     in_downloads_dir; /**< True if inside the Downloads folder */
    bool     in_startup_dir;   /**< True if in a standard persistence location */
    bool     high_entropy;     /**< True if entropy exceeds malware threshold */
    bool     known_bad_hash;   /**< True if hash matches known malware */

    /* PE-aware signals (R-07 / I-20). Valid only when is_pe is true. */
    int      pe_import_count;      /**< Number of import functions seen, -1 if not parsed */
    bool     pe_suspicious_import; /**< CreateRemoteThread/VirtualAllocEx/WriteProcessMemory/SetWindowsHookEx/CreateService */
    bool     pe_packer_marker;     /**< UPX/.MPRESS/.aspack section names, or high section entropy with tiny import table */
    bool     pe_overlay;           /**< File size exceeds SizeOfImage (appended data) */
    bool     pe_rwx_section;       /**< Section with MEM_EXECUTE|MEM_WRITE */
    bool     pe_ep_outside_text;   /**< Entry point not inside the .text section */
    uint32_t pe_resource_size;     /**< Resource directory size in bytes */
} FileFeatures;

/* ============================================================================
 * Public Functions
 * ========================================================================== */

/**
 * @brief Extract features from a file for analysis.
 *
 * Performs static analysis on the file at the specified path to populate
 * the feature vector.
 *
 * @param[in]  path         Absolute path to the file.
 * @param[out] out_features Pointer to the structure to be populated.
 *
 * @return 0 on success, negative error code on failure:
 *         - -1: Invalid parameters
 *         - -2: File not found or is a directory
 */
int extract_file_features(const char *path, FileFeatures *out_features);

/**
 * @brief Long-path-safe variant: extract features from a file addressed by
 *        a fos_path_t (wide path with automatic "\\?\" prefixing). No A->W
 *        conversion is performed.
 *
 * @return 0 on success, negative error code on failure:
 *         - -1: Invalid parameters
 *         - -2: File not found or is a directory
 */
int extract_file_features_wide(const fos_path_t *path, FileFeatures *out_features);

#ifdef __cplusplus
}
#endif

#endif /* FEATURE_EXTRACT_H */