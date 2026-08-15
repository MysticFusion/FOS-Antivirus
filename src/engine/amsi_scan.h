/**
 * @file amsi_scan.h
 * @brief AMSI (Antimalware Scan Interface) client integration (U-10).
 *
 * FOS-Antivirus consumes AMSI as a CLIENT: script-type files (.ps1, .js,
 * .vbs, .hta, ...) are submitted to the OS's registered AMSI providers
 * (Windows Defender et al.) via AmsiScanBuffer, so fileless-style and
 * obfuscated script content is evaluated by the platform's script-aware
 * engines instead of only by our static heuristics.
 *
 * amsi.dll is loaded dynamically and all failures are non-fatal: when AMSI
 * is unavailable (older Windows, stripped server images) every scan simply
 * reports "clean/unavailable" and the heuristic/ML layers still run.
 *
 * Registering this application itself as an AMSI PROVIDER (the other half
 * of MAPv3 U-10) requires a COM DllRegisterServer + HKLM provider
 * registration and an installer with admin rights; it is out of scope for
 * this prototype and documented as such in the MAP.
 */

#ifndef AMSI_SCAN_H
#define AMSI_SCAN_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <wchar.h>
#include "path_utils.h"

#define AMSI_SCAN_CLEAN     0  /**< Not malicious (or AMSI unavailable)   */
#define AMSI_SCAN_MALWARE   1  /**< A registered AMSI provider flagged it */
#define AMSI_SCAN_ERROR    (-1) /**< Local failure (I/O, init)            */

/**
 * @brief Whether the AMSI machinery could be initialized on this system.
 * @return 1 if amsi.dll and its exports resolved, 0 otherwise.
 */
int amsi_scan_available(void);

/**
 * @brief Submit a memory buffer to the registered AMSI providers.
 *
 * @param buf          Content bytes (script text, etc.).
 * @param len          Content length in bytes.
 * @param content_name Attribution name providers see in telemetry
 *                     (typically the file path).
 * @return AMSI_SCAN_CLEAN / AMSI_SCAN_MALWARE / AMSI_SCAN_ERROR.
 */
int amsi_scan_buffer(const void *buf, size_t len, const wchar_t *content_name);

/**
 * @brief Read (up to a cap) and AMSI-scan the file at @p path.
 *
 * @param path         File to scan (fos_path_t, long-path safe).
 * @param content_name Attribution name; pass NULL to use the file's own
 *                     wide path.
 * @return AMSI_SCAN_CLEAN / AMSI_SCAN_MALWARE / AMSI_SCAN_ERROR
 *         (unavailable AMSI or read failure => CLEAN / ERROR, never a
 *         false MALWARE).
 */
int amsi_scan_file_wide(const fos_path_t *path, const wchar_t *content_name);

#ifdef __cplusplus
}
#endif

#endif /* AMSI_SCAN_H */
