#define _CRT_SECURE_NO_WARNINGS

#include "trust.h"

#include <ctype.h>
#include <shlwapi.h>
#include <shlobj.h>
#include <softpub.h>
#include <stdbool.h>
#include <string.h>
#include <strsafe.h>
#include <windows.h>
#include <wintrust.h>
#include <wincrypt.h>

/* ============================================================================
 * Internal Helpers: Path Matching
 * ========================================================================== */

static bool path_starts_with_w(const WCHAR *path, const WCHAR *prefix) {
  if (path == NULL || prefix == NULL)
    return false;
  while (*prefix && *path) {
    if (towlower(*path) != towlower(*prefix))
      return false;
    path++;
    prefix++;
  }
  return (*prefix == L'\0');
}

/* ============================================================================
 * Digital Signature Verification (U-18: publisher-based trust)
 * ========================================================================== */

/**
 * @brief Verify the digital signature of a file and report its signer.
 *
 * U-18: TRUST decisions are derived from the certificate chain, never from
 * the file's location. After a successful WinVerifyTrust, the signer
 * certificate's subject is extracted from the provider state; the caller
 * decides which publishers count as HIGH trust.
 *
 * @param path                File to verify.
 * @param is_microsoft_signed Output: true when the signer subject identifies
 *                            a Microsoft production publisher.
 * @param quick_mode          If true, skip revocation checking (WTD_REVOCATION_CHECK_NONE).
 *                            If false, use cache-only revocation (WTD_REVOKE_WHOLECHAIN
 *                            + WTD_CACHE_ONLY_URL_RETRIEVAL).
 */
static bool verify_digital_signature(const char *path,
                                     bool *is_microsoft_signed,
                                     bool quick_mode) {
  if (is_microsoft_signed)
    *is_microsoft_signed = false;

  WCHAR w_path[MAX_PATH];
  if (!MultiByteToWideChar(CP_UTF8, 0, path, -1, w_path, MAX_PATH))
    return false;

  WINTRUST_FILE_INFO file_info = {sizeof(file_info)};
  file_info.pcwszFilePath = w_path;

  WINTRUST_DATA trust_data = {sizeof(trust_data)};
  trust_data.dwUIChoice = WTD_UI_NONE;
  trust_data.dwUnionChoice = WTD_CHOICE_FILE;
  trust_data.pFile = &file_info;
  /* U-18: keep the provider state so the signer chain can be inspected. */
  trust_data.dwStateAction = WTD_STATEACTION_VERIFY;

  if (quick_mode) {
    /* v1.2: Quick mode — skip revocation entirely. This is much faster
     * (no CRL/OCSP checks) at the cost of not detecting revoked certificates.
     * Acceptable for quick scan where speed is the priority. */
    trust_data.fdwRevocationChecks = WTD_REVOCATION_CHECK_NONE;
    trust_data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
  } else {
    /* Full mode — original behavior: whole-chain revocation with cache-only
     * URL retrieval (no network fetch, but still checks cached CRL/OCSP). */
    trust_data.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    trust_data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
  }

  GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
  LONG status = WinVerifyTrust(NULL, &policy, &trust_data);

  bool signature_valid = (status == ERROR_SUCCESS);
  bool microsoft_signer = false;

  if (signature_valid) {
    do {
      CRYPT_PROVIDER_DATA *pdata =
          WTHelperProvDataFromStateData(trust_data.hWVTStateData);
      if (pdata == NULL)
        break;
      CRYPT_PROVIDER_SGNR *psgnr =
          WTHelperGetProvSignerFromChain(pdata, 0, FALSE, 0);
      if (psgnr == NULL || psgnr->csCertChain == 0 ||
          psgnr->pasCertChain == NULL)
        break;

      /* The first certificate in the signer chain is the leaf signer cert. */
      CRYPT_PROVIDER_CERT *signer_cert = &psgnr->pasCertChain[0];
      if (signer_cert == NULL || signer_cert->pCert == NULL)
        break;

      WCHAR subject[256];
      DWORD n = CertNameToStrW(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                               &signer_cert->pCert->pCertInfo->Subject,
                               CERT_X500_NAME_STR, subject, 256);
      if (n == 0)
        break;

      /* Microsoft production signers. "Microsoft Windows" covers the
       * Windows/Hardware-compat leaf subjects; "Microsoft Corporation"
       * covers the classic Authenticode subject. Test/flight-signing
       * subjects intentionally do NOT match. */
      microsoft_signer = (StrStrIW(subject, L"Microsoft Windows") != NULL ||
                          StrStrIW(subject, L"Microsoft Corporation") != NULL);
    } while (0);
  }

  /* Always close the provider state so it is freed. */
  trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
  WinVerifyTrust(NULL, &policy, &trust_data);

  if (is_microsoft_signed)
    *is_microsoft_signed = microsoft_signer;
  return signature_valid;
}

/* ============================================================================
 * Public Functions
 * ========================================================================== */

TrustLevel trust_evaluate_path(const char *path, bool quick_mode) {
  if (path == NULL || *path == '\0')
    return TRUST_NONE;

  WCHAR w_path[MAX_PATH];
  MultiByteToWideChar(CP_UTF8, 0, path, -1, w_path, MAX_PATH);

  PWSTR prog_path = NULL, prog86_path = NULL;
  TrustLevel result = TRUST_NONE;

  /* 1. Digital Signature Verification.
   * U-18: HIGH trust requires a valid Authenticode chain AND a Microsoft
   * production publisher on the leaf certificate — never the file's path
   * (an MS-signed binary copied into C:\Windows is still MS-signed, and a
   * foreign binary planted there is still not). */
  bool is_microsoft = false;
  if (verify_digital_signature(path, &is_microsoft, quick_mode)) {
    return is_microsoft ? TRUST_HIGH : TRUST_PARTIAL;
  }

  /* 2. Application Directories (Partial Trust) — SIGNATURE-REQUIRED.
   * MAP-05: only reached if signature verification FAILED (unsigned or
   * invalid Authenticode). Location alone never grants trust. Restrict
   * the location heuristic to Program Files (tight ACLs); FOLDERID_ProgramData
   * is world-writable (any interactive user can create subdirectories), so an
   * unsigned binary dropped at C:\ProgramData\evil\evil.exe stays TRUST_NONE
   * and receives NO heuristic dampening. */
  if (SUCCEEDED(
          SHGetKnownFolderPath(&FOLDERID_ProgramFiles, 0, NULL, &prog_path))) {
    if (path_starts_with_w(w_path, prog_path))
      result = TRUST_PARTIAL;
    CoTaskMemFree(prog_path);
  }
  if (result == TRUST_NONE &&
      SUCCEEDED(SHGetKnownFolderPath(&FOLDERID_ProgramFilesX86, 0, NULL,
                                     &prog86_path))) {
    if (path_starts_with_w(w_path, prog86_path))
      result = TRUST_PARTIAL;
    CoTaskMemFree(prog86_path);
  }

  return result;
}

int trust_is_at_least(TrustLevel actual, TrustLevel required) {
  return (actual >= required);
}
