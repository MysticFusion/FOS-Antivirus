#include "scan_executor.h"

#include <stdio.h>
#include <string.h>

static int expect_action(const char *name, const SignatureResult *sig,
                         const HeuristicResult *heur, double ml_score,
                         TrustLevel trust, ResponseAction expected) {
  ScanDecision decision;
  execute_scan_decision("sample.exe", sig, heur, ml_score, trust, &decision);
  if (decision.action != expected) {
    fprintf(stderr, "%s: expected action %d, got %d (%s)\n", name, expected,
            decision.action, decision.reason);
    return 1;
  }
  return 0;
}

int main(void) {
  int failures = 0;

  SignatureResult sig_match = {.matched = true, .label = "Test.Signature"};
  HeuristicResult high_heur = {.score = 95};
  HeuristicResult medium_heur = {.score = 60};

  failures += expect_action("signature quarantines", &sig_match, NULL, -1.0,
                            TRUST_NONE, ACTION_QUARANTINE);
  failures += expect_action("unsigned high heuristic quarantines", NULL,
                            &high_heur, -1.0, TRUST_NONE, ACTION_QUARANTINE);
  failures += expect_action("signed high heuristic monitors", NULL, &high_heur,
                            -1.0, TRUST_PARTIAL, ACTION_MONITOR);
  failures += expect_action("ml 0.81 monitors", NULL, NULL, 0.81, TRUST_NONE,
                            ACTION_MONITOR);
  failures += expect_action("ml 0.95 monitors", NULL, NULL, 0.95, TRUST_NONE,
                            ACTION_MONITOR);
  failures += expect_action("medium heuristic monitors", NULL, &medium_heur,
                            -1.0, TRUST_NONE, ACTION_MONITOR);

  return failures == 0 ? 0 : 1;
}
