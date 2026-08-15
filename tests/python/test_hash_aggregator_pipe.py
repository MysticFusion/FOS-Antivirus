#!/usr/bin/env python3
"""
test_hash_aggregator_pipe.py -- Regression tests for U-01 and U-02 (MAPv3).

  U-01: The aggregator error handler must not discard Python tracebacks.
        emit_source_fail() must accept exc_info and surface the full
        traceback in the log when an unexpected exception occurs.
  U-02: _emit() must survive a broken stdout pipe (BrokenPipeError /
        Windows OSError [Errno 22]) instead of crashing the update run.

Run: python tests/python/test_hash_aggregator_pipe.py
"""

import io
import logging
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import hash_aggregator  # noqa: E402

failures = 0


def check(name, cond, detail=""):
    global failures
    safe = lambda s: s.encode("ascii", "backslashreplace").decode("ascii")
    print(f"[{'PASS' if cond else 'FAIL'}] {safe(name)}" + (f" -- {safe(detail)}" if detail else ""))
    if not cond:
        failures += 1


# ---------------------------------------------------------------------------
# U-02: _emit() must tolerate a broken stdout pipe
# ---------------------------------------------------------------------------

def test_emit_survives_broken_pipe():
    real_print = print
    captured = []

    def exploding_print(*args, **kwargs):
        raise OSError(22, "Invalid argument")  # Windows broken-pipe surface

    import builtins
    builtins.print = exploding_print
    try:
        try:
            hash_aggregator._emit({"event": "progress", "pct": 50})
            ok = True
        except OSError:
            ok = False
    finally:
        builtins.print = real_print
    check("U-02 _emit() survives OSError(22) on broken pipe", ok)


def test_emit_survives_brokenpipeerror():
    real_print = print
    captured = []

    def exploding_print(*args, **kwargs):
        raise BrokenPipeError(32, "Broken pipe")

    import builtins
    builtins.print = exploding_print
    try:
        try:
            hash_aggregator._emit({"event": "source_done", "count": 1})
            ok = True
        except BrokenPipeError:
            ok = False
    finally:
        builtins.print = real_print
    check("U-02 _emit() survives BrokenPipeError", ok)


# ---------------------------------------------------------------------------
# U-01: emit_source_fail() must log full tracebacks when exc_info is set
# ---------------------------------------------------------------------------

def test_emit_source_fail_logs_traceback():
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    logger = logging.getLogger("hash_aggregator")
    old_level = logger.level
    logger.setLevel(logging.ERROR)
    logger.addHandler(handler)
    try:
        # Suppress the JSONL stdout output during the call
        real_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            try:
                raise RuntimeError("boom inside adapter")
            except Exception as e:
                hash_aggregator.emit_source_fail(
                    "test_source", f"unexpected error: {type(e).__name__}: {e}",
                    exc_info=True,
                )
        finally:
            sys.stdout = real_stdout
        log_text = stream.getvalue()
        check("U-01 traceback text present in log",
              "Traceback (most recent call last)" in log_text,
              detail=repr(log_text[:200]))
        check("U-01 exception message present in log",
              "boom inside adapter" in log_text)
        check("U-01 error line present in log",
              "Source test_source failed" in log_text)
    finally:
        logger.removeHandler(handler)
        logger.setLevel(old_level)


def test_emit_source_fail_without_exc_info():
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    logger = logging.getLogger("hash_aggregator")
    old_level = logger.level
    logger.setLevel(logging.ERROR)
    logger.addHandler(handler)
    try:
        real_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            hash_aggregator.emit_source_fail("test_source", "HTTP 503")
        finally:
            sys.stdout = real_stdout
        log_text = stream.getvalue()
        check("U-01 no traceback for expected errors",
              "Traceback (most recent call last)" not in log_text)
        check("U-01 expected-error line still logged",
              "Source test_source failed: HTTP 503" in log_text)
    finally:
        logger.removeHandler(handler)
        logger.setLevel(old_level)


if __name__ == "__main__":
    test_emit_survives_broken_pipe()
    test_emit_survives_brokenpipeerror()
    test_emit_source_fail_logs_traceback()
    test_emit_source_fail_without_exc_info()
    print()
    if failures:
        print(f"{failures} check(s) FAILED")
        sys.exit(1)
    print("ALL CHECKS PASSED")
