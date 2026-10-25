Malicious test files for the sandbox attack tests (tests/security/test_phase4_attacks.py).
They are DATA. They are copied into a temporary repository as tests/test_attack.py and run only
inside the Docker sandbox. Never run, import or collect them on the host (SECURITY.md T-32).

Each file fails on purpose so pytest shows its message:
  ATTACK-BLOCKED: ...  the sandbox stopped the attack (expected)
  SANDBOX-ESCAPE: ...  the attack worked (the host-side test fails)
