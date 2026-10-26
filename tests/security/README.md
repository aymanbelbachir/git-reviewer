# Security test suite

Each test here plays an attack against git-reviewer and asserts that it fails (docs/SPEC.md
security requirement 9; threat IDs refer to SECURITY.md). Files under `fixtures/` are malicious
samples: they are data, never collected by pytest (`norecursedirs`) and only ever run inside the
Docker sandbox.

## The attacks the spec requires

| Attack | Test | Threat |
|---|---|---|
| Diff with a prompt injection in a comment | `test_phase3_attacks.py::test_injection_in_a_comment_never_reaches_the_reviewer` | T-01 |
| Patch with path traversal | `test_phase5_attacks.py::test_edits_outside_the_reviewed_file_are_refused` | T-18 |
| Test that attempts network access | `test_phase4_attacks.py::test_network_is_unreachable` (fixture `network.txt`) | T-10 |
| Test that reads `~/.ssh` | `test_phase4_attacks.py::test_host_secrets_and_environment_are_not_visible` (fixture `host_secrets.txt`) | T-11 |
| Infinite loop | `test_phase4_attacks.py::test_infinite_loop_is_stopped` | T-12 |
| Fork bomb | `test_phase4_attacks.py::test_fork_bomb_is_contained` | T-12 |
| Symlink pointing outside the repository | `test_phase4_attacks.py::test_out_of_repo_symlinks_and_untracked_secrets_never_reach_the_sandbox`, `test_phase5_attacks.py::test_a_file_swapped_for_a_symlink_before_applying_is_not_followed` | T-18 |

## By phase

- `test_phase2_attacks.py`: git option injection, planted binaries, `git commit -a` bypass,
  exfiltration through the model endpoint or tracing, `.gitattributes` and submodule tricks.
- `test_phase3_attacks.py`: prompt injection, canary extraction, guardian flooding and failure,
  Trojan Source, hidden encodings, blinded scanners.
- `test_phase4_attacks.py`: weakened Docker commands, remote Docker, and, with Docker (marker
  `docker`), network, host secrets, resource bombs, writes, a planted `pytest`.
- `test_phase5_attacks.py`: backdoored or test-weakening patches, edits outside the reviewed file,
  symlink and time-of-check races when applying, hidden code in a patch.
- `test_phase6_attacks.py`: the pre-commit hook through real `git commit` runs.

The Docker tests are skipped when Docker or the sandbox image is missing; the `verify` skill reports
such a skip as a failure.
