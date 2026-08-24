A release candidate cut for one reason: to prove the release automation added
in 0.1.2 actually works end to end, rather than discovering it on a real
release. Nothing in the tool changed.

### Changed

- The release job no longer marks every release as `--latest`. A version
  carrying a PEP 440 pre-release marker (`a`, `b`, `rc`, `.dev`) is published
  with `--prerelease` instead, so a candidate cannot present itself as the
  current version. Found by writing this test.
