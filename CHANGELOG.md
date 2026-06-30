# Changelog

## 2026-06-29 - Public And Developer Delivery Refresh

- Added a public changelog for release status.
- Updated CI to current `actions/checkout` and removed the floating CMake
  setup action.
- Normalized scanner-blocking dash punctuation in public docs, headers, tests,
  and examples.

## Current Status

- Runtime: Windows x64 C++23 static library.
- Surfaces: headers, static library target, examples, docs, public claim files,
  and CTest tests.
- Verification: CMake configure, build, CTest, and public surface sweep.
