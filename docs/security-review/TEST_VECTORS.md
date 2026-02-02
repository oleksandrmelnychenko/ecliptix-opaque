# Test Vectors and Reproducibility

## Current State
- The implementation uses system RNG via libsodium. There is no built-in deterministic test vector generator.
- Protocol logs print hex values for many internal buffers, which can be used to extract transcripts for review.

## Generating Sample Transcripts
1) Build with tests enabled
2) Run the test suite and capture stdout

Example:
```sh
./build.sh native Release ON
ctest --test-dir build-macos-release --output-on-failure > test_log.txt
```

The log output includes:
- Registration request/response
- KE1, KE2, KE3 values
- Transcript hash and derived keys

## If Deterministic Vectors Are Required
- Introduce a deterministic RNG hook in crypto::random_bytes for review builds
- Capture a single full flow and publish as a fixed test vector
