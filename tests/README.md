# NEHONIX FileGuard Tests

This directory contains comprehensive tests for the NEHONIX FileGuard library.

## Test Structure

The tests are organized into the following directories:

- `core/`: Tests for core functionality like FileGuardManager and binary formats
- `utils/`: Tests for utility functions like cryptUtils and Fortify integration
- `security/`: Tests specifically focused on security features
- `performance/`: Tests that measure the performance of different encryption methods

## Running Tests

To run all tests:

```bash
npm test
```

To run a specific test file:

```bash
npm test -- tests/core/fileGuardManager.test.ts
```

To run tests with a specific pattern:

```bash
npm test -- -t "should encrypt and decrypt"
```

## Test Output Directory

Test files are created in the `tests/output` directory, which is automatically created and cleaned up during tests.

## Performance Tests

Performance tests measure the execution time of different encryption methods with various data sizes. These tests may take longer to run and are included in the regular test suite.

To run only performance tests:

```bash
npm test -- tests/performance
```

## Coverage Reports

Test coverage reports are generated in the `coverage` directory. You can view the HTML report by opening `coverage/lcov-report/index.html` in a browser.

## Test Utilities

The `tests/utils/testUtils.ts` file contains utility functions for testing, such as:

- Generating test data of various sizes
- Creating and cleaning up test directories
- Generating encryption keys and RSA key pairs
- Verifying data integrity
- Measuring execution time

## Notes

- Tests are configured to run in a special "test" environment where fallback mode is enabled
- Some tests may fail if the required cryptographic algorithms are not available on your system
- Ultra-secure encryption tests may be skipped on some systems due to algorithm compatibility issues
