# NEHONIX FileGuard Manual Tests

This directory contains manual tests for the NEHONIX FileGuard library. These tests are designed to be run manually using `ts-node` and provide a comprehensive verification of the library's functionality.

## Test Files

- `cryptUtils.manual.ts`: Tests for the cryptUtils module, which provides simplified encryption and decryption functions
- `fileGuardManager.manual.ts`: Tests for the FileGuardManager class, which is the core component of the library
- `security.manual.ts`: Tests for the security features of the library

## Running the Tests

Before running the tests, make sure you have built the library:

```bash
npm run build
```

Then, you can run the tests using `ts-node`:

```bash
npx ts-node tests/manual/cryptUtils.manual.ts
npx ts-node tests/manual/fileGuardManager.manual.ts
npx ts-node tests/manual/security.manual.ts
```

## Test Output

The tests will create encrypted files in the `tests/output` directory. This directory is created automatically if it doesn't exist.

Each test will output detailed information about the encryption and decryption process, including:

- File paths
- File sizes
- Encryption and decryption times
- Compression ratios
- Data integrity checks

## Test Coverage

The manual tests cover the following functionality:

### cryptUtils.manual.ts
- Basic encryption and decryption
- Binary format encryption and decryption
- Performance testing with large data

### fileGuardManager.manual.ts
- Advanced encryption and decryption
- Binary secure format encryption and decryption
- Simple binary format encryption and decryption
- Testing different security levels

### security.manual.ts
- Tamper protection
- Key security
- Persistent RSA keys

## Troubleshooting

If you encounter any issues running the tests, check the following:

1. Make sure you have built the library with `npm run build`
2. Ensure you have the necessary dependencies installed
3. Check that the output directory is writable
4. If you get errors about missing modules, make sure you're running the tests from the project root directory

## Adding New Tests

To add a new manual test:

1. Create a new file in the `tests/manual` directory with a `.manual.ts` extension
2. Import the necessary modules from the `dist` directory (not the `src` directory)
3. Follow the pattern of the existing tests:
   - Set up the test environment
   - Run the tests
   - Verify the results
   - Clean up after the tests
4. Add your new test to this README file
