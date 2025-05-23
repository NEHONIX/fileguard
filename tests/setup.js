// Jest setup file

// Increase timeout for all tests
jest.setTimeout(30000); // 30 seconds

// Suppress console output during tests
if (process.env.JEST_HIDE_CONSOLE) {
  global.console = {
    ...console,
    log: jest.fn(),
    info: jest.fn(),
    debug: jest.fn(),
    warn: jest.fn(),
    // Keep error for debugging
    error: console.error,
  };
}

// Create a global beforeAll hook
beforeAll(() => {
  // Set NODE_ENV to test
  process.env.NODE_ENV = 'test';
});
