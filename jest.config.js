module.exports = {
  preset: "ts-jest",
  testEnvironment: "node",
  testMatch: ["**/tests/**/*.ts"],
  collectCoverage: true,
  coverageDirectory: "coverage",
  collectCoverageFrom: ["src/**/*.ts"],
  // Handle ESM modules
  transformIgnorePatterns: [
    "/node_modules/(?!(nehoid|nehonix-uri-processor|chalk)/)",
  ],
  // Increase timeout for async tests
  testTimeout: 30000,
};
