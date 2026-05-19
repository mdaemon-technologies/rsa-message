import type { Config } from "jest";

const config: Config = {
  preset: 'ts-jest',
  verbose: true,
  transform: {
    "^.+\\.ts?$": ["ts-jest", { tsconfig: "tsconfig.test.json" }]
  },
  testEnvironment: 'jsdom',
  setupFiles: ['<rootDir>/src/setupTests.ts'],
  testPathIgnorePatterns: [
    "<rootDir>/dist/",
    "<rootDir>/public/",
  ]
};

export default config;