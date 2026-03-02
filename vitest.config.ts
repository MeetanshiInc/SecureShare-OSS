import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      include: ['src/**/*.ts'],
      exclude: ['src/**/*.d.ts']
    },
    testTimeout: 30000, // 30 seconds for property-based tests
  },
  resolve: {
    alias: {
      '@shared': './src/shared',
      '@worker': './src/worker',
      '@frontend': './src/frontend'
    }
  }
});
