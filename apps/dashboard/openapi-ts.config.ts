import { defineConfig } from '@hey-api/openapi-ts';

// Types for the admin API, generated from schema/openapi.json (`pnpm gen:api`); CI fails
// when src/api/ is out of date.
export default defineConfig({
  input: '../../schema/openapi.json',
  output: { path: 'src/api', format: false, lint: false },
  plugins: ['@hey-api/typescript'],
});
