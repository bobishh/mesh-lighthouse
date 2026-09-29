import { defineConfig } from "@playwright/test"

const port = Number(process.env.LIGHTHOUSE_E2E_PORT ?? 4243)

export default defineConfig({
  testDir: "./e2e",
  workers: 1,
  use: { baseURL: `http://127.0.0.1:${port}`, trace: "retain-on-failure" },
  webServer: {
    command: `npm run dev -- --host 127.0.0.1 --port ${port}`,
    port,
    reuseExistingServer: false,
  },
})
