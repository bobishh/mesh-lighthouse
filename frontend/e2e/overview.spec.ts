import { expect, test } from "@playwright/test"

const overview = (state: string) => ({
  keeper: {
    displayName: "mesh-lighthouse", personId: "keeper-person", deviceId: "keeper-device",
    boards: [{ workspaceId: "board-1", title: "Garden", isPrimary: true, heads: ["head-1"], peerCount: 2,
      replication: { state, activePeers: state === "connected" ? 1 : 0 } }],
  },
  triggers: [{ id: "jev", name: "JEV", configured: true, model: "jev-1.13.0", pendingCount: 0,
    outcomes: { awaitingMesh: 0, chatQueued: 0, cardCreated: 1 } }],
  replication: { state, activePeers: state === "connected" ? 1 : 0 },
})

test("Given an operator session, when overview changes, then Lighthouse updates without manual refresh", async ({ page }) => {
  await page.clock.install()
  let reads = 0
  await page.route("**/admin/api/session", route => route.fulfill({ json: {
    csrfToken: "csrf", personId: null, displayName: "Operator", operator: true,
  } }))
  await page.route("**/admin/api/overview", route => route.fulfill({ json: overview(++reads === 1 ? "idle" : "connected") }))
  await page.route("**/admin/api/pairings", route => route.fulfill({ json: { pairings: [] } }))

  await page.goto("/admin/")
  await expect(page.getByRole("heading", { name: "LIGHTHOUSE", exact: true })).toBeVisible()
  await expect(page.getByText("Replication idle", { exact: true })).toBeVisible()
  await expect(page.getByText("Garden")).toBeVisible()
  await expect(page.getByRole("button", { name: "Refresh overview" })).toHaveCount(0)
  await expect(page.getByText("Service keeper")).toHaveCount(0)
  await expect(page.getByText("Separate from keeper status")).toHaveCount(0)
  await page.clock.runFor(5_000)
  await expect(page.getByText("Replication connected", { exact: true })).toBeVisible()
  expect(reads).toBeGreaterThan(1)
})

test("Given a live overview, when one poll fails, then prior data stays and next poll recovers", async ({ page }) => {
  await page.clock.install()
  let reads = 0
  await page.route("**/admin/api/session", route => route.fulfill({ json: {
    csrfToken: "csrf", personId: null, displayName: "Operator", operator: true,
  } }))
  await page.route("**/admin/api/overview", route => {
    reads++
    if (reads === 2) return route.fulfill({ status: 503, json: { message: "Temporarily unavailable" } })
    return route.fulfill({ json: overview(reads === 1 ? "idle" : "connected") })
  })
  await page.route("**/admin/api/pairings", route => route.fulfill({ json: { pairings: [] } }))

  await page.goto("/admin/")
  await expect(page.getByText("Garden")).toBeVisible()
  await page.clock.runFor(5_000)
  await expect(page.getByRole("status")).toContainText("Temporarily unavailable")
  await expect(page.getByText("Garden")).toBeVisible()
  await page.clock.runFor(5_000)
  await expect(page.getByText("Replication connected", { exact: true })).toBeVisible()
  await expect(page.getByRole("status")).toHaveCount(0)
})
