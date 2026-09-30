import { expect, test } from "@playwright/test"

const matchOrigin = "https://match.example"

async function signedInOperator(page: import("@playwright/test").Page) {
  await page.route("**/admin/api/session", route => route.fulfill({ json: {
    csrfToken: "operator-csrf", personId: null, displayName: "Operator", operator: true,
  } }))
  await page.route("**/admin/api/overview", route => route.fulfill({ json: {
    keeper: { displayName: "Lighthouse", personId: "person", deviceId: "device", boards: [] },
    triggers: [], replication: { state: "idle", activePeers: 0 },
  } }))
  await page.route("**/admin/api/pairings", route => route.fulfill({ json: { pairings: [] } }))
}

test("Given an operator, when allowed origins are saved, then Match stays required and homepage is accepted", async ({ page }) => {
  await signedInOperator(page)
  await page.route("**/admin/api/settings/cors", route => {
    if (route.request().method() === "GET") return route.fulfill({ json: {
      requiredOrigin: matchOrigin, origins: [matchOrigin],
    } })
    expect(route.request().headers()["x-csrf-token"]).toBe("operator-csrf")
    expect(route.request().postDataJSON()).toEqual({ origins: [matchOrigin, "https://meta-uber-engineer.dev"] })
    return route.fulfill({ json: { requiredOrigin: matchOrigin, origins: [matchOrigin, "https://meta-uber-engineer.dev"] } })
  })
  await page.goto("/admin/")
  await expect(page.getByRole("heading", { name: "Settings" })).toBeVisible()
  await expect(page.getByText(`Match: ${matchOrigin}`)).toBeVisible()
  await page.getByRole("textbox", { name: "Additional origins" }).fill("https://meta-uber-engineer.dev")
  await page.getByRole("button", { name: "Save origins" }).click()
  await expect(page.getByRole("status")).toContainText("Allowed origins saved")
})

test("Given a save failure, when operator retries later, then draft remains and error is visible", async ({ page }) => {
  await signedInOperator(page)
  await page.route("**/admin/api/settings/cors", route => route.request().method() === "GET"
    ? route.fulfill({ json: { requiredOrigin: matchOrigin, origins: [matchOrigin] } })
    : route.fulfill({ status: 503, json: { message: "Settings unavailable" } }))
  await page.goto("/admin/")
  const origins = page.getByRole("textbox", { name: "Additional origins" })
  await origins.fill("https://meta-uber-engineer.dev")
  await page.getByRole("button", { name: "Save origins" }).click()
  await expect(page.getByRole("alert")).toContainText("Settings unavailable")
  await expect(origins).toHaveValue("https://meta-uber-engineer.dev")
})
