<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from "vue"
import LighthouseMark from "./LighthouseMark.vue"

type Board = {
  workspaceId: string
  title: string
  isPrimary: boolean
  heads: string[]
  peerCount: number
  lastSavedAt?: number | null
  replication?: { state: string; activePeers: number; lastSuccessAt?: number | null; lastErrorCategory?: string | null }
}
type Trigger = {
  id: string
  name: string
  configured: boolean
  model: string
  pendingCount: number
  outcomes: { awaitingMesh: number; chatQueued: number; cardCreated: number }
}
type Overview = {
  keeper: { displayName: string; personId: string; deviceId: string; boards: Board[] }
  triggers: Trigger[]
  replication: { state: string; activePeers: number; lastSuccessAt?: number | null; lastErrorCategory?: string | null }
}
type AdminIdentity = { personId: string | null; displayName: string; operator: boolean }
type CorsSettings = { origins: string[]; requiredOrigin: string }
type Pairing = {
  id: string
  comparisonCode: string
  controller: { displayName: string }
  controllerFingerprint: string
  serviceFingerprint: string
  scopes: { title: string; mode: string }[]
  futureBoards: boolean
  operatorApproved: boolean | null
  controllerApproved: boolean | null
}

const csrf = ref("")
const token = ref("")
const signedIn = ref(false)
const adminIdentity = ref<AdminIdentity | null>(null)
const sessionLoading = ref(true)
const sessionUnavailable = ref(false)
const loading = ref(false)
const error = ref("")
const overview = ref<Overview | null>(null)
const pairings = ref<Pairing[]>([])
const corsRequired = ref("")
const corsDraft = ref("")
const corsLoaded = ref(false)
const corsSaving = ref(false)
const corsError = ref("")
const corsNotice = ref("")
const pollIntervalMs = 5_000
let pollTimer: ReturnType<typeof setInterval> | undefined
let refreshInFlight = false
let sessionVersion = 0
const replicationState = computed(() => overview.value?.replication.state ?? "idle")

class ApiError extends Error {
  constructor(message: string, readonly status: number) { super(message) }
}

async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(path, {
    credentials: "same-origin",
    cache: "no-store",
    ...options,
    headers: {
      "content-type": "application/json",
      ...(csrf.value ? { "x-csrf-token": csrf.value } : {}),
      ...(options.headers ?? {}),
    },
  })
  const value = await response.json().catch(() => ({}))
  if (!response.ok) throw new ApiError(value.message || `Request failed (${response.status})`, response.status)
  return value as T
}

function validMatchLoginUrl(value: string, challengeId: string) {
  const target = new URL(value)
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(target.hostname)
  if (target.username || target.password || target.hash || target.pathname !== "/login" || target.searchParams.size !== 2
    || target.searchParams.get("keeper") !== window.location.origin
    || target.searchParams.get("challenge") !== challengeId
    || (target.protocol !== "https:" && !(loopback && target.protocol === "http:"))) {
    throw new Error("Lighthouse returned an unsafe Match sign-in link.")
  }
  return target.toString()
}

async function signInWithMatch() {
  error.value = ""
  loading.value = true
  try {
    const response = await api<{ challengeId: string; matchUrl: string }>("/admin/api/login/challenge", {
      method: "POST",
      body: JSON.stringify({}),
    })
    window.location.assign(validMatchLoginUrl(response.matchUrl, response.challengeId))
  } catch (cause) {
    loading.value = false
    error.value = cause instanceof Error ? cause.message : "Could not start Match sign-in."
  }
}

function clearIdentity() {
  sessionVersion++
  csrf.value = ""
  signedIn.value = false
  adminIdentity.value = null
  overview.value = null
  pairings.value = []
  corsLoaded.value = false
  corsDraft.value = ""
}

async function loadCorsSettings() {
  if (!adminIdentity.value?.operator) return
  corsError.value = ""
  try {
    const settings = await api<CorsSettings>("/admin/api/settings/cors")
    corsRequired.value = settings.requiredOrigin
    corsDraft.value = settings.origins.filter(origin => origin !== settings.requiredOrigin).join("\n")
    corsLoaded.value = true
  } catch (cause) {
    corsLoaded.value = false
    corsError.value = cause instanceof Error ? cause.message : "Could not load allowed origins"
  }
}

async function saveCorsSettings() {
  if (!corsLoaded.value || corsSaving.value) return
  corsSaving.value = true
  corsError.value = ""
  corsNotice.value = ""
  try {
    const origins = [corsRequired.value, ...corsDraft.value.split(/\r?\n/).map(origin => origin.trim()).filter(Boolean)]
    const settings = await api<CorsSettings>("/admin/api/settings/cors", {
      method: "POST", body: JSON.stringify({ origins }),
    })
    corsDraft.value = settings.origins.filter(origin => origin !== settings.requiredOrigin).join("\n")
    corsNotice.value = "Allowed origins saved"
  } catch (cause) {
    corsError.value = cause instanceof Error ? cause.message : "Could not save allowed origins"
  } finally {
    corsSaving.value = false
  }
}

async function logout() {
  error.value = ""
  try {
    await api("/admin/api/logout", { method: "POST", body: JSON.stringify({}) })
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : "Could not sign out."
    return
  }
  clearIdentity()
}

async function exchangeLoginCode() {
  const code = new URLSearchParams(window.location.hash.slice(1)).get("login")
  window.history.replaceState(null, "", window.location.pathname + window.location.search)
  if (!code) return false
  sessionLoading.value = true
  error.value = ""
  try {
    const identity = await api<{ csrfToken: string } & AdminIdentity>("/admin/api/login/exchange", {
      method: "POST",
      body: JSON.stringify({ code }),
    })
    csrf.value = identity.csrfToken
    adminIdentity.value = identity
    signedIn.value = true
    await refresh()
    await loadCorsSettings()
  } catch (cause) {
    clearIdentity()
    error.value = cause instanceof Error ? cause.message : "Could not complete Match sign-in."
  } finally {
    sessionLoading.value = false
  }
  return true
}

async function restoreSession() {
  sessionLoading.value = true
  sessionUnavailable.value = false
  error.value = ""
  try {
    const response = await api<{ csrfToken: string } & AdminIdentity>("/admin/api/session")
    csrf.value = response.csrfToken
    adminIdentity.value = response
    signedIn.value = true
    await refresh()
    await loadCorsSettings()
  } catch (cause) {
    if (cause instanceof ApiError && cause.status === 403) {
      clearIdentity()
    } else {
      sessionUnavailable.value = true
      error.value = cause instanceof Error ? cause.message : "Could not check operator session"
    }
  } finally {
    sessionLoading.value = false
  }
}

async function signIn() {
  error.value = ""
  try {
    const response = await api<{ csrfToken: string } & AdminIdentity>("/admin/api/session", {
      method: "POST",
      body: JSON.stringify({ secret: token.value }),
    })
    csrf.value = response.csrfToken
    adminIdentity.value = response
    signedIn.value = true
    sessionUnavailable.value = false
    token.value = ""
    await refresh()
    await loadCorsSettings()
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : "Sign-in failed"
  }
}

async function refresh() {
  if (refreshInFlight || !signedIn.value) return
  refreshInFlight = true
  const version = sessionVersion
  try {
    const [nextOverview, nextPairings] = await Promise.all([
      api<Overview>("/admin/api/overview"),
      api<{ pairings: Pairing[] }>("/admin/api/pairings"),
    ])
    if (version !== sessionVersion) return
    overview.value = nextOverview
    pairings.value = nextPairings.pairings
    error.value = ""
  } catch (cause) {
    if (version !== sessionVersion) return
    if (cause instanceof ApiError && cause.status === 403) clearIdentity()
    error.value = cause instanceof Error ? cause.message : "Could not load keeper overview"
  } finally {
    refreshInFlight = false
  }
}

function refreshWhenVisible() {
  if (!document.hidden && signedIn.value) void refresh()
}

async function decide(pairing: Pairing, decision: "approve" | "decline") {
  error.value = ""
  try {
    await api(`/admin/api/pairings/${encodeURIComponent(pairing.id)}/decision`, {
      method: "POST",
      body: JSON.stringify({ decision }),
    })
    await refresh()
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : "Decision failed"
  }
}

function date(value?: number | null) {
  if (!value) return "No saved timestamp"
  return new Date(value * 1000).toLocaleString()
}

function pairingStatus(pairing: Pairing) {
  if (pairing.operatorApproved === false || pairing.controllerApproved === false) return "Keeper request declined. No access granted."
  if (pairing.operatorApproved === null) return "Waiting for keeper operator to approve service access."
  if (pairing.controllerApproved === null) return "Waiting for Match identity confirmation."
  return "Both approvals are recorded. See board rows above for keeper replication status."
}

onMounted(async () => {
  pollTimer = setInterval(refreshWhenVisible, pollIntervalMs)
  document.addEventListener("visibilitychange", refreshWhenVisible)
  if (window.location.hash.startsWith("#login=")) {
    if (await exchangeLoginCode()) return
  }
  await restoreSession()
})

onUnmounted(() => {
  if (pollTimer) clearInterval(pollTimer)
  document.removeEventListener("visibilitychange", refreshWhenVisible)
})

</script>

<template>
  <div class="shell lighthouse-admin">
    <header class="topbar">
      <div class="brand">
        <LighthouseMark />
        <div>
          <h1>LIGHTHOUSE</h1>
        </div>
      </div>
      <div v-if="signedIn" class="admin-header-actions">
        <button class="button button-quiet" type="button" @click="logout">Sign out</button>
      </div>
    </header>

    <main class="admin-content">
      <p v-if="sessionLoading" class="empty-state" role="status">Checking operator session…</p>
      <section v-else-if="sessionUnavailable" class="login-card">
        <h2>Session check unavailable</h2>
        <p class="section-copy">Could not reach Lighthouse. Retry to check your operator session.</p>
        <button class="button button-primary" type="button" @click="restoreSession">Retry session check</button>
      </section>
      <form v-else-if="!signedIn" class="login-card" @submit.prevent="signIn">
        <h2>Sign in</h2>
        <p class="section-copy">Use your Match identity to see boards connected to your account.</p>
        <button class="button button-primary" type="button" :disabled="loading" @click="signInWithMatch">{{ loading ? "Opening Match…" : "Sign in with Match" }}</button>
        <details class="service-admin-fallback">
          <summary>Service administration</summary>
          <p class="section-copy">Operator token grants service-wide approval access.</p>
          <label class="field-label" for="operator-token">Operator token</label>
          <input id="operator-token" v-model="token" type="password" autocomplete="current-password" required />
          <button class="button button-quiet" type="submit">Sign in as operator</button>
        </details>
      </form>

      <p v-if="error" class="admin-notice admin-notice-error" role="status">{{ error }}</p>

      <template v-if="signedIn && overview">
        <section v-if="adminIdentity?.operator" aria-labelledby="settings-title" class="admin-section">
          <div class="section-heading"><h2 id="settings-title">Settings</h2></div>
          <form class="keeper-card cors-settings" @submit.prevent="saveCorsSettings">
            <h3>Allowed website origins</h3>
            <p class="section-copy">Match sign-in origin stays enabled. Add other websites allowed to reach Lighthouse intake, one HTTPS origin per line.</p>
            <p class="muted">Match: {{ corsRequired || "Loading…" }}</p>
            <label class="field-label" for="cors-origins">Additional origins</label>
            <textarea id="cors-origins" v-model="corsDraft" :disabled="!corsLoaded || corsSaving" rows="3" placeholder="https://example.com"></textarea>
            <div class="cors-actions">
              <button class="button button-small button-primary" type="submit" :disabled="!corsLoaded || corsSaving">{{ corsSaving ? "Saving…" : "Save origins" }}</button>
              <button v-if="!corsLoaded" class="button button-small" type="button" @click="loadCorsSettings">Retry loading</button>
            </div>
            <p v-if="corsError" class="admin-notice admin-notice-error" role="alert">{{ corsError }}</p>
            <p v-if="corsNotice" class="admin-notice" role="status">{{ corsNotice }}</p>
          </form>
        </section>
        <section aria-labelledby="keepers-title" class="admin-section">
          <div class="section-heading">
            <div>
              <h2 id="keepers-title">Keepers</h2>
            </div>
            <p class="replication-status" :data-state="replicationState">Replication {{ replicationState }}</p>
          </div>

          <article class="keeper-card">
            <div class="keeper-heading">
              <div>
                <h3>{{ overview.keeper.displayName }}</h3>
                <p class="muted">{{ overview.keeper.personId }}</p>
              </div>
            </div>

            <div class="overview-grid">
              <section class="overview-group">
                <h4>Boards</h4>
                <p v-if="!overview.keeper.boards.length" class="muted">No attached boards.</p>
                <article v-for="board in overview.keeper.boards" :key="board.workspaceId" class="board-row">
                  <div class="board-title"><strong>{{ board.title }}</strong><span v-if="board.isPrimary" class="muted">(primary board)</span></div>
                  <p>{{ board.peerCount }} authorized peers · {{ board.heads.length }} current heads</p>
                  <p>Saved {{ date(board.lastSavedAt) }} · replication {{ board.replication?.state ?? "idle" }}</p>
                  <p v-if="board.replication?.lastSuccessAt">Last exchange {{ date(board.replication.lastSuccessAt) }}</p>
                  <p v-if="board.replication?.lastErrorCategory" class="muted">Last transport state: {{ board.replication.lastErrorCategory }}</p>
                </article>
              </section>

              <section class="overview-group">
                <h4>Triggers</h4>
                <p v-if="!overview.triggers.length" class="muted">No configured triggers.</p>
                <article v-for="trigger in overview.triggers" :key="trigger.id" class="board-row">
                  <div class="board-title"><strong>{{ trigger.name }}</strong></div>
                  <p>{{ trigger.configured ? "Configured" : "Not configured" }} · {{ trigger.pendingCount }} pending · {{ trigger.model }}</p>
                  <p>{{ trigger.outcomes.cardCreated }} cards created · {{ trigger.outcomes.chatQueued }} chats queued · {{ trigger.outcomes.awaitingMesh }} awaiting Match</p>
                </article>
              </section>
            </div>
          </article>
        </section>

        <section aria-labelledby="approvals-title" class="admin-section approvals-section">
          <div class="section-heading">
            <h2 id="approvals-title">Approvals<span v-if="pairings.length"> ({{ pairings.length }})</span></h2>
          </div>
          <p v-if="!pairings.length" class="empty-state">No pending keeper requests. Create one from Match → Sync → Add keeper.</p>
          <article v-for="pairing in pairings" :key="pairing.id" class="approval-card">
            <h3>{{ pairing.controller.displayName }} · {{ pairing.comparisonCode }}</h3>
            <p class="muted">Controller {{ pairing.controllerFingerprint }} · service {{ pairing.serviceFingerprint }}</p>
            <ul><li v-for="scope in pairing.scopes" :key="scope.title">{{ scope.title }} · {{ scope.mode }}</li></ul>
            <p>{{ pairing.futureBoards ? "Future boards included in approval" : "Future boards not included" }}</p>
            <p>Controller approval: {{ pairing.controllerApproved === true ? "approved" : pairing.controllerApproved === false ? "declined" : "pending" }}</p>
            <div class="dialog-actions">
              <template v-if="adminIdentity?.operator">
                <button class="button button-primary" type="button" :disabled="pairing.operatorApproved !== null || pairing.controllerApproved === false" @click="decide(pairing, 'approve')">Approve exact boards</button>
                <button class="button" type="button" :disabled="pairing.operatorApproved !== null || pairing.controllerApproved === false" @click="decide(pairing, 'decline')">Decline</button>
              </template>
            <p v-else class="muted" role="status">{{ pairingStatus(pairing) }}</p>
            </div>
          </article>
        </section>
      </template>
    </main>
  </div>
</template>

<style scoped>
.admin-header-actions { display: flex; gap: 8px; }
.service-admin-fallback { display: grid; gap: 10px; margin-top: 18px; padding-top: 14px; border-top: 1px solid var(--soft); }
.service-admin-fallback summary { color: var(--muted); cursor: pointer; font-weight: 750; }
.service-admin-fallback input { width: min(360px, 80vw); min-height: var(--control-size); padding: 9px 12px; border: 2px solid var(--line); background: var(--panel); }
.cors-settings { display: grid; gap: 12px; }
.cors-settings h3, .cors-settings p { margin: 0; }
.cors-settings textarea { width: 100%; padding: 10px 12px; border: 2px solid var(--line); background: var(--panel); color: var(--ink); font: inherit; resize: vertical; }
.cors-actions { display: flex; gap: 10px; }
</style>
