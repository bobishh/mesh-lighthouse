<script setup lang="ts">
import { computed, ref } from "vue"
import LighthouseMark from "@match/components/LighthouseMark.vue"

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
const loading = ref(false)
const error = ref("")
const status = ref("")
const overview = ref<Overview | null>(null)
const pairings = ref<Pairing[]>([])
const replicationState = computed(() => overview.value?.replication.state ?? "idle")
const online = computed(() => replicationState.value === "connected")
const reconnecting = computed(() => ["connecting", "retrying"].includes(replicationState.value))

async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(path, {
    credentials: "same-origin",
    ...options,
    headers: {
      "content-type": "application/json",
      ...(csrf.value ? { "x-csrf-token": csrf.value } : {}),
      ...(options.headers ?? {}),
    },
  })
  const value = await response.json().catch(() => ({}))
  if (!response.ok) throw new Error(value.message || `Request failed (${response.status})`)
  return value as T
}

async function signIn() {
  error.value = ""
  status.value = ""
  try {
    const response = await api<{ csrfToken: string }>("/admin/api/session", {
      method: "POST",
      body: JSON.stringify({ secret: token.value }),
    })
    csrf.value = response.csrfToken
    signedIn.value = true
    token.value = ""
    await refresh()
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : "Sign-in failed"
  }
}

async function refresh() {
  loading.value = true
  error.value = ""
  try {
    const [nextOverview, nextPairings] = await Promise.all([
      api<Overview>("/admin/api/overview"),
      api<{ pairings: Pairing[] }>("/admin/api/pairings"),
    ])
    overview.value = nextOverview
    pairings.value = nextPairings.pairings
    status.value = "Overview updated"
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : "Could not load keeper overview"
  } finally {
    loading.value = false
  }
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

</script>

<template>
  <div class="shell lighthouse-admin">
    <header class="topbar">
      <div class="brand">
        <LighthouseMark :online="online" :reconnecting="reconnecting" />
        <div>
          <h1>Lighthouse</h1>
          <p class="brand-subtitle">Keeper service · {{ overview?.keeper.displayName || "Operator console" }}</p>
        </div>
      </div>
      <button v-if="signedIn" class="button button-small button-quiet" type="button" :disabled="loading" @click="refresh">
        {{ loading ? "Refreshing…" : "Refresh overview" }}
      </button>
    </header>

    <main class="admin-content">
      <form v-if="!signedIn" class="login-card" @submit.prevent="signIn">
        <h2>Sign in</h2>
        <p class="section-copy">Use service operator token to view keeper boards and approve requests.</p>
        <label class="field-label" for="operator-token">Operator token</label>
        <input id="operator-token" v-model="token" type="password" autocomplete="current-password" required />
        <button class="button button-primary" type="submit">Sign in</button>
      </form>

      <p v-if="error" class="notice notice-error" role="status">{{ error }}</p>
      <p v-else-if="status" class="notice" role="status">{{ status }}</p>

      <template v-if="signedIn && overview">
        <section aria-labelledby="keepers-title" class="admin-section">
          <div class="section-heading">
            <div>
              <p class="eyebrow">This Lighthouse identity</p>
              <h2 id="keepers-title">Keepers</h2>
            </div>
            <span class="state-pill" :data-state="replicationState">Replication {{ replicationState }}</span>
          </div>

          <article class="keeper-card">
            <div class="keeper-heading">
              <div>
                <h3>{{ overview.keeper.displayName }}</h3>
                <p class="muted">{{ overview.keeper.personId }}</p>
              </div>
              <span class="service-label">Service keeper</span>
            </div>

            <div class="overview-grid">
              <section class="overview-group">
                <h4>Boards</h4>
                <p v-if="!overview.keeper.boards.length" class="muted">No attached boards.</p>
                <article v-for="board in overview.keeper.boards" :key="board.workspaceId" class="board-row">
                  <div class="board-title"><strong>{{ board.title }}</strong><span v-if="board.isPrimary" class="tag">Primary</span></div>
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
                  <div class="board-title"><strong>{{ trigger.name }}</strong><span class="tag" :data-state="trigger.configured ? 'ready' : 'off'">{{ trigger.configured ? "configured" : "not configured" }}</span></div>
                  <p>{{ trigger.pendingCount }} pending · {{ trigger.model }}</p>
                  <p>{{ trigger.outcomes.cardCreated }} cards created · {{ trigger.outcomes.chatQueued }} chats queued · {{ trigger.outcomes.awaitingMesh }} awaiting Match</p>
                </article>
              </section>
            </div>
          </article>
        </section>

        <section aria-labelledby="approvals-title" class="admin-section approvals-section">
          <div class="section-heading">
            <div><p class="eyebrow">Separate from keeper status</p><h2 id="approvals-title">Approvals</h2></div>
            <span class="count-pill">{{ pairings.length }}</span>
          </div>
          <p v-if="!pairings.length" class="empty-state">No pending keeper requests. Create one from Match → Sync → Add keeper.</p>
          <article v-for="pairing in pairings" :key="pairing.id" class="approval-card">
            <h3>{{ pairing.controller.displayName }} · {{ pairing.comparisonCode }}</h3>
            <p class="muted">Controller {{ pairing.controllerFingerprint }} · service {{ pairing.serviceFingerprint }}</p>
            <ul><li v-for="scope in pairing.scopes" :key="scope.title">{{ scope.title }} · {{ scope.mode }}</li></ul>
            <p>{{ pairing.futureBoards ? "Future boards included in approval" : "Future boards not included" }}</p>
            <p>Controller approval: {{ pairing.controllerApproved === true ? "approved" : pairing.controllerApproved === false ? "declined" : "pending" }}</p>
            <div class="dialog-actions">
              <button class="button button-primary button-small" type="button" :disabled="pairing.operatorApproved !== null || pairing.controllerApproved === false" @click="decide(pairing, 'approve')">Approve exact boards</button>
              <button class="button button-small" type="button" :disabled="pairing.operatorApproved !== null || pairing.controllerApproved === false" @click="decide(pairing, 'decline')">Decline</button>
            </div>
          </article>
        </section>
      </template>
    </main>
  </div>
</template>
