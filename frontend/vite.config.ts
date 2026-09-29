import { fileURLToPath, URL } from "node:url"
import { defineConfig } from "vite"
import vue from "@vitejs/plugin-vue"

const matchSource = process.env.MATCH_UI_SOURCE
  ? fileURLToPath(new URL(process.env.MATCH_UI_SOURCE, import.meta.url))
  : fileURLToPath(new URL("../match/src", import.meta.url))

export default defineConfig({
  base: "/admin/",
  plugins: [vue()],
  resolve: { alias: { "@match": matchSource }, dedupe: ["vue"] },
  build: { outDir: "dist", emptyOutDir: true },
})
