import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  root: import.meta.dirname,
  plugins: [react()],
  build: { outDir: "../dist/web", emptyOutDir: true },
  // The API only takes cookie requests from its own origin, so the dev server presents itself as that origin.
  server: { proxy: { "/api": { target: "http://localhost:8080", headers: { origin: "http://localhost:8080" } } } },
});
