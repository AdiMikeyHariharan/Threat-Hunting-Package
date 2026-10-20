import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Proxy /api to the FastAPI backend so the browser only ever talks to Vite,
// avoiding CORS during development.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": "http://localhost:8000",
      // Direct (non-PEP) access to the mock backends, used by the bypass demo.
      "/backend-direct": {
        target: "http://localhost:8081",
        rewrite: (path) => path.replace(/^\/backend-direct/, ""),
      },
    },
  },
});
