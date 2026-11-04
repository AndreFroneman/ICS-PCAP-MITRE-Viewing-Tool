import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    host: "0.0.0.0",
    port: 8734,
    strictPort: true,
  },
  preview: {
    host: "127.0.0.1",
    port: 8734,
    strictPort: true,
  },
  test: {
    include: ["tests/**/*.test.ts"],
    testTimeout: 60000,
  },
});
