import { defineConfig, loadEnv } from "vite";

export const a = defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  return {
    // ruleid: sast.js.vite-loadenv-all-vars
    define: { "process.env": env },
  };
});

export const b = defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  return {
    // ruleid: sast.js.vite-loadenv-all-vars
    define: { ...env },
  };
});

export const c = defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  return {
    // ruleid: sast.js.vite-loadenv-all-vars
    define: { __ENV__: JSON.stringify(env) },
  };
});

export const d = defineConfig(({ mode }) => {
  const all = loadEnv(mode, ".", "");
  return {
    // ruleid: sast.js.vite-loadenv-all-vars
    define: { "process.env": JSON.stringify(all) },
  };
});

export const ok1 = defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const port = Number(env.PORT);
  return {
    server: { port },
  };
});

export const ok2 = defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  return {
    // ok: sast.js.vite-loadenv-all-vars
    define: { __API_URL__: JSON.stringify(env.API_URL) },
  };
});

export const ok3 = defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd());
  return {
    // ok: sast.js.vite-loadenv-all-vars
    define: { "process.env": env },
  };
});

export const ok4 = defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "VITE_");
  return {
    // ok: sast.js.vite-loadenv-all-vars
    define: { "import.meta.env": JSON.stringify(env) },
  };
});

export const ok5 = defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  return {
    // ok: sast.js.vite-loadenv-all-vars
    define: { __BUILD__: JSON.stringify(env["BUILD_ID"]) },
  };
});
