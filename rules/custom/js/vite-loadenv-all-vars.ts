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

// any local function can be called pickPublic; the name alone proves nothing
const pickPublic = (x: any) => x;
export const e = defineConfig(({ mode }) => {
  return {
    // ruleid: sast.js.vite-loadenv-all-vars
    define: pickPublic(loadEnv(mode, process.cwd(), "")),
  };
});

// the assignment form puts the whole environment into define too
export const f = defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const cfg: any = { plugins: [] };
  // ruleid: sast.js.vite-loadenv-all-vars
  cfg.define = { "process.env": env };
  return cfg;
});

// a plain default-exported config object (vite.config.ts without defineConfig)
const envDefault = loadEnv("production", process.cwd(), "");
export default {
  plugins: [],
  // ruleid: sast.js.vite-loadenv-all-vars
  define: { __ALL__: JSON.stringify(envDefault) },
};

const envCjs = loadEnv("production", process.cwd(), "");
module.exports = {
  // ruleid: sast.js.vite-loadenv-all-vars
  define: { ...envCjs },
};

// an unrelated object that happens to have a define key is not a Vite config
const envUnrelated = loadEnv("production", process.cwd(), "");
export const unrelated1 = {
  // ok: sast.js.vite-loadenv-all-vars
  define: envUnrelated,
};
export const unrelated3 = {
  label: "x",
  // ok: sast.js.vite-loadenv-all-vars
  define: envUnrelated,
};
export function unrelated2() {
  const c: any = {};
  // ok: sast.js.vite-loadenv-all-vars
  c.define = envUnrelated;
  return c;
}

// a default-exported config object whose only key is define (no Vite-only sibling key)
const envBareDefault = loadEnv("production", process.cwd(), "");
export default {
  // ruleid: sast.js.vite-loadenv-all-vars
  define: { __ENV__: JSON.stringify(envBareDefault) },
};

// default-exported config that picks specific keys stays quiet
export default {
  // ok: sast.js.vite-loadenv-all-vars
  define: { __API__: JSON.stringify(envBareDefault.API_URL) },
};

// a config built in a variable is still recognised by its Vite-only key
const envViaVar = loadEnv("production", process.cwd(), "");
const viteCfg = {
  server: { port: 3000 },
  // ruleid: sast.js.vite-loadenv-all-vars
  define: { __ALL__: JSON.stringify(envViaVar) },
};

// a default-exported config function: the object it returns is the config (PR #11 review 4)
export default ({ mode }) => ({
  // ruleid: sast.js.vite-loadenv-all-vars
  define: { __ALL__: loadEnv(mode, '.', '') },
});

export default function (cfg) {
  const fnEnv = loadEnv(cfg.mode, '.', '');
  return {
    // ruleid: sast.js.vite-loadenv-all-vars
    define: { __ALL__: JSON.stringify(fnEnv) },
  };
}

export default async function ({ mode }) {
  return {
    // ruleid: sast.js.vite-loadenv-all-vars
    define: { ...loadEnv(mode, '.', '') },
  };
}

// NOT FIXED: a named default-exported function; the engines read `export default function f` like `export function f`
export default function namedConfig({ mode }) {
  return {
    // (not matched today, so no annotation here)
    define: { ...loadEnv(mode, '.', '') },
  };
}

export default async ({ mode }) => {
  const asyncEnv = loadEnv(mode, '.', '');
  return {
    // ruleid: sast.js.vite-loadenv-all-vars
    define: { __ALL__: JSON.stringify(asyncEnv) },
  };
};

// a default-exported config function that picks specific variables stays quiet
export default ({ mode }) => {
  const okFnEnv = loadEnv(mode, '.', '');
  return {
    // ok: sast.js.vite-loadenv-all-vars
    define: { __API_URL__: JSON.stringify(okFnEnv.API_URL) },
  };
};

export default function (cfg) {
  const okFnEnv2 = loadEnv(cfg.mode, '.', '');
  return {
    // ok: sast.js.vite-loadenv-all-vars
    define: { __API_URL__: JSON.stringify(okFnEnv2.API_URL) },
  };
}

// a function that is not the default export is not a config
export function helper({ mode }) {
  return {
    // ok: sast.js.vite-loadenv-all-vars
    define: { __ALL__: loadEnv(mode, '.', '') },
  };
}
