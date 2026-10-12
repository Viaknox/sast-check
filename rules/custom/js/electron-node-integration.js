const { app, BrowserWindow, BrowserView } = require("electron");

function a() {
  // ruleid: sast.js.electron-node-integration
  return new BrowserWindow({ width: 800, webPreferences: { nodeIntegration: true } });
}
function b() {
  // ruleid: sast.js.electron-node-integration
  return new BrowserWindow({ webPreferences: { contextIsolation: false, preload: p } });
}
function c() {
  // ruleid: sast.js.electron-node-integration
  return new BrowserView({ webPreferences: { sandbox: false } });
}
function d() {
  // ruleid: sast.js.electron-node-integration
  return new BrowserWindow({ webPreferences: { webSecurity: false } });
}
function e() {
  // ruleid: sast.js.electron-node-integration
  return new BrowserWindow({ webPreferences: { nodeIntegrationInWorker: true } });
}

function ok1() {
  // ok: sast.js.electron-node-integration
  return new BrowserWindow({ webPreferences: { nodeIntegration: false, contextIsolation: true } });
}
function ok2() {
  // ok: sast.js.electron-node-integration
  return new BrowserWindow({ width: 800, height: 600 });
}
function ok3() {
  // ok: sast.js.electron-node-integration
  return new BrowserWindow({ webPreferences: { sandbox: true, webSecurity: true, preload: p } });
}
function ok4() {
  // ok: sast.js.electron-node-integration
  const cfg = { nodeIntegration: true };
  return cfg;
}
