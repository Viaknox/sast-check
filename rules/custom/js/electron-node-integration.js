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

function f() {
  // ruleid: sast.js.electron-node-integration
  const prefs = { nodeIntegration: true, preload: p };
  return new BrowserWindow({ width: 800, webPreferences: prefs });
}
function g() {
  // ruleid: sast.js.electron-node-integration
  const wp = { contextIsolation: false };
  const win = new BrowserView({ webPreferences: wp });
  return win;
}
function h() {
  // ruleid: sast.js.electron-node-integration
  const wp = { sandbox: false };
  loadSettings();
  return new BrowserWindow({ show: false, webPreferences: wp });
}

// settings objects that never reach an Electron window constructor
function cfgA() {
  // ok: sast.js.electron-node-integration
  return { name: "runner", webPreferences: { sandbox: false } };
}
function cfgB(Widget) {
  // ok: sast.js.electron-node-integration
  return new Widget({ webPreferences: { contextIsolation: false } });
}
function cfgC() {
  // ok: sast.js.electron-node-integration
  const wp = { sandbox: false };
  return new Panel({ webPreferences: wp });
}
function cfgD() {
  // ok: sast.js.electron-node-integration
  const wp = { webSecurity: false };
  return wp;
}

function secure() {
  // ok: sast.js.electron-node-integration
  const wp = { nodeIntegration: false, contextIsolation: true, sandbox: true };
  return new BrowserWindow({ webPreferences: wp });
}
function m() {
  // ruleid: sast.js.electron-node-integration
  const wp = { nodeIntegrationInWorker: true };
  return new BrowserWindow({ webPreferences: wp });
}
function n() {
  // ruleid: sast.js.electron-node-integration
  const wp = { webSecurity: false };
  return new BrowserWindow({ webPreferences: wp });
}

function k() {
  // ruleid: sast.js.electron-node-integration
  return new WebContentsView({ webPreferences: { sandbox: false } });
}
function l() {
  // ruleid: sast.js.electron-node-integration
  const wp = { sandbox: false };
  return new WebContentsView({ webPreferences: wp });
}

// qualified constructors: they count only when the qualifier is bound from the electron module
function qa() {
  const electron = require("electron");
  // ruleid: sast.js.electron-node-integration
  return new electron.BrowserWindow({ webPreferences: { nodeIntegration: true } });
}
function qb() {
  const el = require("electron");
  // ruleid: sast.js.electron-node-integration
  const wp = { contextIsolation: false };
  return new el.BrowserView({ webPreferences: wp });
}
function qc() {
  const el = require("electron");
  // ruleid: sast.js.electron-node-integration
  return new el.WebContentsView({ webPreferences: { sandbox: false } });
}
function qd() {
  const el = require("electron");
  // ok: sast.js.electron-node-integration
  return new el.BrowserWindow({ webPreferences: { nodeIntegration: false, contextIsolation: true } });
}
function qe() {
  const other = require("some-ui-kit");
  // ok: sast.js.electron-node-integration
  return new other.BrowserWindow({ webPreferences: { nodeIntegration: true } });
}
function qf() {
  const other = require("some-ui-kit");
  // ok: sast.js.electron-node-integration
  const wp = { sandbox: false };
  return new other.BrowserView({ webPreferences: wp });
}
function qg(host) {
  // a qualifier that is a parameter, not bound from electron
  // ok: sast.js.electron-node-integration
  return new host.BrowserWindow({ webPreferences: { nodeIntegration: true } });
}
function qh() {
  const el = require("electron");
  // ok: sast.js.electron-node-integration
  return new el.Notification({ webPreferences: { nodeIntegration: true } });
}

import * as elNs from "electron";
function qi() {
  // ruleid: sast.js.electron-node-integration
  return new elNs.BrowserWindow({ webPreferences: { nodeIntegration: true } });
}
function qj() {
  // ruleid: sast.js.electron-node-integration
  const wp = { webSecurity: false };
  return new elNs.BrowserWindow({ webPreferences: wp });
}
import elDefault from "electron";
function qk() {
  // ruleid: sast.js.electron-node-integration
  return new elDefault.BrowserView({ webPreferences: { sandbox: false } });
}
function ql() {
  // ruleid: sast.js.electron-node-integration
  const wp = { nodeIntegrationInWorker: true };
  return new elDefault.WebContentsView({ webPreferences: wp });
}
function qm() {
  const el = require("electron");
  // ok: sast.js.electron-node-integration
  const wp = { nodeIntegration: true };
  return new el.Tray({ webPreferences: wp });
}

// renamed constructors: bound from the electron module by a destructure with rename, or an import alias
function ra() {
  const { BrowserWindow: BW } = require("electron");
  // ruleid: sast.js.electron-node-integration
  return new BW({ webPreferences: { nodeIntegration: true } });
}
function rb() {
  const { BrowserView: BV } = require("electron");
  // ruleid: sast.js.electron-node-integration
  const wp = { contextIsolation: false };
  return new BV({ webPreferences: wp });
}
function rc() {
  const { app, WebContentsView: WCV } = require("electron");
  // ruleid: sast.js.electron-node-integration
  return new WCV({ webPreferences: { sandbox: false } });
}
function rd() {
  const { BrowserWindow: BW } = require("electron");
  // ok: sast.js.electron-node-integration
  return new BW({ webPreferences: { nodeIntegration: false, contextIsolation: true } });
}
function re() {
  const { BrowserWindow: BW } = require("some-ui-kit");
  // ok: sast.js.electron-node-integration
  return new BW({ webPreferences: { nodeIntegration: true } });
}
function rf() {
  const { BrowserView: BV } = require("some-ui-kit");
  // ok: sast.js.electron-node-integration
  const wp = { sandbox: false };
  return new BV({ webPreferences: wp });
}
function rg() {
  const { Tray: TR } = require("electron");
  // ok: sast.js.electron-node-integration
  return new TR({ webPreferences: { nodeIntegration: true } });
}
import { BrowserWindow as IBW, BrowserView as IBV } from "electron";
function ri() {
  // ruleid: sast.js.electron-node-integration
  return new IBW({ webPreferences: { nodeIntegration: true } });
}
function rj() {
  // ruleid: sast.js.electron-node-integration
  const wp = { webSecurity: false };
  return new IBV({ webPreferences: wp });
}
import { BrowserWindow as KBW } from "some-ui-kit";
function rk() {
  // ok: sast.js.electron-node-integration
  return new KBW({ webPreferences: { nodeIntegration: true } });
}
function rh() {
  const { Tray: TR } = require("electron");
  // ok: sast.js.electron-node-integration
  const wp = { nodeIntegration: true };
  return new TR({ webPreferences: wp });
}
