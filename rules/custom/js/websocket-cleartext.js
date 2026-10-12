// ruleid: sast.js.websocket-cleartext
const a = new WebSocket("ws://chat.example.com/stream");

// ruleid: sast.js.websocket-cleartext
const b = new WebSocket("ws://10.0.3.4:8080/feed", ["v1"]);

// ruleid: sast.js.websocket-cleartext
const c = io("http://api.example.com:3000");

// ruleid: sast.js.websocket-cleartext
const d = io.connect("http://realtime.example.org", { transports: ["websocket"] });

// ruleid: sast.js.websocket-cleartext
const e = new WebSocket("ws://localhost.attacker.example/ws");

// ok: sast.js.websocket-cleartext
const o1 = new WebSocket("ws://localhost:8080");

// ok: sast.js.websocket-cleartext
const o2 = new WebSocket("ws://127.0.0.1:9000/ws");

// ok: sast.js.websocket-cleartext
const o3 = new WebSocket("wss://chat.example.com/stream");

// ok: sast.js.websocket-cleartext
const o4 = io("https://api.example.com");

// ok: sast.js.websocket-cleartext
const o5 = io("http://localhost:3000");

// ok: sast.js.websocket-cleartext
const o6 = new WebSocket(buildUrl());
