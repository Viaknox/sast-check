const grpc = require("@grpc/grpc-js");
const { credentials, ServerCredentials } = require("@grpc/grpc-js");

// ruleid: sast.js.grpc-insecure
const client = new Svc("api.example.com:443", grpc.credentials.createInsecure());

// ruleid: sast.js.grpc-insecure
const c2 = new Svc(addr, credentials.createInsecure());

function start(server) {
  // ruleid: sast.js.grpc-insecure
  server.bindAsync("0.0.0.0:50051", grpc.ServerCredentials.createInsecure(), () => {});
}

function start2(server) {
  // ruleid: sast.js.grpc-insecure
  server.bindAsync("0.0.0.0:50052", ServerCredentials.createInsecure(), () => {});
}

// ok: sast.js.grpc-insecure
const s1 = new Svc(addr, grpc.credentials.createSsl(rootCa));

// ok: sast.js.grpc-insecure
server.bindAsync(addr, grpc.ServerCredentials.createSsl(root, [{ private_key: k, cert_chain: c }]), () => {});

// ok: sast.js.grpc-insecure
const s3 = new Svc(addr, creds.combineChannelCredentials(a, b));

// ok: sast.js.grpc-insecure
const t = tlsOptions.createInsecureAgent();
