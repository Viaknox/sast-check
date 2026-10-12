const { Sequelize } = require("sequelize");
const { Pool } = require("pg");
const mysql = require("mysql2");

// ruleid: sast.js.sequelize-no-tls
const s1 = new Sequelize("db", "u", "p", { dialect: "postgres", dialectOptions: { ssl: false } });

// ruleid: sast.js.sequelize-no-tls
const s2 = new Sequelize(url, { dialectOptions: { ssl: { require: true, rejectUnauthorized: false } } });

// ruleid: sast.js.sequelize-no-tls
const p1 = new Pool({ host: "db.internal", ssl: { rejectUnauthorized: false } });

// ruleid: sast.js.sequelize-no-tls
const conn = mysql.createConnection({ host: "h", user: "u", ssl: { rejectUnauthorized: false } });

const s3 = new Sequelize(
  // ruleid: sast.js.sequelize-no-tls
  "postgres://u:p@db.example.com:5432/app?sslmode=disable"
);

// ruleid: sast.js.sequelize-no-tls
const p2 = new Pool({ connectionString: process.env.DB, ssl: false });

// ok: sast.js.sequelize-no-tls
const o1 = new Sequelize("db", "u", "p", { dialect: "postgres", dialectOptions: { ssl: { require: true, rejectUnauthorized: true, ca } } });

// ok: sast.js.sequelize-no-tls
const o2 = new Pool({ host: "db", ssl: true });

// ok: sast.js.sequelize-no-tls
const o3 = new Sequelize("postgres://u:p@db.example.com:5432/app?sslmode=verify-full");

// ok: sast.js.sequelize-no-tls
const o4 = https.get(url, { agent: new https.Agent({}) });

// ok: sast.js.sequelize-no-tls
const o5 = new Sequelize("sqlite::memory:", { logging: false });

// ok: sast.js.sequelize-no-tls
const o6 = someOtherLib({ ssl: false });
