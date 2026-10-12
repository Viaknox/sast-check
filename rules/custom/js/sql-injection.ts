import express, { Request, Response } from 'express';
import mysql from 'mysql2';
import { Pool } from 'pg';
import knex from 'knex';

const app = express();
const pool: Pool = new Pool();
const connection = mysql.createConnection({});
const db: any = {};
const kx = knex({ client: 'pg' });

app.get('/user', (req: Request, res: Response) => {
  const id: string = req.query.id as string;
  // ruleid: sast.js.sql-injection
  connection.query('SELECT * FROM users WHERE id = ' + id, (err, rows) => res.json(rows));
});

app.get('/search', async (req: Request, res: Response) => {
  // ruleid: sast.js.sql-injection
  const r = await pool.query(`SELECT * FROM items WHERE name = '${req.query.name}'`);
  res.json(r.rows);
});

app.get('/lite', (req: Request, res: Response) => {
  const term = req.params.term;
  // ruleid: sast.js.sql-injection
  db.all("SELECT * FROM docs WHERE title LIKE '%" + term + "%'", (e: Error, rows: any[]) => res.json(rows));
});

app.get('/knex', async (req: Request, res: Response) => {
  // ruleid: sast.js.sql-injection
  const rows = await kx.raw('SELECT * FROM t ORDER BY ' + req.query.order);
  // ruleid: sast.js.sql-injection
  const more = await kx('t').whereRaw(`owner = ${req.body.owner}`);
  res.json([rows, more]);
});

app.get('/prisma', async (req: Request, res: Response) => {
  const prisma: any = {};
  // ruleid: sast.js.sql-injection
  const a = await prisma.$queryRawUnsafe(`SELECT * FROM u WHERE email = '${req.body.email}'`);
  res.json(a);
});

app.get('/decoy-escape', async (req: Request, res: Response) => {
  // bare escape() is not a SQL escaper (could be an HTML escape or homegrown helper)
  // ruleid: sast.js.sql-injection
  const a = await pool.query("SELECT * FROM users WHERE name = '" + escape(req.query.name) + "'");
  // ruleid: sast.js.sql-injection
  const b = await pool.query("SELECT * FROM users WHERE name = '" + html.escape(req.query.name) + "'");
  res.json([a, b]);
});

app.get('/safe', async (req: Request, res: Response) => {
  const prisma: any = {};
  // ok: sast.js.sql-injection
  const a = await pool.query('SELECT * FROM users WHERE id = $1', [req.query.id]);
  // ok: sast.js.sql-injection
  connection.query('SELECT * FROM users WHERE id = ?', [req.query.id], () => {});
  // ok: sast.js.sql-injection
  db.get('SELECT * FROM users WHERE id = ?', req.params.id, () => {});
  // ok: sast.js.sql-injection
  const b = await prisma.$queryRaw`SELECT * FROM users WHERE id = ${req.query.id}`;
  // ok: sast.js.sql-injection
  const c = await pool.query('SELECT * FROM users WHERE id = ' + Number(req.query.id));
  // ok: sast.js.sql-injection
  const f = await pool.query("SELECT * FROM users WHERE name = " + connection.escape(req.query.name));
  // ok: sast.js.sql-injection
  const d = await pool.query({ text: 'SELECT * FROM users WHERE id = $1', values: [req.query.id] });
  // ok: sast.js.sql-injection
  const e = await kx.raw('SELECT * FROM t WHERE id = ?', [req.query.id]);
  // ok: sast.js.sql-injection
  const cache = new Map<string, string>(); cache.get(req.params.key);
  res.json([a, b, c, d, e]);
});
