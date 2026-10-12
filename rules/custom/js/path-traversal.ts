import fs from 'fs';
import { promises as fsp } from 'fs';
import path from 'path';
import express, { Request, Response } from 'express';

const app = express();
const BASE: string = '/srv/files';

app.get('/read', (req: Request, res: Response) => {
  // ruleid: sast.js.path-traversal
  const data = fs.readFileSync(BASE + '/' + req.query.name);
  res.send(data);
});

app.get('/join', async (req: Request, res: Response) => {
  const p: string = path.join(BASE, req.params.file);
  // ruleid: sast.js.path-traversal
  const data = await fsp.readFile(p, 'utf8');
  res.send(data);
});

app.get('/stream', (req: Request, res: Response) => {
  // ruleid: sast.js.path-traversal
  fs.createReadStream(path.resolve(BASE, String(req.query.f))).pipe(res);
});

app.get('/dl', (req: Request, res: Response) => {
  // ruleid: sast.js.path-traversal
  res.sendFile(req.query.file as string);
});

app.get('/dl2', (req: Request, res: Response) => {
  // ruleid: sast.js.path-traversal
  res.download(path.join(BASE, req.body.name));
});

app.delete('/rm', (req: Request, res: Response) => {
  // ruleid: sast.js.path-traversal
  fs.unlink(`${BASE}/${req.params.id}`, () => res.end());
});

app.get('/safe', async (req: Request, res: Response) => {
  // ok: sast.js.path-traversal
  const a = fs.readFileSync(path.join(BASE, path.basename(String(req.query.name))));
  // ok: sast.js.path-traversal
  const b = fs.readFileSync('/etc/app/config.json');
  // ok: sast.js.path-traversal
  res.sendFile(String(req.query.file), { root: BASE });
  // ok: sast.js.path-traversal
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
  // ok: sast.js.path-traversal
  const c = await fsp.readFile(path.join(BASE, `${Number(req.params.id)}.json`));
  // ok: sast.js.path-traversal
  const d = new Map<string, string>().get(req.params.key);
  res.send([a, b, c, d]);
});
