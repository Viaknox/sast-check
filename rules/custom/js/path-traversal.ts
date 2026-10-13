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
  // ruleid: sast.js.path-traversal
  const e = fs.readFileSync(sanitize(req.query.file as string));
  res.send([a, b, c, d]);
});

// a helper that only ever receives constant paths
function loadAsset(rel: string): Buffer {
  // ok: sast.js.path-traversal
  return fs.readFileSync(path.join(BASE, rel));
}
const LOGO = loadAsset('logo.png');
app.get('/asset', (req: Request, res: Response) => {
  res.send(loadAsset('banner.png'));
});

// a value reduced to letters and digits cannot hold a separator or ..
app.get('/alnum1', (req: Request, res: Response) => {
  const id = String(req.query.id).replace(/[^A-Za-z0-9]/g, '');
  // ok: sast.js.path-traversal
  res.send(fs.readFileSync(path.join(BASE, id)));
});
app.get('/alnum2', (req: Request, res: Response) => {
  const id = String(req.query.id);
  if (/^[A-Za-z0-9]+$/.test(id)) {
    // ok: sast.js.path-traversal
    res.send(fs.readFileSync(path.join(BASE, id)));
  }
});
app.get('/alnum3', (req: Request, res: Response) => {
  const id = String(req.query.id);
  if (!/^[A-Za-z0-9]+$/.test(id)) {
    res.sendStatus(400);
    return;
  }
  // ok: sast.js.path-traversal
  res.send(fs.readFileSync(path.join(BASE, id)));
});
app.get('/alnum4', (req: Request, res: Response) => {
  const id = String(req.query.id);
  if (!/^[a-z0-9]*$/i.test(id)) {
    throw new Error('bad id');
  }
  // ok: sast.js.path-traversal
  res.send(fs.readFileSync(path.join(BASE, id)));
});
app.get('/alnum1b', (req: Request, res: Response) => {
  const id = String(req.query.id).replaceAll(/[^A-Za-z0-9]/g, '');
  // ok: sast.js.path-traversal
  res.send(fs.readFileSync(path.join(BASE, id)));
});
// only the tested value is cleared, not other request data used in the same branch
app.get('/alnum9', (req: Request, res: Response) => {
  const id = String(req.query.id);
  const other = String(req.query.other);
  if (/^[A-Za-z0-9]+$/.test(id)) {
    // ruleid: sast.js.path-traversal
    res.send(fs.readFileSync(path.join(BASE, other)));
  }
});
app.get('/alnum10', (req: Request, res: Response) => {
  const id = String(req.query.id);
  const other = String(req.query.other);
  if (!/^[A-Za-z0-9]+$/.test(id)) {
    return;
  }
  // ruleid: sast.js.path-traversal
  res.send(fs.readFileSync(path.join(BASE, other)));
});
app.get('/alnum11', (req: Request, res: Response) => {
  const id = String(req.query.id);
  if (!/^[a-z0-9./]+$/.test(id)) {
    return;
  }
  // ruleid: sast.js.path-traversal
  res.send(fs.readFileSync(path.join(BASE, id)));
});
// look-alikes that still let ../ through
app.get('/alnum5', (req: Request, res: Response) => {
  const id = String(req.query.id).replace(/\./g, '');
  // ruleid: sast.js.path-traversal
  res.send(fs.readFileSync(path.join(BASE, id)));
});
app.get('/alnum6', (req: Request, res: Response) => {
  const id = String(req.query.id).replace(/[^A-Za-z0-9]/, '');
  // ruleid: sast.js.path-traversal
  res.send(fs.readFileSync(path.join(BASE, id)));
});
app.get('/alnum7', (req: Request, res: Response) => {
  const id = String(req.query.id);
  if (/^[a-z0-9./]+$/.test(id)) {
    // ruleid: sast.js.path-traversal
    res.send(fs.readFileSync(path.join(BASE, id)));
  }
});
app.get('/alnum8', (req: Request, res: Response) => {
  const id = String(req.query.id);
  if (!/^[A-Za-z0-9]+$/.test(id)) {
    console.warn('odd id');
  }
  // ruleid: sast.js.path-traversal
  res.send(fs.readFileSync(path.join(BASE, id)));
});

// joined under a root and checked before use
app.get('/root1', (req: Request, res: Response) => {
  const full = path.resolve(BASE, String(req.query.f));
  if (!full.startsWith(BASE + path.sep)) {
    res.sendStatus(403);
    return;
  }
  // ok: sast.js.path-traversal
  res.send(fs.readFileSync(full));
});
app.get('/root2', (req: Request, res: Response) => {
  const full = path.resolve(BASE, String(req.query.f));
  if (!full.startsWith(BASE + path.sep)) {
    throw new Error('outside');
  }
  // ok: sast.js.path-traversal
  res.send(fs.readFileSync(full));
});
app.get('/root2b', (req: Request, res: Response) => {
  const full = path.resolve(BASE, String(req.query.f));
  if (full.startsWith(BASE + path.sep)) {
    // ok: sast.js.path-traversal
    res.send(fs.readFileSync(full));
  }
});
app.get('/root3b', (req: Request, res: Response) => {
  const full = path.resolve(BASE, String(req.query.f));
  const rel = path.relative(BASE, full);
  if (rel.startsWith('..') || path.isAbsolute(rel)) {
    throw new Error('outside');
  }
  // ok: sast.js.path-traversal
  res.send(fs.readFileSync(full));
});
app.get('/root3', (req: Request, res: Response) => {
  const full = path.resolve(BASE, String(req.query.f));
  const rel = path.relative(BASE, full);
  if (rel.startsWith('..') || path.isAbsolute(rel)) {
    res.sendStatus(403);
    return;
  }
  // ok: sast.js.path-traversal
  res.send(fs.readFileSync(full));
});
// only the checked path is cleared
app.get('/root6', (req: Request, res: Response) => {
  const full = path.resolve(BASE, String(req.query.f));
  const other = path.resolve(BASE, String(req.query.g));
  if (!full.startsWith(BASE + path.sep)) {
    return;
  }
  // ruleid: sast.js.path-traversal
  res.send(fs.readFileSync(other));
});
// a prefix test without a separator also accepts sibling folders such as /srv/files-private
app.get('/root4', (req: Request, res: Response) => {
  const full = path.resolve(BASE, String(req.query.f));
  if (!full.startsWith(BASE)) {
    res.sendStatus(403);
    return;
  }
  // ruleid: sast.js.path-traversal
  res.send(fs.readFileSync(full));
});
// a check that does not stop the request protects nothing
app.get('/root5', (req: Request, res: Response) => {
  const full = path.resolve(BASE, String(req.query.f));
  if (!full.startsWith(BASE + path.sep)) {
    console.warn('outside');
  }
  // ruleid: sast.js.path-traversal
  res.send(fs.readFileSync(full));
});
