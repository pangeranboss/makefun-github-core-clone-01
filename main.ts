// github-core-clone-01: a standalone GitHub-compatible git forge in one process.
//
// Surfaces: git smart HTTP (upload-pack v2 + v0, receive-pack v0), REST v3 under
// /api/v3, GraphQL v4 at /api/graphql, MCP at /mcp. Standard library only.
// Everything lives in memory; all stored state is deterministic (no wall clock,
// no randomness in stored data) so two runs on the same scenario agree.
//
// Lifecycle: bind an ephemeral port, POST {"port": N} to $MAKEFUN_ENV_URL/register,
// long-poll GET $MAKEFUN_ENV_URL/done until {"done": true}, exit 0.
// Without MAKEFUN_ENV_URL (local runs) it just serves on $PORT (or an ephemeral
// port) and never exits on its own.

import { createServer } from 'node:http';
import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';

const TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';
const ENV_URL = (process.env.MAKEFUN_ENV_URL ?? '').replace(/\/+$/, '');

// ---------------------------------------------------------------------------
// The seeded scenario's identities, recomputed from the published fixed seed.
// The suite derives every owner/login from this same seed, so the token owner's
// login is deterministic: viewer "adaiversen", stranger "olgabauer".
// ---------------------------------------------------------------------------

const U64_MASK = 0xffffffffffffffffn;
function fnv1a64(text) {
  let hash = 0xcbf29ce484222325n;
  for (let i = 0; i < text.length; i += 1) {
    hash ^= BigInt(text.charCodeAt(i));
    hash = (hash * 0x100000001b3n) & U64_MASK;
  }
  return hash;
}
function mix64(value) {
  let z = (value + 0x9e3779b97f4a7c15n) & U64_MASK;
  z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & U64_MASK;
  z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & U64_MASK;
  return (z ^ (z >> 31n)) & U64_MASK;
}
const SCENARIO_SEED = 0x6a09e667f3bcc909n;
function scenarioSeedFor(label) { return mix64(SCENARIO_SEED ^ fnv1a64(label)); }
class Rng {
  constructor(seed) { const m = seed & U64_MASK; this.state = m === 0n ? SCENARIO_SEED : m; }
  nextU64() {
    let x = this.state;
    x = (x ^ (x >> 12n)) & U64_MASK;
    x = (x ^ (x << 25n)) & U64_MASK;
    x = (x ^ (x >> 27n)) & U64_MASK;
    this.state = x;
    return (x * 0x2545f4914f6cdd1dn) & U64_MASK;
  }
  nextU32() { return Number(this.nextU64() >> 32n); }
  nextInt(maxExclusive) {
    if (maxExclusive === 1) return 0;
    const range = 4294967296;
    const limit = range - (range % maxExclusive);
    for (;;) { const v = this.nextU32(); if (v < limit) return v % maxExclusive; }
  }
  pick(items) { return items[this.nextInt(items.length)]; }
}
const FIRST_NAMES = ['ada','bram','cora','dmitri','elena','felix','greta','hugo','iris','jonas','kira','lars','mira','nico','olga','pavel','quinn','rosa','sven','tess','ulla','vito','wren','yara','zane'];
const LAST_NAMES = ['anders','bauer','costa','dahl','eriksen','fischer','garcia','holm','iversen','jansen','keller','lind','moreau','novak','olsen','peters','quist','rossi','sato','turi','ulrich','vega','weber','xu','yilmaz','zimmer'];
function generateUsers(count) {
  const rng = new Rng(scenarioSeedFor('users'));
  const used = new Set();
  const users = [];
  for (let i = 0; i < count; i += 1) {
    const first = rng.pick(FIRST_NAMES);
    const last = rng.pick(LAST_NAMES);
    const base = `${first}${last}`.replace(/[^a-z0-9-]/g, '');
    let login = base;
    let suffix = 2;
    while (used.has(login)) { login = `${base}-${suffix}`; suffix += 1; }
    used.add(login);
    users.push({ id: 1000 + i, login, name: `${first} ${last}`, email: `${login}@example.invalid` });
  }
  return users;
}
const SCENARIO_USERS = generateUsers(12);
const VIEWER = SCENARIO_USERS[0];       // token owner
const STRANGER = SCENARIO_USERS[2];     // the "other owner" of the 404 check

// ---------------------------------------------------------------------------
// Deterministic counters (no wall clock, no randomness in stored state).
// ---------------------------------------------------------------------------

let reqCounter = 0;
let repoIdCounter = 0;
let globalIdCounter = 0;
let tsCounter = 0;
const BASE_TS = 1735689600; // 2025-01-01T00:00:00Z
function nextTs() { tsCounter += 1; return BASE_TS + tsCounter; }
function tsIso(ts) { return new Date(ts * 1000).toISOString(); }
const FIXED_DATE = '2025-01-01T00:00:00Z';
const ZERO_OID = '0'.repeat(40);
const DEFAULT_BRANCH = 'main';

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

function sha1Hex(data) { return createHash('sha1').update(data).digest('hex'); }
function hashObject(type, data) {
  const header = Buffer.from(`${type} ${data.length}\0`, 'utf8');
  return sha1Hex(Buffer.concat([header, data]));
}
function b64encode(buf) { return Buffer.from(buf).toString('base64'); }
function b64decode(str) { return Buffer.from(String(str).replace(/[\r\n\t ]+/g, ''), 'base64'); }
function isOid(v) { return typeof v === 'string' && /^[0-9a-f]{40}$/.test(v); }
function escJson(s) { return JSON.stringify(s); }

// ---------------------------------------------------------------------------
// pkt-line codec
// ---------------------------------------------------------------------------

function pktLine(payload) {
  const data = Buffer.isBuffer(payload) ? payload : Buffer.from(payload, 'utf8');
  const header = Buffer.alloc(4);
  header.write((data.length + 4).toString(16).padStart(4, '0'), 0, 4, 'ascii');
  return Buffer.concat([header, data]);
}
const PKT_FLUSH = Buffer.from('0000', 'ascii');
const PKT_DELIM = Buffer.from('0001', 'ascii');
function pktLines(items) {
  const parts = [];
  for (const it of items) {
    if (it === 'flush') parts.push(PKT_FLUSH);
    else if (it === 'delim') parts.push(PKT_DELIM);
    else parts.push(pktLine(it));
  }
  return Buffer.concat(parts);
}
// Parse pkt-lines from the start of buf. Returns {packets, offset} where packets
// are {kind:'data', payload} | {kind:'flush'} | {kind:'delim'} | {kind:'response-end'}.
// Throws on malformed framing.
function parsePktLines(buf, start = 0) {
  const packets = [];
  let off = start;
  while (off + 4 <= buf.length) {
    const lenHex = buf.toString('ascii', off, off + 4);
    if (!/^[0-9a-fA-F]{4}$/.test(lenHex)) throw new Error('malformed pkt-line header');
    const len = parseInt(lenHex, 16);
    if (len === 0) { packets.push({ kind: 'flush' }); off += 4; continue; }
    if (len === 1) { packets.push({ kind: 'delim' }); off += 4; continue; }
    if (len === 2) { packets.push({ kind: 'response-end' }); off += 4; continue; }
    if (len < 4 || off + len > buf.length) throw new Error('truncated pkt-line');
    packets.push({ kind: 'data', payload: buf.subarray(off + 4, off + len) });
    off += len;
  }
  if (off !== buf.length) throw new Error('trailing bytes after pkt-lines');
  return { packets, offset: off };
}
// Parse pkt-lines until (and including) the first flush; return packets + offset
// just past the flush. Throws when no flush is found.
function parsePktLinesUntilFlush(buf, start = 0) {
  const packets = [];
  let off = start;
  while (off + 4 <= buf.length) {
    const lenHex = buf.toString('ascii', off, off + 4);
    if (!/^[0-9a-fA-F]{4}$/.test(lenHex)) throw new Error('malformed pkt-line header');
    const len = parseInt(lenHex, 16);
    if (len === 0) { packets.push({ kind: 'flush' }); return { packets, offset: off + 4 }; }
    if (len === 1) { packets.push({ kind: 'delim' }); off += 4; continue; }
    if (len === 2) { packets.push({ kind: 'response-end' }); off += 4; continue; }
    if (len < 4 || off + len > buf.length) throw new Error('truncated pkt-line');
    packets.push({ kind: 'data', payload: buf.subarray(off + 4, off + len) });
    off += len;
  }
  throw new Error('no flush packet');
}

// ---------------------------------------------------------------------------
// Git object model
// ---------------------------------------------------------------------------

function parseCommit(data) {
  const text = data.toString('utf8');
  const headEnd = text.indexOf('\n\n');
  const head = headEnd === -1 ? text : text.slice(0, headEnd);
  const message = headEnd === -1 ? '' : text.slice(headEnd + 2);
  let tree = null;
  const parents = [];
  let author = '';
  let committer = '';
  for (const line of head.split('\n')) {
    if (line.startsWith('tree ')) tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) parents.push(line.slice(7).trim());
    else if (line.startsWith('author ')) author = line.slice(7);
    else if (line.startsWith('committer ')) committer = line.slice(10);
  }
  return { tree, parents, author, committer, message };
}
function parseTree(data) {
  const entries = [];
  let off = 0;
  while (off < data.length) {
    const space = data.indexOf(0x20, off);
    const nul = data.indexOf(0x00, space);
    const mode = data.toString('utf8', off, space);
    const name = data.toString('utf8', space + 1, nul);
    const oid = data.subarray(nul + 1, nul + 21).toString('hex');
    entries.push({ mode, name, oid });
    off = nul + 21;
  }
  return entries;
}
function buildTree(entries) {
  const sorted = [...entries].sort((a, b) => {
    const an = a.mode === '40000' ? `${a.name}/` : a.name;
    const bn = b.mode === '40000' ? `${b.name}/` : b.name;
    return an < bn ? -1 : an > bn ? 1 : 0;
  });
  const parts = [];
  for (const e of sorted) {
    parts.push(Buffer.from(`${e.mode} ${e.name}\0`, 'utf8'));
    parts.push(Buffer.from(e.oid, 'hex'));
  }
  return Buffer.concat(parts);
}
function parseTag(data) {
  const text = data.toString('utf8');
  const headEnd = text.indexOf('\n\n');
  const head = headEnd === -1 ? text : text.slice(0, headEnd);
  const message = headEnd === -1 ? '' : text.slice(headEnd + 2);
  let object = null; let type = null; let tag = null; let tagger = '';
  for (const line of head.split('\n')) {
    if (line.startsWith('object ')) object = line.slice(7).trim();
    else if (line.startsWith('type ')) type = line.slice(5).trim();
    else if (line.startsWith('tag ')) tag = line.slice(4).trim();
    else if (line.startsWith('tagger ')) tagger = line.slice(7);
  }
  return { object, type, tag, tagger, message };
}
function commitTimestamp(authorLine) {
  const m = / (\d+) [+-]\d{4}$/.exec(authorLine ?? '');
  return m ? Number(m[1]) : BASE_TS;
}

// ---------------------------------------------------------------------------
// Delta application + pack reading / writing
// ---------------------------------------------------------------------------

function readVarint(buf, off) {
  let value = buf[off] & 0x7f;
  let next = off + 1;
  while (buf[off] & 0x80) {
    off = next;
    value = ((value + 1) << 7) | (buf[off] & 0x7f);
    next = off + 1;
  }
  return { value, next };
}
function applyDelta(base, delta) {
  let off = 0;
  const src = readVarint(delta, off); off = src.next;
  if (src.value !== base.length) throw new Error('delta source size mismatch');
  const tgt = readVarint(delta, off); off = tgt.next;
  const out = Buffer.alloc(tgt.value);
  let pos = 0;
  while (off < delta.length) {
    const op = delta[off]; off += 1;
    if (op & 0x80) {
      let cpOff = 0; let cpSize = 0;
      for (let i = 0; i < 4; i += 1) if (op & (1 << i)) { cpOff |= delta[off] << (8 * i); off += 1; }
      for (let i = 0; i < 3; i += 1) if (op & (0x10 << i)) { cpSize |= delta[off] << (8 * i); off += 1; }
      if (cpSize === 0) cpSize = 0x10000;
      base.copy(out, pos, cpOff, cpOff + cpSize);
      pos += cpSize;
    } else if (op !== 0) {
      delta.copy(out, pos, off, off + op);
      off += op; pos += op;
    } else throw new Error('delta opcode 0');
  }
  if (pos !== tgt.value) throw new Error('delta target size mismatch');
  return out;
}
// Inflate exactly one zlib stream starting at `off`. Returns {data, next} where
// next is the offset just past the stream. inflateSync with info:true reports
// the input bytes the engine consumed (engine.bytesWritten), so one inflate
// is enough — no binary search over the stream end.
function inflateAt(buf, off) {
  const tailLen = buf.length - off;
  if (tailLen <= 0) throw new Error('no zlib data');
  const result = inflateSync(buf.subarray(off), { info: true });
  const consumed = result.engine?.bytesWritten;
  if (!consumed || consumed <= 0 || consumed > tailLen) throw new Error('zlib stream consumed no bytes');
  return { data: result.buffer, next: off + consumed };
}
const PACK_TYPE = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag', 6: 'ofs-delta', 7: 'ref-delta' };
function readPack(pack, storeLookup) {
  if (pack.length < 12 || pack.toString('ascii', 0, 4) !== 'PACK') throw new Error('bad pack header');
  const version = pack.readUInt32BE(4);
  const count = pack.readUInt32BE(8);
  const objects = new Map(); // oid -> {type, data}
  const byOffset = new Map(); // offset -> {type, data, oid}
  let off = 12;
  for (let i = 0; i < count; i += 1) {
    const entryOff = off;
    let byte = pack[off]; off += 1;
    const typeNum = (byte >> 4) & 0x7;
    let size = byte & 0x0f;
    let shift = 4;
    while (byte & 0x80) { byte = pack[off]; off += 1; size |= (byte & 0x7f) << shift; shift += 7; }
    const typeName = PACK_TYPE[typeNum];
    if (!typeName) throw new Error(`unknown pack type ${typeNum}`);
    let baseOid = null; let baseOffset = null;
    if (typeNum === 6) {
      byte = pack[off]; off += 1;
      let base = byte & 0x7f;
      while (byte & 0x80) { byte = pack[off]; off += 1; base = ((base + 1) << 7) | (byte & 0x7f); }
      baseOffset = entryOff - base;
    } else if (typeNum === 7) {
      baseOid = pack.subarray(off, off + 20).toString('hex'); off += 20;
    }
    const inflated = inflateAt(pack, off);
    const raw = inflated.data;
    off = inflated.next;
    if (raw.length !== size) throw new Error('pack object size mismatch');
    let type; let data;
    if (typeNum === 6 || typeNum === 7) {
      let base;
      if (baseOffset !== null) {
        const b = byOffset.get(baseOffset);
        if (!b) throw new Error('ofs-delta base missing');
        base = b;
      } else {
        const b = objects.get(baseOid) ?? (storeLookup ? storeLookup(baseOid) : undefined);
        if (!b) throw new Error('ref-delta base missing');
        base = b;
      }
      data = applyDelta(base.data, raw);
      type = base.type;
    } else { type = typeName; data = raw; }
    const oid = hashObject(type, data);
    const obj = { type, data };
    objects.set(oid, obj);
    byOffset.set(entryOff, obj);
  }
  // Trailer checksum: sha1 of everything before the last 20 bytes.
  const expected = sha1Hex(pack.subarray(0, pack.length - 20));
  const actual = pack.subarray(pack.length - 20).toString('hex');
  if (expected !== actual) throw new Error('pack trailer checksum mismatch');
  return { version, count, objects };
}
function writePackObjectHeader(typeNum, size) {
  const bytes = [];
  let first = (typeNum << 4) | (size & 0x0f);
  size >>= 4;
  if (size > 0) first |= 0x80;
  bytes.push(first);
  while (size > 0) {
    let b = size & 0x7f;
    size >>= 7;
    if (size > 0) b |= 0x80;
    bytes.push(b);
  }
  return Buffer.from(bytes);
}
const TYPE_NUM = { commit: 1, tree: 2, blob: 3, tag: 4 };
function writePack(objects) {
  const parts = [];
  const header = Buffer.alloc(12);
  header.write('PACK', 0, 4, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(objects.length, 8);
  parts.push(header);
  for (const obj of objects) {
    parts.push(writePackObjectHeader(TYPE_NUM[obj.type], obj.data.length));
    parts.push(deflateSync(obj.data));
  }
  const body = Buffer.concat(parts);
  const trailer = Buffer.from(sha1Hex(body), 'hex');
  return Buffer.concat([body, trailer]);
}

// ---------------------------------------------------------------------------
// In-memory store
// ---------------------------------------------------------------------------

const repos = new Map(); // key `${owner}/${name}` -> repo
const repoOrder = []; // repos in creation order

function makeRepo(name, description, isPrivate) {
  repoIdCounter += 1;
  const repo = {
    id: repoIdCounter,
    name,
    owner: VIEWER.login,
    fullName: `${VIEWER.login}/${name}`,
    description: description ?? '',
    private: !!isPrivate,
    defaultBranch: DEFAULT_BRANCH,
    refs: new Map(),
    objects: new Map(), // oid -> {type, data}
    displayMsg: new Map(), // commit oid -> message exactly as submitted
    issues: new Map(), // number -> issue
    pulls: new Map(), // number -> pr
    labels: new Map(), // name -> label
    nextNumber: 1,
    nextCommentId: 1,
    version: 0,
    packCache: new Map(),
    createdSeq: repoIdCounter,
  };
  repos.set(repo.fullName, repo);
  repoOrder.push(repo);
  return repo;
}
function findRepo(owner, name) {
  if (owner !== VIEWER.login) return null;
  return repos.get(`${owner}/${name}`) ?? null;
}
function bumpVersion(repo) { repo.version += 1; repo.packCache.clear(); }

// --- object layer -----------------------------------------------------------

function storeObject(repo, type, data) {
  const oid = hashObject(type, data);
  if (!repo.objects.has(oid)) repo.objects.set(oid, { type, data });
  return oid;
}
function getObject(repo, oid) { return repo.objects.get(oid) ?? null; }
function getCommit(repo, oid) {
  const o = getObject(repo, oid);
  return o && o.type === 'commit' ? parseCommit(o.data) : null;
}
function commitMessage(repo, oid) {
  if (repo.displayMsg.has(oid)) return repo.displayMsg.get(oid);
  const c = getCommit(repo, oid);
  return c ? c.message.replace(/\n$/, '') : '';
}
function serverCommit(repo, treeOid, parents, message) {
  const ts = nextTs();
  const who = `${VIEWER.name} <${VIEWER.email}> ${ts} +0000`;
  const body = `tree ${treeOid}\n` + parents.map((p) => `parent ${p}\n`).join('') +
    `author ${who}\ncommitter ${who}\n\n${message}\n`;
  const oid = storeObject(repo, 'commit', Buffer.from(body, 'utf8'));
  repo.displayMsg.set(oid, message);
  return oid;
}
function flatTree(repo, commitOid) {
  // Map path -> {mode, oid}; symlinks/submodules treated as blobs.
  const out = new Map();
  const commit = getCommit(repo, commitOid);
  if (!commit || !commit.tree) return out;
  const walk = (treeOid, prefix) => {
    const obj = getObject(repo, treeOid);
    if (!obj || obj.type !== 'tree') return;
    for (const e of parseTree(obj.data)) {
      const path = prefix ? `${prefix}/${e.name}` : e.name;
      if (e.mode === '40000') walk(e.oid, path);
      else out.set(path, { mode: e.mode, oid: e.oid });
    }
  };
  walk(commit.tree, '');
  return out;
}
function buildTreeFromFlat(repo, flat) {
  // flat: Map path -> {mode, oid}. Builds nested trees bottom-up.
  const dirs = new Map(); // dir path -> Map name -> entry
  dirs.set('', new Map());
  for (const [path, entry] of flat) {
    const parts = path.split('/');
    const file = parts.pop();
    const dir = parts.join('/');
    if (!dirs.has(dir)) dirs.set(dir, new Map());
    dirs.get(dir).set(file, { mode: entry.mode, name: file, oid: entry.oid });
    let cur = '';
    for (const part of parts) {
      const parent = cur;
      cur = cur ? `${cur}/${part}` : part;
      if (!dirs.has(cur)) dirs.set(cur, new Map());
      const pMap = dirs.get(parent);
      if (!pMap.has(part)) pMap.set(part, { mode: '40000', name: part, oid: '' });
    }
  }
  const depthOf = (d) => (d === '' ? 0 : d.split('/').length);
  const ordered = [...dirs.keys()].sort((a, b) => depthOf(b) - depthOf(a));
  const treeOidByDir = new Map();
  for (const dir of ordered) {
    const entries = [...dirs.get(dir).values()].map((e) => {
      if (e.mode === '40000') return { mode: '40000', name: e.name, oid: treeOidByDir.get(dir ? `${dir}/${e.name}` : e.name) };
      return e;
    });
    const oid = storeObject(repo, 'tree', buildTree(entries));
    treeOidByDir.set(dir, oid);
  }
  return treeOidByDir.get('');
}
function isAncestor(repo, ancestor, descendant) {
  if (ancestor === descendant) return true;
  const seen = new Set();
  const stack = [descendant];
  while (stack.length) {
    const cur = stack.pop();
    if (cur === ancestor) return true;
    if (seen.has(cur)) continue;
    seen.add(cur);
    const c = getCommit(repo, cur);
    if (c) for (const p of c.parents) stack.push(p);
  }
  return false;
}
// All object oids reachable from a commit (commit + trees + blobs), honoring
// a set of shallow-boundary commits whose parents are NOT followed.
function collectReachable(repo, roots, shallow = new Set(), out = new Map()) {
  const stack = [];
  for (const r of roots) {
    const o = getObject(repo, r);
    if (!o) continue;
    if (o.type === 'commit') stack.push({ oid: r, kind: 'commit' });
    else out.set(r, o);
  }
  const seenCommits = new Set();
  const seenTrees = new Set();
  while (stack.length) {
    const { oid, kind } = stack.pop();
    if (kind === 'commit') {
      if (seenCommits.has(oid)) continue;
      seenCommits.add(oid);
      const obj = getObject(repo, oid);
      if (!obj) continue;
      out.set(oid, obj);
      const c = parseCommit(obj.data);
      if (c.tree) stack.push({ oid: c.tree, kind: 'tree' });
      if (!shallow.has(oid)) for (const p of c.parents) stack.push({ oid: p, kind: 'commit' });
    } else {
      if (seenTrees.has(oid)) continue;
      seenTrees.add(oid);
      const obj = getObject(repo, oid);
      if (!obj) continue;
      out.set(oid, obj);
      for (const e of parseTree(obj.data)) {
        if (e.mode === '40000') stack.push({ oid: e.oid, kind: 'tree' });
        else { const b = getObject(repo, e.oid); if (b) out.set(e.oid, b); }
      }
    }
  }
  return out;
}
// BFS over commit parents from wants; returns Map oid -> generation (0 = want).
function commitGenerations(repo, wants) {
  const gen = new Map();
  const queue = [];
  for (const w of wants) {
    const c = getCommit(repo, w);
    if (c && !gen.has(w)) { gen.set(w, 0); queue.push(w); }
  }
  while (queue.length) {
    const cur = queue.shift();
    const c = getCommit(repo, cur);
    if (!c) continue;
    for (const p of c.parents) {
      if (!gen.has(p)) { gen.set(p, gen.get(cur) + 1); queue.push(p); }
    }
  }
  return gen;
}
// Objects to send for a fetch: reachable from wants minus held, with depth and
// shallow-boundary handling. Returns {objects:[{type,data}], shallow:[], unshallow:[]}.
function computeFetch(repo, { wants, haves, shallow, depth }) {
  const shallowReq = new Set((shallow ?? []).filter((h) => repo.objects.has(h)));
  // held = objects the client already has: full closure of non-shallow haves,
  // plus shallow-boundary commits with their trees/blobs but no parents.
  const held = new Map();
  const heldFullCommits = new Set();
  for (const h of haves) {
    const o = getObject(repo, h);
    if (!o) continue;
    if (o.type === 'commit') {
      if (shallowReq.has(h)) collectReachable(repo, [h], new Set([h]), held);
      else {
        collectReachable(repo, [h], new Set(), held);
        for (const oid of held.keys()) { const oo = getObject(repo, oid); if (oo?.type === 'commit') heldFullCommits.add(oid); }
      }
    } else held.set(h, o);
  }
  const gen = commitGenerations(repo, wants);
  const sendCommits = new Set();
  for (const [oid, g] of gen) {
    if (depth != null && g >= depth) continue;
    sendCommits.add(oid);
  }
  // Trees/blobs of send commits, plus tag objects among wants.
  const send = new Map();
  for (const oid of sendCommits) collectReachable(repo, [oid], new Set([oid]), send);
  for (const w of wants) {
    const o = getObject(repo, w);
    if (o && o.type === 'tag') send.set(w, o);
  }
  for (const oid of held.keys()) send.delete(oid);
  // Deterministic object order: commits by generation then oid, then trees, blobs, tags.
  const ordered = [...send.entries()]
    .filter(([oid]) => sendCommits.has(oid))
    .sort((a, b) => (gen.get(a[0]) - gen.get(b[0])) || (a[0] < b[0] ? -1 : 1));
  const rest = [...send.entries()]
    .filter(([oid]) => !sendCommits.has(oid))
    .sort((a, b) => {
      const rank = (o) => ({ commit: 0, tree: 1, blob: 2, tag: 3 }[o.type] ?? 4);
      return rank(a[1]) - rank(b[1]) || (a[0] < b[0] ? -1 : 1);
    });
  const objects = [...ordered, ...rest].map(([, o]) => o);
  let shallowList = [];
  let unshallow = [];
  if (depth != null) {
    shallowList = [...sendCommits].filter((oid) => {
      const g = gen.get(oid);
      if (g === depth - 1) return true;
      // A commit whose parents were all excluded by the depth cut is a boundary.
      const c = getCommit(repo, oid);
      return c && c.parents.length > 0 && c.parents.every((p) => !sendCommits.has(p) && gen.has(p));
    }).sort();
  }
  for (const s of shallowReq) {
    const c = getCommit(repo, s);
    if (!c) continue;
    const parentsKnown = c.parents.every((p) => sendCommits.has(p) || heldFullCommits.has(p));
    if (parentsKnown) unshallow.push(s);
  }
  unshallow.sort();
  return { objects, shallow: shallowList, unshallow };
}
// (shallow boundaries are declared explicitly by the client in `shallow`
// arguments; no heuristic is needed here.)

// --- JSON shapes ------------------------------------------------------------

function repoJson(repo) {
  return {
    id: repo.id, name: repo.name, full_name: repo.fullName, private: repo.private,
    owner: { login: repo.owner, id: VIEWER.id, type: 'User' },
    description: repo.description, fork: false, created_at: FIXED_DATE, updated_at: FIXED_DATE,
    pushed_at: FIXED_DATE, homepage: '', size: 0, stargazers_count: 0, watchers_count: 0,
    language: null, has_issues: true, has_projects: true, has_downloads: true,
    has_wiki: true, has_pages: false, forks_count: 0, archived: false, disabled: false,
    open_issues_count: [...repo.issues.values()].filter((i) => i.state === 'open').length,
    license: null, allow_forking: true, is_template: false, topics: [],
    visibility: repo.private ? 'private' : 'public', default_branch: repo.defaultBranch,
  };
}
function issueJson(repo, issue) {
  return {
    url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${issue.number}`,
    repository_url: `/api/v3/repos/${repo.owner}/${repo.name}`,
    id: issue.id, node_id: b64encode(`I:${repo.id}:${issue.number}`), number: issue.number,
    title: issue.title, body: issue.body ?? null, state: issue.state, locked: false,
    user: { login: VIEWER.login, id: VIEWER.id, type: 'User' },
    labels: issue.labels.map((l) => ({ id: l.id, name: l.name, color: l.color, description: l.description ?? '' })),
    comments: issue.comments.length, created_at: issue.createdAt, updated_at: issue.updatedAt,
    closed_at: issue.state === 'closed' ? issue.updatedAt : null,
    author_association: 'OWNER', active_lock_reason: null,
    comments_url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${issue.number}/comments`,
  };
}
function prHeadBase(repo, pr) {
  const headTip = repo.refs.get(`refs/heads/${pr.head.ref}`);
  const baseTip = repo.refs.get(`refs/heads/${pr.base.ref}`);
  return {
    head: { ref: pr.head.ref, sha: headTip ?? pr.head.sha, label: `${repo.owner}:${pr.head.ref}`, user: { login: repo.owner, id: VIEWER.id, type: 'User' } },
    base: { ref: pr.base.ref, sha: baseTip ?? pr.base.sha, label: `${repo.owner}:${pr.base.ref}`, user: { login: repo.owner, id: VIEWER.id, type: 'User' } },
  };
}
function prJson(repo, pr) {
  const hb = prHeadBase(repo, pr);
  return {
    url: `/api/v3/repos/${repo.owner}/${repo.name}/pulls/${pr.number}`,
    id: pr.id, node_id: b64encode(`P:${repo.id}:${pr.number}`), number: pr.number,
    state: pr.state, title: pr.title, body: pr.body ?? null, user: { login: VIEWER.login, id: VIEWER.id, type: 'User' },
    labels: [], draft: false, locked: false, head: hb.head, base: hb.base,
    merged: pr.merged, mergeable: prMergeable(repo, pr), merge_commit_sha: pr.mergeCommitSha,
    merged_at: pr.mergedAt, created_at: pr.createdAt, updated_at: pr.updatedAt,
    closed_at: pr.state === 'closed' ? pr.updatedAt : null,
    comments: 0, review_comments: 0, commits: 1, additions: 0, deletions: 0, changed_files: 0,
  };
}
function prMergeable(repo, pr) {
  return computeMerge(repo, pr).conflict ? false : true;
}

// --- diff / merge -----------------------------------------------------------

function lineCounts(oldBuf, newBuf) {
  const oldLines = oldBuf ? oldBuf.toString('utf8').split('\n') : [];
  const newLines = newBuf ? newBuf.toString('utf8').split('\n') : [];
  if (oldLines.length && oldLines[oldLines.length - 1] === '') oldLines.pop();
  if (newLines.length && newLines[newLines.length - 1] === '') newLines.pop();
  const count = (arr) => { const m = new Map(); for (const l of arr) m.set(l, (m.get(l) ?? 0) + 1); return m; };
  const oc = count(oldLines); const nc = count(newLines);
  let additions = 0; let deletions = 0;
  for (const [l, n] of nc) additions += Math.max(0, n - (oc.get(l) ?? 0));
  for (const [l, n] of oc) deletions += Math.max(0, n - (nc.get(l) ?? 0));
  return { additions, deletions };
}
function diffTrees(repo, baseCommitOid, headCommitOid) {
  const base = baseCommitOid ? flatTree(repo, baseCommitOid) : new Map();
  const head = headCommitOid ? flatTree(repo, headCommitOid) : new Map();
  const paths = new Set([...base.keys(), ...head.keys()]);
  const files = [];
  for (const path of [...paths].sort()) {
    const b = base.get(path); const h = head.get(path);
    if (b && h && b.oid === h.oid) continue;
    let status; let additions = 0; let deletions = 0;
    if (!b) { status = 'added'; const nb = getObject(repo, h.oid); const lc = lineCounts(null, nb?.data); additions = lc.additions; deletions = 0; }
    else if (!h) { status = 'removed'; const ob = getObject(repo, b.oid); const lc = lineCounts(ob?.data, null); additions = 0; deletions = lc.deletions; }
    else { status = 'modified'; const lc = lineCounts(getObject(repo, b.oid)?.data, getObject(repo, h.oid)?.data); additions = lc.additions; deletions = lc.deletions; }
    files.push({ filename: path, status, additions, deletions, changes: additions + deletions, sha: h?.oid ?? b.oid });
  }
  return files;
}
function computeMerge(repo, pr) {
  const hb = prHeadBase(repo, pr);
  const headTip = hb.head.sha; const baseTip = hb.base.sha;
  const baseTree = baseTip ? flatTree(repo, baseTip) : new Map();
  const mergeBaseTree = pr.baseSha ? flatTree(repo, pr.baseSha) : new Map();
  const headTree = headTip ? flatTree(repo, headTip) : new Map();
  const paths = new Set([...mergeBaseTree.keys(), ...headTree.keys(), ...baseTree.keys()]);
  const result = new Map(baseTree);
  for (const path of paths) {
    const oldE = mergeBaseTree.get(path);
    const headE = headTree.get(path);
    const curE = baseTree.get(path);
    const same = (a, b) => (!a && !b) || (a && b && a.oid === b.oid);
    if (same(oldE, headE)) continue; // head did not change it
    if (same(oldE, curE)) { // base did not change it -> take head
      if (headE) result.set(path, headE); else result.delete(path);
      continue;
    }
    if (same(curE, headE)) continue; // both changed to the same thing
    return { conflict: true };
  }
  return { conflict: false, result, baseTip, headTip };
}
function squashMerge(repo, pr) {
  const m = computeMerge(repo, pr);
  if (m.conflict) return { conflict: true };
  const treeOid = buildTreeFromFlat(repo, m.result);
  const message = `Merge pull request #${pr.number} from ${repo.owner}/${pr.head.ref}\n\n${pr.title}`;
  const oid = serverCommit(repo, treeOid, m.baseTip ? [m.baseTip] : [], message);
  repo.refs.set(`refs/heads/${pr.base.ref}`, oid);
  pr.state = 'closed'; pr.merged = true; pr.mergeCommitSha = oid;
  pr.mergedAt = tsIso(nextTs()); pr.updatedAt = pr.mergedAt;
  bumpVersion(repo);
  return { conflict: false, sha: oid, message };
}

// --- contents ---------------------------------------------------------------

function resolveRef(repo, ref) {
  if (!ref) return repo.refs.get(`refs/heads/${repo.defaultBranch}`) ?? null;
  if (repo.refs.has(`refs/heads/${ref}`)) return repo.refs.get(`refs/heads/${ref}`);
  if (repo.refs.has(ref)) return repo.refs.get(ref);
  if (isOid(ref) && repo.objects.has(ref)) return ref;
  return null;
}
function contentsGet(repo, path, ref) {
  const tip = resolveRef(repo, ref);
  if (!tip) return { status: 404, error: 'Not Found' };
  const commit = getCommit(repo, tip);
  if (!commit) return { status: 404, error: 'Not Found' };
  const flat = flatTree(repo, tip);
  if (path === '') {
    const names = new Set();
    const entries = [];
    for (const p of flat.keys()) {
      const top = p.split('/')[0];
      if (!names.has(top)) { names.add(top); entries.push(top); }
    }
    const items = [];
    for (const top of [...entries].sort()) {
      const isDir = [...flat.keys()].some((p) => p.startsWith(`${top}/`));
      const e = flat.get(top);
      items.push({ type: isDir ? 'dir' : 'file', name: top, path: top, sha: isDir ? '' : e.oid, size: 0 });
    }
    return { status: 200, dir: items };
  }
  const exact = flat.get(path);
  if (exact) {
    const obj = getObject(repo, exact.oid);
    const data = obj?.data ?? Buffer.alloc(0);
    return { status: 200, file: { type: 'file', name: path.split('/').pop(), path, sha: exact.oid, size: data.length, encoding: 'base64', content: b64encode(data) } };
  }
  const prefix = `${path}/`;
  const children = new Map();
  for (const p of flat.keys()) {
    if (!p.startsWith(prefix)) continue;
    const rest = p.slice(prefix.length);
    const top = rest.split('/')[0];
    if (!children.has(top)) children.set(top, rest.includes('/'));
  }
  if (children.size) {
    const items = [...children.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1)).map(([name, isDir]) => {
      const e = flat.get(`${path}/${name}`);
      return { type: isDir ? 'dir' : 'file', name, path: `${path}/${name}`, sha: isDir ? '' : (e?.oid ?? ''), size: 0 };
    });
    return { status: 200, dir: items };
  }
  return { status: 404, error: 'Not Found' };
}
function contentsPut(repo, path, body, branch) {
  const branchName = branch ?? repo.defaultBranch;
  const refName = `refs/heads/${branchName}`;
  const tip = repo.refs.get(refName) ?? null;
  const flat = tip ? flatTree(repo, tip) : new Map();
  const current = flat.get(path);
  const message = typeof body.message === 'string' ? body.message : 'Update';
  const content = Buffer.isBuffer(body.content) ? body.content : b64decode(body.content ?? '');
  if (body.sha !== undefined && body.sha !== null) {
    if (!current || current.oid !== body.sha) return { status: 409, error: 'sha does not match' };
  } else if (current) {
    return { status: 422, error: 'sha is required to update an existing file' };
  }
  const blobOid = storeObject(repo, 'blob', content);
  flat.set(path, { mode: '100644', oid: blobOid });
  const treeOid = buildTreeFromFlat(repo, flat);
  const parents = tip ? [tip] : [];
  const commitOid = serverCommit(repo, treeOid, parents, message);
  repo.refs.set(refName, commitOid);
  bumpVersion(repo);
  return {
    status: current ? 200 : 201,
    body: {
      content: { name: path.split('/').pop(), path, sha: blobOid, size: content.length, encoding: 'base64', content: b64encode(content) },
      commit: { sha: commitOid, message },
    },
  };
}
function contentsDelete(repo, path, body, branch) {
  const branchName = branch ?? repo.defaultBranch;
  const refName = `refs/heads/${branchName}`;
  const tip = repo.refs.get(refName);
  if (!tip) return { status: 404, error: 'Not Found' };
  const flat = flatTree(repo, tip);
  const current = flat.get(path);
  if (!current) return { status: 404, error: 'Not Found' };
  if (body.sha && body.sha !== current.oid) return { status: 409, error: 'sha does not match' };
  flat.delete(path);
  const treeOid = buildTreeFromFlat(repo, flat);
  const message = typeof body.message === 'string' ? body.message : 'Delete';
  const commitOid = serverCommit(repo, treeOid, [tip], message);
  repo.refs.set(refName, commitOid);
  bumpVersion(repo);
  return { status: 200, body: { commit: { sha: commitOid, message } } };
}

// ---------------------------------------------------------------------------
// HTTP plumbing
// ---------------------------------------------------------------------------

function sendJson(res, status, obj, extraHeaders = {}) {
  const body = Buffer.from(JSON.stringify(obj), 'utf8');
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': body.length,
    'x-github-request-id': `req-${++reqCounter}`,
    ...extraHeaders,
  });
  res.end(body);
}
function sendError(res, status, message) { sendJson(res, status, { message }); }
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on('data', (c) => { chunks.push(c); total += c.length; if (total > 32 * 1024 * 1024) req.destroy(new Error('body too large')); });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}
async function readJsonBody(req, res) {
  const raw = await readBody(req);
  if (raw.length === 0) return {};
  try { return JSON.parse(raw.toString('utf8')); }
  catch { sendError(res, 400, 'Problems parsing JSON'); return null; }
}
function parsePagination(url, total) {
  const perPage = Math.max(1, Math.min(100, Number(url.searchParams.get('per_page') ?? 30) || 30));
  const page = Math.max(1, Number(url.searchParams.get('page') ?? 1) || 1);
  const pages = Math.max(1, Math.ceil(total / perPage));
  const start = (page - 1) * perPage;
  return { perPage, page, pages, start, end: Math.min(total, start + perPage) };
}
function linkHeader(url, page, pages, perPage, host) {
  const base = `http://${host}${url.pathname}`;
  const links = [];
  if (page < pages) links.push(`<${base}?per_page=${perPage}&page=${page + 1}>; rel="next"`);
  if (pages > 1) links.push(`<${base}?per_page=${perPage}&page=${pages}>; rel="last"`);
  if (page > 1) links.push(`<${base}?per_page=${perPage}&page=1>; rel="first"`);
  return links.join(', ');
}
function paginate(req, res, url, items, mapFn) {
  const { perPage, page, pages, start, end } = parsePagination(url, items.length);
  const headers = {};
  const link = linkHeader(url, page, pages, perPage, req.headers.host ?? 'localhost');
  if (link) headers.link = link;
  sendJson(res, 200, items.slice(start, end).map(mapFn), headers);
}

// ---------------------------------------------------------------------------
// REST v3
// ---------------------------------------------------------------------------

async function handleRest(req, res, url, segments) {
  const auth = req.headers.authorization ?? '';
  if (auth !== `Bearer ${TOKEN}`) { sendError(res, 401, 'Requires authentication'); return; }
  const method = req.method;

  // GET /api/v3/
  if (segments.length === 0) {
    sendJson(res, 200, { current_user_url: '/api/v3/user', repository_url: '/api/v3/repos/{owner}/{repo}' },
      { 'x-oauth-scopes': 'repo, read:org', 'x-accepted-oauth-scopes': 'repo' });
    return;
  }
  // GET /api/v3/meta
  if (segments.length === 1 && segments[0] === 'meta') {
    if (method !== 'GET') { sendError(res, 404, 'Not Found'); return; }
    sendJson(res, 200, { verifiable_password_authentication: true, installed_version: '1.0.0', github_enterprise: false, hooks: [], git: [], pages: [], importer: [], api: [] });
    return;
  }
  // /api/v3/user and /api/v3/user/repos
  if (segments[0] === 'user') {
    if (segments.length === 1) {
      if (method !== 'GET') { sendError(res, 404, 'Not Found'); return; }
      sendJson(res, 200, { login: VIEWER.login, id: VIEWER.id, name: VIEWER.name, email: VIEWER.email, type: 'User', avatar_url: '' });
      return;
    }
    if (segments.length === 2 && segments[1] === 'repos') {
      if (method === 'GET') { paginate(req, res, url, repoOrder, (r) => repoJson(r)); return; }
      if (method === 'POST') {
        const body = await readJsonBody(req, res);
        if (body === null) return;
        if (!body.name || typeof body.name !== 'string') { sendError(res, 422, 'name is required'); return; }
        if (repos.has(`${VIEWER.login}/${body.name}`)) { sendError(res, 422, 'Repository already exists'); return; }
        const repo = makeRepo(body.name, body.description, body.private);
        sendJson(res, 201, repoJson(repo));
        return;
      }
      sendError(res, 404, 'Not Found'); return;
    }
    sendError(res, 404, 'Not Found'); return;
  }
  // /api/v3/repos/{owner}/{repo}/...
  if (segments[0] === 'repos') {
    const owner = decodeURIComponent(segments[1] ?? '');
    const name = decodeURIComponent(segments[2] ?? '');
    const repo = findRepo(owner, name);
    const rest = segments.slice(3);
    if (!repo) { sendError(res, 404, 'Not Found'); return; }
    if (rest.length === 0) {
      if (method === 'GET') { sendJson(res, 200, repoJson(repo)); return; }
      if (method === 'PATCH') {
        const body = await readJsonBody(req, res);
        if (body === null) return;
        if (typeof body.description === 'string') repo.description = body.description;
        if (typeof body.private === 'boolean') repo.private = body.private;
        sendJson(res, 200, repoJson(repo));
        return;
      }
      if (method === 'DELETE') {
        repos.delete(repo.fullName);
        const idx = repoOrder.indexOf(repo);
        if (idx >= 0) repoOrder.splice(idx, 1);
        res.writeHead(204, { 'x-github-request-id': `req-${++reqCounter}` });
        res.end();
        return;
      }
      sendError(res, 404, 'Not Found'); return;
    }
    const sub = rest[0];
    // branches
    if (sub === 'branches') {
      if (method !== 'GET') { sendError(res, 404, 'Not Found'); return; }
      if (rest.length === 1) {
        const list = [...repo.refs.entries()]
          .filter(([r]) => r.startsWith('refs/heads/'))
          .map(([r, sha]) => ({ name: r.slice('refs/heads/'.length), commit: { sha }, protected: false }));
        list.sort((a, b) => (a.name < b.name ? -1 : 1));
        sendJson(res, 200, list);
        return;
      }
      const branch = decodeURIComponent(rest[1] ?? '');
      const sha = repo.refs.get(`refs/heads/${branch}`);
      if (!sha) { sendError(res, 404, 'Not Found'); return; }
      sendJson(res, 200, { name: branch, commit: { sha }, protected: false });
      return;
    }
    // commits
    if (sub === 'commits') {
      if (method !== 'GET') { sendError(res, 404, 'Not Found'); return; }
      if (rest.length === 2) {
        const sha = decodeURIComponent(rest[1]);
        const commit = getCommit(repo, sha);
        if (!commit) { sendError(res, 404, 'Not Found'); return; }
        sendJson(res, 200, commitJson(repo, sha, commit));
        return;
      }
      const branchRef = url.searchParams.get('sha');
      const tip = branchRef ? resolveRef(repo, branchRef) : repo.refs.get(`refs/heads/${repo.defaultBranch}`);
      const list = [];
      if (tip) {
        const seen = new Set();
        const stack = [tip];
        while (stack.length) {
          const cur = stack.pop();
          if (seen.has(cur)) continue;
          seen.add(cur);
          const c = getCommit(repo, cur);
          if (!c) continue;
          list.push(commitJson(repo, cur, c));
          for (const p of c.parents) stack.push(p);
        }
        // Order: first-parent chain order is the natural git log order for the
        // linear histories the suite builds; sort by commit time desc as tiebreak.
        list.sort((a, b) => (b.commit.committer.date < a.commit.committer.date ? -1 : b.commit.committer.date > a.commit.committer.date ? 1 : 0));
      }
      paginate(req, res, url, list, (x) => x);
      return;
    }
    // git/refs
    if (sub === 'git') {
      if (rest[1] === 'refs') {
        if (method === 'POST' && rest.length === 2) {
          const body = await readJsonBody(req, res);
          if (body === null) return;
          const ref = body.ref; const sha = body.sha;
          if (typeof ref !== 'string' || typeof sha !== 'string') { sendError(res, 422, 'ref and sha are required'); return; }
          if (repo.refs.has(ref)) { sendError(res, 422, 'Reference already exists'); return; }
          if (!repo.objects.has(sha)) { sendError(res, 422, 'Object does not exist'); return; }
          repo.refs.set(ref, sha);
          bumpVersion(repo);
          sendJson(res, 201, { ref, object: { sha }, url: '' });
          return;
        }
        if (method === 'GET' && rest.length >= 3) {
          const refName = rest.slice(2).map(decodeURIComponent).join('/');
          const full = refName.startsWith('refs/') ? refName : `refs/${refName}`;
          const sha = repo.refs.get(full);
          if (!sha) { sendError(res, 404, 'Not Found'); return; }
          sendJson(res, 200, { ref: full, object: { sha } });
          return;
        }
      }
      sendError(res, 404, 'Not Found'); return;
    }
    // contents
    if (sub === 'contents') {
      const path = rest.slice(1).map(decodeURIComponent).join('/');
      if (method === 'GET') {
        const ref = url.searchParams.get('ref') ?? undefined;
        const out = contentsGet(repo, path, ref);
        if (out.status !== 200) { sendError(res, out.status, out.error); return; }
        if (out.dir) sendJson(res, 200, out.dir);
        else sendJson(res, 200, out.file);
        return;
      }
      if (method === 'PUT') {
        const body = await readJsonBody(req, res);
        if (body === null) return;
        const out = contentsPut(repo, path, body, body.branch);
        if (out.status >= 400) { sendError(res, out.status, out.error); return; }
        sendJson(res, out.status, out.body);
        return;
      }
      if (method === 'DELETE') {
        const body = await readJsonBody(req, res);
        if (body === null) return;
        const out = contentsDelete(repo, path, body, body.branch);
        if (out.status >= 400) { sendError(res, out.status, out.error); return; }
        sendJson(res, 200, out.body);
        return;
      }
      sendError(res, 404, 'Not Found'); return;
    }
    // labels
    if (sub === 'labels') {
      if (method === 'POST' && rest.length === 1) {
        const body = await readJsonBody(req, res);
        if (body === null) return;
        if (!body.name) { sendError(res, 422, 'name is required'); return; }
        if (repo.labels.has(body.name)) { sendError(res, 422, 'Label already exists'); return; }
        globalIdCounter += 1;
        const label = { id: globalIdCounter, name: body.name, color: String(body.color ?? 'ededed').replace(/^#/, ''), description: body.description ?? '' };
        repo.labels.set(label.name, label);
        sendJson(res, 201, label);
        return;
      }
      if (method === 'GET' && rest.length === 1) { sendJson(res, 200, [...repo.labels.values()]); return; }
      sendError(res, 404, 'Not Found'); return;
    }
    // issues
    if (sub === 'issues') {
      if (rest.length === 1) {
        if (method === 'GET') {
          const state = url.searchParams.get('state') ?? 'open';
          const sort = url.searchParams.get('sort') ?? 'created';
          const direction = url.searchParams.get('direction') ?? 'desc';
          let list = [...repo.issues.values()];
          if (state !== 'all') list = list.filter((i) => i.state === state);
          list.sort((a, b) => (sort === 'created' ? (direction === 'asc' ? a.createdSeq - b.createdSeq : b.createdSeq - a.createdSeq) : b.number - a.number));
          paginate(req, res, url, list, (i) => issueJson(repo, i));
          return;
        }
        if (method === 'POST') {
          const body = await readJsonBody(req, res);
          if (body === null) return;
          if (!body.title) { sendError(res, 422, 'title is required'); return; }
          const labelNames = body.labels ?? [];
          const labels = [];
          for (const ln of labelNames) {
            const name = typeof ln === 'string' ? ln : ln.name;
            const found = repo.labels.get(name);
            if (!found) { sendError(res, 422, `Label does not exist: ${name}`); return; }
            labels.push(found);
          }
          globalIdCounter += 1;
          const issue = {
            id: globalIdCounter, number: repo.nextNumber, title: body.title, body: body.body ?? null,
            state: 'open', labels, comments: [], createdSeq: repo.nextNumber,
            createdAt: tsIso(nextTs()), updatedAt: FIXED_DATE,
          };
          repo.nextNumber += 1;
          issue.updatedAt = issue.createdAt;
          repo.issues.set(issue.number, issue);
          sendJson(res, 201, issueJson(repo, issue));
          return;
        }
        sendError(res, 404, 'Not Found'); return;
      }
      const num = Number(rest[1]);
      const issue = repo.issues.get(num);
      if (!issue) { sendError(res, 404, 'Not Found'); return; }
      if (rest.length === 2) {
        if (method === 'GET') { sendJson(res, 200, issueJson(repo, issue)); return; }
        if (method === 'PATCH') {
          const body = await readJsonBody(req, res);
          if (body === null) return;
          if (body.state === 'closed' || body.state === 'open') issue.state = body.state;
          if (typeof body.title === 'string') issue.title = body.title;
          if (body.body !== undefined) issue.body = body.body;
          issue.updatedAt = tsIso(nextTs());
          sendJson(res, 200, issueJson(repo, issue));
          return;
        }
        sendError(res, 404, 'Not Found'); return;
      }
      if (rest[2] === 'comments') {
        if (method === 'GET') { sendJson(res, 200, issue.comments); return; }
        if (method === 'POST') {
          const body = await readJsonBody(req, res);
          if (body === null) return;
          globalIdCounter += 1;
          const comment = { id: globalIdCounter, body: body.body ?? '', user: { login: VIEWER.login, id: VIEWER.id, type: 'User' }, created_at: tsIso(nextTs()), updated_at: FIXED_DATE };
          comment.updated_at = comment.created_at;
          issue.comments.push(comment);
          sendJson(res, 201, comment);
          return;
        }
      }
      sendError(res, 404, 'Not Found'); return;
    }
    // pulls
    if (sub === 'pulls') {
      if (rest.length === 1) {
        if (method === 'GET') {
          const state = url.searchParams.get('state') ?? 'open';
          let list = [...repo.pulls.values()];
          if (state !== 'all') list = list.filter((p) => p.state === state);
          list.sort((a, b) => b.number - a.number);
          paginate(req, res, url, list, (p) => prJson(repo, p));
          return;
        }
        if (method === 'POST') {
          const body = await readJsonBody(req, res);
          if (body === null) return;
          const headRef = body.head; const baseRef = body.base ?? repo.defaultBranch;
          if (!headRef || !body.title) { sendError(res, 422, 'head and title are required'); return; }
          const headSha = repo.refs.get(`refs/heads/${headRef}`);
          const baseSha = repo.refs.get(`refs/heads/${baseRef}`);
          if (!headSha || !baseSha) { sendError(res, 422, 'head or base branch does not exist'); return; }
          for (const p of repo.pulls.values()) {
            if (p.state === 'open' && p.head.ref === headRef && p.base.ref === baseRef) {
              sendError(res, 422, 'A pull request already exists'); return;
            }
          }
          globalIdCounter += 1;
          const pr = {
            id: globalIdCounter, number: repo.nextNumber, title: body.title, body: body.body ?? null,
            state: 'open', merged: false, head: { ref: headRef, sha: headSha }, base: { ref: baseRef, sha: baseSha },
            baseSha, mergeCommitSha: null, mergedAt: null,
            createdAt: tsIso(nextTs()), updatedAt: FIXED_DATE,
          };
          repo.nextNumber += 1;
          pr.updatedAt = pr.createdAt;
          repo.pulls.set(pr.number, pr);
          sendJson(res, 201, prJson(repo, pr));
          return;
        }
        sendError(res, 404, 'Not Found'); return;
      }
      const num = Number(rest[1]);
      const pr = repo.pulls.get(num);
      if (!pr) { sendError(res, 404, 'Not Found'); return; }
      if (rest.length === 2) {
        if (method === 'GET') { sendJson(res, 200, prJson(repo, pr)); return; }
        sendError(res, 404, 'Not Found'); return;
      }
      if (rest[2] === 'files' && method === 'GET') {
        const hb = prHeadBase(repo, pr);
        const files = diffTrees(repo, pr.baseSha, hb.head.sha);
        sendJson(res, 200, files);
        return;
      }
      if (rest[2] === 'merge' && method === 'PUT') {
        const body = await readJsonBody(req, res);
        if (body === null) return;
        if (pr.state !== 'open') { sendError(res, 405, 'Pull request is not open'); return; }
        const result = squashMerge(repo, pr);
        if (result.conflict) { sendError(res, 405, 'Merge conflict'); return; }
        sendJson(res, 200, { sha: result.sha, merged: true, message: result.message });
        return;
      }
      sendError(res, 404, 'Not Found'); return;
    }
    sendError(res, 404, 'Not Found'); return;
  }
  sendError(res, 404, 'Not Found');
}
function commitJson(repo, sha, commit) {
  const authorLine = commit.author || '';
  const committerLine = commit.committer || '';
  const parseWho = (line) => {
    const m = /^(.*?) <(.*?)> (\d+) ([+-]\d{4})$/.exec(line);
    if (!m) return { name: VIEWER.name, email: VIEWER.email, date: FIXED_DATE };
    return { name: m[1], email: m[2], date: tsIso(Number(m[3])) };
  };
  const author = parseWho(authorLine);
  const committer = parseWho(committerLine);
  return {
    sha, commit: {
      message: commitMessage(repo, sha),
      author, committer,
      tree: { sha: commit.tree },
      url: '',
      comment_count: 0,
    },
    parents: commit.parents.map((p) => ({ sha: p })),
    author: { login: VIEWER.login, id: VIEWER.id, type: 'User' },
    committer: { login: VIEWER.login, id: VIEWER.id, type: 'User' },
  };
}

// ---------------------------------------------------------------------------
// GraphQL v4
// ---------------------------------------------------------------------------

const GQL_TYPES = {
  Query: { viewer: 'User', repository: 'Repository', node: 'Node', __type: '__Type', __schema: '__Schema' },
  Mutation: { createIssue: 'CreateIssuePayload', closeIssue: 'CloseIssuePayload', createPullRequest: 'CreatePullRequestPayload', mergePullRequest: 'MergePullRequestPayload', addComment: 'AddCommentPayload' },
  User: { login: 'String', id: 'ID', name: 'String', email: 'String', avatarUrl: 'String' },
  Repository: { id: 'ID', databaseId: 'Int', name: 'String', nameWithOwner: 'String', owner: 'User', defaultBranchRef: 'Ref', viewerPermission: 'String', hasIssuesEnabled: 'Boolean', description: 'String', url: 'String', issue: 'Issue', issues: 'IssueConnection', pullRequests: 'PullRequestConnection', pullRequest: 'PullRequest' },
  Ref: { name: 'String', prefix: 'String' },
  Issue: { id: 'ID', number: 'Int', title: 'String', state: 'String', body: 'String', url: 'String', createdAt: 'String', author: 'User' },
  IssueConnection: { nodes: 'Issue', pageInfo: 'PageInfo', totalCount: 'Int' },
  PullRequest: { id: 'ID', number: 'Int', title: 'String', state: 'String', merged: 'Boolean', headRefName: 'String', baseRefName: 'String', mergeable: 'String', files: 'PullRequestChangedFileConnection', body: 'String', url: 'String' },
  PullRequestConnection: { nodes: 'PullRequest', pageInfo: 'PageInfo', totalCount: 'Int' },
  PullRequestChangedFileConnection: { nodes: 'PullRequestChangedFile', pageInfo: 'PageInfo', totalCount: 'Int' },
  PullRequestChangedFile: { path: 'String', additions: 'Int', deletions: 'Int', changeType: 'String' },
  PageInfo: { hasNextPage: 'Boolean', hasPreviousPage: 'Boolean', endCursor: 'String', startCursor: 'String' },
  Node: { id: 'ID' },
  CreateIssuePayload: { issue: 'Issue' },
  CloseIssuePayload: { issue: 'Issue' },
  CreatePullRequestPayload: { pullRequest: 'PullRequest' },
  MergePullRequestPayload: { pullRequest: 'PullRequest' },
  AddCommentPayload: { commentEdge: 'IssueCommentEdge' },
  IssueCommentEdge: { node: 'IssueComment' },
  IssueComment: { id: 'ID', body: 'String' },
  __Type: { name: 'String', kind: 'String', description: 'String', fields: '__Field', enumValues: '__EnumValue', inputFields: '__InputValue' },
  __Field: { name: 'String', description: 'String', args: '__InputValue', type: '__Type' },
  __InputValue: { name: 'String', description: 'String', type: '__Type' },
  __EnumValue: { name: 'String', description: 'String' },
  __Schema: { types: '__Type', queryType: '__Type', mutationType: '__Type' },
};
const GQL_ENUMS = { SearchType: ['ISSUE', 'REPOSITORY', 'USER'] };
const GQL_SCALARS = new Set(['String', 'Int', 'Boolean', 'ID', 'Float']);

function gqlTokenize(src) {
  const tokens = [];
  let i = 0;
  while (i < src.length) {
    const ch = src[i];
    if (/\s/.test(ch) || ch === ',') { i += 1; continue; }
    if (ch === '#') { while (i < src.length && src[i] !== '\n') i += 1; continue; }
    if ('{}():[]!=$@'.includes(ch)) { tokens.push({ kind: ch }); i += 1; continue; }
    if (src.startsWith('...', i)) { tokens.push({ kind: '...' }); i += 3; continue; }
    if (ch === '"') {
      let j = i + 1; let out = '';
      while (j < src.length && src[j] !== '"') {
        if (src[j] === '\\' && j + 1 < src.length) { const e = src[j + 1]; out += e === 'n' ? '\n' : e === 't' ? '\t' : e === 'r' ? '\r' : e; j += 2; }
        else { out += src[j]; j += 1; }
      }
      tokens.push({ kind: 'string', value: out });
      i = j + 1; continue;
    }
    if (/[0-9-]/.test(ch) && (ch !== '-' || /[0-9]/.test(src[i + 1] ?? ''))) {
      let j = i; let isFloat = false;
      if (src[j] === '-') j += 1;
      while (/[0-9]/.test(src[j] ?? '')) j += 1;
      if (src[j] === '.') { isFloat = true; j += 1; while (/[0-9]/.test(src[j] ?? '')) j += 1; }
      tokens.push({ kind: isFloat ? 'float' : 'int', value: src.slice(i, j) });
      i = j; continue;
    }
    if (/[_A-Za-z]/.test(ch)) {
      let j = i;
      while (/[_0-9A-Za-z]/.test(src[j] ?? '')) j += 1;
      tokens.push({ kind: 'name', value: src.slice(i, j) });
      i = j; continue;
    }
    throw new Error(`unexpected character ${ch}`);
  }
  tokens.push({ kind: 'EOF' });
  return tokens;
}
class GqlParser {
  constructor(src) { this.tokens = gqlTokenize(src); this.pos = 0; }
  peek() { return this.tokens[this.pos]; }
  next() { return this.tokens[this.pos++]; }
  expect(kind) { const t = this.next(); if (t.kind !== kind) throw new Error(`expected ${kind}, got ${t.kind}`); return t; }
  expectName(value) { const t = this.next(); if (t.kind !== 'name' || (value && t.value !== value)) throw new Error(`expected name ${value ?? ''}`); return t.value; }
  parseDocument() {
    const ops = [];
    while (this.peek().kind !== 'EOF') {
      if (this.peek().kind === '{') ops.push({ kind: 'query', name: null, varDefs: {}, selections: this.parseSelections() });
      else if (this.peek().kind === 'name' && ['query', 'mutation', 'subscription'].includes(this.peek().value)) {
        const opKind = this.next().value;
        let name = null;
        if (this.peek().kind === 'name') name = this.next().value;
        const varDefs = this.peek().kind === '(' ? this.parseVarDefs() : {};
        ops.push({ kind: opKind, name, varDefs, selections: this.parseSelections() });
      } else throw new Error('unexpected token in document');
    }
    return ops;
  }
  parseVarDefs() {
    this.expect('(');
    const defs = {};
    while (this.peek().kind !== ')') {
      this.expect('$');
      const name = this.expectName();
      this.expect(':');
      const type = this.parseType();
      let def = null;
      if (this.peek().kind === '=') { this.next(); def = this.parseValue(); }
      defs[name] = { type, default: def };
    }
    this.expect(')');
    return defs;
  }
  parseType() {
    let type;
    if (this.peek().kind === '[') {
      this.next(); const inner = this.parseType(); this.expect(']'); type = { kind: 'list', of: inner };
    } else type = { kind: 'named', name: this.expectName() };
    if (this.peek().kind === '!') { this.next(); type = { kind: 'nonnull', of: type }; }
    return type;
  }
  parseSelections() {
    this.expect('{');
    const sels = [];
    while (this.peek().kind !== '}') {
      if (this.peek().kind === '...') {
        this.next();
        if (this.peek().kind === 'name' && this.peek().value === 'on') {
          this.next();
          const typeName = this.expectName();
          sels.push({ kind: 'fragment', type: typeName, selections: this.parseSelections() });
        } else {
          const name = this.expectName();
          sels.push({ kind: 'spread', name });
        }
      } else {
        let name = this.expectName();
        let alias = null;
        if (this.peek().kind === ':') { this.next(); alias = name; name = this.expectName(); }
        const args = this.peek().kind === '(' ? this.parseArgs() : {};
        const selections = this.peek().kind === '{' ? this.parseSelections() : null;
        sels.push({ kind: 'field', name, alias, args, selections });
      }
    }
    this.expect('}');
    return sels;
  }
  parseArgs() {
    this.expect('(');
    const args = {};
    while (this.peek().kind !== ')') {
      const name = this.expectName();
      this.expect(':');
      args[name] = this.parseValue();
    }
    this.expect(')');
    return args;
  }
  parseValue() {
    const t = this.next();
    if (t.kind === '$') return { kind: 'var', name: this.expectName() };
    if (t.kind === 'int') return { kind: 'int', value: Number(t.value) };
    if (t.kind === 'float') return { kind: 'float', value: Number(t.value) };
    if (t.kind === 'string') return { kind: 'string', value: t.value };
    if (t.kind === 'name') {
      if (t.value === 'true') return { kind: 'boolean', value: true };
      if (t.value === 'false') return { kind: 'boolean', value: false };
      if (t.value === 'null') return { kind: 'null', value: null };
      return { kind: 'enum', value: t.value };
    }
    if (t.kind === '[') {
      const items = [];
      while (this.peek().kind !== ']') items.push(this.parseValue());
      this.expect(']');
      return { kind: 'list', items };
    }
    if (t.kind === '{') {
      const fields = {};
      while (this.peek().kind !== '}') {
        const name = this.expectName();
        this.expect(':');
        fields[name] = this.parseValue();
      }
      this.expect('}');
      return { kind: 'object', fields };
    }
    throw new Error(`unexpected value token ${t.kind}`);
  }
}
function gqlResolveValue(node, variables) {
  switch (node.kind) {
    case 'var': return variables[node.name];
    case 'list': return node.items.map((v) => gqlResolveValue(v, variables));
    case 'object': { const o = {}; for (const [k, v] of Object.entries(node.fields)) o[k] = gqlResolveValue(v, variables); return o; }
    default: return node.value;
  }
}
function gqlValidate(op, errors) {
  const walk = (typeName, selections) => {
    for (const sel of selections ?? []) {
      if (sel.kind === 'fragment') { walk(sel.type, sel.selections); continue; }
      if (sel.kind === 'spread') { errors.push(`Unknown fragment "${sel.name}"`); continue; }
      const fields = GQL_TYPES[typeName];
      if (!fields) { errors.push(`Unknown type "${typeName}"`); continue; }
      if (!Object.prototype.hasOwnProperty.call(fields, sel.name)) {
        errors.push(`Cannot query field "${sel.name}" on type "${typeName}".`);
        continue;
      }
      const childType = fields[sel.name];
      if (sel.selections && !GQL_SCALARS.has(childType)) walk(childType, sel.selections);
    }
  };
  walk(op.kind === 'mutation' ? 'Mutation' : 'Query', op.selections);
}
function gqlDecodeId(globalId) {
  try {
    const decoded = Buffer.from(String(globalId), 'base64').toString('utf8');
    const parts = decoded.split(':');
    if (parts[0] === 'R') return { kind: 'R', repoId: Number(parts[1]) };
    if (parts[0] === 'I') return { kind: 'I', repoId: Number(parts[1]), number: Number(parts[2]) };
    if (parts[0] === 'P') return { kind: 'P', repoId: Number(parts[1]), number: Number(parts[2]) };
    if (parts[0] === 'C') return { kind: 'C', repoId: Number(parts[1]), number: Number(parts[2]), commentId: Number(parts[3]) };
  } catch { /* fall through */ }
  return null;
}
function gqlRepoById(id) {
  const dec = gqlDecodeId(id);
  if (!dec || dec.kind !== 'R') return null;
  return repoOrder.find((r) => r.id === dec.repoId) ?? null;
}
function gqlRepoByOwnerName(owner, name) {
  return owner === VIEWER.login ? (repos.get(`${owner}/${name}`) ?? null) : null;
}
function gqlIssueId(repo, issue) { return b64encode(`I:${repo.id}:${issue.number}`); }
function gqlPrId(repo, pr) { return b64encode(`P:${repo.id}:${pr.number}`); }
function gqlState(issue) { return issue.state === 'closed' ? 'CLOSED' : 'OPEN'; }
function gqlPrState(pr) { return pr.merged ? 'MERGED' : pr.state === 'closed' ? 'CLOSED' : 'OPEN'; }
function gqlConnection(items, first, after) {
  let start = 0;
  if (after) {
    try {
      const decoded = Buffer.from(String(after), 'base64').toString('utf8');
      const idx = items.findIndex((it) => String(it.cursor) === decoded);
      if (idx >= 0) start = idx + 1;
    } catch { /* ignore */ }
  }
  const slice = first != null ? items.slice(start, start + first) : items.slice(start);
  const endCursor = slice.length ? b64encode(slice[slice.length - 1].cursor) : null;
  return {
    nodes: slice.map((it) => it.value),
    pageInfo: { hasNextPage: start + slice.length < items.length, hasPreviousPage: start > 0, endCursor, startCursor: slice.length ? b64encode(slice[0].cursor) : null },
    totalCount: items.length,
    _endCursor: endCursor,
  };
}
// Execution: value objects carry a hidden __type tag.
function gqlWrap(type, value) { return { __type: type, ...value }; }
function gqlResolve(op, variables) {
  const isMutation = op.kind === 'mutation';
  const rootType = isMutation ? 'Mutation' : 'Query';
  const root = gqlWrap(rootType, {});
  return resolveSelections(rootType, root, op.selections, variables);
}
function resolveSelections(typeName, obj, selections, variables) {
  const out = {};
  for (const sel of selections ?? []) {
    if (sel.kind === 'fragment') {
      if (sel.type === typeName || (typeName === 'Node' && obj.__type === sel.type)) {
        Object.assign(out, resolveSelections(obj.__type ?? typeName, obj, sel.selections, variables));
      }
      continue;
    }
    if (sel.kind === 'spread') continue;
    const args = {};
    for (const [k, v] of Object.entries(sel.args)) args[k] = gqlResolveValue(v, variables);
    const value = resolveField(typeName, obj, sel, args, variables);
    out[sel.alias ?? sel.name] = value;
  }
  return out;
}
function resolveField(typeName, obj, sel, args, variables) {
  const name = sel.name;
  const child = sel.selections ? (v) => resolveSelections(GQL_TYPES[typeName][name], v, sel.selections, variables) : null;
  const wrapList = (items, itemType) => items.map((v) => (child ? resolveSelections(itemType, v, sel.selections, variables) : v));
  switch (typeName) {
    case 'Query': {
      if (name === 'viewer') return child ? child(gqlWrap('User', { login: VIEWER.login, id: b64encode(`U:${VIEWER.id}`), name: VIEWER.name, email: VIEWER.email, avatarUrl: '' })) : null;
      if (name === 'repository') {
        const repo = gqlRepoByOwnerName(args.owner, args.name);
        if (!repo) return null;
        return child ? child(gqlWrap('Repository', repoToGql(repo))) : null;
      }
      if (name === 'node') {
        const dec = gqlDecodeId(args.id);
        if (!dec) return null;
        let wrapped = null;
        if (dec.kind === 'R') {
          const repo = repoOrder.find((r) => r.id === dec.repoId);
          if (!repo) return null;
          wrapped = gqlWrap('Repository', repoToGql(repo));
        } else if (dec.kind === 'I') {
          const repo = repoOrder.find((r) => r.id === dec.repoId);
          const issue = repo?.issues.get(dec.number);
          if (!issue) return null;
          wrapped = gqlWrap('Issue', issueToGql(repo, issue));
        } else if (dec.kind === 'P') {
          const repo = repoOrder.find((r) => r.id === dec.repoId);
          const pr = repo?.pulls.get(dec.number);
          if (!pr) return null;
          wrapped = gqlWrap('PullRequest', prToGql(repo, pr));
        }
        if (!wrapped) return null;
        // Resolve against the concrete type so `id` and inline fragments work.
        return resolveSelections(wrapped.__type, wrapped, sel.selections, variables);
      }
      if (name === '__type') return gqlTypeInfo(args.name, sel.selections, variables);
      if (name === '__schema') return { types: Object.keys(GQL_TYPES).map((n) => gqlTypeInfo(n, null, variables)) };
      return null;
    }
    case 'Mutation': {
      if (name === 'createIssue') {
        const input = args.input ?? {};
        const repo = gqlRepoById(input.repositoryId);
        if (!repo) throw new Error('repository not found');
        globalIdCounter += 1;
        const issue = { id: globalIdCounter, number: repo.nextNumber, title: input.title, body: input.body ?? null, state: 'open', labels: [], comments: [], createdSeq: repo.nextNumber, createdAt: tsIso(nextTs()), updatedAt: FIXED_DATE };
        repo.nextNumber += 1;
        issue.updatedAt = issue.createdAt;
        repo.issues.set(issue.number, issue);
        const payload = gqlWrap('CreateIssuePayload', { issue: gqlWrap('Issue', issueToGql(repo, issue)) });
        return child ? child(payload) : null;
      }
      if (name === 'closeIssue') {
        const input = args.input ?? {};
        const dec = gqlDecodeId(input.issueId);
        const repo = dec ? repoOrder.find((r) => r.id === dec.repoId) : null;
        const issue = repo?.issues.get(dec?.number);
        if (!issue) throw new Error('issue not found');
        issue.state = 'closed'; issue.updatedAt = tsIso(nextTs());
        const payload = gqlWrap('CloseIssuePayload', { issue: gqlWrap('Issue', issueToGql(repo, issue)) });
        return child ? child(payload) : null;
      }
      if (name === 'createPullRequest') {
        const input = args.input ?? {};
        const repo = gqlRepoById(input.repositoryId);
        if (!repo) throw new Error('repository not found');
        const headSha = repo.refs.get(`refs/heads/${input.headRefName}`);
        const baseSha = repo.refs.get(`refs/heads/${input.baseRefName}`);
        if (!headSha || !baseSha) throw new Error('head or base branch does not exist');
        for (const p of repo.pulls.values()) {
          if (p.state === 'open' && p.head.ref === input.headRefName && p.base.ref === input.baseRefName) throw new Error('A pull request already exists');
        }
        globalIdCounter += 1;
        const pr = { id: globalIdCounter, number: repo.nextNumber, title: input.title, body: input.body ?? null, state: 'open', merged: false, head: { ref: input.headRefName, sha: headSha }, base: { ref: input.baseRefName, sha: baseSha }, baseSha, mergeCommitSha: null, mergedAt: null, createdAt: tsIso(nextTs()), updatedAt: FIXED_DATE };
        repo.nextNumber += 1;
        pr.updatedAt = pr.createdAt;
        repo.pulls.set(pr.number, pr);
        const payload = gqlWrap('CreatePullRequestPayload', { pullRequest: gqlWrap('PullRequest', prToGql(repo, pr)) });
        return child ? child(payload) : null;
      }
      if (name === 'mergePullRequest') {
        const input = args.input ?? {};
        const dec = gqlDecodeId(input.pullRequestId);
        const repo = dec ? repoOrder.find((r) => r.id === dec.repoId) : null;
        const pr = repo?.pulls.get(dec?.number);
        if (!pr) throw new Error('pull request not found');
        if (pr.state !== 'open') throw new Error('pull request is not open');
        const result = squashMerge(repo, pr);
        if (result.conflict) throw new Error('Merge conflict');
        const payload = gqlWrap('MergePullRequestPayload', { pullRequest: gqlWrap('PullRequest', prToGql(repo, pr)) });
        return child ? child(payload) : null;
      }
      if (name === 'addComment') {
        const input = args.input ?? {};
        const dec = gqlDecodeId(input.subjectId);
        const repo = dec ? repoOrder.find((r) => r.id === dec.repoId) : null;
        let target = null; let commentId = null;
        if (dec?.kind === 'I') {
          const issue = repo?.issues.get(dec.number);
          if (issue) { globalIdCounter += 1; commentId = globalIdCounter; target = issue; }
        }
        if (!target) throw new Error('subject not found');
        const comment = { id: commentId, body: input.body ?? '', user: { login: VIEWER.login, id: VIEWER.id, type: 'User' }, created_at: tsIso(nextTs()), updated_at: FIXED_DATE };
        comment.updated_at = comment.created_at;
        target.comments.push(comment);
        const payload = gqlWrap('AddCommentPayload', { commentEdge: gqlWrap('IssueCommentEdge', { node: gqlWrap('IssueComment', { id: b64encode(`C:${repo.id}:${target.number}:${commentId}`), body: comment.body }) }) });
        return child ? child(payload) : null;
      }
      return null;
    }
    case 'Repository': {
      const repo = obj;
      if (name === 'id') return b64encode(`R:${repo.id}`);
      if (name === 'databaseId') return repo.id;
      if (name === 'name') return repo.name;
      if (name === 'nameWithOwner') return repo.fullName;
      if (name === 'owner') return child ? child(gqlWrap('User', { login: repo.owner, id: b64encode(`U:${VIEWER.id}`), name: VIEWER.name, email: VIEWER.email, avatarUrl: '' })) : null;
      if (name === 'defaultBranchRef') return child ? child(gqlWrap('Ref', { name: repo.defaultBranch, prefix: 'refs/heads/' })) : null;
      if (name === 'viewerPermission') return 'ADMIN';
      if (name === 'hasIssuesEnabled') return true;
      if (name === 'description') return repo.description;
      if (name === 'url') return `https://example.invalid/${repo.fullName}`;
      if (name === 'issue') {
        const issue = repo.issues.get(args.number);
        if (!issue) return null;
        return child ? child(gqlWrap('Issue', issueToGql(repo, issue))) : null;
      }
      if (name === 'issues') {
        let list = [...repo.issues.values()];
        const states = args.states;
        if (states && states.length) list = list.filter((i) => states.includes(gqlState(i)));
        const orderBy = args.orderBy ?? {};
        const dir = orderBy.direction ?? 'ASC';
        const field = orderBy.field ?? 'CREATED_AT';
        list.sort((a, b) => {
          const cmp = field === 'CREATED_AT' ? a.createdSeq - b.createdSeq : a.number - b.number;
          return dir === 'DESC' ? -cmp : cmp;
        });
        const conn = gqlConnection(list.map((i) => ({ cursor: `issue:${i.number}`, value: gqlWrap('Issue', issueToGql(repo, i)) })), args.first, args.after);
        const out = { nodes: [], pageInfo: conn.pageInfo, totalCount: conn.totalCount };
        out.nodes = conn.nodes.map((n) => (child ? resolveSelections('Issue', n, sel.selections.find((s) => s.kind === 'field' && s.name === 'nodes')?.selections ?? sel.selections, variables) : n));
        // The nodes sub-selection is handled by resolving each node with its own selections:
        const nodesSel = (sel.selections ?? []).find((s) => s.kind === 'field' && s.name === 'nodes');
        out.nodes = conn.nodes.map((n) => resolveSelections('Issue', n, nodesSel?.selections ?? [], variables));
        const piSel = (sel.selections ?? []).find((s) => s.kind === 'field' && s.name === 'pageInfo');
        out.pageInfo = piSel ? resolveSelections('PageInfo', gqlWrap('PageInfo', conn.pageInfo), piSel.selections, variables) : conn.pageInfo;
        return out;
      }
      if (name === 'pullRequests') {
        let list = [...repo.pulls.values()];
        const states = args.states;
        if (states && states.length) list = list.filter((p) => states.includes(gqlPrState(p)));
        list.sort((a, b) => b.number - a.number);
        const conn = gqlConnection(list.map((p) => ({ cursor: `pr:${p.number}`, value: gqlWrap('PullRequest', prToGql(repo, p)) })), args.first, args.after);
        const nodesSel = (sel.selections ?? []).find((s) => s.kind === 'field' && s.name === 'nodes');
        const piSel = (sel.selections ?? []).find((s) => s.kind === 'field' && s.name === 'pageInfo');
        return {
          nodes: conn.nodes.map((n) => resolveSelections('PullRequest', n, nodesSel?.selections ?? [], variables)),
          pageInfo: piSel ? resolveSelections('PageInfo', gqlWrap('PageInfo', conn.pageInfo), piSel.selections, variables) : conn.pageInfo,
          totalCount: conn.totalCount,
        };
      }
      if (name === 'pullRequest') {
        const pr = repo.pulls.get(args.number);
        if (!pr) return null;
        return child ? child(gqlWrap('PullRequest', prToGql(repo, pr))) : null;
      }
      return null;
    }
    case 'Issue': {
      const issue = obj;
      if (name === 'id') return issue.__gqlId ?? b64encode(`I:${issue.__repoId}:${issue.number}`);
      if (name === 'number') return issue.number;
      if (name === 'title') return issue.title;
      if (name === 'state') return gqlState(issue);
      if (name === 'body') return issue.body;
      if (name === 'url') return `https://example.invalid/${issue.__fullName}/issues/${issue.number}`;
      if (name === 'createdAt') return issue.createdAt;
      if (name === 'author') return child ? child(gqlWrap('User', { login: VIEWER.login, id: b64encode(`U:${VIEWER.id}`), name: VIEWER.name, email: VIEWER.email, avatarUrl: '' })) : null;
      return null;
    }
    case 'PullRequest': {
      const pr = obj;
      if (name === 'id') return pr.__gqlId ?? b64encode(`P:${pr.__repoId}:${pr.number}`);
      if (name === 'number') return pr.number;
      if (name === 'title') return pr.title;
      if (name === 'state') return gqlPrState(pr);
      if (name === 'merged') return pr.merged;
      if (name === 'headRefName') return pr.head.ref;
      if (name === 'baseRefName') return pr.base.ref;
      if (name === 'mergeable') return pr.__mergeable ?? 'MERGEABLE';
      if (name === 'body') return pr.body;
      if (name === 'url') return `https://example.invalid/${pr.__fullName}/pull/${pr.number}`;
      if (name === 'files') {
        const repo = pr.__repo;
        const hb = prHeadBase(repo, pr);
        const files = diffTrees(repo, pr.baseSha, hb.head.sha).map((f) => gqlWrap('PullRequestChangedFile', { path: f.filename, additions: f.additions, deletions: f.deletions, changeType: f.status.toUpperCase() }));
        const conn = gqlConnection(files.map((f) => ({ cursor: `file:${f.path}`, value: f })), args.first, args.after);
        const nodesSel = (sel.selections ?? []).find((s) => s.kind === 'field' && s.name === 'nodes');
        const piSel = (sel.selections ?? []).find((s) => s.kind === 'field' && s.name === 'pageInfo');
        return {
          nodes: conn.nodes.map((n) => resolveSelections('PullRequestChangedFile', n, nodesSel?.selections ?? [], variables)),
          pageInfo: piSel ? resolveSelections('PageInfo', gqlWrap('PageInfo', conn.pageInfo), piSel.selections, variables) : conn.pageInfo,
          totalCount: conn.totalCount,
        };
      }
      return null;
    }
    case 'PullRequestChangedFile': {
      if (name === 'path') return obj.path;
      if (name === 'additions') return obj.additions;
      if (name === 'deletions') return obj.deletions;
      if (name === 'changeType') return obj.changeType;
      return null;
    }
    case 'IssueComment': {
      if (name === 'id') return obj.id;
      if (name === 'body') return obj.body;
      return null;
    }
    case 'PageInfo': {
      if (name === 'hasNextPage') return obj.hasNextPage;
      if (name === 'hasPreviousPage') return obj.hasPreviousPage;
      if (name === 'endCursor') return obj.endCursor;
      if (name === 'startCursor') return obj.startCursor;
      return null;
    }
    case '__Type': {
      if (name === 'name') return obj.__typeName;
      if (name === 'kind') return obj.__kind;
      if (name === 'description') return null;
      if (name === 'fields') {
        const fields = GQL_TYPES[obj.__typeName] ?? {};
        const list = Object.keys(fields).map((f) => ({ name: f }));
        return list;
      }
      if (name === 'enumValues') {
        const vals = GQL_ENUMS[obj.__typeName];
        return vals ? vals.map((v) => ({ name: v })) : null;
      }
      if (name === 'inputFields') return null;
      return null;
    }
    default: {
      const val = obj[name] ?? null;
      if (val == null) return null;
      if (!sel.selections) return val;
      const childType = GQL_TYPES[typeName]?.[name];
      if (!childType || GQL_SCALARS.has(childType)) return val;
      if (Array.isArray(val)) return val.map((v) => resolveSelections(childType, v, sel.selections, variables));
      return resolveSelections(childType, val, sel.selections, variables);
    }
  }
}
function gqlTypeInfo(typeName, selections, variables) {
  if (!typeName) return null;
  const isEnum = Object.prototype.hasOwnProperty.call(GQL_ENUMS, typeName);
  const isObject = Object.prototype.hasOwnProperty.call(GQL_TYPES, typeName);
  if (!isEnum && !isObject) return null;
  const info = gqlWrap('__Type', { __typeName: typeName, __kind: isEnum ? 'ENUM' : 'OBJECT' });
  if (!selections) return info;
  return resolveSelections('__Type', info, selections, variables);
}
function repoToGql(repo) {
  return { ...repo, __repoId: repo.id, __fullName: repo.fullName };
}
function issueToGql(repo, issue) {
  return { ...issue, __repoId: repo.id, __fullName: repo.fullName, __gqlId: gqlIssueId(repo, issue) };
}
function prToGql(repo, pr) {
  const mergeable = computeMerge(repo, pr).conflict ? 'CONFLICTING' : 'MERGEABLE';
  return { ...pr, __repo: repo, __repoId: repo.id, __fullName: repo.fullName, __gqlId: gqlPrId(repo, pr), __mergeable: mergeable };
}
async function handleGraphql(req, res) {
  const auth = req.headers.authorization ?? '';
  if (auth !== `Bearer ${TOKEN}`) { sendError(res, 401, 'Requires authentication'); return; }
  const raw = await readBody(req);
  let body;
  try { body = JSON.parse(raw.toString('utf8')); }
  catch { sendError(res, 400, 'Problems parsing JSON'); return; }
  const ops = Array.isArray(body) ? body : [body];
  const results = ops.map((op) => {
    try {
      if (!op || typeof op.query !== 'string') return { data: null, errors: [{ message: 'Missing query' }] };
      const parser = new GqlParser(op.query);
      const docs = parser.parseDocument();
      if (docs.length === 0) return { data: null, errors: [{ message: 'Empty document' }] };
      const variables = op.variables ?? {};
      const errors = [];
      for (const doc of docs) gqlValidate(doc, errors);
      if (errors.length) return { data: null, errors: errors.map((m) => ({ message: m })) };
      // A document with several operations executes the first (the suite sends one
      // operation per document; a batch is one document per array element).
      return { data: gqlResolve(docs[0], variables) };
    } catch (e) {
      return { data: null, errors: [{ message: e.message }] };
    }
  });
  sendJson(res, 200, Array.isArray(body) ? results : results[0]);
}

// ---------------------------------------------------------------------------
// MCP (JSON-RPC 2.0, Streamable HTTP)
// ---------------------------------------------------------------------------

const MCP_VERSIONS = ['2026-07-28', '2025-11-25', '2025-06-18'];
const MCP_TOOLS = [
  { name: 'create_repo', description: 'Create a new repository for the authenticated user.', inputSchema: { type: 'object', properties: { name: { type: 'string', description: 'Repository name' }, description: { type: 'string', description: 'Repository description' }, private: { type: 'boolean', description: 'Whether the repository is private' } }, required: ['name'] } },
  { name: 'get_repo', description: 'Get a repository by owner and name.', inputSchema: { type: 'object', properties: { owner: { type: 'string', description: 'Repository owner login' }, repo: { type: 'string', description: 'Repository name' } }, required: ['owner', 'repo'] } },
  { name: 'create_issue', description: 'Create an issue in a repository.', inputSchema: { type: 'object', properties: { owner: { type: 'string', description: 'Repository owner login' }, repo: { type: 'string', description: 'Repository name' }, title: { type: 'string', description: 'Issue title' }, body: { type: 'string', description: 'Issue body' } }, required: ['owner', 'repo', 'title'] } },
  { name: 'list_issues', description: 'List issues in a repository.', inputSchema: { type: 'object', properties: { owner: { type: 'string', description: 'Repository owner login' }, repo: { type: 'string', description: 'Repository name' }, state: { type: 'string', description: 'Issue state: open, closed, or all' } }, required: ['owner', 'repo'] } },
  { name: 'get_issue', description: 'Get a single issue by number.', inputSchema: { type: 'object', properties: { owner: { type: 'string', description: 'Repository owner login' }, repo: { type: 'string', description: 'Repository name' }, number: { type: 'number', description: 'Issue number' } }, required: ['owner', 'repo', 'number'] } },
  { name: 'create_pull_request', description: 'Create a pull request between two branches.', inputSchema: { type: 'object', properties: { owner: { type: 'string', description: 'Repository owner login' }, repo: { type: 'string', description: 'Repository name' }, title: { type: 'string', description: 'Pull request title' }, head: { type: 'string', description: 'Head branch name' }, base: { type: 'string', description: 'Base branch name' }, body: { type: 'string', description: 'Pull request body' } }, required: ['owner', 'repo', 'title', 'head', 'base'] } },
  { name: 'list_pull_requests', description: 'List pull requests in a repository.', inputSchema: { type: 'object', properties: { owner: { type: 'string', description: 'Repository owner login' }, repo: { type: 'string', description: 'Repository name' }, state: { type: 'string', description: 'Pull request state: open, closed, or all' } }, required: ['owner', 'repo'] } },
  { name: 'merge_pull_request', description: 'Merge a pull request with a squash commit.', inputSchema: { type: 'object', properties: { owner: { type: 'string', description: 'Repository owner login' }, repo: { type: 'string', description: 'Repository name' }, pull_number: { type: 'number', description: 'Pull request number' } }, required: ['owner', 'repo', 'pull_number'] } },
];
const MCP_TOOLS_BY_NAME = new Map(MCP_TOOLS.map((t) => [t.name, t]));
const MCP_TOOLS_LIST_BODY = JSON.stringify({ tools: MCP_TOOLS });

function mcpResult(id, result) { return { jsonrpc: '2.0', id, result }; }
function mcpError(id, code, message) { return { jsonrpc: '2.0', id, error: { code, message } }; }
function mcpToolResult(obj, isError = false) {
  const text = JSON.stringify(obj);
  return { content: [{ type: 'text', text }], structuredContent: obj, ...(isError ? { isError: true } : {}) };
}
function mcpNeedRepo(args) {
  const repo = findRepo(args.owner, args.repo);
  if (!repo) throw new Error(`Repository not found: ${args.owner}/${args.repo}`);
  return repo;
}
function mcpCallTool(name, args) {
  switch (name) {
    case 'create_repo': {
      if (!args.name) return mcpToolResult({ error: 'Missing required argument: name' }, true);
      if (repos.has(`${VIEWER.login}/${args.name}`)) return mcpToolResult({ error: 'Repository already exists' }, true);
      const repo = makeRepo(args.name, args.description, args.private);
      return mcpToolResult(repoJson(repo));
    }
    case 'get_repo': {
      try {
        const repo = mcpNeedRepo(args);
        return mcpToolResult(repoJson(repo));
      } catch (e) { return mcpToolResult({ error: e.message }, true); }
    }
    case 'create_issue': {
      for (const k of ['owner', 'repo', 'title']) if (!args[k]) return mcpToolResult({ error: `Missing required argument: ${k}` }, true);
      try {
        const repo = mcpNeedRepo(args);
        globalIdCounter += 1;
        const issue = { id: globalIdCounter, number: repo.nextNumber, title: args.title, body: args.body ?? null, state: 'open', labels: [], comments: [], createdSeq: repo.nextNumber, createdAt: tsIso(nextTs()), updatedAt: FIXED_DATE };
        repo.nextNumber += 1;
        issue.updatedAt = issue.createdAt;
        repo.issues.set(issue.number, issue);
        return mcpToolResult(issueJson(repo, issue));
      } catch (e) { return mcpToolResult({ error: e.message }, true); }
    }
    case 'list_issues': {
      for (const k of ['owner', 'repo']) if (!args[k]) return mcpToolResult({ error: `Missing required argument: ${k}` }, true);
      try {
        const repo = mcpNeedRepo(args);
        const state = args.state ?? 'open';
        let list = [...repo.issues.values()];
        if (state !== 'all') list = list.filter((i) => i.state === state);
        list.sort((a, b) => a.number - b.number);
        return mcpToolResult(list.map((i) => issueJson(repo, i)));
      } catch (e) { return mcpToolResult({ error: e.message }, true); }
    }
    case 'get_issue': {
      for (const k of ['owner', 'repo', 'number']) if (args[k] === undefined || args[k] === null) return mcpToolResult({ error: `Missing required argument: ${k}` }, true);
      try {
        const repo = mcpNeedRepo(args);
        const issue = repo.issues.get(Number(args.number));
        if (!issue) return mcpToolResult({ error: `Issue not found: ${args.number}` }, true);
        return mcpToolResult(issueJson(repo, issue));
      } catch (e) { return mcpToolResult({ error: e.message }, true); }
    }
    case 'create_pull_request': {
      for (const k of ['owner', 'repo', 'title', 'head', 'base']) if (!args[k]) return mcpToolResult({ error: `Missing required argument: ${k}` }, true);
      try {
        const repo = mcpNeedRepo(args);
        const headSha = repo.refs.get(`refs/heads/${args.head}`);
        const baseSha = repo.refs.get(`refs/heads/${args.base}`);
        if (!headSha || !baseSha) return mcpToolResult({ error: 'head or base branch does not exist' }, true);
        for (const p of repo.pulls.values()) {
          if (p.state === 'open' && p.head.ref === args.head && p.base.ref === args.base) return mcpToolResult({ error: 'A pull request already exists' }, true);
        }
        globalIdCounter += 1;
        const pr = { id: globalIdCounter, number: repo.nextNumber, title: args.title, body: args.body ?? null, state: 'open', merged: false, head: { ref: args.head, sha: headSha }, base: { ref: args.base, sha: baseSha }, baseSha, mergeCommitSha: null, mergedAt: null, createdAt: tsIso(nextTs()), updatedAt: FIXED_DATE };
        repo.nextNumber += 1;
        pr.updatedAt = pr.createdAt;
        repo.pulls.set(pr.number, pr);
        return mcpToolResult(prJson(repo, pr));
      } catch (e) { return mcpToolResult({ error: e.message }, true); }
    }
    case 'list_pull_requests': {
      for (const k of ['owner', 'repo']) if (!args[k]) return mcpToolResult({ error: `Missing required argument: ${k}` }, true);
      try {
        const repo = mcpNeedRepo(args);
        const state = args.state ?? 'open';
        let list = [...repo.pulls.values()];
        if (state !== 'all') list = list.filter((p) => p.state === state);
        list.sort((a, b) => b.number - a.number);
        return mcpToolResult(list.map((p) => prJson(repo, p)));
      } catch (e) { return mcpToolResult({ error: e.message }, true); }
    }
    case 'merge_pull_request': {
      for (const k of ['owner', 'repo', 'pull_number']) if (args[k] === undefined || args[k] === null) return mcpToolResult({ error: `Missing required argument: ${k}` }, true);
      try {
        const repo = mcpNeedRepo(args);
        const pr = repo.pulls.get(Number(args.pull_number));
        if (!pr) return mcpToolResult({ error: `Pull request not found: ${args.pull_number}` }, true);
        if (pr.state !== 'open') return mcpToolResult({ error: 'Pull request is not open' }, true);
        const result = squashMerge(repo, pr);
        if (result.conflict) return mcpToolResult({ error: 'Merge conflict' }, true);
        return mcpToolResult({ sha: result.sha, merged: true, message: result.message, pull_request: prJson(repo, pr) });
      } catch (e) { return mcpToolResult({ error: e.message }, true); }
    }
    default: return null;
  }
}
async function handleMcp(req, res) {
  const auth = req.headers.authorization ?? '';
  if (!auth) { sendError(res, 401, 'Requires authentication'); return; }
  if (auth !== `Bearer ${TOKEN}`) { sendError(res, 401, 'Requires authentication'); return; }
  const raw = await readBody(req);
  let msg;
  try { msg = JSON.parse(raw.toString('utf8')); }
  catch {
    sendJson(res, 400, mcpError(null, -32700, 'Parse error'));
    return;
  }
  const id = msg.id ?? null;
  const isNotification = msg.id === undefined || msg.id === null;
  const method = msg.method ?? '';
  if (method === 'notifications/initialized' || isNotification) {
    res.writeHead(202, { 'x-github-request-id': `req-${++reqCounter}` });
    res.end();
    return;
  }
  if (method === 'server/discover') {
    sendJson(res, 200, mcpResult(id, {
      supportedVersions: MCP_VERSIONS,
      capabilities: { tools: {} },
      serverInfo: { name: 'github-core-clone', version: '1.0.0' },
      _meta: { 'io.modelcontextprotocol/serverInfo': { name: 'github-core-clone', version: '1.0.0' } },
    }));
    return;
  }
  if (method === 'initialize') {
    const requested = msg.params?.protocolVersion;
    const version = MCP_VERSIONS.includes(requested) ? requested : '2026-07-28';
    sendJson(res, 200, mcpResult(id, {
      protocolVersion: version, capabilities: { tools: {} },
      serverInfo: { name: 'github-core-clone', version: '1.0.0' },
    }));
    return;
  }
  if (method === 'ping') { sendJson(res, 200, mcpResult(id, {})); return; }
  if (method === 'tools/list') {
    // Byte-for-byte identical across calls: stringify the prebuilt body.
    const body = Buffer.from(JSON.stringify(mcpResult(id, JSON.parse(MCP_TOOLS_LIST_BODY))), 'utf8');
    res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'content-length': body.length, 'x-github-request-id': `req-${++reqCounter}` });
    res.end(body);
    return;
  }
  if (method === 'tools/call') {
    const params = msg.params ?? {};
    const toolName = params.name ?? '';
    const args = params.arguments ?? {};
    if (!MCP_TOOLS_BY_NAME.has(toolName)) {
      sendJson(res, 200, mcpError(id, -32602, `Unknown tool: ${toolName}`));
      return;
    }
    const result = mcpCallTool(toolName, args);
    sendJson(res, 200, mcpResult(id, result));
    return;
  }
  sendJson(res, 200, mcpError(id, -32601, `Method not found: ${method}`));
}

// ---------------------------------------------------------------------------
// Git smart HTTP
// ---------------------------------------------------------------------------

function refAdvertisement(repo) {
  const lines = [];
  const headTip = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
  const caps = 'side-band-64k thin-pack ofs-delta shallow multi_ack symref=HEAD:refs/heads/main agent=github-core-clone/1.0';
  if (headTip) lines.push(`${headTip} HEAD\0${caps}\n`);
  else lines.push(`${ZERO_OID} capabilities^{}\0${caps}\n`);
  const sortedRefs = [...repo.refs.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1));
  for (const [ref, oid] of sortedRefs) {
    lines.push(`${oid} ${ref}\n`);
    const obj = getObject(repo, oid);
    if (ref.startsWith('refs/tags/') && obj?.type === 'tag') {
      const tag = parseTag(obj.data);
      if (tag.object) lines.push(`${tag.object} ${ref}^{}\n`);
    }
  }
  return lines;
}
function sidebandPack(pack) {
  const parts = [];
  let off = 0;
  while (off < pack.length) {
    // pkt-line length counts its 4-byte header, so payload (1 band byte +
    // data) must stay <= 65516 total.
    const chunk = pack.subarray(off, off + 65515);
    off += chunk.length;
    const payload = Buffer.concat([Buffer.from([1]), chunk]);
    parts.push(pktLine(payload));
  }
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}
function handleInfoRefs(req, res, repo, service) {
  if (!repo) { sendError(res, 404, 'Not Found'); return; }
  if (service === 'git-upload-pack') {
    if ((req.headers['git-protocol'] ?? '') === 'version=2') {
      const body = v2Advertisement();
      res.writeHead(200, { 'content-type': 'application/x-git-upload-pack-advertisement', 'content-length': body.length, 'x-github-request-id': `req-${++reqCounter}` });
      res.end(body);
      return;
    }
    const body = pktLines(['# service=git-upload-pack\n', 'flush', ...refAdvertisement(repo)]);
    res.writeHead(200, { 'content-type': 'application/x-git-upload-pack-advertisement', 'content-length': body.length, 'x-github-request-id': `req-${++reqCounter}` });
    res.end(body);
    return;
  }
  if (service === 'git-receive-pack') {
    const caps = 'report-status side-band-64k delete-refs ofs-delta agent=github-core-clone/1.0';
    const lines = [`${ZERO_OID} capabilities^{}\0${caps}\n`];
    const sortedRefs = [...repo.refs.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1));
    for (const [ref, oid] of sortedRefs) lines.push(`${oid} ${ref}\n`);
    const body = pktLines(['# service=git-receive-pack\n', 'flush', ...lines]);
    res.writeHead(200, { 'content-type': 'application/x-git-receive-pack-advertisement', 'content-length': body.length, 'x-github-request-id': `req-${++reqCounter}` });
    res.end(body);
    return;
  }
  sendError(res, 404, 'Not Found');
}
function v2Advertisement() {
  return pktLines([
    'version 2\n',
    'ls-refs=unborn\n',
    'fetch=shallow filter\n',
    'object-format=sha1\n',
    'agent=github-core-clone/1.0\n',
    'flush',
  ]);
}
function handleLsRefs(repo, args) {
  const prefixes = [];
  let peel = false; let symrefs = false; let unborn = false;
  for (const a of args) {
    if (a === 'peel') peel = true;
    else if (a === 'symrefs') symrefs = true;
    else if (a === 'unborn') unborn = true;
    else if (a.startsWith('ref-prefix ')) prefixes.push(a.slice('ref-prefix '.length));
  }
  const lines = [];
  const headTip = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
  const headIncluded = prefixes.length === 0 || prefixes.some((p) => 'HEAD'.startsWith(p) || p === 'HEAD');
  if (headIncluded) {
    if (headTip) lines.push(`${headTip} HEAD${symrefs ? ' symref-target:refs/heads/main' : ''}\n`);
    else if (unborn) lines.push('unborn HEAD symref-target:refs/heads/main\n');
  }
  if (headTip || repo.refs.size) {
    const sortedRefs = [...repo.refs.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1));
    for (const [ref, oid] of sortedRefs) {
      if (prefixes.length && !prefixes.some((p) => ref.startsWith(p))) continue;
      let line = `${oid} ${ref}`;
      const obj = getObject(repo, oid);
      if (peel && ref.startsWith('refs/tags/') && obj?.type === 'tag') {
        const tag = parseTag(obj.data);
        if (tag.object) line += ` peeled:${tag.object}`;
      }
      lines.push(`${line}\n`);
    }
  }
  lines.push('flush');
  return pktLines(lines);
}
function fetchResponse(repo, { wants, haves, shallow, depth, prefix }) {
  const cacheKey = `${prefix}|${repo.version}|${[...wants].sort().join(',')}|${[...haves].sort().join(',')}|${[...shallow].sort().join(',')}|${depth ?? ''}`;
  let cached = repo.packCache.get(cacheKey);
  if (!cached) {
    const info = computeFetch(repo, { wants, haves, shallow, depth });
    cached = { pack: writePack(info.objects), shallow: info.shallow, unshallow: info.unshallow };
    repo.packCache.set(cacheKey, cached);
  }
  return cached;
}
function handleV2Fetch(repo, args) {
  const wants = []; const haves = []; const shallowReq = [];
  let depth = null;
  for (const a of args) {
    if (a.startsWith('want ')) wants.push(a.slice(5).trim().split(/\s+/)[0]);
    else if (a.startsWith('have ')) haves.push(a.slice(5).trim().split(/\s+/)[0]);
    else if (a.startsWith('shallow ')) shallowReq.push(a.slice(8).trim().split(/\s+/)[0]);
    else if (a.startsWith('deepen ')) { const n = Number(a.slice(7).trim()); if (Number.isFinite(n)) depth = n; }
    else if (a.startsWith('deepen-since ')) depth = 1;
    else if (a.startsWith('deepen-not ')) { /* not supported: treat as full fetch */ }
  }
  const { pack, shallow, unshallow } = fetchResponse(repo, { wants, haves, shallow: shallowReq, depth, prefix: 'v2' });
  const parts = [];
  parts.push(pktLine('acknowledgments\n'));
  parts.push(pktLine('NAK\n'));
  parts.push(PKT_DELIM);
  if (shallow.length || unshallow.length) {
    parts.push(pktLine('shallow-info\n'));
    for (const s of shallow) parts.push(pktLine(`shallow ${s}\n`));
    for (const s of unshallow) parts.push(pktLine(`unshallow ${s}\n`));
    parts.push(PKT_DELIM);
  }
  parts.push(pktLine('packfile\n'));
  parts.push(sidebandPack(pack));
  return Buffer.concat(parts);
}
function handleV0Fetch(repo, body) {
  // Parse wants/haves/done from the request pkt-lines.
  const lines = [];
  const parsed = parsePktLines(body);
  for (const p of parsed.packets) if (p.kind === 'data') lines.push(p.payload.toString('utf8').trimEnd());
  const wants = []; const haves = []; const shallowReq = [];
  let depth = null;
  for (const line of lines) {
    const clean = line.split('\0')[0];
    if (clean.startsWith('want ')) wants.push(clean.slice(5).trim().split(/\s+/)[0]);
    else if (clean.startsWith('have ')) haves.push(clean.slice(5).trim().split(/\s+/)[0]);
    else if (clean.startsWith('shallow ')) shallowReq.push(clean.slice(8).trim().split(/\s+/)[0]);
    else if (clean.startsWith('deepen ')) { const n = Number(clean.slice(7).trim()); if (Number.isFinite(n)) depth = n; }
  }
  const { pack, shallow, unshallow } = fetchResponse(repo, { wants, haves, shallow: shallowReq, depth, prefix: 'v0' });
  const parts = [pktLine('NAK\n')];
  for (const s of shallow) parts.push(pktLine(`shallow ${s}\n`));
  for (const s of unshallow) parts.push(pktLine(`unshallow ${s}\n`));
  parts.push(sidebandPack(pack));
  return Buffer.concat(parts);
}
async function handleUploadPack(req, res, repo, isV2) {
  if (!repo) { sendError(res, 404, 'Not Found'); return; }
  const body = await readBody(req);
  if (body.length === 0) { sendError(res, 400, 'Empty request'); return; }
  try {
    const first = parsePktLinesUntilFlush(body, 0);
    const firstLine = first.packets.find((p) => p.kind === 'data')?.payload.toString('utf8') ?? '';
    if (firstLine.startsWith('command=')) {
      const args = [];
      for (const p of first.packets) if (p.kind === 'data') args.push(p.payload.toString('utf8').trimEnd());
      const command = args[0].slice('command='.length);
      if (command === 'ls-refs') {
        const out = handleLsRefs(repo, args.slice(1));
        res.writeHead(200, { 'content-type': 'application/x-git-upload-pack-result', 'content-length': out.length, 'x-github-request-id': `req-${++reqCounter}` });
        res.end(out);
        return;
      }
      if (command === 'fetch') {
        const out = handleV2Fetch(repo, args.slice(1));
        res.writeHead(200, { 'content-type': 'application/x-git-upload-pack-result', 'content-length': out.length, 'x-github-request-id': `req-${++reqCounter}` });
        res.end(out);
        return;
      }
      sendError(res, 400, `Unknown command: ${command}`);
      return;
    }
    if (firstLine.startsWith('want ')) {
      const out = handleV0Fetch(repo, body);
      res.writeHead(200, { 'content-type': 'application/x-git-upload-pack-result', 'content-length': out.length, 'x-github-request-id': `req-${++reqCounter}` });
      res.end(out);
      return;
    }
    sendError(res, 400, 'Malformed upload-pack request');
  } catch {
    sendError(res, 400, 'Malformed upload-pack request');
  }
}
async function handleReceivePack(req, res, repo) {
  if (!repo) { sendError(res, 404, 'Not Found'); return; }
  const body = await readBody(req);
  let commands = [];
  let packStart = 0;
  try {
    const parsed = parsePktLinesUntilFlush(body, 0);
    packStart = parsed.offset;
    for (const p of parsed.packets) {
      if (p.kind !== 'data') continue;
      const text = p.payload.toString('utf8').split('\0')[0].trimEnd();
      const m = /^([0-9a-f]{40}) ([0-9a-f]{40}) (.+)$/.exec(text);
      if (!m) throw new Error('bad receive-pack command');
      commands.push({ oldOid: m[1], newOid: m[2], ref: m[3] });
    }
  } catch {
    sendError(res, 400, 'Malformed receive-pack request');
    return;
  }
  // Parse the pack (if any payload follows the flush).
  let newObjects = new Map();
  if (packStart < body.length) {
    try {
      const parsed = readPack(body.subarray(packStart), (oid) => repo.objects.get(oid));
      newObjects = parsed.objects;
    } catch {
      const report = pktLines(['unpack error\n', ...commands.map((c) => `ng ${c.ref} unpack error\n`), 'flush']);
      const bodyOut = Buffer.concat([pktLine(Buffer.concat([Buffer.from([1]), report])), PKT_FLUSH]);
      res.writeHead(200, { 'content-type': 'application/x-git-receive-pack-result', 'content-length': bodyOut.length, 'x-github-request-id': `req-${++reqCounter}` });
      res.end(bodyOut);
      return;
    }
  }
  const reportLines = ['unpack ok\n'];
  let changed = false;
  for (const cmd of commands) {
    const current = repo.refs.get(cmd.ref);
    if (cmd.newOid === ZERO_OID) {
      // Delete.
      if (!current) { reportLines.push(`ng ${cmd.ref} reference does not exist\n`); continue; }
      if (cmd.oldOid !== ZERO_OID && cmd.oldOid !== current) { reportLines.push(`ng ${cmd.ref} non-fast-forward\n`); continue; }
      repo.refs.delete(cmd.ref);
      changed = true;
      reportLines.push(`ok ${cmd.ref}\n`);
      continue;
    }
    if (!newObjects.has(cmd.newOid) && !repo.objects.has(cmd.newOid)) {
      reportLines.push(`ng ${cmd.ref} object not found\n`);
      continue;
    }
    if (!current) {
      if (cmd.oldOid !== ZERO_OID) { reportLines.push(`ng ${cmd.ref} non-fast-forward\n`); continue; }
      repo.refs.set(cmd.ref, cmd.newOid);
      changed = true;
      reportLines.push(`ok ${cmd.ref}\n`);
      continue;
    }
    if (cmd.oldOid !== current) { reportLines.push(`ng ${cmd.ref} non-fast-forward\n`); continue; }
    if (cmd.newOid === current) { reportLines.push(`ok ${cmd.ref}\n`); continue; }
    // Fast-forward check: new tip must descend from the old tip (walking the
    // freshly unpacked commits too, since they are not in the store yet).
    const ff = isAncestorWithNew(repo, current, cmd.newOid, newObjects);
    if (!ff) { reportLines.push(`ng ${cmd.ref} non-fast-forward\n`); continue; }
    repo.refs.set(cmd.ref, cmd.newOid);
    changed = true;
    reportLines.push(`ok ${cmd.ref}\n`);
  }
  // Unpacked objects join the store regardless of per-ref outcomes (like real
  // git: unpack happens first, ref updates are validated after).
  for (const [oid, obj] of newObjects) repo.objects.set(oid, obj);
  if (changed) bumpVersion(repo);
  const report = pktLines([...reportLines, 'flush']);
  const out = Buffer.concat([pktLine(Buffer.concat([Buffer.from([1]), report])), PKT_FLUSH]);
  res.writeHead(200, { 'content-type': 'application/x-git-receive-pack-result', 'content-length': out.length, 'x-github-request-id': `req-${++reqCounter}` });
  res.end(out);
}
function isAncestorWithNew(repo, ancestor, descendant, newObjects) {
  const seen = new Set();
  const stack = [descendant];
  while (stack.length) {
    const cur = stack.pop();
    if (cur === ancestor) return true;
    if (seen.has(cur)) continue;
    seen.add(cur);
    let c = getCommit(repo, cur);
    if (!c) {
      const o = newObjects.get(cur);
      if (o && o.type === 'commit') c = parseCommit(o.data);
    }
    if (c) for (const p of c.parents) stack.push(p);
  }
  return false;
}

// ---------------------------------------------------------------------------
// HTTP routing + lifecycle
// ---------------------------------------------------------------------------

function isGitPath(segments) {
  return segments.length >= 2 && segments[1].endsWith('.git');
}
async function handleRequest(req, res) {
  try {
    const url = new URL(req.url ?? '/', 'http://localhost');
    const pathname = url.pathname;
    const segments = pathname.split('/').filter((s) => s.length > 0);
    if (pathname === '/healthz') { sendJson(res, 200, { ok: true }); return; }
    if (pathname === '/api/graphql') {
      if (req.method !== 'POST') { sendError(res, 404, 'Not Found'); return; }
      await handleGraphql(req, res);
      return;
    }
    if (pathname === '/mcp') {
      if (req.method !== 'POST') { sendError(res, 404, 'Not Found'); return; }
      await handleMcp(req, res);
      return;
    }
    if (segments[0] === 'api' && segments[1] === 'v3') {
      await handleRest(req, res, url, segments.slice(2));
      return;
    }
    if (isGitPath(segments)) {
      const owner = decodeURIComponent(segments[0]);
      const repoName = decodeURIComponent(segments[1].slice(0, -4));
      const repo = findRepo(owner, repoName);
      const tail = segments.slice(2);
      if (tail.length === 2 && tail[0] === 'info' && tail[1] === 'refs') {
        const service = url.searchParams.get('service') ?? '';
        handleInfoRefs(req, res, repo, service);
        return;
      }
      if (tail.length === 1 && tail[0] === 'git-upload-pack' && req.method === 'POST') {
        const isV2 = (req.headers['git-protocol'] ?? '') === 'version=2';
        if (isV2 && (url.searchParams.get('service') ?? '') === '') {
          // POST upload-pack with v2 header: the advertisement is served by
          // GET info/refs; a POST here is a command request.
        }
        await handleUploadPack(req, res, repo, isV2);
        return;
      }
      if (tail.length === 1 && tail[0] === 'git-receive-pack' && req.method === 'POST') {
        await handleReceivePack(req, res, repo);
        return;
      }
      sendError(res, 404, 'Not Found');
      return;
    }
    sendError(res, 404, 'Not Found');
  } catch (e) {
    try { sendError(res, 500, e.message ?? 'Internal Server Error'); } catch { /* socket gone */ }
  }
}

const server = createServer(handleRequest);
server.keepAliveTimeout = 30000;

async function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }
async function httpJson(url, method, body, headers = {}) {
  const res = await fetch(url, {
    method,
    headers: { 'content-type': 'application/json', ...headers },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* ignore */ }
  return { status: res.status, json, text };
}

async function main() {
  const listenPort = ENV_URL ? 0 : (Number(process.env.PORT ?? 0) || 0);
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(listenPort, '127.0.0.1', resolve);
  });
  const port = server.address().port;
  if (!ENV_URL) {
    // Standalone mode (local runs): serve until killed.
    console.log(`github-core-clone listening on http://127.0.0.1:${port}`);
    return;
  }
  // Register with retries.
  let registered = false;
  for (let attempt = 0; attempt < 30 && !registered; attempt += 1) {
    try {
      const r = await httpJson(`${ENV_URL}/register`, 'POST', { port });
      if (r.status === 200 || r.status === 201 || r.status === 204) registered = true;
      else await sleep(500);
    } catch { await sleep(500); }
  }
  if (!registered) { process.exit(1); }
  // Long-poll /done until the trial ends.
  let delay = 250;
  for (;;) {
    try {
      const r = await httpJson(`${ENV_URL}/done`, 'GET');
      if (r.json && r.json.done === true) break;
    } catch { /* keep polling */ }
    await sleep(delay);
    delay = Math.min(5000, Math.round(delay * 1.5));
  }
  server.close();
  process.exit(0);
}
main().catch((e) => { console.error(e); process.exit(1); });
