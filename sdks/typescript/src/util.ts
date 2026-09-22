/**
 * Internal shared utilities: endpoint parsing, host-pattern matching for the
 * router, small timing/formatting helpers, and the batching primitive used
 * for window-credit updates. Nothing here is protocol-specific.
 */

import { Buffer } from 'node:buffer';

/** Minimal structured logger surface used across the SDK. */
export interface Logger {
  trace?: (msg: string, extra?: Record<string, unknown>) => void;
  debug: (msg: string, extra?: Record<string, unknown>) => void;
  info: (msg: string, extra?: Record<string, unknown>) => void;
  warn: (msg: string, extra?: Record<string, unknown>) => void;
  error: (msg: string, extra?: Record<string, unknown>) => void;
  child?: (suffix: string) => Logger;
}

/** A logger that swallows everything (the SDK default). */
export function noopLogger(): Logger {
  const fn = (): void => {};
  const log: Logger = {
    trace: fn, debug: fn, info: fn, warn: fn, error: fn,
    child: () => log,
  };
  return log;
}

/** Parsed endpoint / stream target. */
export interface ParsedTarget {
  host: string;
  port: number;
  unix?: string;
}

/** Anything parseTarget accepts: "host:port", "[v6]:port", ["host", port], or an object. */
export type TargetInput =
  | string
  | [string, number | string]
  | { host?: string | null; port?: number | string; unix?: string };

/** Parse "host:port" / "[v6]:port" / "host" with default port. */
export function parseTarget(str: TargetInput, defaultPort = 0): ParsedTarget {
  if (Array.isArray(str)) return { host: str[0]!, port: Number(str[1]) };
  if (typeof str === 'object' && str !== null) {
    if (str.unix !== undefined) return { host: '', port: 0, unix: str.unix };
    return { host: String(str.host ?? ''), port: Number(str.port ?? defaultPort) };
  }
  const s = String(str).trim();
  if (s.startsWith('[')) {
    const end = s.indexOf(']');
    if (end === -1) throw new Error(`invalid target: ${s}`);
    const host = s.slice(1, end);
    const rest = s.slice(end + 1);
    const port = rest.startsWith(':') ? Number(rest.slice(1)) : defaultPort;
    return { host, port };
  }
  const idx = s.lastIndexOf(':');
  if (idx === -1) return { host: s, port: defaultPort };
  const host = s.slice(0, idx);
  const port = Number(s.slice(idx + 1));
  if (!Number.isFinite(port)) throw new Error(`invalid target: ${s}`);
  return { host, port };
}

/** Lowercase, strip port and trailing dot. */
export function normalizeHost(h: unknown): string | null {
  if (!h) return null;
  let s = String(h).trim().toLowerCase();
  if (s.includes(':') && !s.startsWith('[')) s = s.slice(0, s.lastIndexOf(':')); // strip :port (v4/hostname)
  s = s.replace(/^\[/, '').replace(/\]$/, '').replace(/\.$/, '');
  return s || null;
}

/** Wildcard host match: "*", "*.example.com" (suffix, label-aware), exact. */
export function hostMatches(pattern: string, host: string): boolean {
  const p = normalizeHost(pattern);
  const h = normalizeHost(host);
  if (!p || !h) return false;
  if (p === '*' || p === h) return true;
  if (p.startsWith('*.')) {
    const suffix = p.slice(1); // ".example.com"
    return h.endsWith(suffix) && !h.slice(0, -suffix.length).endsWith('.');
  }
  return false;
}

/** Promise-based sleep (ms). */
export function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

/** Random hex id of `bytes` bytes (non-crypto; ids only, never secrets). */
export function randomId(bytes = 8): string {
  const b = Buffer.allocUnsafe(bytes);
  b.fill(0);
  for (let i = 0; i < bytes; i++) b[i] = (Math.random() * 256) | 0;
  return b.toString('hex');
}

/** Human-readable byte count, e.g. "1.50MB". */
export function fmtBytes(n: number): string {
  if (!Number.isFinite(n)) return String(n);
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v >= 100 || i === 0 ? 0 : 2)}${u[i]}`;
}

/** Monotonic-ish millisecond timestamp (hrtime-based, for stats/RTT). */
export function nowMs(): number {
  return Number(process.hrtime.bigint() / 1000000n);
}

/** Normalize config value: single item -> array. */
export function toArray<T>(v: T | T[] | undefined | null): T[] {
  if (v === undefined || v === null) return [];
  return Array.isArray(v) ? v : [v];
}

/** Accumulate-and-flush batching helper. */
export class Batch {
  private readonly _flushFn: (v: number) => void;
  private readonly _threshold: number;
  private readonly _intervalMs: number;
  private _acc = 0;
  private _timer: NodeJS.Timeout | null = null;

  constructor(flushFn: (v: number) => void, { threshold = 1, intervalMs = 5 }: { threshold?: number; intervalMs?: number } = {}) {
    this._flushFn = flushFn;
    this._threshold = threshold;
    this._intervalMs = intervalMs;
  }

  add(n: number): void {
    this._acc += n;
    if (this._acc >= this._threshold) {
      this.flush();
      return;
    }
    if (!this._timer) {
      this._timer = setTimeout(() => this.flush(), this._intervalMs);
      this._timer.unref();
    }
  }

  flush(): void {
    if (this._timer) {
      clearTimeout(this._timer);
      this._timer = null;
    }
    if (this._acc > 0) {
      const v = this._acc;
      this._acc = 0;
      this._flushFn(v);
    }
  }

  dispose(): void {
    if (this._timer) {
      clearTimeout(this._timer);
      this._timer = null;
    }
    this._acc = 0;
  }
}

const LEVELS: Record<string, number> = { trace: 10, debug: 20, info: 30, warn: 40, error: 50, silent: 100 };

/**
 * Create a structured logger (levelled text or JSON lines). Zero dependencies.
 */
export function createLog(
  { level = 'info', name = 'krymux', json = false, sink = null }: {
    level?: string;
    name?: string;
    json?: boolean;
    sink?: ((...a: unknown[]) => void) | null;
  } = {},
): Logger {
  const threshold = LEVELS[level] ?? LEVELS.info;
  const write = sink ?? ((...a: unknown[]) => console.error(...a));

  function emit(lvl: 'trace' | 'debug' | 'info' | 'warn' | 'error', msg: string, extra?: Record<string, unknown>): void {
    if ((LEVELS[lvl] ?? 100) < threshold) return;
    const ts = new Date().toISOString();
    if (json) {
      write(JSON.stringify({ ts, level: lvl, name, msg, ...extra }));
    } else {
      const e = extra && Object.keys(extra).length ? ' ' + JSON.stringify(extra) : '';
      write(`${ts} ${lvl.toUpperCase().padEnd(5)} [${name}] ${msg}${e}`);
    }
  }

  const log: Logger = {
    trace: (m, x) => emit('trace', m, x),
    debug: (m, x) => emit('debug', m, x),
    info: (m, x) => emit('info', m, x),
    warn: (m, x) => emit('warn', m, x),
    error: (m, x) => emit('error', m, x),
    child(suffix: string): Logger {
      return createLog({ level, name: `${name}:${suffix}`, json, sink });
    },
  };
  return log;
}
