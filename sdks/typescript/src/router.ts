// Routing: decides, for each inbound stream target ({host, port}), which upstream
// to dial — a configured route, the fallback upstream, the client-specified target
// (if allowed), or deny.

import { hostMatches, normalizeHost, toArray } from './util.js';

/** A dialable upstream: {host, port} or {unix}. */
export interface UpstreamAddr {
  host?: string;
  port?: number;
  unix?: string;
}

/** Anything that can name an upstream: "host:port", "unix:/path", [host, port], object. */
export type UpstreamInput = string | [string, number | string] | UpstreamAddr | null | undefined;

/** A single configured route. */
export interface RouteConfig {
  host?: string | string[];
  hosts?: string | string[];
  port?: PortPatterns;
  ports?: PortPatterns;
  upstream?: UpstreamInput;
}

/** A single port pattern: number, "80", "*", "1000-2000", [lo, hi], {min, max}. */
export type PortPattern = number | string | [number, number] | { min?: number; max?: number };
/** One pattern or a list of patterns. */
export type PortPatterns = PortPattern | PortPattern[];

/** Client-dial permission block. */
export interface ClientTargetsConfig {
  enabled?: boolean;
  allowHosts?: string | string[];
  allowPorts?: PortPatterns | null;
}

/** Compiled route (internal). */
export interface CompiledRoute {
  order: number;
  hosts: string[];
  ports: PortPatterns | null;
  upstream: UpstreamAddr | null;
}

/** Resolver verdict for one inbound stream target. */
export type RouteDecision =
  | { action: 'route'; route: number; upstream: UpstreamAddr | null }
  | { action: 'dial'; target: UpstreamAddr }
  | { action: 'deny'; reason: string };

function compileUpstream(u: UpstreamInput): UpstreamAddr | null {
  if (!u) return null;
  if (typeof u === 'string') {
    const idx = u.lastIndexOf(':');
    if (u.startsWith('unix:')) return { unix: u.slice(5) };
    return { host: u.slice(0, idx), port: Number(u.slice(idx + 1)) };
  }
  if (Array.isArray(u)) return { host: u[0], port: Number(u[1]) };
  if ((u as UpstreamAddr).unix !== undefined) return { unix: (u as UpstreamAddr).unix };
  return { host: (u as UpstreamAddr).host ?? '127.0.0.1', port: Number((u as UpstreamAddr).port ?? 0) };
}

function portMatches(patterns: PortPatterns, port: number): boolean {
  for (const p of toArray(patterns)) {
    if (typeof p === 'number') {
      if (p === port) return true;
      continue;
    }
    if (Array.isArray(p) || typeof p === 'object') {
      const lo = Array.isArray(p) ? p[0] : p.min ?? 0;
      const hi = Array.isArray(p) ? p[1] : p.max ?? 65535;
      if (port >= Number(lo) && port <= Number(hi)) return true;
      continue;
    }
    const s = String(p);
    if (s === '*' || s === String(port)) return true;
    const dash = s.match(/^(\d+)-(\d+)$/);
    if (dash && port >= Number(dash[1]) && port <= Number(dash[2])) return true;
  }
  return false;
}

/**
 * Compile a routing config into a resolver.
 * @param opts.routes ordered [{host|hosts, port|ports, upstream}]
 * @param opts.fallbackUpstream used when no route matches
 * @param opts.clientTargets {enabled, allowHosts, allowPorts} —
 *   when enabled, otherwise-unrouted streams may dial their requested target
 * @returns {resolve, routes, fallback} — resolve(target) returns
 *   {action:'route', upstream} | {action:'dial', target} | {action:'deny', reason}
 */
export function compileRoutes(
  { routes = [], fallbackUpstream = null, clientTargets = null }: {
    routes?: RouteConfig | RouteConfig[];
    fallbackUpstream?: UpstreamInput;
    clientTargets?: ClientTargetsConfig | boolean | null;
  } = {},
): { resolve: (target: { host?: string | null; port?: number; unix?: string | null }) => RouteDecision; routes: CompiledRoute[]; fallback: UpstreamAddr | null } {
  const compiled: CompiledRoute[] = toArray(routes).map((r, i) => ({
    order: i,
    hosts: toArray(r.host ?? r.hosts ?? []).map((h) => normalizeHost(h)).filter((h): h is string => !!h),
    ports: (r.port ?? r.ports ?? null) as PortPatterns | null,
    upstream: compileUpstream(r.upstream),
  }));

  const fallback = compileUpstream(fallbackUpstream);

  let ct: { allowHosts: string[]; allowPorts: PortPatterns | null } | null = null;
  if (clientTargets) {
    const enabled = clientTargets === true || clientTargets.enabled === true;
    if (enabled) {
      const cfg = clientTargets === true ? {} : clientTargets;
      ct = {
        allowHosts: toArray((cfg as ClientTargetsConfig).allowHosts ?? ['*']),
        allowPorts: (cfg as ClientTargetsConfig).allowPorts ?? null, // null = any
      };
    }
  }

  function resolve(target: { host?: string | null; port?: number; unix?: string | null }): RouteDecision {
    const host = normalizeHost(target?.host);
    const port = Number(target?.port ?? 0);
    for (const r of compiled) {
      const hostOk = r.hosts.length === 0 || (host != null && r.hosts.some((h) => hostMatches(h, host)));
      const portOk = r.ports == null || portMatches(r.ports, port);
      if (hostOk && portOk) {
        return { action: 'route', route: r.order, upstream: r.upstream ?? fallback };
      }
    }
    if (fallback) return { action: 'route', route: -1, upstream: fallback };
    if (ct) {
      const hostOk = host == null || ct.allowHosts.some((p) => hostMatches(p, host));
      const portOk = ct.allowPorts == null || portMatches(ct.allowPorts, port);
      if (hostOk && portOk && (port > 0 || target?.unix)) {
        return { action: 'dial', target: target?.unix ? { unix: target.unix } : { host: target?.host ?? undefined, port } };
      }
      return { action: 'deny', reason: 'client target not allowed' };
    }
    return { action: 'deny', reason: 'no route matched and client targets are disabled' };
  }

  return { resolve, routes: compiled, fallback };
}
