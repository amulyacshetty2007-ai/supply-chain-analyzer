"""Graph algorithms. Edge direction: parent -> child means 'parent depends on child'."""
import heapq
import math
from collections import deque


class Graph:
    def __init__(self, nodes, edges):
        self.adj = {n: [] for n in nodes}      # hash maps for O(1) neighbour lookup
        self.radj = {n: [] for n in nodes}
        seen = set()
        for a, b in edges:
            if a in self.adj and b in self.adj and (a, b) not in seen:
                seen.add((a, b))
                self.adj[a].append(b)
                self.radj[b].append(a)
        self.nodes = list(self.adj)

    # ---- BFS: hop distance + parent pointers (unweighted shortest paths)
    def bfs(self, src, adj=None):
        adj = adj or self.adj
        dist, par, q = {src: 0}, {src: None}, deque([src])
        while q:
            u = q.popleft()
            for v in adj[u]:
                if v not in dist:
                    dist[v], par[v] = dist[u] + 1, u
                    q.append(v)
        return dist, par

    @staticmethod
    def path_to(par, t):
        out = []
        while t is not None:
            out.append(t)
            t = par[t]
        return out[::-1]

    def dependents(self, node):
        """Everything that transitively depends on `node` (reverse BFS)."""
        return set(self.bfs(node, self.radj)[0]) - {node}

    def descendants(self, node):
        return set(self.bfs(node)[0]) - {node}

    # ---- Tarjan SCC (iterative) -> cycle detection
    def scc(self):
        index, low, onstack, stack, out, c = {}, {}, set(), [], [], 0
        for s in self.nodes:
            if s in index:
                continue
            index[s] = low[s] = c; c += 1
            stack.append(s); onstack.add(s)
            work = [(s, iter(self.adj[s]))]
            while work:
                v, it = work[-1]
                for w in it:
                    if w not in index:
                        index[w] = low[w] = c; c += 1
                        stack.append(w); onstack.add(w)
                        work.append((w, iter(self.adj[w])))
                        break
                    if w in onstack:
                        low[v] = min(low[v], index[w])
                else:
                    work.pop()
                    if work:
                        p = work[-1][0]
                        low[p] = min(low[p], low[v])
                    if low[v] == index[v]:
                        comp = []
                        while True:
                            w = stack.pop(); onstack.discard(w); comp.append(w)
                            if w == v:
                                break
                        out.append(comp)
        return out

    def cycles(self):
        return [c for c in self.scc() if len(c) > 1 or c[0] in self.adj[c[0]]]

    # ---- Topological sort (Kahn) on the SCC condensation, so it works even with cycles
    def topo_order(self):
        comps = self.scc()
        cid = {n: i for i, comp in enumerate(comps) for n in comp}
        cadj = {i: set() for i in range(len(comps))}
        indeg = {i: 0 for i in cadj}
        for a in self.nodes:
            for b in self.adj[a]:
                if cid[a] != cid[b] and cid[b] not in cadj[cid[a]]:
                    cadj[cid[a]].add(cid[b]); indeg[cid[b]] += 1
        q = deque(i for i, d in indeg.items() if d == 0)
        order = []
        while q:
            i = q.popleft()
            order.extend(comps[i])
            for j in cadj[i]:
                indeg[j] -= 1
                if indeg[j] == 0:
                    q.append(j)
        return order            # dependents first, deepest dependencies last

    # ---- Dijkstra with custom edge cost
    def dijkstra(self, src, cost):
        dist, par, pq = {src: 0.0}, {src: None}, [(0.0, src)]
        while pq:
            d, u = heapq.heappop(pq)
            if d > dist[u]:
                continue
            for v in self.adj[u]:
                nd = d + cost(u, v)
                if nd < dist.get(v, math.inf):
                    dist[v], par[v] = nd, u
                    heapq.heappush(pq, (nd, v))
        return dist, par

    # ---- DFS: enumerate simple root->target paths, pruned to ancestors of target
    def k_paths(self, src, target, k=3, max_len=12, cap=400):
        anc = set(self.bfs(target, self.radj)[0])
        if src not in anc:
            return []
        found, stack = [], [(src, [src], {src})]
        while stack and len(found) < cap:
            u, path, seen = stack.pop()
            if u == target:
                found.append(path); continue
            if len(path) > max_len:
                continue
            for v in self.adj[u]:
                if v in anc and v not in seen:
                    stack.append((v, path + [v], seen | {v}))
        found.sort(key=len)
        return found[:k]


SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


def analyze_project(root, packages, edges, vulns):
    """root={'ref','name'}, packages=[{ref,name,version,ecosystem,is_direct}],
    edges=[(parent,child)], vulns={ref:[{id,severity,cvss,summary,fixed}]}"""
    R = root["ref"]
    meta = {p["ref"]: p for p in packages}
    g = Graph([R, *meta], edges)
    dist, par = g.bfs(R)
    cyc = g.cycles()
    cyc_nodes = {n for c in cyc for n in c}
    topo = g.topo_order()
    pos = {n: i for i, n in enumerate(topo)}
    indeg = {n: len(g.radj[n]) for n in g.nodes}

    _, hpar = g.dijkstra(R, lambda u, v: 1 / (1 + math.log(1 + indeg[v])))  # hubs are cheap
    items = []
    for ref, vs in vulns.items():
        if ref not in meta or not vs:
            continue
        deps = g.dependents(ref) - {R}
        hops = dist.get(ref)
        cvss = max(v["cvss"] for v in vs)
        exposure = 1 + math.log(1 + len(deps))
        score = cvss * exposure / (1 + 0.15 * ((hops or 1) - 1))
        sev = min((v["severity"] for v in vs), key=SEV_ORDER.index)
        hub_path = g.path_to(hpar, ref) if ref in hpar else []
        paths = g.k_paths(R, ref)
        items.append({
            "ref": ref, "name": meta[ref]["name"], "version": meta[ref]["version"],
            "ecosystem": meta[ref]["ecosystem"], "direct": meta[ref]["is_direct"],
            "severity": sev, "cvss": cvss, "depth": hops, "reachable": hops is not None,
            "blast_radius": len(deps), "dependents": sorted(deps), "score": round(score, 2),
            "vulns": vs, "paths": paths, "hub_path": hub_path,
            "shortest_path": g.path_to(par, ref) if hops is not None else [],
            "in_cycle": ref in cyc_nodes,
        })
    items.sort(key=lambda i: -i["score"])

    # Ranked dependency paths (shortest + most exposed first)
    ranked = []
    for it in items:
        for p in it["paths"]:
            ranked.append({"vuln_ref": it["ref"], "path": p, "hops": len(p) - 1,
                           "score": round(it["score"] * 2 / len(p), 2) if len(p) else 0})
    ranked.sort(key=lambda x: -x["score"])

    # Fix-first set: greedy weighted set cover. Candidates are the project's direct
    # dependencies (what the developer can actually upgrade); each covers the
    # vulnerable packages at or beneath it.
    weight = {i["ref"]: i["score"] for i in items}
    uncovered = {i["ref"] for i in items}
    cands = {c: ({c} | g.descendants(c)) & uncovered for c in g.adj[R] if c in meta}
    fix_first = []
    while uncovered:
        best = max(cands, key=lambda c: (sum(weight[x] for x in cands[c] & uncovered), -len(cands[c])),
                   default=None)
        gain = cands[best] & uncovered if best else set()
        if not gain:
            break
        fix_first.append({"ref": best, "name": meta[best]["name"], "version": meta[best]["version"],
                          "covers": sorted(gain), "gain": round(sum(weight[x] for x in gain), 2)})
        uncovered -= gain
    unreachable = sorted(uncovered)

    sev_counts = {s: 0 for s in SEV_ORDER}
    for it in items:
        for v in it["vulns"]:
            sev_counts[v["severity"]] = sev_counts.get(v["severity"], 0) + 1
    risk = round(100 * (1 - math.exp(-sum(weight.values()) / 40)), 1)

    vuln_flag = {i["ref"]: i for i in items}
    nodes = [{"id": R, "label": root["name"], "version": "", "depth": 0, "root": True}]
    for r, p in meta.items():
        v = vuln_flag.get(r)
        nodes.append({"id": r, "label": p["name"], "version": p["version"], "eco": p["ecosystem"],
                      "depth": dist.get(r), "direct": p["is_direct"], "cycle": r in cyc_nodes,
                      "sev": v["severity"] if v else None, "cvss": v["cvss"] if v else None})
    return {
        "summary": {"packages": len(meta), "edges": sum(len(a) for a in g.adj.values()),
                    "max_depth": max(dist.values()), "vulnerable_packages": len(items),
                    "findings": sum(sev_counts.values()), "severity": sev_counts,
                    "cycles": len(cyc), "risk_score": risk,
                    "fix_first_count": len(fix_first)},
        "vulnerable": items,
        "top_paths": ranked[:10],
        "fix_first": fix_first,
        "unreachable_vulnerable": unreachable,
        "remediation_order": sorted((i["ref"] for i in items), key=lambda r: -pos[r]),
        "cycles": [[meta[n]["name"] if n in meta else root["name"] for n in c] for c in cyc],
        "graph": {"root": R, "nodes": nodes, "edges": [[a, b] for a in g.adj for b in g.adj[a]]},
    }
