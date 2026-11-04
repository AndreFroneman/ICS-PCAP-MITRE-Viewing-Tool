import { useVirtualizer } from "@tanstack/react-virtual";
import { useEffect, useMemo, useRef, useState } from "react";
import { FILTER_FIELDS, FILTER_PRESETS } from "../lib/filter.ts";
import type { Row, Severity, TreeNode } from "../lib/model.ts";
import { narrate } from "../lib/narrate.ts";
import { Button } from "./ui.tsx";

export function FilterBar({
  value,
  error,
  shown,
  total,
  onChange,
}: {
  value: string;
  error: string;
  shown: number;
  total: number;
  onChange: (value: string) => void;
}) {
  const [group, setGroup] = useState(FILTER_FIELDS[0].group);
  const fields = FILTER_FIELDS.filter((f) => f.group === group);
  const [field, setField] = useState(fields[0].id);
  const [op, setOp] = useState("==");
  const [raw, setRaw] = useState("");
  const groups = [...new Set(FILTER_FIELDS.map((f) => f.group))];
  const chosen = FILTER_FIELDS.find((f) => f.id === field) ?? fields[0];

  return (
    <div className="border-b border-line bg-surface px-3 py-2" data-tour="filter">
      <div className="flex flex-wrap items-center gap-2">
        <input
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder='Filter, e.g. modbus.func == 16 or dns'
          className="h-9 min-w-[16rem] flex-1 rounded-full border border-line bg-raise px-4 font-mono text-sm outline-none focus:border-accent"
          aria-label="Display filter"
          spellCheck={false}
        />
        <span className="text-xs text-muted">{shown.toLocaleString()} of {total.toLocaleString()}</span>
      </div>
      <div className="mt-2 flex flex-wrap items-center gap-2">
        {FILTER_PRESETS.map((p) => (
          <button key={p.label} className="rounded-full bg-raise px-2 py-1 text-xs text-muted hover:text-ink" onClick={() => onChange(p.expr)} type="button">
            {p.label}
          </button>
        ))}
      </div>
      <div className="mt-2 flex flex-wrap items-center gap-2 text-sm">
        <select className="h-8 rounded-lg border border-line bg-surface px-2" value={group} onChange={(e) => {
          const next = FILTER_FIELDS.find((f) => f.group === e.target.value);
          setGroup(e.target.value);
          if (next) setField(next.id);
        }} aria-label="Filter group">
          {groups.map((g) => <option key={g}>{g}</option>)}
        </select>
        <select className="h-8 rounded-lg border border-line bg-surface px-2" value={chosen.id} onChange={(e) => setField(e.target.value)} aria-label="Filter field">
          {fields.map((f) => <option key={f.id} value={f.id}>{f.label}</option>)}
        </select>
        <select className="h-8 rounded-lg border border-line bg-surface px-2" value={op} onChange={(e) => setOp(e.target.value)} aria-label="Operator">
          {(chosen.type === "string" ? ["==", "!=", "contains"] : ["==", "!=", ">", "<", ">=", "<="]).map((item) => <option key={item}>{item}</option>)}
        </select>
        <input value={raw} onChange={(e) => setRaw(e.target.value)} placeholder="Value" className="h-8 w-36 rounded-lg border border-line bg-surface px-2" aria-label="Filter value" />
        <Button type="button" onClick={() => {
          const literal = chosen.type === "string" ? `"${raw.replaceAll('"', "")}"` : raw || "0";
          const clause = `${chosen.id} ${op} ${literal}`;
          onChange(value.trim() ? `${value} && ${clause}` : clause);
        }}>Add</Button>
        {value && <Button type="button" variant="ghost" onClick={() => onChange("")}>Clear</Button>}
      </div>
      {error && <p className="mt-1 text-xs text-accent">{error}</p>}
    </div>
  );
}

export function PacketDesk({
  rows,
  active,
  names,
  t0,
  marks,
  selected,
  onSelect,
  tree,
  bytes,
  field,
  onField,
  onFilter,
  onFollow,
}: {
  rows: Row[];
  active: Row | null;
  names: Record<string, string>;
  t0: number;
  marks: Map<number, Severity>;
  selected: number | null;
  onSelect: (n: number) => void;
  tree: TreeNode[];
  bytes: Uint8Array | null;
  field: TreeNode | null;
  onField: (node: TreeNode) => void;
  onFilter: (expr: string, add: boolean) => void;
  onFollow: () => void;
}) {
  const parentRef = useRef<HTMLDivElement>(null);
  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 34,
    overscan: 20,
  });
  useEffect(() => {
    if (selected == null) return;
    const index = rows.findIndex((r) => r.n === selected);
    if (index >= 0) virtualizer.scrollToIndex(index, { align: "auto" });
    // The virtualizer instance is not referentially stable; scrolling follows the selection.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected, rows]);

  const row = active;
  const story = row ? narrate(row) : null;

  return (
    <div className="grid min-h-0 flex-1 grid-cols-1 grid-rows-[minmax(220px,1fr)_auto] lg:grid-cols-[minmax(0,1fr)_320px] lg:grid-rows-[minmax(0,1fr)_280px]">
      <div className="flex min-h-[320px] flex-col border-b border-line lg:min-h-0 lg:border-r" data-tour="packets">
        <div className="pkt-head">
          <span>No.</span><span className="hide-sm">Time</span><span>Source</span><span className="hide-sm">Destination</span><span>Protocol</span><span className="hide-sm">Len</span><span>Info</span>
        </div>
        <div ref={parentRef} className="min-h-0 flex-1 overflow-auto">
          {rows.length === 0 ? (
            <p className="p-6 text-sm text-muted">No packets match this filter.</p>
          ) : (
            <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
              {virtualizer.getVirtualItems().map((item) => {
                const packet = rows[item.index];
                const sev = marks.get(packet.n);
                return (
                  <button
                    key={packet.n}
                    type="button"
                    className="pkt absolute left-0 top-0"
                    style={{ transform: `translateY(${item.start}px)` }}
                    data-selected={packet.n === selected}
                    data-sev={sev ?? ""}
                    onClick={() => onSelect(packet.n)}
                  >
                    <span className="cell">{packet.n}</span>
                    <span className="cell hide-sm">{(packet.ts - t0).toFixed(3)}</span>
                    <span className="cell" title={names[packet.src] ?? packet.src}>{labelIp(packet.src, names)}</span>
                    <span className="cell hide-sm" title={names[packet.dst] ?? packet.dst}>{labelIp(packet.dst, names)}</span>
                    <span className="cell">{packet.proto}</span>
                    <span className="cell hide-sm">{packet.len}</span>
                    <span className="cell">{packet.info}</span>
                  </button>
                );
              })}
            </div>
          )}
        </div>
      </div>
      <aside className="max-h-72 overflow-auto border-b border-line p-4 lg:max-h-none lg:border-r-0" data-tour="story">
        {story && row ? (
          <>
            <p className="text-xs uppercase tracking-[0.14em] text-muted">In plain language</p>
            <h2 className="mt-1 font-serif text-2xl italic">{story.title}</h2>
            <p className="mt-2 text-sm leading-relaxed">{story.body}</p>
            <div className="mt-3">
              <Button type="button" variant="solid" onClick={onFollow}>Follow this stream</Button>
            </div>
            {field && (
              <div className="mt-4 rounded-xl bg-raise p-3 text-sm">
                <p className="font-medium">{field.label}: {field.value}</p>
                <p className="mt-1 text-muted">{field.explain}</p>
                {field.filter && (
                  <div className="mt-2 flex gap-2">
                    <Button type="button" onClick={() => onFilter(field.filter ?? "", false)}>Filter on this</Button>
                    <Button type="button" variant="ghost" onClick={() => onFilter(field.filter ?? "", true)}>And…</Button>
                  </div>
                )}
              </div>
            )}
          </>
        ) : (
          <p className="text-sm text-muted">Select a packet. The note here is the plain-language version of that one frame.</p>
        )}
      </aside>
      <div className="min-h-52 overflow-auto border-t border-line p-2 lg:border-r lg:border-t" data-tour="decode">
        {tree.length === 0 ? <p className="p-3 text-sm text-muted">The decode tree opens when a packet is selected.</p> : tree.map((node, i) => (
          <TreeNodeView key={`${node.label}-${i}`} node={node} depth={0} active={field} onPick={onField} />
        ))}
      </div>
      <div className="min-h-40 overflow-auto border-t border-line p-3">
        {bytes ? <HexView bytes={bytes} field={field} onPick={(offset) => {
          const hit = deepest(tree, offset);
          if (hit) onField(hit);
        }} /> : <p className="text-sm text-muted">Hex and ASCII land here, with the selected field highlighted.</p>}
      </div>
    </div>
  );
}

function labelIp(ip: string, names: Record<string, string>): string {
  if (!ip) return "—";
  const name = names[ip];
  if (!name) return ip;
  const short = name.split(".")[0];
  return `${ip} ${short}`;
}

function TreeNodeView({ node, depth, active, onPick }: { node: TreeNode; depth: number; active: TreeNode | null; onPick: (node: TreeNode) => void }) {
  return (
    <div style={{ marginLeft: depth ? 12 : 0 }}>
      <button type="button" className="tree-row" data-on={active === node} onClick={() => onPick(node)} title={node.explain}>
        <span className="text-muted">{node.label}</span>
        <span className="truncate font-mono text-xs">{node.value}</span>
      </button>
      {node.children.map((child, i) => <TreeNodeView key={`${child.label}-${i}`} node={child} depth={depth + 1} active={active} onPick={onPick} />)}
    </div>
  );
}

function HexView({ bytes, field, onPick }: { bytes: Uint8Array; field: TreeNode | null; onPick: (offset: number) => void }) {
  const lines = useMemo(() => {
    const out: { off: number; bytes: number[] }[] = [];
    for (let i = 0; i < bytes.length; i += 16) out.push({ off: i, bytes: [...bytes.subarray(i, i + 16)] });
    return out;
  }, [bytes]);
  const on = (offset: number) => !!field && offset >= field.offset && offset < field.offset + Math.max(field.length, field.length === 0 ? 0 : field.length);
  return (
    <div>
      {lines.map((line) => (
        <div key={line.off} className="hex-row">
          <span className="text-faint">{line.off.toString(16).padStart(4, "0")}</span>
          <span className="hex-bytes">
            {line.bytes.map((b, i) => (
              <span key={line.off + i} data-on={on(line.off + i)} className="mr-1 cursor-pointer" onClick={() => onPick(line.off + i)}>
                {b.toString(16).padStart(2, "0")}
              </span>
            ))}
          </span>
          <span>
            {line.bytes.map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : ".")).join("")}
          </span>
        </div>
      ))}
    </div>
  );
}

function deepest(nodes: TreeNode[], offset: number): TreeNode | null {
  let best: TreeNode | null = null;
  const walk = (node: TreeNode) => {
    if (node.length > 0 && offset >= node.offset && offset < node.offset + node.length) {
      if (!best || node.length <= best.length) best = node;
    }
    node.children.forEach(walk);
  };
  nodes.forEach(walk);
  return best;
}
