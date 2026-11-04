import type { AssetRecord } from "../lib/forensic.ts";
import { roleLabel } from "../lib/forensic.ts";

/**
 * Roles are hypotheses. The heading always says "likely".
 * Confidence is taken from the record. There is no control that strengthens it.
 */
export function AssetMap({ assets, onPacket }: { assets: AssetRecord[]; onPacket: (n: number) => void }) {
  if (!assets.length) return <p className="p-6 text-sm text-muted">No addresses with enough traffic to guess a role.</p>;
  return (
    <div className="grid gap-3 overflow-auto p-4 md:grid-cols-2">
      {assets.map((asset) => (
        <article key={asset.id} className="card p-4">
          <p className="font-mono text-[11px] tracking-[0.16em] text-muted">ROLE HYPOTHESIS · {asset.confidence.toUpperCase()} CONFIDENCE</p>
          <h3 className="display mt-2 text-2xl">{asset.role === "unknown" ? "No strong role" : `Likely ${roleLabel(asset.role)}`}</h3>
          <p className="mt-1 font-mono text-sm text-accent">{asset.ip}{asset.hostname ? ` · ${asset.hostname}` : ""}{asset.mac ? ` · ${asset.mac}` : ""}</p>
          <p className="mt-3 text-sm">{asset.hypothesis}</p>
          <p className="mt-2 text-sm text-muted">Also possible: {asset.alternateHypothesis}</p>
          <div className="mt-3 flex flex-wrap gap-2">
            {asset.evidence.map((item) => (
              <button key={`${asset.id}-${item.n}`} type="button" className="text-sm text-accent underline" onClick={() => onPacket(item.n)}>Packet {item.n}</button>
            ))}
          </div>
        </article>
      ))}
    </div>
  );
}
