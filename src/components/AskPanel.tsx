import { useState } from "react";
import { answerOffline, briefForModel, runTools, type AskAnswer, type AskContext } from "../lib/ask.ts";
import { PROVIDERS, askCapture, loadSettings } from "../lib/providers.ts";
import { Button } from "./ui.tsx";

interface Turn { role: "user" | "primer"; text: string; packets: number[]; provider?: string }

export function AskPanel({ ctx, onPacket }: { ctx: AskContext; onPacket: (n: number) => void }) {
  const [question, setQuestion] = useState("");
  const [turns, setTurns] = useState<Turn[]>([]);
  const [busy, setBusy] = useState("");
  const [consent, setConsent] = useState<string | null>(null);
  const [pending, setPending] = useState<string>("");
  const settings = loadSettings();

  const ask = async (text: string, approved = false) => {
    const q = text.trim();
    if (!q || busy) return;
    const provider = PROVIDERS.find((item) => item.id === settings.provider);
    if (provider?.cloud && !approved) {
      setPending(q);
      setConsent(briefForModel(q, ctx, runTools(q, ctx), settings.redact));
      return;
    }
    setTurns((list) => [...list, { role: "user", text: q, packets: [] }]);
    setQuestion("");
    setBusy(settings.provider === "webllm" ? "Preparing the local model" : "Reading the capture");
    const answer: AskAnswer = settings.provider === "offline"
      ? answerOffline(q, ctx)
      : await askCapture(q, ctx, settings, setBusy);
    setTurns((list) => [...list, { role: "primer", text: answer.text, packets: answer.packets, provider: answer.provider }]);
    setBusy("");
  };

  return (
    <div className="flex min-h-0 flex-1 flex-col" data-tour="ask">
      <div className="border-b border-line px-4 py-3">
        <p className="eyebrow">Ask your capture</p>
        <p className="mt-2 max-w-3xl text-sm text-muted">Questions are answered from the parsed packets and findings, with the packet numbers attached. The default analyst stays on this computer. A model, if you turn one on, only sees the tool summary — never the raw capture.</p>
      </div>
      <div className="flex flex-wrap gap-2 px-4 py-3">
        {["Which devices wrote to the PLC?", "Anything that looks like C2?", "Were any passwords visible?", "What did the port scan touch?"].map((prompt) => (
          <button key={prompt} type="button" className="chip-pkt" onClick={() => void ask(prompt)}>{prompt}</button>
        ))}
      </div>
      <div className="chat-log min-h-0 flex-1 overflow-auto px-4 pb-4">
        {turns.length === 0 && <p className="text-sm text-muted">No question yet. The capture is already loaded, so the tools can answer without a model.</p>}
        {turns.map((turn, index) => (
          <div key={index} className={`bubble ${turn.role === "user" ? "user" : ""}`}>
            <p className="text-xs uppercase tracking-[0.16em] text-muted">{turn.role === "user" ? "You" : `Primer · ${turn.provider ?? "offline"}`}</p>
            <p className="mt-1 whitespace-pre-wrap text-sm">{turn.text}</p>
            {turn.packets.length > 0 && (
              <div className="mt-2 flex flex-wrap gap-2">
                {turn.packets.slice(0, 18).map((n) => (
                  <button key={n} type="button" className="chip-pkt" onClick={() => onPacket(n)}>Packet {n}</button>
                ))}
              </div>
            )}
          </div>
        ))}
        {busy && (
          <div className="bubble">
            <p className="text-sm text-accent">{busy}</p>
            <div className="mt-2 h-1 overflow-hidden bg-line"><div className="h-full w-1/2 animate-pulse bg-accent" /></div>
          </div>
        )}
      </div>
      <form className="flex gap-2 border-t border-line p-3" onSubmit={(event) => { event.preventDefault(); void ask(question); }}>
        <input value={question} onChange={(event) => setQuestion(event.target.value)} placeholder="Ask in plain English" className="hz-field min-w-0 flex-1" aria-label="Question about this capture" />
        <Button type="submit" variant="solid" disabled={!!busy}>Ask</Button>
      </form>
      {consent && (
        <div className="fixed inset-0 z-40 grid place-items-center bg-black/70 p-4">
          <div className="card max-h-[80dvh] w-[min(720px,100%)] overflow-auto p-5">
            <span className="corner tl" /><span className="corner br" />
            <p className="eyebrow">Before this leaves the machine</p>
            <h2 className="display mt-3 text-2xl">This is the exact summary that will be sent</h2>
            <p className="mt-2 text-sm text-muted">It is not the capture file. Addresses are {settings.redact ? "replaced with host-1, host-2…" : "included, because redaction is off in settings"}.</p>
            <pre className="mt-3 max-h-72 overflow-auto whitespace-pre-wrap font-mono text-xs text-muted">{consent}</pre>
            <div className="mt-4 flex gap-2">
              <Button type="button" variant="solid" onClick={() => { const q = pending; setConsent(null); void ask(q, true); }}>Send this</Button>
              <Button type="button" onClick={() => setConsent(null)}>Cancel</Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
