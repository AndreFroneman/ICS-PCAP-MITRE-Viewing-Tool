import { useEffect, useState } from "react";
import { getKey, rememberedFolder, rememberFolder, setKey, SUGGESTED_CAPTURE_FOLDER } from "../lib/keys.ts";
import { DEFAULT_SETTINGS, PROVIDERS, loadSettings, saveSettings, type ModelSettings, type ProviderId } from "../lib/providers.ts";
import { Button, Modal } from "./ui.tsx";

const CLOUD: ProviderId[] = ["groq", "gemini", "openrouter", "openai", "anthropic", "deepseek"];

export function SettingsDialog({ open, onClose, onOpenFolder }: { open: boolean; onClose: () => void; onOpenFolder: () => void }) {
  const [settings, setSettings] = useState<ModelSettings>(DEFAULT_SETTINGS);
  const [keys, setKeys] = useState<Record<string, string>>({});
  const [folder, setFolder] = useState(SUGGESTED_CAPTURE_FOLDER);
  const [note, setNote] = useState("");

  useEffect(() => {
    if (!open) return;
    setSettings(loadSettings());
    setFolder(rememberedFolder());
    void Promise.all(CLOUD.map(async (id) => [id, await getKey(id)] as const)).then((pairs) => {
      setKeys(Object.fromEntries(pairs));
    });
  }, [open]);

  const save = async () => {
    saveSettings(settings);
    rememberFolder(folder);
    for (const id of CLOUD) {
      if (keys[id] !== undefined) await setKey(id, keys[id] ?? "");
    }
    setNote(inDesktop() ? "Saved. API keys went to the operating-system keychain." : "Saved in this browser only. They are not sent anywhere until you approve a question.");
  };

  return (
    <Modal open={open} onOpenChange={(next) => !next && onClose()} title="Settings" wide>
      <p className="text-sm text-muted">ChatGPT and Claude sign-in cannot be connected here. Those products do not offer consumer login to third-party apps. Use an API key from the provider's own console. Keys stay on this computer.</p>
      <label className="mt-4 block text-xs uppercase tracking-[0.16em] text-muted">Answer with</label>
      <select className="hz-field mt-2 w-full" value={settings.provider} onChange={(event) => setSettings({ ...settings, provider: event.target.value as ProviderId })}>
        {PROVIDERS.map((item) => <option key={item.id} value={item.id}>{item.label}</option>)}
      </select>
      <p className="mt-2 text-sm text-muted">{PROVIDERS.find((item) => item.id === settings.provider)?.hint}</p>
      <label className="mt-4 flex items-center gap-2 text-sm">
        <input type="checkbox" checked={settings.redact} onChange={(event) => setSettings({ ...settings, redact: event.target.checked })} />
        Redact IP and MAC addresses before a cloud call
      </label>
      <div className="mt-4 grid gap-3 md:grid-cols-2">
        <Field label="Ollama model" value={settings.ollamaModel} onChange={(ollamaModel) => setSettings({ ...settings, ollamaModel })} />
        <Field label="Groq model" value={settings.groqModel} onChange={(groqModel) => setSettings({ ...settings, groqModel })} />
        <Field label="Gemini model" value={settings.geminiModel} onChange={(geminiModel) => setSettings({ ...settings, geminiModel })} />
        <Field label="OpenRouter model" value={settings.openrouterModel} onChange={(openrouterModel) => setSettings({ ...settings, openrouterModel })} />
        <Field label="OpenAI model" value={settings.openaiModel} onChange={(openaiModel) => setSettings({ ...settings, openaiModel })} />
        <Field label="Anthropic model" value={settings.anthropicModel} onChange={(anthropicModel) => setSettings({ ...settings, anthropicModel })} />
      </div>
      <div className="mt-4 grid gap-3">
        {CLOUD.map((id) => (
          <Field key={id} label={`${id} API key`} value={keys[id] ?? ""} secret onChange={(value) => setKeys({ ...keys, [id]: value })} />
        ))}
      </div>
      <div className="mt-5 border-t border-line pt-4">
        <p className="eyebrow">Capture folder</p>
        <p className="mt-2 text-sm text-muted">On Windows the suggested default is {SUGGESTED_CAPTURE_FOLDER}. Primer remembers the last folder you choose. The web app can only open a folder you pick; the desktop app can list it.</p>
        <input className="hz-field mt-2 w-full font-mono text-sm" value={folder} onChange={(event) => setFolder(event.target.value)} aria-label="Default capture folder" />
        <Button type="button" className="mt-2" onClick={onOpenFolder}>Open folder</Button>
      </div>
      <div className="mt-4 flex items-center gap-3">
        <Button type="button" variant="solid" onClick={() => void save()}>Save</Button>
        {note && <p className="text-sm text-good">{note}</p>}
      </div>
    </Modal>
  );
}

function Field({ label, value, onChange, secret = false }: { label: string; value: string; onChange: (value: string) => void; secret?: boolean }) {
  return (
    <label className="block text-sm">
      <span className="text-xs uppercase tracking-[0.14em] text-muted">{label}</span>
      <input className="hz-field mt-1 w-full" type={secret ? "password" : "text"} value={value} autoComplete="off" onChange={(event) => onChange(event.target.value)} />
    </label>
  );
}

function inDesktop(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}
