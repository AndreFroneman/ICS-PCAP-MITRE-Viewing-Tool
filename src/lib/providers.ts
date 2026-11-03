import { TOOL_GUIDE, answerOffline, briefForModel, packetsFromReply, runTools, type AskAnswer, type AskContext } from "./ask.ts";
import { getKey } from "./keys.ts";

export type ProviderId = "offline" | "webllm" | "ollama" | "groq" | "gemini" | "openrouter" | "openai" | "anthropic" | "deepseek";

export const PROVIDERS: { id: ProviderId; label: string; cloud: boolean; hint: string }[] = [
  { id: "offline", label: "Offline analyst", cloud: false, hint: "No model. Answers come from the capture tools on this computer." },
  { id: "webllm", label: "In-browser model", cloud: false, hint: "Downloads a small instruct model once, then runs it with WebGPU. Nothing is uploaded." },
  { id: "ollama", label: "Ollama on this machine", cloud: false, hint: "Uses http://127.0.0.1:11434. Install Ollama separately and pull a model." },
  { id: "groq", label: "Groq", cloud: true, hint: "Free tier with your own key from console.groq.com." },
  { id: "gemini", label: "Google Gemini", cloud: true, hint: "Free tier with your own key from Google AI Studio." },
  { id: "openrouter", label: "OpenRouter", cloud: true, hint: "Free-model route with your own key. The model id can be changed." },
  { id: "openai", label: "OpenAI", cloud: true, hint: "API key from platform.openai.com. A ChatGPT login cannot be connected to this app." },
  { id: "anthropic", label: "Anthropic", cloud: true, hint: "API key from console.anthropic.com. A Claude account login cannot be connected to this app." },
  { id: "deepseek", label: "DeepSeek", cloud: true, hint: "API key from platform.deepseek.com." },
];

export interface ModelSettings {
  provider: ProviderId;
  ollamaModel: string;
  groqModel: string;
  geminiModel: string;
  openrouterModel: string;
  openaiModel: string;
  anthropicModel: string;
  deepseekModel: string;
  redact: boolean;
}

export const DEFAULT_SETTINGS: ModelSettings = {
  provider: "offline",
  ollamaModel: "llama3.2",
  groqModel: "llama-3.1-8b-instant",
  geminiModel: "gemini-2.0-flash",
  openrouterModel: "meta-llama/llama-3.2-3b-instruct:free",
  openaiModel: "gpt-4o-mini",
  anthropicModel: "claude-3-5-haiku-latest",
  deepseekModel: "deepseek-chat",
  redact: true,
};

const SETTINGS_KEY = "primer-model-settings";

export function loadSettings(): ModelSettings {
  try {
    const raw = localStorage.getItem(SETTINGS_KEY);
    return raw ? { ...DEFAULT_SETTINGS, ...JSON.parse(raw) as Partial<ModelSettings> } : { ...DEFAULT_SETTINGS };
  } catch {
    return { ...DEFAULT_SETTINGS };
  }
}

export function saveSettings(settings: ModelSettings) {
  localStorage.setItem(SETTINGS_KEY, JSON.stringify(settings));
}

export async function askCapture(
  question: string,
  ctx: AskContext,
  settings: ModelSettings,
  onProgress?: (text: string) => void,
): Promise<AskAnswer> {
  const results = runTools(question, ctx);
  const offline = answerOffline(question, ctx);
  if (settings.provider === "offline") return offline;
  onProgress?.("Asking the model to explain the tool results");
  try {
    const brief = briefForModel(question, ctx, results, settings.redact || PROVIDERS.find((p) => p.id === settings.provider)?.cloud === true && settings.redact);
    const reply = await complete(settings, [
      { role: "system", content: TOOL_GUIDE },
      { role: "user", content: brief },
    ], onProgress);
    const packets = packetsFromReply(reply, offline.packets);
    const cleaned = reply.replace(/\nPackets:.*$/i, "").trim();
    return {
      text: cleaned || offline.text,
      packets: packets.length ? packets : offline.packets,
      tools: offline.tools,
      provider: settings.provider,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : "The model call failed.";
    return { ...offline, text: `${offline.text}\n\nThe ${settings.provider} model was not used: ${message}`, provider: "offline" };
  }
}

async function complete(settings: ModelSettings, messages: { role: string; content: string }[], onProgress?: (text: string) => void): Promise<string> {
  if (settings.provider === "webllm") return webllm(messages, onProgress);
  if (settings.provider === "ollama") return ollama(settings.ollamaModel, messages);
  const key = await getKey(settings.provider);
  if (!key) throw new Error("Add an API key in settings first.");
  if (settings.provider === "groq") return openaiCompatible("https://api.groq.com/openai/v1/chat/completions", key, settings.groqModel, messages);
  if (settings.provider === "openrouter") return openaiCompatible("https://openrouter.ai/api/v1/chat/completions", key, settings.openrouterModel, messages);
  if (settings.provider === "openai") return openaiCompatible("https://api.openai.com/v1/chat/completions", key, settings.openaiModel, messages);
  if (settings.provider === "deepseek") return openaiCompatible("https://api.deepseek.com/chat/completions", key, settings.deepseekModel, messages);
  if (settings.provider === "gemini") return gemini(key, settings.geminiModel, messages);
  if (settings.provider === "anthropic") return anthropic(key, settings.anthropicModel, messages);
  throw new Error("Choose a provider in settings.");
}

async function cloudFetch(url: string, init: RequestInit): Promise<Response> {
  const tauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
  if (tauri) {
    const mod = await import("@tauri-apps/plugin-http");
    return mod.fetch(url, init);
  }
  return fetch(url, init);
}

async function openaiCompatible(url: string, key: string, model: string, messages: { role: string; content: string }[]): Promise<string> {
  const res = await cloudFetch(url, {
    method: "POST",
    headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
    body: JSON.stringify({ model, temperature: 0.2, messages }),
  });
  if (!res.ok) throw new Error(await trimError(res));
  const json = await res.json() as { choices?: { message?: { content?: string } }[] };
  return json.choices?.[0]?.message?.content ?? "";
}

async function gemini(key: string, model: string, messages: { role: string; content: string }[]): Promise<string> {
  const res = await cloudFetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${encodeURIComponent(key)}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      systemInstruction: { parts: [{ text: messages[0]?.content ?? "" }] },
      contents: messages.filter((m) => m.role !== "system").map((m) => ({ role: "user", parts: [{ text: m.content }] })),
    }),
  });
  if (!res.ok) throw new Error(await trimError(res));
  const json = await res.json() as { candidates?: { content?: { parts?: { text?: string }[] } }[] };
  return json.candidates?.[0]?.content?.parts?.map((p) => p.text ?? "").join("") ?? "";
}

async function anthropic(key: string, model: string, messages: { role: string; content: string }[]): Promise<string> {
  const res = await cloudFetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "x-api-key": key,
      "anthropic-version": "2023-06-01",
      "content-type": "application/json",
    },
    body: JSON.stringify({
      model,
      max_tokens: 900,
      system: messages.find((m) => m.role === "system")?.content ?? "",
      messages: messages.filter((m) => m.role !== "system").map((m) => ({ role: "user", content: m.content })),
    }),
  });
  if (!res.ok) throw new Error(await trimError(res));
  const json = await res.json() as { content?: { text?: string }[] };
  return json.content?.map((c) => c.text ?? "").join("") ?? "";
}

async function ollama(model: string, messages: { role: string; content: string }[]): Promise<string> {
  const res = await cloudFetch("http://127.0.0.1:11434/api/chat", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ model, stream: false, messages }),
  });
  if (!res.ok) throw new Error("Ollama did not answer. Is it running on this machine?");
  const json = await res.json() as { message?: { content?: string } };
  return json.message?.content ?? "";
}

type LocalEngine = {
  chat: {
    completions: {
      create: (req: { messages: { role: "system" | "user"; content: string }[]; temperature: number }) => Promise<{ choices: { message?: { content?: string | null } }[] }>;
    };
  };
};

let enginePromise: Promise<LocalEngine> | null = null;

async function webllm(messages: { role: string; content: string }[], onProgress?: (text: string) => void): Promise<string> {
  if (!enginePromise) {
    onProgress?.("Loading the in-browser model runtime");
    const webllm = await import("@mlc-ai/web-llm");
    enginePromise = webllm.CreateMLCEngine("Qwen2.5-0.5B-Instruct-q4f16_1-MLC", {
      initProgressCallback: (report) => onProgress?.(report.text || `Downloading model ${Math.round((report.progress ?? 0) * 100)}%`),
    }) as Promise<LocalEngine>;
  }
  const engine = await enginePromise;
  const typed = messages.map((message) => ({
    role: message.role === "system" ? "system" as const : "user" as const,
    content: message.content,
  }));
  const reply = await engine.chat.completions.create({ messages: typed, temperature: 0.2 });
  return reply.choices[0]?.message?.content ?? "";
}

async function trimError(res: Response): Promise<string> {
  const text = await res.text();
  return `${res.status} ${text.slice(0, 180)}`;
}
