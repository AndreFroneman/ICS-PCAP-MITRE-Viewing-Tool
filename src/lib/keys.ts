const MEMORY = "primer-api-keys";

function readLocal(): Record<string, string> {
  try {
    return JSON.parse(localStorage.getItem(MEMORY) ?? "{}") as Record<string, string>;
  } catch {
    return {};
  }
}

function inTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

export async function getKey(provider: string): Promise<string> {
  if (inTauri()) {
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      const value = await invoke<string>("key_get", { provider });
      if (value) return value;
    } catch {
      /* fall through to the browser store */
    }
  }
  return readLocal()[provider] ?? "";
}

export async function setKey(provider: string, secret: string): Promise<void> {
  if (inTauri()) {
    const { invoke } = await import("@tauri-apps/api/core");
    await invoke("key_set", { provider, secret });
    const local = readLocal();
    delete local[provider];
    localStorage.setItem(MEMORY, JSON.stringify(local));
    return;
  }
  const local = readLocal();
  if (secret) local[provider] = secret;
  else delete local[provider];
  localStorage.setItem(MEMORY, JSON.stringify(local));
}

export const SUGGESTED_CAPTURE_FOLDER = "C:\\Virtual Share\\Pcap";

export function rememberedFolder(): string {
  return localStorage.getItem("primer-capture-folder") || SUGGESTED_CAPTURE_FOLDER;
}

export function rememberFolder(path: string) {
  localStorage.setItem("primer-capture-folder", path);
}
