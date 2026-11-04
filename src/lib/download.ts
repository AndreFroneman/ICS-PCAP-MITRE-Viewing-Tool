export function downloadText(name: string, body: string, type: string) {
  downloadBytes(name, new TextEncoder().encode(body), type);
}

export function downloadBytes(name: string, data: Uint8Array, type: string) {
  const copy = new Uint8Array(data.byteLength);
  copy.set(data);
  const url = URL.createObjectURL(new Blob([copy], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}
