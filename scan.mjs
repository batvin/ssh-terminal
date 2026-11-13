import net from "node:net";

function probe(ip, port, timeout) {
  return new Promise((resolve) => {
    const t0 = Date.now();
    const s = new net.Socket();
    let done = false;
    const finish = (open) => {
      if (done) return;
      done = true;
      try { s.destroy(); } catch {}
      resolve({ port, open, ms: Date.now() - t0 });
    };
    s.setTimeout(timeout);
    s.once("connect", () => finish(true));
    s.once("timeout", () => finish(false));
    s.once("error", () => finish(false));
    try { s.connect(port, ip); } catch { finish(false); }
  });
}

export async function scanPorts(ip, ports, timeout = 280, concurrency = 900) {
  const results = new Array(ports.length);
  let next = 0;
  const workers = Math.min(concurrency, ports.length);
  async function worker() {
    while (true) {
      const i = next++;
      if (i >= ports.length) return;
      results[i] = await probe(ip, ports[i], timeout);
    }
  }
  await Promise.all(Array.from({ length: workers }, worker));
  return results;
}
