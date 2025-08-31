// main.js for IP Inspector
// Author: Cagatay URESIN (cagatayuresin@gmail.com)
// Project: https://cagatayuresin.github.io/ip-inspector
// All logic for IP & CIDR analysis and UI wiring

// =============================
//  Utility: IPv4 & CIDR logic
// =============================
// All code is plain JS; no build step; works on GitHub Pages.

function ipToInt(ip) {
  const parts = ip.trim().split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    if (!/^\d+$/.test(p)) return null;
    const v = Number(p);
    if (v < 0 || v > 255) return null;
    n = (n << 8) + v;
  }
  return n >>> 0;
}

function intToIp(n) {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(
    "."
  );
}

function prefixToMask(prefix) {
  if (prefix < 0 || prefix > 32) return null;
  if (prefix === 0) return 0 >>> 0;
  return (0xffffffff << (32 - prefix)) >>> 0;
}

function countIPs(prefix) {
  if (prefix < 0 || prefix > 32) return 0n;
  return 2n ** BigInt(32 - prefix);
}

function maskToString(mask) {
  return intToIp(mask);
}

function wildcardFromMask(mask) {
  return intToIp(~mask >>> 0);
}

function ipToBinary(ip) {
  const parts = ip.split(".").map((n) => Number(n));
  const bin = parts.map((v) => v.toString(2).padStart(8, "0")).join(".");
  return bin;
}

function addressClass(ip) {
  const first = Number(ip.split(".")[0]);
  if (first <= 127) return "A";
  if (first <= 191) return "B";
  if (first <= 223) return "C";
  if (first <= 239) return "D (Multicast)";
  return "E (Experimental)";
}

function isRFC1918(a, b) {
  if (a === 10) return "Private (RFC1918 10.0.0.0/8)";
  if (a === 172 && b >= 16 && b <= 31) return "Private (RFC1918 172.16.0.0/12)";
  if (a === 192 && b === 168) return "Private (RFC1918 192.168.0.0/16)";
  return null;
}

function isDocumentation(a, b, c) {
  if (a === 192 && b === 0 && c === 2)
    return "TEST-NET-1 (192.0.2.0/24, documentation)";
  if (a === 198 && (b === 51 || b === 18) && c === 100)
    return "TEST-NET-2/3 (198.51.100.0/24, documentation)";
  if (a === 203 && b === 0 && c === 113)
    return "TEST-NET-3 (203.0.113.0/24, documentation)";
  return null;
}

function isSpecial(a, b, c, d) {
  if (a === 127) return "Loopback (127.0.0.0/8)";
  if (a === 169 && b === 254) return "Link-Local (169.254.0.0/16)";
  if (a >= 224 && a <= 239) return "Multicast (224.0.0.0/4)";
  if (a === 255 && b === 255 && c === 255 && d === 255)
    return "Limited Broadcast";
  if (a === 0 && b === 0 && c === 0 && d === 0) return "Unspecified (0.0.0.0)";
  return null;
}

function rfcType(ip) {
  const [a, b, c, d] = ip.split(".").map(Number);
  const rfc1918 = isRFC1918(a, b);
  if (rfc1918) return rfc1918;
  const special = isSpecial(a, b, c, d);
  if (special) return special;
  const doc = isDocumentation(a, b, c);
  if (doc) return doc;
  return "Public";
}

function analyze(input) {
  const q = input.trim();
  const cidrMatch = q.match(/^\s*(\d+\.\d+\.\d+\.\d+)\s*\/\s*(\d{1,2})\s*$/);
  if (cidrMatch) {
    return analyzeCIDR(q, cidrMatch);
  }
  return analyzePlainIP(q);
}

function analyzeCIDR(q, cidrMatch) {
  const baseIp = cidrMatch[1];
  const prefix = Number(cidrMatch[2]);
  const baseInt = ipToInt(baseIp);
  const mask = prefixToMask(prefix);
  if (baseInt === null || mask === null) throw new Error("Invalid CIDR");
  const network = (baseInt & mask) >>> 0;
  const broadcast = (network | (~mask >>> 0)) >>> 0;
  const total = countIPs(prefix);
  let firstUsable = null,
    lastUsable = null,
    usableCount;
  if (prefix === 31) {
    firstUsable = network >>> 0;
    lastUsable = broadcast >>> 0;
    usableCount = 2n;
  } else if (prefix === 32) {
    firstUsable = network >>> 0;
    lastUsable = network >>> 0;
    usableCount = 1n;
  } else if (total >= 4n) {
    firstUsable = (network + 1) >>> 0;
    lastUsable = (broadcast - 1) >>> 0;
    usableCount = BigInt(
      Number((broadcast - 1) >>> 0) - Number((network + 1) >>> 0) + 1
    );
  } else {
    firstUsable = (network + 1) >>> 0;
    lastUsable = (broadcast - 1) >>> 0;
    usableCount = total >= 2n ? total - 2n : 0n;
  }
  const maskStr = maskToString(mask);
  const wildcard = wildcardFromMask(mask);
  return {
    kind: "cidr",
    query: q,
    ipClass: addressClass(intToIp(network)),
    rfcType: rfcType(baseIp),
    prefix,
    network: intToIp(network),
    broadcast: intToIp(broadcast),
    mask: maskStr,
    wildcard,
    totalIPs:
      typeof total === "bigint" || typeof total === "number"
        ? total.toString()
        : String(Number(total)),
    usableHosts: usableCount.toString(),
    firstUsable: intToIp(firstUsable),
    lastUsable: intToIp(lastUsable),
    suggestedGateway: prefix <= 30 ? intToIp(firstUsable) : intToIp(network),
    baseIPBinary: ipToBinary(baseIp),
    maskBinary: ipToBinary(maskStr),
  };
}

function analyzePlainIP(q) {
  const ipInt = ipToInt(q);
  if (ipInt === null) throw new Error("Invalid IP");
  const ipStr = intToIp(ipInt);
  const prefix = 24;
  const mask = prefixToMask(prefix);
  const network = (ipInt & mask) >>> 0;
  const broadcast = (network | (~mask >>> 0)) >>> 0;
  return {
    kind: "ip",
    query: ipStr,
    ipClass: addressClass(ipStr),
    rfcType: rfcType(ipStr),
    mask: maskToString(mask),
    wildcard: wildcardFromMask(mask),
    network: intToIp(network),
    broadcast: intToIp(broadcast),
    firstUsable: intToIp((network + 1) >>> 0),
    lastUsable: intToIp((broadcast - 1) >>> 0),
    baseIPBinary: ipToBinary(ipStr),
  };
}

// =============================
//  UI Wiring & Rendering
// =============================

document.addEventListener("DOMContentLoaded", function () {
  const qEl = document.getElementById("query");
  const analyzeBtn = document.getElementById("analyze");
  const resultWrap = document.getElementById("resultWrap");
  const grid = resultWrap.querySelector(".grid-cards");
  const exportBtn = document.getElementById("exportBtn");
  const copyBtn = document.getElementById("copyBtn");
  const statusMsg = document.getElementById("statusMsg");
  const HISTORY_KEY = "ip_inspector_history_v1";
  const historyList = document.getElementById("historyList");
  const clearHistoryBtn = document.getElementById("clearHistory");

  function card(label, value) {
    const el = document.createElement("div");
    el.className = "card glass animate-pop";
    el.innerHTML = `<div class="label">${label}</div><div class="value mono">${value}</div>`;
    return el;
  }

  function show(info) {
    grid.innerHTML = "";
    resultWrap.classList.remove("hidden");
    const parts = [];
    parts.push(card("Type", info.kind.toUpperCase()));
    parts.push(card("RFC/Scope", info.rfcType));
    parts.push(card("Class", info.ipClass));
    if (info.kind === "cidr") {
      parts.push(card("CIDR", info.query));
      parts.push(card("Network", info.network));
      parts.push(card("Broadcast", info.broadcast));
      parts.push(card("Mask", `${info.mask} /${info.prefix}`));
      parts.push(card("Wildcard", info.wildcard));
      parts.push(card("First usable", info.firstUsable));
      parts.push(card("Last usable", info.lastUsable));
      parts.push(card("Usable hosts", info.usableHosts));
      parts.push(card("Total IPs", info.totalIPs));
      parts.push(card("Suggested gateway", info.suggestedGateway));
      parts.push(card("IP (binary)", info.baseIPBinary));
      parts.push(card("Mask (binary)", info.maskBinary));
    } else {
      parts.push(card("IP", info.query));
      parts.push(card("Network (/24 heuristic)", info.network));
      parts.push(card("Broadcast (/24 heuristic)", info.broadcast));
      parts.push(card("Mask (/24)", info.mask));
      parts.push(card("Wildcard", info.wildcard));
      parts.push(card("First usable", info.firstUsable));
      parts.push(card("Last usable", info.lastUsable));
      parts.push(card("IP (binary)", info.baseIPBinary));
    }
    for (const p of parts) grid.appendChild(p);
  }

  function getHistory() {
    try {
      return JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
    } catch {
      return [];
    }
  }
  function setHistory(arr) {
    localStorage.setItem(HISTORY_KEY, JSON.stringify(arr.slice(0, 200)));
  }
  function addHistory(entry) {
    const h = getHistory();
    h.unshift({ q: entry, t: Date.now() });
    setHistory(h);
    renderHistory();
  }
  function renderHistory() {
    const h = getHistory();
    historyList.innerHTML = "";
    if (h.length === 0) {
      historyList.innerHTML =
        '<div class="text-neutral-500">No history yet.</div>';
      return;
    }
    for (const item of h) {
      const row = document.createElement("div");
      row.className =
        "flex items-center justify-between py-1 border-b border-transparent hover:border-[var(--line)]";
      const time = new Date(item.t).toLocaleString();
      row.innerHTML = `
        <div class="truncate max-w-[70%]"><span class="mono">${item.q}</span></div>
        <div class="flex items-center gap-2 text-neutral-400">
          <span class="hidden sm:inline">${time}</span>
          <button class="btn text-xs" title="Re-analyze"><i class="ti ti-refresh"></i></button>
        </div>`;
      row.querySelector("button").addEventListener("click", () => {
        qEl.value = item.q;
        handleAnalyze();
      });
      historyList.appendChild(row);
    }
  }
  clearHistoryBtn.addEventListener("click", () => {
    localStorage.removeItem(HISTORY_KEY);
    renderHistory();
  });
  function summarize(info) {
    const lines = [];
    lines.push(`IP Inspector Report`);
    lines.push(`Query: ${info.query}`);
    lines.push(`Kind: ${info.kind}`);
    lines.push(`RFC/Scope: ${info.rfcType}`);
    lines.push(`Class: ${info.ipClass}`);
    if (info.kind === "cidr") {
      lines.push(`Network: ${info.network}`);
      lines.push(`Broadcast: ${info.broadcast}`);
      lines.push(`Mask: ${info.mask} /${info.prefix}`);
      lines.push(`Wildcard: ${info.wildcard}`);
      lines.push(`First usable: ${info.firstUsable}`);
      lines.push(`Last usable: ${info.lastUsable}`);
      lines.push(`Usable hosts: ${info.usableHosts}`);
      lines.push(`Total IPs: ${info.totalIPs}`);
      lines.push(`Suggested gateway: ${info.suggestedGateway}`);
      lines.push(`IP (binary): ${info.baseIPBinary}`);
      lines.push(`Mask (binary): ${info.maskBinary}`);
    } else {
      lines.push(`IP: ${info.query}`);
      lines.push(`Network (/24 heuristic): ${info.network}`);
      lines.push(`Broadcast (/24 heuristic): ${info.broadcast}`);
      lines.push(`Mask (/24): ${info.mask}`);
      lines.push(`Wildcard: ${info.wildcard}`);
      lines.push(`First usable: ${info.firstUsable}`);
      lines.push(`Last usable: ${info.lastUsable}`);
      lines.push(`IP (binary): ${info.baseIPBinary}`);
    }
    return lines.join("\n");
  }
  function downloadTxt(filename, text) {
    const blob = new Blob([text], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }
  function handleAnalyze() {
    statusMsg.textContent = "";
    try {
      const info = analyze(qEl.value);
      show(info);
      addHistory(qEl.value.trim());
      statusMsg.textContent = "Analysis complete";
      setTimeout(() => (statusMsg.textContent = ""), 1600);
      exportBtn.onclick = () =>
        downloadTxt(`ip-inspector-${Date.now()}.txt`, summarize(info));
      copyBtn.onclick = async () => {
        try {
          await navigator.clipboard.writeText(summarize(info));
          statusMsg.textContent = "Copied to clipboard";
          setTimeout(() => (statusMsg.textContent = ""), 1400);
        } catch (e) {
          console.error("Clipboard copy failed:", e);
          statusMsg.textContent = "Copy failed";
          setTimeout(() => (statusMsg.textContent = ""), 1400);
        }
      };
      setTimeout(() => {
        const resultSection = document.getElementById("resultWrap");
        if (resultSection) {
          resultSection.scrollIntoView({ behavior: "smooth", block: "start" });
        }
      }, 100);
    } catch (e) {
      resultWrap.classList.remove("hidden");
      grid.innerHTML = "";
      grid.appendChild(card("Error", e.message));
    }
  }
  analyzeBtn.addEventListener("click", handleAnalyze);
  qEl.addEventListener("keydown", (e) => {
    if (e.key === "Enter") handleAnalyze();
  });
  renderHistory();
});

// =============================
//  Three.js background (generative)
// =============================
// Minimal particle field with gentle drift. Subtle, not distracting.

document.addEventListener("DOMContentLoaded", function () {
  const canvas = document.getElementById("bg3d");
  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(
    60,
    window.innerWidth / window.innerHeight,
    1,
    1000
  );
  camera.position.z = 60;
  const renderer = new THREE.WebGLRenderer({
    canvas,
    antialias: true,
    alpha: true,
  });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
  renderer.setSize(window.innerWidth, window.innerHeight);
  const COUNT = 1200;
  const geometry = new THREE.BufferGeometry();
  const positions = new Float32Array(COUNT * 3);
  for (let i = 0; i < COUNT; i++) {
    positions[i * 3 + 0] = (Math.random() - 0.5) * 160;
    positions[i * 3 + 1] = (Math.random() - 0.5) * 90;
    positions[i * 3 + 2] = (Math.random() - 0.5) * 120;
  }
  geometry.setAttribute("position", new THREE.BufferAttribute(positions, 3));
  const material = new THREE.PointsMaterial({
    size: 0.7,
    color: new THREE.Color(0.9, 0.22, 0.22),
    transparent: true,
    opacity: 0.7,
  });
  const points = new THREE.Points(geometry, material);
  scene.add(points);
  function animate() {
    requestAnimationFrame(animate);
    points.rotation.y += 0.0009;
    points.rotation.x += 0.0003;
    renderer.render(scene, camera);
  }
  animate();
  window.addEventListener("resize", () => {
    camera.aspect = window.innerWidth / window.innerHeight;
    camera.updateProjectionMatrix();
    renderer.setSize(window.innerWidth, window.innerHeight);
  });
});
