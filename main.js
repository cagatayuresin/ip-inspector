"use strict";

// IPv4 and CIDR math for IP Inspector. No network access. Safe to require() from Node.

const PUBLIC_SCOPE = {
  name: "Global unicast",
  rfc: "",
  cidr: "",
  mixed: false,
};

const RANGE_DEFS = [
  ["0.0.0.0/32", "Unspecified", "RFC 1122"],
  ["0.0.0.0/8", "This network", "RFC 1122"],
  ["10.0.0.0/8", "Private", "RFC 1918"],
  ["100.64.0.0/10", "Shared (CGNAT)", "RFC 6598"],
  ["127.0.0.0/8", "Loopback", "RFC 1122"],
  ["169.254.0.0/16", "Link-local", "RFC 3927"],
  ["172.16.0.0/12", "Private", "RFC 1918"],
  ["192.0.0.0/24", "IETF protocol assignments", "RFC 6890"],
  ["192.0.2.0/24", "Documentation (TEST-NET-1)", "RFC 5737"],
  ["192.88.99.0/24", "6to4 anycast (deprecated)", "RFC 7526"],
  ["192.168.0.0/16", "Private", "RFC 1918"],
  ["198.18.0.0/15", "Benchmarking", "RFC 2544"],
  ["198.51.100.0/24", "Documentation (TEST-NET-2)", "RFC 5737"],
  ["203.0.113.0/24", "Documentation (TEST-NET-3)", "RFC 5737"],
  ["224.0.0.0/4", "Multicast", "RFC 1112"],
  ["240.0.0.0/4", "Reserved", "RFC 1112"],
  ["255.255.255.255/32", "Limited broadcast", "RFC 919"],
];

const ROLE_LABEL = {
  host: "Usable host",
  network: "Network address",
  broadcast: "Broadcast address",
  "point-to-point": "Point-to-point",
  "host-route": "Host route",
};

function prefixToMask(prefix) {
  // JavaScript shift counts are taken modulo 32, so `<< 32` becomes `<< 0`.
  if (prefix === 0) return 0;
  return (0xffffffff << (32 - prefix)) >>> 0;
}

function intToIp(n) {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
}

function parseOctets(text) {
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(text)) return null;
  const parts = text.split(".");
  const octets = [];
  for (const part of parts) {
    const value = Number(part);
    if (!Number.isInteger(value) || value > 255) return null;
    octets.push(value);
  }
  return octets;
}

function octetsToInt(octets) {
  return ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
}

function dottedBinary(ipInt) {
  const bits = ipInt.toString(2).padStart(32, "0");
  return [0, 8, 16, 24].map((index) => bits.slice(index, index + 8)).join(".");
}

function addressClass(ipInt) {
  const first = ipInt >>> 24;
  if (first <= 127) return "A";
  if (first <= 191) return "B";
  if (first <= 223) return "C";
  if (first <= 239) return "D";
  return "E";
}

function expandRange(def) {
  const [cidr, name, rfc] = def;
  const slash = cidr.indexOf("/");
  const prefix = Number(cidr.slice(slash + 1));
  const ipInt = octetsToInt(parseOctets(cidr.slice(0, slash)));
  const mask = prefixToMask(prefix);
  const start = (ipInt & mask) >>> 0;
  return {
    name,
    rfc,
    cidr,
    prefix,
    start,
    end: (start | (~mask >>> 0)) >>> 0,
    mixed: false,
  };
}

const RANGES = RANGE_DEFS.map(expandRange);

function scopeOfAddress(ipInt) {
  let best = null;
  for (const range of RANGES) {
    if (ipInt < range.start || ipInt > range.end) continue;
    if (!best || range.prefix > best.prefix) best = range;
  }
  if (!best) return { name: PUBLIC_SCOPE.name, rfc: "", cidr: "", mixed: false };
  return { name: best.name, rfc: best.rfc, cidr: best.cidr, mixed: false };
}

function scopeOfBlock(start, end) {
  let best = null;
  for (const range of RANGES) {
    if (start < range.start || end > range.end) continue;
    if (!best || range.prefix > best.prefix) best = range;
  }
  if (best) return { name: best.name, rfc: best.rfc, cidr: best.cidr, mixed: false };
  for (const range of RANGES) {
    if (start <= range.end && end >= range.start) {
      return { name: "Mixed scopes", rfc: "", cidr: "", mixed: true };
    }
  }
  return { name: PUBLIC_SCOPE.name, rfc: "", cidr: "", mixed: false };
}

function buildSubnet(ipInt, prefix) {
  const mask = prefixToMask(prefix);
  const network = (ipInt & mask) >>> 0;
  const broadcast = (network | (~mask >>> 0)) >>> 0;
  const total = 1n << BigInt(32 - prefix);
  const usable = prefix >= 31 ? total : total - 2n;
  let role = "host";
  if (prefix === 32) role = "host-route";
  else if (prefix === 31) role = "point-to-point";
  else if (ipInt === network) role = "network";
  else if (ipInt === broadcast) role = "broadcast";

  return {
    prefix,
    canonical: intToIp(network) + "/" + prefix,
    network: intToIp(network),
    broadcast: prefix >= 31 ? null : intToIp(broadcast),
    mask: intToIp(mask),
    wildcard: intToIp(~mask >>> 0),
    firstUsable: intToIp(prefix >= 31 ? network : (network + 1) >>> 0),
    lastUsable: intToIp(prefix === 32 ? network : prefix === 31 ? broadcast : (broadcast - 1) >>> 0),
    usableHosts: usable.toString(),
    totalAddresses: total.toString(),
    role,
    blockScope: scopeOfBlock(network, broadcast),
    gateway: prefix <= 30 ? intToIp((network + 1) >>> 0) : null,
    maskBinary: dottedBinary(mask),
    addressBits: ipInt.toString(2).padStart(32, "0"),
    maskBits: mask.toString(2).padStart(32, "0"),
  };
}

function analyze(input) {
  const raw = String(input == null ? "" : input).trim();
  if (!raw) {
    throw new Error("Enter an IPv4 address or a CIDR block.");
  }
  if (raw.includes(":")) {
    throw new Error("IPv6 is not supported. Enter an IPv4 address or CIDR block.");
  }

  const match = raw.match(/^(\d{1,3}(?:\.\d{1,3}){3})(?:\s*\/\s*(\d{1,2}))?$/);
  if (!match) {
    throw new Error("That is not a valid IPv4 address or CIDR block.");
  }

  const octets = parseOctets(match[1]);
  if (!octets) {
    throw new Error("That is not a valid IPv4 address.");
  }

  let prefix = null;
  if (match[2] !== undefined) {
    prefix = Number(match[2]);
    if (prefix > 32) {
      throw new Error("The prefix must be an integer from 0 to 32.");
    }
  }

  const ipInt = octetsToInt(octets);
  const address = intToIp(ipInt);
  const hadPrefix = prefix !== null;

  return {
    input: raw,
    normalized: hadPrefix ? address + "/" + prefix : address,
    address,
    hadPrefix,
    integer: String(ipInt),
    hex: "0x" + ipInt.toString(16).toUpperCase().padStart(8, "0"),
    reverseDns: address.split(".").reverse().join(".") + ".in-addr.arpa",
    className: addressClass(ipInt),
    scope: scopeOfAddress(ipInt),
    binary: dottedBinary(ipInt),
    addressBits: ipInt.toString(2).padStart(32, "0"),
    typedAddress: match[1],
    subnet: hadPrefix ? buildSubnet(ipInt, prefix) : null,
  };
}

function plural(count, word) {
  return count + " " + word + (count === 1 ? "" : "s");
}

function scopeLabel(scope) {
  return scope.rfc ? scope.name + " · " + scope.rfc : scope.name;
}

function scopeHint(scope) {
  if (scope.mixed) return "This block covers more than one kind of address.";
  if (scope.cidr) return scope.cidr;
  return "No special-purpose reservation.";
}

function classHint(name) {
  if (name === "D") return "Multicast. Classful routing does not apply.";
  if (name === "E") return "Reserved. Classful routing does not apply.";
  return "Obsolete for routing. Informational only.";
}

function pushCard(cards, label, value, hint, extra) {
  if (value === null || value === undefined) return;
  cards.push({
    label,
    value: String(value),
    hint: hint || "",
    wide: Boolean(extra && extra.wide),
    bits: (extra && extra.bits) || null,
  });
}

function present(info) {
  const addressCards = [];
  const typedDiffers = info.typedAddress !== info.address;
  pushCard(
    addressCards,
    "Address",
    info.address,
    typedDiffers ? "Normalized from " + info.typedAddress : ""
  );
  pushCard(addressCards, "Scope", scopeLabel(info.scope), scopeHint(info.scope));
  pushCard(addressCards, "Class", info.className, classHint(info.className));
  pushCard(addressCards, "Integer", info.integer, "32-bit unsigned");
  pushCard(addressCards, "Hexadecimal", info.hex, "");
  pushCard(addressCards, "Reverse DNS", info.reverseDns, "");

  const groups = [{ title: "Address", note: "", cards: addressCards }];
  const subnet = info.subnet;

  if (subnet) {
    const cards = [];
    let note = "";
    if (subnet.prefix === 31) {
      note =
        "Point-to-point link (RFC 3021). Both addresses are usable, and there is no broadcast address.";
    } else if (subnet.prefix === 32) {
      note = "Host route. One address, with no separate network or broadcast.";
    }

    pushCard(cards, "Network CIDR", subnet.canonical, "");
    pushCard(cards, "Role", ROLE_LABEL[subnet.role], "");
    pushCard(
      cards,
      "Prefix",
      "/" + subnet.prefix,
      plural(subnet.prefix, "network bit") + ", " + plural(32 - subnet.prefix, "host bit")
    );
    if (subnet.blockScope.mixed || subnet.blockScope.name !== info.scope.name) {
      pushCard(cards, "Block scope", scopeLabel(subnet.blockScope), scopeHint(subnet.blockScope));
    }
    pushCard(cards, "Network", subnet.network, "");
    pushCard(cards, "Broadcast", subnet.broadcast, "");
    pushCard(cards, "Netmask", subnet.mask, "");
    pushCard(cards, "Wildcard", subnet.wildcard, "");
    pushCard(cards, "First usable", subnet.firstUsable, "");
    if (subnet.prefix < 32) pushCard(cards, "Last usable", subnet.lastUsable, "");
    pushCard(cards, "Usable hosts", subnet.usableHosts, "");
    pushCard(cards, "Total addresses", subnet.totalAddresses, "");
    pushCard(
      cards,
      "Typical gateway",
      subnet.gateway,
      "Usually the first usable address. The protocol does not require it."
    );

    groups.push({ title: "Subnet", note, cards });
  }

  const bitPrefix = subnet ? subnet.prefix : null;
  const binaryCards = [];
  let binaryNote = "";
  if (bitPrefix === null) binaryNote = "";
  else if (bitPrefix === 32) binaryNote = "All 32 bits identify this address.";
  else binaryNote = "Red digits are the host bits.";

  pushCard(binaryCards, "Address bits", info.binary, "", {
    wide: true,
    bits: { text: info.addressBits, prefix: bitPrefix },
  });
  if (subnet) {
    pushCard(binaryCards, "Netmask bits", subnet.maskBinary, "", {
      wide: true,
      bits: { text: subnet.maskBits, prefix: bitPrefix },
    });
  }
  groups.push({ title: "Binary", note: binaryNote, cards: binaryCards });

  return {
    normalized: info.normalized,
    address: info.address,
    groups,
  };
}

function summarize(view) {
  const lines = ["IP Inspector", "Query: " + view.normalized, ""];
  for (const group of view.groups) {
    lines.push(group.title);
    if (group.note) lines.push(group.note);
    for (const card of group.cards) {
      lines.push(card.label + ": " + card.value);
      if (card.hint) lines.push("  " + card.hint);
    }
    lines.push("");
  }
  return lines.join("\n").trim() + "\n";
}

const HISTORY_KEY = "ip_inspector_history_v1";
const HISTORY_LIMIT = 200;

function init() {
  const form = document.getElementById("inspect-form");
  const input = document.getElementById("query");
  const errorEl = document.getElementById("form-error");
  const results = document.getElementById("results");
  const resultRoot = document.getElementById("result-root");
  const exportBtn = document.getElementById("export-btn");
  const copyBtn = document.getElementById("copy-btn");
  const statusEl = document.getElementById("status");
  const historyList = document.getElementById("history-list");
  const historyCount = document.getElementById("history-count");
  const clearBtn = document.getElementById("clear-history");
  const clearLabel = document.getElementById("clear-label");
  const examples = document.getElementById("examples");

  let statusTimer = 0;
  let clearTimer = 0;
  let clearArmed = false;
  let currentView = null;

  function setStatus(message) {
    statusEl.textContent = message;
    window.clearTimeout(statusTimer);
    if (!message) return;
    statusTimer = window.setTimeout(function () {
      statusEl.textContent = "";
    }, 1600);
  }

  function resetClear() {
    clearArmed = false;
    clearLabel.textContent = "Clear";
    window.clearTimeout(clearTimer);
  }

  function showError(message) {
    errorEl.textContent = message;
    input.setAttribute("aria-invalid", "true");
    results.hidden = true;
    resultRoot.replaceChildren();
    document.body.classList.remove("has-results");
    currentView = null;
  }

  function clearError() {
    errorEl.textContent = "";
    input.setAttribute("aria-invalid", "false");
  }

  async function copyText(text) {
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
        return true;
      }
    } catch (err) {
      // Fall through to the textarea path for insecure contexts and denied permissions.
    }
    try {
      const area = document.createElement("textarea");
      area.value = text;
      area.setAttribute("readonly", "");
      area.style.position = "fixed";
      area.style.left = "-9999px";
      document.body.appendChild(area);
      area.select();
      const ok = document.execCommand("copy");
      area.remove();
      return ok;
    } catch (err) {
      return false;
    }
  }

  function icon(id) {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("class", "icon");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("aria-hidden", "true");
    const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
    use.setAttribute("href", "#" + id);
    svg.appendChild(use);
    return svg;
  }

  function bitsNode(bits) {
    const wrap = document.createElement("p");
    wrap.className = "bits";
    const groups = [];
    for (let octet = 0; octet < 4; octet += 1) {
      const group = document.createElement("span");
      group.className = "octet";
      for (let bit = 0; bit < 8; bit += 1) {
        const index = octet * 8 + bit;
        const digit = document.createElement("span");
        const isHost = bits.prefix !== null && bits.prefix < 32 && index >= bits.prefix;
        digit.className = isHost ? "bit bit-host" : "bit";
        digit.textContent = bits.text[index];
        group.appendChild(digit);
      }
      groups.push(group);
    }
    wrap.setAttribute("role", "img");
    wrap.setAttribute(
      "aria-label",
      groups.map((group) => group.textContent).join(".")
    );
    groups.forEach(function (group, index) {
      if (index > 0) {
        const dot = document.createElement("span");
        dot.className = "bit-dot";
        dot.setAttribute("aria-hidden", "true");
        dot.textContent = ".";
        wrap.appendChild(dot);
      }
      group.setAttribute("aria-hidden", "true");
      wrap.appendChild(group);
    });
    return wrap;
  }

  function renderCard(card) {
    const article = document.createElement("article");
    article.className = card.wide ? "card card-wide" : "card";

    const top = document.createElement("div");
    top.className = "card-top";
    const heading = document.createElement("h3");
    heading.className = "label";
    heading.textContent = card.label;
    const copy = document.createElement("button");
    copy.type = "button";
    copy.className = "card-copy";
    copy.setAttribute("aria-label", "Copy " + card.label);
    copy.appendChild(icon("i-clipboard"));
    copy.addEventListener("click", async function () {
      const ok = await copyText(card.value);
      setStatus(ok ? "Copied " + card.label.toLowerCase() : "Copy failed");
    });
    top.append(heading, copy);

    const value = document.createElement("div");
    value.className = "value";
    if (card.bits) value.appendChild(bitsNode(card.bits));
    else value.textContent = card.value;

    article.append(top, value);
    if (card.hint) {
      const hint = document.createElement("p");
      hint.className = "hint";
      hint.textContent = card.hint;
      article.appendChild(hint);
    }
    return article;
  }

  function render(view) {
    resultRoot.replaceChildren();
    for (const group of view.groups) {
      const section = document.createElement("section");
      section.className = "result-group";
      const title = document.createElement("h2");
      title.className = "group-title";
      title.textContent = group.title;
      section.appendChild(title);
      if (group.note) {
        const note = document.createElement("p");
        note.className = "note";
        note.textContent = group.note;
        section.appendChild(note);
      }
      const grid = document.createElement("div");
      grid.className = "grid-cards";
      for (const card of group.cards) grid.appendChild(renderCard(card));
      section.appendChild(grid);
      resultRoot.appendChild(section);
    }

    results.hidden = false;
    document.body.classList.add("has-results");
    currentView = view;
  }

  function loadHistory() {
    try {
      const parsed = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
      if (!Array.isArray(parsed)) return [];
      return parsed
        .filter(function (item) {
          return (
            item &&
            typeof item.q === "string" &&
            typeof item.t === "number" &&
            item.q.length <= 64 &&
            /^[\d.\s/]+$/.test(item.q)
          );
        })
        .slice(0, HISTORY_LIMIT);
    } catch (err) {
      return [];
    }
  }

  function saveHistory(items) {
    try {
      localStorage.setItem(HISTORY_KEY, JSON.stringify(items.slice(0, HISTORY_LIMIT)));
    } catch (err) {
      // Private mode and full storage still leave the calculation usable.
    }
  }

  function renderHistory() {
    const items = loadHistory();
    historyCount.textContent = String(items.length);
    historyList.replaceChildren();
    if (items.length === 0) {
      const empty = document.createElement("p");
      empty.className = "muted";
      empty.textContent = "Nothing here yet.";
      historyList.appendChild(empty);
      return;
    }
    for (const item of items) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "history-item";
      const query = document.createElement("span");
      query.className = "mono";
      query.textContent = item.q;
      const time = document.createElement("time");
      const when = new Date(item.t);
      time.dateTime = when.toISOString();
      time.textContent = when.toLocaleString(undefined, {
        dateStyle: "medium",
        timeStyle: "short",
      });
      button.append(query, time);
      button.addEventListener("click", function () {
        input.value = item.q;
        run();
      });
      historyList.appendChild(button);
    }
  }

  function remember(query) {
    const items = loadHistory().filter(function (item) {
      return item.q !== query;
    });
    items.unshift({ q: query, t: Date.now() });
    saveHistory(items);
    renderHistory();
  }

  function run() {
    setStatus("");
    try {
      const info = analyze(input.value);
      const view = present(info);
      clearError();
      input.value = info.normalized;
      render(view);
      remember(info.normalized);
    } catch (err) {
      showError(err.message || "Could not analyze that input.");
    }
  }

  form.addEventListener("submit", function (event) {
    event.preventDefault();
    run();
  });

  examples.addEventListener("click", function (event) {
    const button = event.target.closest("button[data-query]");
    if (!button) return;
    input.value = button.getAttribute("data-query");
    run();
  });

  exportBtn.addEventListener("click", function () {
    if (!currentView) return;
    const slug = currentView.normalized.replace("/", "-").replace(/[^0-9a-z.-]/gi, "");
    const blob = new Blob([summarize(currentView)], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "ip-inspector-" + slug + ".txt";
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    setStatus("Report downloaded");
  });

  copyBtn.addEventListener("click", async function () {
    if (!currentView) return;
    const ok = await copyText(summarize(currentView));
    setStatus(ok ? "Copied the summary" : "Copy failed");
  });

  clearBtn.addEventListener("click", function () {
    if (!clearArmed) {
      clearArmed = true;
      clearLabel.textContent = "Confirm clear";
      window.clearTimeout(clearTimer);
      clearTimer = window.setTimeout(resetClear, 2500);
      return;
    }
    try {
      localStorage.removeItem(HISTORY_KEY);
    } catch (err) {
      // Ignore storage failures and still clear the list on screen.
    }
    resetClear();
    renderHistory();
  });

  renderHistory();
}

if (typeof document !== "undefined") {
  document.addEventListener("DOMContentLoaded", init);
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { analyze, present, summarize };
}
