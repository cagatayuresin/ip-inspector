"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { JSDOM } = require("jsdom");

const HISTORY_KEY = "ip_inspector_history_v1";
const html = fs.readFileSync(path.join(__dirname, "../index.html"), "utf8");

function fakeThree() {
  class Color {
    constructor(value) {
      this.value = value;
    }
    copy(other) {
      this.value = other.value;
      return this;
    }
  }
  return {
    Color,
    LinearFilter: 1006,
    Scene: class {
      add() {}
    },
    PerspectiveCamera: class {
      constructor() {
        this.position = { z: 0 };
        this.aspect = 1;
      }
      updateProjectionMatrix() {}
    },
    WebGLRenderer: class {
      setPixelRatio() {}
      setSize() {}
      render() {}
    },
    Group: class {
      constructor() {
        this.rotation = { x: 0, y: 0 };
      }
      add() {}
    },
    Points: class {
      constructor(_geometry, material) {
        this.material = material;
      }
    },
    BufferGeometry: class {
      setAttribute() {}
    },
    BufferAttribute: class {},
    PointsMaterial: class {
      constructor(options) {
        this.color = options.color;
        this.opacity = options.opacity;
      }
    },
    CanvasTexture: class {
      constructor() {
        this.minFilter = null;
        this.magFilter = null;
        this.generateMipmaps = true;
      }
    },
  };
}

function replaceStorage(window, hooks) {
  const memory = new Map();
  Object.defineProperty(window, "localStorage", {
    configurable: true,
    value: {
      getItem(key) {
        if (hooks.get) return hooks.get(key);
        return memory.has(key) ? memory.get(key) : null;
      },
      setItem(key, value) {
        if (hooks.set) return hooks.set(key, value);
        memory.set(key, String(value));
      },
      removeItem(key) {
        if (hooks.remove) return hooks.remove(key);
        memory.delete(key);
      },
    },
  });
}

function mount(options = {}) {
  const dom = new JSDOM(html.replace(/<script\b[\s\S]*?<\/script>/gi, ""), {
    url: options.secure === false ? "http://127.0.0.1/" : "https://cagatayuresin.github.io/ip-inspector/",
    pretendToBeVisual: true,
    runScripts: "dangerously",
  });
  const { window } = dom;
  let scheme = Boolean(options.dark);
  let motion = Boolean(options.reduce);
  const schemeListeners = [];
  window.matchMedia = (query) => {
    const schemeQuery = query.includes("prefers-color-scheme");
    return {
      get matches() {
        return schemeQuery ? scheme : motion;
      },
      media: query,
      addEventListener(type, fn) {
        if (type === "change" && schemeQuery) schemeListeners.push(fn);
      },
      removeEventListener() {},
    };
  };
  window.innerWidth = options.width || 1024;
  window.innerHeight = 800;
  window.devicePixelRatio = options.pixelRatio === undefined ? 3 : options.pixelRatio;
  const rafs = [];
  window.requestAnimationFrame = (fn) => {
    rafs.push(fn);
    return rafs.length;
  };
  window.cancelAnimationFrame = () => {};
  let hidden = false;
  Object.defineProperty(window.document, "hidden", {
    configurable: true,
    get() {
      return hidden;
    },
  });
  window.HTMLCanvasElement.prototype.getContext = () => ({
    clearRect() {},
    fillText() {},
  });
  window.URL.createObjectURL = () => "blob:report";
  window.URL.revokeObjectURL = () => {};
  const downloads = [];
  window.HTMLAnchorElement.prototype.click = function click() {
    downloads.push(this.download);
  };
  const timers = [];
  window.setTimeout = (fn) => {
    timers.push(fn);
    return timers.length;
  };
  window.clearTimeout = () => {};

  let secure = options.secure !== false;
  Object.defineProperty(window, "isSecureContext", {
    configurable: true,
    get() {
      return secure;
    },
  });
  window.document.execCommand = () => true;
  if (options.three !== false) window.THREE = fakeThree();
  const script = new vm.Script(fs.readFileSync(path.join(__dirname, "../main.js"), "utf8"), {
    filename: path.join(__dirname, "../main.js"),
  });
  script.runInContext(dom.getInternalVMContext());
  window.document.dispatchEvent(new window.Event("DOMContentLoaded"));

  return {
    window,
    document: window.document,
    app: window,
    rafs,
    downloads,
    timers,
    setHidden(value) {
      hidden = value;
    },
    setScheme(value) {
      scheme = value;
      schemeListeners.forEach((fn) => fn());
    },
    setMotion(value) {
      motion = value;
    },
    setSecure(value) {
      secure = value;
    },
  };
}

function flush() {
  return new Promise((resolve) => {
    setImmediate(resolve);
  });
}

describe("page", () => {
  it("analyzes, remembers, copies, and exports", async () => {
    const page = mount();
    const { document } = page;
    const input = document.getElementById("query");
    const form = document.getElementById("inspect-form");

    document.getElementById("export-btn").click();
    document.getElementById("copy-btn").click();
    assert.equal(document.getElementById("status").textContent, "");

    input.value = "not an address";
    form.dispatchEvent(new page.window.Event("submit", { bubbles: true, cancelable: true }));
    assert.match(document.getElementById("form-error").textContent, /not a valid/);
    assert.equal(input.getAttribute("aria-invalid"), "true");
    assert.equal(document.getElementById("results").hidden, true);

    input.value = "192.168.001.010/24";
    form.dispatchEvent(new page.window.Event("submit", { bubbles: true, cancelable: true }));
    assert.equal(input.value, "192.168.1.10/24");
    assert.equal(input.getAttribute("aria-invalid"), "false");
    assert.equal(document.getElementById("results").hidden, false);
    assert.equal(document.body.classList.contains("has-results"), true);
    assert.equal(document.querySelector(".bit-host").textContent.length, 1);
    assert.match(document.querySelector(".note").textContent, /host bits/);
    assert.equal(document.getElementById("history-count").textContent, "1");

    document.getElementById("examples").dispatchEvent(new page.window.MouseEvent("click", { bubbles: true }));
    document.querySelector('[data-query="8.8.8.8"]').click();
    assert.equal(input.value, "8.8.8.8");
    assert.equal(document.getElementById("history-count").textContent, "2");

    document.querySelector(".history-item").click();
    assert.equal(input.value, "8.8.8.8");

    page.window.navigator.clipboard = {
      writeText: async () => {},
    };
    document.querySelector(".card-copy").click();
    await flush();
    assert.match(document.getElementById("status").textContent, /Copied /);
    page.timers.at(-1)();
    assert.equal(document.getElementById("status").textContent, "");

    document.getElementById("copy-btn").click();
    await flush();
    assert.equal(document.getElementById("status").textContent, "Copied the summary");

    page.window.navigator.clipboard = {
      writeText: async () => {
        throw new Error("denied");
      },
    };
    document.execCommand = () => true;
    document.getElementById("copy-btn").click();
    await flush();
    assert.equal(document.getElementById("status").textContent, "Copied the summary");

    document.execCommand = () => {
      throw new Error("unavailable");
    };
    document.getElementById("copy-btn").click();
    await flush();
    assert.equal(document.getElementById("status").textContent, "Copy failed");

    document.getElementById("export-btn").click();
    assert.equal(page.downloads.at(-1), "ip-inspector-8.8.8.8.txt");
  });

  it("keeps a valid history and clears it after confirmation", () => {
    const page = mount();
    const stored = [
      { q: "10.0.0.1", t: 1 },
      { q: "10.0.0.1", t: 2 },
      null,
      { q: 12, t: 3 },
      { q: "10.1.1.1", t: "yesterday" },
      { q: "x".repeat(65), t: 4 },
      { q: "nope", t: 5 },
      ...Array.from({ length: 205 }, (_item, index) => ({ q: `1.2.3.${index % 10}/${index}`, t: index + 10 })),
    ];
    page.window.localStorage.setItem(HISTORY_KEY, JSON.stringify(stored));
    page.app.init();
    const count = Number(page.document.getElementById("history-count").textContent);
    assert.equal(count, 200);

    const clear = page.document.getElementById("clear-history");
    clear.click();
    assert.equal(page.document.getElementById("clear-label").textContent, "Confirm clear");
    page.timers.at(-1)();
    assert.equal(page.document.getElementById("clear-label").textContent, "Clear");

    clear.click();
    clear.click();
    assert.equal(page.window.localStorage.getItem(HISTORY_KEY), null);
    assert.equal(page.document.getElementById("history-count").textContent, "0");
    assert.match(page.document.getElementById("history-list").textContent, /Nothing here yet/);
  });

  it("survives blocked or corrupt storage", () => {
    const page = mount();
    page.window.localStorage.setItem(HISTORY_KEY, "{");
    page.app.init();
    assert.equal(page.document.getElementById("history-count").textContent, "0");

    page.window.localStorage.setItem(HISTORY_KEY, JSON.stringify({ nope: true }));
    page.app.init();
    assert.match(page.document.getElementById("history-list").textContent, /Nothing here yet/);

    replaceStorage(page.window, {
      get() {
        throw new Error("blocked");
      },
    });
    page.app.init();
    assert.equal(page.document.getElementById("history-count").textContent, "0");

    replaceStorage(page.window, {
      set() {
        throw new Error("blocked");
      },
    });
    page.document.getElementById("query").value = "10.0.0.1";
    page.document
      .getElementById("inspect-form")
      .dispatchEvent(new page.window.Event("submit", { bubbles: true, cancelable: true }));
    assert.equal(page.document.getElementById("results").hidden, false);

    replaceStorage(page.window, {
      remove() {
        throw new Error("blocked");
      },
    });
    const clear = page.document.getElementById("clear-history");
    clear.click();
    clear.click();
    assert.equal(page.document.getElementById("history-count").textContent, "0");
  });

  it("switches theme, including when storage and the meta tag are missing", () => {
    const page = mount({ dark: true });
    assert.equal(page.document.documentElement.dataset.theme, "dark");
    assert.equal(page.document.querySelector('meta[name="theme-color"]').getAttribute("content"), "#0d1117");

    page.document.querySelector(".theme-switch").dispatchEvent(new page.window.MouseEvent("click", { bubbles: true }));
    page.document.querySelector('[data-theme-choice="light"]').click();
    assert.equal(page.document.documentElement.dataset.theme, "light");
    assert.equal(page.document.querySelector('[data-theme-choice="light"]').getAttribute("aria-pressed"), "true");

    replaceStorage(page.window, {
      set() {
        throw new Error("blocked");
      },
    });
    page.document.querySelector('[data-theme-choice="system"]').click();
    assert.equal(page.document.documentElement.dataset.themeChoice, "system");
    page.setScheme(false);
    assert.equal(page.document.documentElement.dataset.theme, "light");
    page.setScheme(true);
    assert.equal(page.document.documentElement.dataset.theme, "dark");

    page.document.querySelector('meta[name="theme-color"]').remove();
    page.document.querySelector('[data-theme-choice="light"]').click();
    assert.equal(page.document.documentElement.dataset.theme, "light");

    page.document.querySelector(".theme-switch").remove();
    page.app.initTheme();
  });

  it("draws the digit field and pauses it", () => {
    const page = mount();
    assert.equal(page.rafs.length > 0, true);
    const started = page.rafs.length;

    page.setHidden(true);
    page.rafs[started - 1]();
    page.setHidden(false);
    page.rafs.at(-1)();

    page.document.documentElement.style.setProperty("--particle", "#7ab2b2");
    page.document.documentElement.style.setProperty("--particle-opacity", "0.7");
    page.document.dispatchEvent(new page.window.Event("themechange"));

    page.window.dispatchEvent(new page.window.Event("resize"));
    page.window.dispatchEvent(new page.window.Event("pagehide"));

    page.setMotion(true);
    page.window.innerWidth = 500;
    page.window.devicePixelRatio = 0;
    page.app.startBackground();
    page.window.dispatchEvent(new page.window.Event("resize"));

    page.document.getElementById("bg3d").remove();
    page.app.startBackground();
  });

  it("skips the field when THREE is absent", () => {
    const page = mount({ three: false });
    assert.equal(page.rafs.length, 0);
    page.app.startBackground();
    assert.equal(page.rafs.length, 0);
  });

  it("uses the fallback particle color when the theme variables are unreadable", () => {
    const page = mount({ reduce: true });
    const created = [];
    const Material = page.window.THREE.PointsMaterial;
    page.window.THREE.PointsMaterial = class extends Material {
      constructor(options) {
        super(options);
        created.push(this);
      }
    };
    page.window.getComputedStyle = () => ({
      getPropertyValue(name) {
        return String(name).includes("opacity") ? "not-a-number" : "";
      },
    });
    page.app.startBackground();
    page.document.dispatchEvent(new page.window.Event("themechange"));
    assert.equal(created.length > 0, true);
    assert.equal(created[0].color.value, "#088395");
    assert.equal(created[0].opacity, 0.6);
  });
});
