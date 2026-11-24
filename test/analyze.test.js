"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { analyze, present, summarize } = require("../main.js");

function card(view, label) {
  for (const group of view.groups) {
    const found = group.cards.find((item) => item.label === label);
    if (found) return found;
  }
  return null;
}

function maskOnes(mask) {
  return mask.split(".").reduce((sum, octet) => {
    const bits = Number(octet).toString(2).match(/1/g);
    return sum + (bits ? bits.length : 0);
  }, 0);
}

describe("analyze", () => {
  it("calculates a normal /24", () => {
    const info = analyze("192.168.1.50/24");
    assert.equal(info.address, "192.168.1.50");
    assert.equal(info.integer, "3232235826");
    assert.equal(info.hex, "0xC0A80132");
    assert.equal(info.reverseDns, "50.1.168.192.in-addr.arpa");
    assert.equal(info.scope.name, "Private");
    assert.equal(info.subnet.canonical, "192.168.1.0/24");
    assert.equal(info.subnet.network, "192.168.1.0");
    assert.equal(info.subnet.broadcast, "192.168.1.255");
    assert.equal(info.subnet.mask, "255.255.255.0");
    assert.equal(info.subnet.wildcard, "0.0.0.255");
    assert.equal(info.subnet.firstUsable, "192.168.1.1");
    assert.equal(info.subnet.lastUsable, "192.168.1.254");
    assert.equal(info.subnet.usableHosts, "254");
    assert.equal(info.subnet.totalAddresses, "256");
    assert.equal(info.subnet.role, "host");
    assert.equal(info.subnet.gateway, "192.168.1.1");
    assert.equal(info.subnet.blockScope.mixed, false);
  });

  it("uses the classful mask when no prefix is given", () => {
    const address = analyze("10.1.2.3");
    assert.equal(address.hadPrefix, false);
    assert.equal(address.subnet.mode, "classful");
    assert.equal(address.subnet.prefix, 8);
    assert.equal(address.subnet.network, "10.0.0.0");
    assert.equal(address.subnet.broadcast, "10.255.255.255");

    const classB = analyze("172.16.5.4");
    assert.equal(classB.subnet.prefix, 16);
    assert.equal(classB.subnet.network, "172.16.0.0");

    const multicast = analyze("224.0.0.1");
    assert.equal(multicast.subnet, null);
    assert.equal(multicast.scope.name, "Multicast");
  });

  it("keeps an explicit prefix instead of the classful mask", () => {
    const info = analyze("10.1.2.3/24");
    assert.equal(info.subnet.mode, "cidr");
    assert.equal(info.subnet.network, "10.1.2.0");
    assert.equal(info.subnet.prefix, 24);
  });

  it("treats /31 and /32 without a broadcast address", () => {
    const point = analyze("10.0.0.0/31");
    assert.equal(point.subnet.broadcast, null);
    assert.equal(point.subnet.usableHosts, "2");
    assert.equal(point.subnet.totalAddresses, "2");
    assert.equal(point.subnet.firstUsable, "10.0.0.0");
    assert.equal(point.subnet.lastUsable, "10.0.0.1");
    assert.equal(point.subnet.role, "point-to-point");
    assert.equal(point.subnet.gateway, null);

    const host = analyze("10.0.0.1/32");
    assert.equal(host.subnet.broadcast, null);
    assert.equal(host.subnet.usableHosts, "1");
    assert.equal(host.subnet.totalAddresses, "1");
    assert.equal(host.subnet.role, "host-route");
    assert.equal(host.subnet.network, "10.0.0.1");
  });

  it("counts the full IPv4 space for /0", () => {
    const info = analyze("8.8.8.8/0");
    assert.equal(info.subnet.network, "0.0.0.0");
    assert.equal(info.subnet.broadcast, "255.255.255.255");
    assert.equal(info.subnet.totalAddresses, "4294967296");
    assert.equal(info.subnet.usableHosts, "4294967294");
    assert.equal(info.subnet.mask, "0.0.0.0");
    assert.equal(info.subnet.wildcard, "255.255.255.255");
    assert.equal(info.subnet.blockScope.mixed, true);
  });

  it("names address roles", () => {
    assert.equal(analyze("192.168.1.0/24").subnet.role, "network");
    assert.equal(analyze("192.168.1.255/24").subnet.role, "broadcast");
    assert.equal(analyze("192.168.1.1/24").subnet.role, "host");
  });

  it("aligns every prefix and keeps the mask width", () => {
    for (let prefix = 0; prefix <= 32; prefix += 1) {
      const info = analyze(`203.0.113.55/${prefix}`);
      assert.equal(maskOnes(info.subnet.mask), prefix);
      assert.equal(info.subnet.totalAddresses, (1n << BigInt(32 - prefix)).toString());
      const again = analyze(`${info.subnet.network}/${prefix}`);
      assert.equal(again.subnet.network, info.subnet.network);
      assert.equal(again.subnet.role === "network" || prefix >= 31, true);
    }
  });

  it("normalizes leading zeros and spaces", () => {
    const info = analyze("192.168.001.010 / 24");
    assert.equal(info.address, "192.168.1.10");
    assert.equal(info.normalized, "192.168.1.10/24");
    assert.equal(info.subnet.network, "192.168.1.0");
  });

  it("rejects input that is not an IPv4 target", () => {
    assert.throws(() => analyze(""), /Enter an IPv4/);
    assert.throws(() => analyze("::1"), /IPv6/);
    assert.throws(() => analyze("10.0.0.256"), /not a valid IPv4/);
    assert.throws(() => analyze("10.0.0.1/33"), /0 to 32/);
    assert.throws(() => analyze("10.0.0.1/24 extra"), /not a valid/);
  });

  it("classifies special-purpose ranges, including the old documentation bug", () => {
    const cases = [
      ["0.0.0.0", "Unspecified"],
      ["0.1.2.3", "This network"],
      ["10.0.0.1", "Private"],
      ["100.64.0.1", "Shared (CGNAT)"],
      ["100.127.255.255", "Shared (CGNAT)"],
      ["100.128.0.1", "Global unicast"],
      ["100.63.255.255", "Global unicast"],
      ["127.0.0.1", "Loopback"],
      ["169.254.1.1", "Link-local"],
      ["172.15.255.255", "Global unicast"],
      ["172.16.0.1", "Private"],
      ["172.31.255.255", "Private"],
      ["172.32.0.1", "Global unicast"],
      ["192.0.2.1", "Documentation (TEST-NET-1)"],
      ["192.0.2.1", "Documentation (TEST-NET-1)"],
      ["198.18.0.1", "Benchmarking"],
      ["198.18.100.1", "Benchmarking"],
      ["198.51.100.5", "Documentation (TEST-NET-2)"],
      ["203.0.113.5", "Documentation (TEST-NET-3)"],
      ["224.0.0.1", "Multicast"],
      ["240.0.0.1", "Reserved"],
      ["255.255.255.255", "Limited broadcast"],
    ];
    for (const [query, name] of cases) {
      assert.equal(analyze(query).scope.name, name, query);
    }
    assert.equal(analyze("255.255.255.255").className, "E");
    assert.equal(analyze("10.0.0.1").className, "A");
    assert.equal(analyze("172.16.0.1").className, "B");
    assert.equal(analyze("192.168.0.1").className, "C");
  });

  it("marks a block as mixed when it crosses scopes", () => {
    const wide = analyze("10.0.0.0/7");
    assert.equal(wide.scope.name, "Private");
    assert.equal(wide.subnet.blockScope.mixed, true);

    const docs = analyze("203.0.113.10/23");
    assert.equal(docs.scope.name, "Documentation (TEST-NET-3)");
    assert.equal(docs.subnet.blockScope.mixed, true);

    const exact = analyze("203.0.113.10/24");
    assert.equal(exact.subnet.blockScope.name, "Documentation (TEST-NET-3)");
    assert.equal(exact.subnet.blockScope.mixed, false);
  });

  it("splits a /12 on the correct boundary", () => {
    const info = analyze("172.16.5.1/12");
    assert.equal(info.subnet.network, "172.16.0.0");
    assert.equal(info.subnet.broadcast, "172.31.255.255");
    assert.equal(info.subnet.mask, "255.240.0.0");
  });
});

describe("present", () => {
  it("does not invent a /24 for a class A address", () => {
    const view = present(analyze("10.1.2.3"));
    assert.equal(view.groups[1].title, "Classful network");
    assert.equal(card(view, "Network CIDR").value, "10.0.0.0/8");
    assert.equal(card(view, "Broadcast"), null);
    assert.match(view.groups[1].note, /historical classful/);
    const text = summarize(view);
    assert.match(text, /10\.0\.0\.0\/8/);
    assert.doesNotMatch(text, /heuristic/);
  });

  it("omits broadcast on /31 and explains why", () => {
    const view = present(analyze("172.16.0.1/31"));
    assert.equal(card(view, "Broadcast"), null);
    assert.equal(card(view, "Usable hosts").value, "2");
    assert.equal(card(view, "Role").value, "Point-to-point");
    assert.match(view.groups[1].note, /RFC 3021/);
  });

  it("shows a differing block scope", () => {
    const view = present(analyze("0.0.0.0/8"));
    assert.equal(card(view, "Scope").value, "Unspecified · RFC 1122");
    assert.equal(card(view, "Block scope").value, "This network · RFC 1122");
  });
});
