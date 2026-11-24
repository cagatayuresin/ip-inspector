# IP Inspector

[![GitHub stars](https://img.shields.io/github/stars/cagatayuresin/ip-inspector?style=social)](https://github.com/cagatayuresin/ip-inspector) [![GitHub forks](https://img.shields.io/github/forks/cagatayuresin/ip-inspector?style=social)](https://github.com/cagatayuresin/ip-inspector) [![GitHub issues](https://img.shields.io/github/issues/cagatayuresin/ip-inspector)](https://github.com/cagatayuresin/ip-inspector/issues) [![MIT License](https://img.shields.io/github/license/cagatayuresin/ip-inspector)](LICENSE) [![GitHub Pages](https://img.shields.io/badge/GitHub%20Pages-Live-green)](https://cagatayuresin.github.io/ip-inspector/)

IPv4 and CIDR calculator that runs entirely in the browser. No backend, no account, no tracking.

## Features

- IPv4 addresses and CIDR blocks, including `/0`, `/31`, and `/32`
- Network, broadcast, mask, wildcard, usable range, and host counts
- Special-purpose ranges: private, shared CGNAT, loopback, link-local, documentation, benchmarking, multicast, and reserved
- A block that crosses those ranges is marked as mixed
- Without a prefix, class A/B/C shows the historical classful network and labels it as historical
- Binary view with host bits marked
- Export a text report, copy the summary, or copy a single value
- History stays in this browser
- No build step

## Usage

1. Enter an IPv4 address (`192.168.1.10`) or a CIDR block (`10.0.0.0/24`).
2. Choose **Analyze** or press **Enter**.
3. Read the result, export it, or copy it.

A prefix is the subnet you mean. The classful section is only a fallback, and only when you leave the prefix out.

## Live demo

[https://cagatayuresin.github.io/ip-inspector/](https://cagatayuresin.github.io/ip-inspector/)

## Development

The calculator is plain JavaScript in `main.js`. Run the tests with Node:

```bash
node --test
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT. See [LICENSE](LICENSE).

Created by [Cagatay URESIN](https://github.com/cagatayuresin).
