# IP Inspector

[![GitHub stars](https://img.shields.io/github/stars/cagatayuresin/ip-inspector?style=social)](https://github.com/cagatayuresin/ip-inspector) [![GitHub forks](https://img.shields.io/github/forks/cagatayuresin/ip-inspector?style=social)](https://github.com/cagatayuresin/ip-inspector) [![GitHub issues](https://img.shields.io/github/issues/cagatayuresin/ip-inspector)](https://github.com/cagatayuresin/ip-inspector/issues) [![MIT License](https://img.shields.io/github/license/cagatayuresin/ip-inspector)](LICENSE) [![GitHub Pages](https://img.shields.io/badge/GitHub%20Pages-Live-green)](https://cagatayuresin.github.io/ip-inspector/)

IPv4 and CIDR calculator that runs entirely in the browser. No backend, no account, no tracking.

## Features

- IPv4 addresses and CIDR blocks, including `/0`, `/31`, and `/32`
- Network, broadcast, mask, wildcard, usable range, and host counts
- Special-purpose ranges: private, shared CGNAT, loopback, link-local, documentation, benchmarking, multicast, and reserved
- A block that crosses those ranges is marked as mixed
- A bare address shows that address only. Subnet details appear when you include a prefix
- Binary view, with host bits marked once a prefix is present
- Export a text report, copy the summary, or copy a single value
- History stays in this browser
- No build step

## Usage

1. Enter an IPv4 address (`192.168.1.10`) or a CIDR block (`10.0.0.0/24`).
2. Choose **Analyze** or press **Enter**.
3. Read the result, export it, or copy it.

A prefix is the subnet. Leave it out to inspect the address itself.

## Live demo

[https://cagatayuresin.github.io/ip-inspector/](https://cagatayuresin.github.io/ip-inspector/)

## Development

The calculator is plain JavaScript in `main.js`. There is no build step. The page does not depend on the packages below; they are only for checks.

```bash
npm ci
npm test
npm run check
```

`npm run check` runs ESLint, Stylelint, HTML-validate, and the tests. Pull requests run the same checks. `npm test` fails if line, branch, or function coverage of `main.js` drops below 90%. GitHub Actions also runs [CodeQL](.github/workflows/codeql.yml). SonarCloud reads the repository on its own and is not part of this pipeline.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT. See [LICENSE](LICENSE).

Created by [Cagatay URESIN](https://github.com/cagatayuresin).
