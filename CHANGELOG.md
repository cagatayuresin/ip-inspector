# Changelog

## [0.2.0] - 2026-11-24

### Fixed

- CIDR math for `/0`, `/31`, and `/32`, including usable counts and the missing broadcast address.
- Special-purpose ranges. Documentation, benchmarking, CGNAT, and the rest of the reserved space are no longer mislabeled.
- A bare address is no longer given a default mask. Subnet math is shown only when a prefix is entered.
- Block scope is based on the whole subnet, so a block that crosses ranges is marked mixed.

### Changed

- Results are grouped into address, subnet, and binary.
- History sits in the page instead of covering the results.
- The page no longer loads Tailwind, icon fonts, or web fonts. The particle field stays.
- Colors follow the cagatayuresin.com palette, with light, dark, and system themes.
- Pull requests run ESLint, Stylelint, HTML validation, and the test suite. Coverage of `main.js` must stay at or above 90%. CodeQL covers security and quality. SonarCloud analyzes the repository on its own.

## [0.1.0] - 2025-08-30

### Added

- Initial release of IP Inspector.
- Analyze IPv4 and CIDR, show all network details.
- Export and copy summary features.
- Local history and responsive UI.
