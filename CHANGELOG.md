# Changelog

## [0.2.0] - 2026-11-24

### Fixed

- CIDR math for `/0`, `/31`, and `/32`, including usable counts and the missing broadcast address.
- Special-purpose ranges. Documentation, benchmarking, CGNAT, and the rest of the reserved space are no longer mislabeled.
- A bare address no longer pretends to be a `/24`. Class A/B/C uses the classful mask and says so.
- Block scope is based on the whole subnet, so a block that crosses ranges is marked mixed.

### Changed

- Results are grouped into address, subnet, and binary.
- History sits in the page instead of covering the results.
- The page no longer loads Tailwind, Three.js, icon fonts, or web fonts at runtime.

## [0.1.0] - 2025-08-30

### Added

- Initial release of IP Inspector.
- Analyze IPv4 and CIDR, show all network details.
- Export and copy summary features.
- Local history and responsive UI.
