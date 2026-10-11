# Releases

This fork uses SemVer tags in the `v0.x.y` range. Its first planned release is `v0.1.0`. The current tree is a development snapshot, identified by `VERSION` as `0.1.0-dev`; no release is implied by a successful build.

Patch releases contain fixes that preserve the documented integration contract. Minor releases may change APIs, configuration, resource requirements, or persisted state. Release notes must describe those changes and any migration or downgrade restrictions. These are fork-specific conventions within SemVer's initial-development range.

Upstream's v1/v2 names describe earlier implementations. They do not establish a stability guarantee or set this fork's release numbering. Upstream history is retained; published tags are not rewritten.

Before a release:

1. Run `tests/run-host-tests` and `tests/build-minimal` from a clean checkout with the ESP-IDF environment loaded.
2. Repeat relevant hardware tests for transport, shutdown, and key handling changes. Record the board, SDK, configuration, and remaining gaps.
3. Review the changes for credentials, unsupported claims, and storage compatibility.
4. Set `VERSION` to the release number without the `v` prefix and prepare release notes. The tag must match that value exactly.
5. Publish the reviewed commit and tag. Start the next development version separately.

A `v1.0.0` release requires an explicit decision that the supported integration contract is stable. Protocol coverage and deployment suitability remain separate questions.
