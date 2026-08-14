# Licensing and Clean-Room Policy

## Core license

LatencyDesk original core code is available under either:

- Apache License 2.0; or
- MIT License.

Contributors license their contribution under the same dual terms unless a file clearly states otherwise.

## Why dual MIT/Apache-2.0

The permissive core encourages broad adoption and embedding. Apache-2.0 includes an explicit patent license from contributors; MIT offers simple compatibility. This does not grant rights to third-party codec patents, GPU SDKs, or binaries.

## Clean-room rule

Do not copy implementation code, comments, tables, constants, tests, or derived source from GPL/AGPL competitors into this repository. RustDesk, Sunshine, Moonlight, and other projects can be studied for public behavior and high-level architecture, but permissive-core implementation must be independently authored from official specifications and clean-room observations.

A contribution influenced by another implementation must disclose:

- project and exact files viewed;
- applicable license;
- what public behavior/specification was implemented;
- why no protected implementation expression was copied.

Maintainers may require an independent implementer/reviewer.

## Codec and vendor providers

The following are separate questions for every provider:

1. source-code license;
2. headers/SDK redistribution terms;
3. runtime binary distribution terms;
4. static versus dynamic linking effect;
5. codec patent pool/royalty obligations by distribution channel and country;
6. hardware-driver dependency;
7. whether CI can legally download/use the SDK.

A permissive wrapper does not make the underlying codec or vendor SDK unrestricted.

### H.264 software fallback

Do not assume a non-GPL FFmpeg build includes a distributable software H.264 encoder. OpenH264 may be offered as an optional provider, but Cisco-provided binaries and self-built binaries can have different patent/distribution implications. The core must remain usable without bundling it.

### HEVC and AV1

New providers require technical and legal review. AV1 being royalty-free by design does not eliminate all patent, implementation-license, or hardware-SDK questions. HEVC needs an explicit distribution review before it is enabled in published binaries.

## Dependency policy

Before merging a runtime dependency:

- document why standard library/current dependencies are insufficient;
- verify license and maintenance status;
- check unsafe-code and supply-chain surface;
- pin through `Cargo.lock` for applications;
- include it in SBOM/advisory scanning;
- avoid pulling a framework merely to simplify an M0 prototype.

GPL components may be supported only through a clearly reviewed separate-process boundary when legally appropriate; they are not linked into the permissive core by default.
