# Software Bill of Materials (SBOM)

## Scope

The CycloneDX Gradle plugin produces a dependency-resolution SBOM for `:app`'s `releaseRuntimeClasspath`. It covers resolved direct and transitive runtime dependencies in that configuration, not the entire Android platform, development tools, test dependencies, every bundled native binary, or a byte-for-byte inventory of the final APK. For a release, preserve the SBOM together with the exact source commit and APK checksum; consider a complementary binary-level SBOM and a separate build-tool SBOM.

## Generate locally

```bash
./gradlew :app:cyclonedxDirectBom -PQRSG_SAFE_BROWSING_API_KEY= --no-configuration-cache --no-build-cache
python3 -m json.tool app/build/reports/cyclonedx-direct/bom.json >/dev/null
```

Inspect `metadata`, `components`, Maven package URLs (PURLs), `dependencies` and license information. Confirm the Room, CameraX, ML Kit and protobuf runtime components are present. The plugin writes `bom.json` and `bom.xml` under `app/build/reports/cyclonedx-direct/`.

For a versioned release, copy the generated output only after successful resolution and inspection:

```bash
mkdir -p sbom
cp app/build/reports/cyclonedx-direct/bom.json sbom/qrsg-release.cdx.json
cp app/build/reports/cyclonedx-direct/bom.xml sbom/qrsg-release.cdx.xml
git rev-parse HEAD > sbom/source-commit.txt
sha256sum sbom/qrsg-release.cdx.json sbom/qrsg-release.cdx.xml > sbom/SHA256SUMS
```

Do not commit generated SBOMs with private repository URLs or credentials. CI also publishes per-commit SBOM artifacts and gates high/critical vulnerabilities via Trivy. This is not an assertion that dependencies are vulnerability-free; review scan reports and investigate findings. No API key or phishing dataset is required.

`sbom/declared-dependencies.cdx.json` is a **preliminary, incomplete source inventory** of declared production dependencies at the reviewed commit, before Gradle resolution. Some entries intentionally omit versions managed by the Compose BOM; no transitive dependencies or resolved graph are asserted. It is not suitable as a release SBOM or as evidence of a clean vulnerability scan. Replace it for release purposes with the Gradle-generated SBOM, not by manually guessing versions.

## References

- https://github.com/CycloneDX/cyclonedx-gradle-plugin
- https://cyclonedx.org/specification/overview/
- https://trivy.dev/docs/latest/target/sbom/
