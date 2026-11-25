# Software Composition Analysis Report

## Scan information

- Project: QR Security Gateway
- Application version: 1.0
- Scan date: 2026-11-24
- Scanner: Trivy v0.76.2
- SBOM format: CycloneDX 1.6
- SBOM generator: CycloneDX Gradle Plugin 3.6.1
- Scope: releaseRuntimeClasspath
- Third-party components: 162
- Total package records: 163, including the application itself

## Results

| Severity | Findings |
|---|---:|
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low | 0 |
| Unknown | 0 |
| **Total** | **0** |

## Conclusion

No known vulnerabilities were reported by Trivy for the supplied runtime dependency SBOM at the time of the assessment.

## Limitations

The absence of reported vulnerabilities does not guarantee that the application or its dependencies are free of security defects.

The assessment does not cover application-specific vulnerabilities, Android OS vulnerabilities, all embedded native code, build-time dependencies, or vulnerabilities not represented in the scanner's vulnerability database.

## Recommendations

- Perform automated SCA on every pull request.
- Generate an updated SBOM for every release.
- Perform scheduled vulnerability scans.
- Monitor dependency security advisories.
- Enforce a HIGH and CRITICAL vulnerability security gate in CI.
