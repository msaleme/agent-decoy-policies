# Attribution and license scope

## Project contributions and upstream notices

Agent Decoy Policies is maintained by [msaleme](https://github.com/msaleme).
Project-authored contributions are offered under the [MIT License](LICENSE).
Third-party code, templates, dependencies, and documentation retain their own
copyright notices and terms; the root MIT license does not relicense them.

The standalone projects use the MuleSoft Policy Development Kit (PDK) scaffold.
Their initial repository files carried `Copyright 2026 Salesforce, Inc. All rights
reserved.` notices. Commit `d805a0e504bd025f24e983825d9053030cd263f5` replaced those
notices with the project's MIT notice. This attribution review restores the
original notices alongside separate credit for project modifications, including
coordinator support files reused from that scaffold. Future changes must preserve
upstream notices. The precise original scaffold/tool release is not recorded in
Git; the currently pinned SDK version is not proof of that historical provenance.

The current PDK 1.10.0 crates supply Salesforce Terms of Use in `LICENSE.txt`, not
an MIT or Apache SPDX declaration. A verbatim copy is retained in
[licenses/Salesforce-PDK-1.10.0.txt](licenses/Salesforce-PDK-1.10.0.txt), from the
locked `pdk` crate. Its SHA-256 is
`40e41c7b6c998968bc1c26002776215f57055cdb78c3795c61cef0d269d8fd05`.
This records the SDK's supplied terms; it does not establish the license of every
historical template file. Preserve component-specific notices when distributing
source or compiled artifacts.

## Direct Rust dependencies

Versions and license declarations below were checked against the committed
lockfiles and downloaded crate manifests on 2026-09-20. Dependencies are fetched
by Cargo; their source is not vendored here. This is a direct-dependency summary,
not an exhaustive transitive license inventory for a binary release.

| Dependency | Locked version | Upstream declaration / source |
| --- | --- | --- |
| `pdk` | 1.10.0 | Salesforce `LICENSE.txt`; [MuleSoft PDK](https://docs.mulesoft.com/pdk/latest/policies-pdk-overview) |
| `serde` | 1.0.229 | MIT OR Apache-2.0; [serde-rs/serde](https://github.com/serde-rs/serde) |
| `serde_json` | 1.0.151 | MIT OR Apache-2.0; [serde-rs/json](https://github.com/serde-rs/json) |
| `anyhow` | 1.0.104 | MIT OR Apache-2.0; [dtolnay/anyhow](https://github.com/dtolnay/anyhow) |
| `pdk-test`, `pdk-unit` (tests) | 1.10.0 | Salesforce `LICENSE.txt` in each crate |
| `httpmock` (tests) | 0.6.8 | MIT; [alexliesenfeld/httpmock](https://github.com/alexliesenfeld/httpmock) |
| `reqwest` (tests) | 0.11.27 | MIT OR Apache-2.0; [seanmonstar/reqwest](https://github.com/seanmonstar/reqwest) |

The PDK also resolves internal crates such as `pdk-classy`; inspect the complete
resolved dependency tree and its notices before distributing WASM bundles. Docker
images and build tools are separate upstream products with their own terms.

## Design references

- **CISA:** the original project cites *Using Cyber Decoys to Strengthen Detection
  and Response* as cyber-decoy design inspiration. **Decoy tool** is this project's
  MCP-specific term, not a primitive attributed to CISA. The Expose/Affect/Elicit
  engagement-goal vocabulary is attributed to MITRE Engage below.
  [Original cited PDF](https://www.cisa.gov/sites/default/files/2026-09/using-cyber-decoys-to-strengthen-detection-and-response_508c.pdf).
  The attribution is retained from the project's initial documentation. CISA's
  server returned HTTP 403 during this review, so the document's contents and
  publication metadata were not independently revalidated here.
- **MITRE Engage:** the engagement-goal vocabulary **Expose, Affect, and Elicit**
  comes from [MITRE Engage](https://engage.mitre.org/) and its
  [Starter Kit](https://engage.mitre.org/wp-content/uploads/2022/03/StarterKit-v1.0.pdf).
  These policies provide detection and bounded enforcement; they do not implement
  a complete adversary engagement environment.
- **NIST:** [SP 800-53 Rev. 5](https://doi.org/10.6028/NIST.SP.800-53r5)
  supplies the SC-26, SC-30, SI-4, and SI-20 control references;
  [SP 800-160 Vol. 2 Rev. 1](https://doi.org/10.6028/NIST.SP.800-160v2r1)
  supplies cyber-resiliency design context. These references are not certification.
- **OWASP:** [LLM06: Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/)
  provides threat context for unintended agent actions. A decoy match alone does
  not establish exploitation or compliance coverage.
- **MuleSoft / Salesforce:** the [PDK documentation](https://docs.mulesoft.com/pdk/latest/)
  and [public policy examples](https://github.com/mulesoft/pdk-custom-policy-examples)
  provide the gateway development context.

## P4A community and review

[P4A — Policies for Agents](https://www.p4a.ai/) provides community policy examples
and submission guidance. The [repository comparison](docs/P4A-REPOSITORY-REVIEW.md)
credits the specific repositories consulted. Their code was not imported in this
review, and their licensing choices do not change this project's license scope.

Thanks to [tbolis-at-mulesoft](https://github.com/tbolis-at-mulesoft) for the issue
review and verification recorded in the [acceptance evidence](docs/REMAINING-ISSUES-PLAN.md).
References to organizations, products, and frameworks identify sources and
compatibility targets; they do not imply endorsement or a P4A catalog listing.
