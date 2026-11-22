# Third-party notices

## Firestack / gVisor user-space network stack

- Project: https://github.com/celzero/firestack
- Integrated package: `github.com/celzero/firestack/intra`
- Exact source revision: `c27887056230769ee897b7c7b92976b96d3c9a6d`
- Source URL: https://github.com/celzero/firestack/tree/c27887056230769ee897b7c7b92976b96d3c9a6d
- License: Mozilla Public License 2.0 (MPL-2.0)
- License text: [third_party/licenses/FIRESTACK-MPL-2.0.txt](third_party/licenses/FIRESTACK-MPL-2.0.txt)

The Android AAR is built from the pinned Firestack source during CI. FirewallDNS applies the MPL-2.0 patch at `third_party/patches/firestack-capture-dns-port.patch` to expose DNS port interception for all resolver addresses; the patch is applied only in the CI build workspace and does not rewrite the upstream repository. The original Firestack source remains available at the exact revision above. Firestack includes work under the Apache License 2.0 as identified in its source-file notices. Its Go module dependency graph includes gVisor and other separately licensed projects; their license notices remain those supplied by their respective upstream projects and must accompany any redistribution of their source or binaries.

FirewallDNS does not claim authorship of Firestack, gVisor, smoltcp, or their upstream components. The Kotlin bridge and FirewallDNS policy integration are separate additions maintained in this repository. The pinned Firestack revision is extended at build time with `third_party/patches/firestack-capture-dns-port.patch`, which adds `intra.CaptureDnsPort()` and a focused Go test. This MPL-2.0 patch changes Firestack's DNS capture mode from the default synthetic-IP-only mode to port-53 capture, so hard-coded DNS resolver addresses are also passed through FirewallDNS domain policy. The exact patch source and test are distributed in this repository.

When redistributing the APK or AAR, retain this notice and the MPL-2.0 license text. For any future modification to Firestack source files, publish the corresponding modified source files under MPL-2.0 and preserve the original notices.
