# FirewallDNS Diagnostic

Companion Android APK for exercising the shared FirewallDNS engine and validating the production VPN path on a real device.

## Safety and architecture

- This application does **not** declare or implement a `VpnService`.
- The only production VPN remains `DnsFirewallService` in the FirewallDNS app.
- The diagnostic APK links the same `:engine-core`, `:engine-runtime` and `:android-adapter` modules used by the host app.
- Live counters are read through a read-only `ContentProvider` protected by the signature permission `com.firewall.dns.permission.READ_DIAGNOSTICS`.
- The provider exports aggregate counters only. It does not expose packet payloads, queried domains, IP addresses, UIDs, package names, or browsing history.
- Install the two APKs produced by the same CI run so Android grants the signature permission.

## Test groups

### In-process engine tests

- BLOCK, OBSERVE and ALLOW policy decisions against synthetic DNS questions.
- Malformed/truncated DNS rejection.
- Built-in threat intelligence for a known advertising domain.
- Explicit user ALLOW precedence over a built-in indicator.
- Per-application rule matching in the shared policy engine.
- JNI/smoltcp native initialization with IPv4 and IPv6 address families and a poll smoke test.

### Live device tests

Only run when Android reports an active VPN and the protected metrics provider is readable:

- DNS UDP/53 over IPv4.
- DNS TCP/53 over IPv4, including the two-byte DNS-over-TCP length prefix.
- DNS UDP/53 and TCP/53 over IPv6 when a global IPv6 address is available.
- Before/after deltas for DNS UDP/TCP packets, smoltcp sessions, native errors, TUN queue rejections and TUN write errors.

The probes use synthetic requests for `example.com` and a public DNS endpoint. They do not record ordinary browsing traffic.

## Explicitly not verified by this APK yet

These are deliberately reported as **NO VERIFICADO**, not passed:

- IPv4/IPv6 fragment reassembly through the production TUN.
- The actual `VpnService.protect()` result for upstream sockets.
- Persistence and real-time behavior of the intelligent learning store.
- Blocklist download integrity, hashes and 24-hour refresh behavior.
- DoH, DoT or DoQ inspection. Intercepting DNS/53 does not prove inspection of encrypted DNS.
- Long-duration stability, CPU and battery consumption.
- Full packet-level TCP edge cases (retransmission, out-of-order delivery, FIN/RST, backpressure) on the physical device.

These require additional read-only diagnostic hooks or dedicated instrumented tests in the production service. The diagnostic app must not create a second VPN to simulate them.

## Report

The app creates `FirewallDNS_Diagnostico_<timestamp>.zip` with:

- `diagnostico.json`: machine-readable test outcomes and elapsed times.
- `diagnostico.txt`: human-readable APROBADO/FALLIDO/NO VERIFICADO summary.
- `metricas_iniciales.csv` and `metricas_finales.csv`: aggregate counters from the main app.

No DNS payloads or personal browsing history are included.
