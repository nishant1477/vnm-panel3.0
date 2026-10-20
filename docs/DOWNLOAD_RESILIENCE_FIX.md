# Download Resilience Fix (v2.1.1 / agent 1.4.0)

## The reported problem

On a freshly deployed VPS the panel could not download any OS template.
Every attempt to reach the Debian mirrors (`cloud.debian.org`,
`cdimage.debian.org` - same for Ubuntu/Fedora/CentOS/Alma) died in a couple
of seconds with a TCP-level error (`ETIMEDOUT`) and **never received an HTTP
response**. The UI surfaced it as **HTTP 502 `TEMPLATE_DOWNLOAD_FAILED`**,
while `curl` and `git` on the very same host worked fine.

## Root cause

Node resolves hostnames through `getaddrinfo` and, on hosts that have a
**global IPv6 address**, AAAA records are tried **first**. When the host's
IPv6 egress is broken (a very common VPS situation: the provider assigns a
GUA but never delivers working v6 routing), the first TCP connect goes into
a black hole. curl and git race both families (Happy Eyeballs) or prefer
IPv4, which is why they kept working while Node - and therefore the panel -
hung and timed out.

## The fix (panel AND node agent)

1. **Ordered address resolution** - every download host is resolved into an
   ordered list: **IPv4 first by default** (matching curl's practical
   behavior), AAAA first when `VNM_PREFER_IPV6=1`. 60s TTL cache, IP
   literals untouched.
2. **Per-address iteration** - the downloader tries each resolved address in
   sequence. Only **connect-layer** failures (no HTTP status: timeout,
   refused, no-route, reset) advance to the next address. A real HTTP
   verdict (even 404) is final for that URL and is handed to the existing
   retry / fallback-mirror logic unchanged.
3. **Pinned lookup** - each attempt connects to exactly one address while
   the Host header, TLS SNI and certificate validation still use the real
   hostname, so mirrors see a perfectly normal request.
4. **Per-address connect deadline** (agent) - `AGENT_ADDR_CONNECT_TIMEOUT_MS`
   (default 6000) bounds the time spent reaching each address so a
   black-holed family fails in seconds instead of minutes.
5. **Global Happy Eyeballs** - `net.setDefaultAutoSelectFamily(true)` is
   enabled for the whole panel and agent process, so Discord OAuth,
   monitoring webhooks, license checks and the agent's own panel connection
   get the same family-racing protection. Disable with
   `VNM_NO_HAPPY_EYEBALLS=1`; it is a silent no-op on Node versions without
   the API (the per-address iteration in the downloader still applies).
6. **Honest diagnostics** - every `TEMPLATE_DOWNLOAD_FAILED` 502 now lists,
   per URL, **which addresses of which family were tried**
   (`addresses: ["2001:...:173 (IPv6): timeout", "194.71.11.173 (IPv4): HTTP
   200"]`), and when no URL ever produced an HTTP response the message says
   outright: this is a TCP-level reachability problem on this host, not a
   mirror outage - flip `VNM_PREFER_IPV6` or fix the host's network.

## New environment variables

| Variable | Default | Effect |
|----------|---------|--------|
| `VNM_PREFER_IPV6` | `0` | `1` puts AAAA first in the download order (for hosts whose IPv4 path is broken) |
| `VNM_NO_HAPPY_EYEBALLS` | unset | `1` disables global family racing |
| `AGENT_ADDR_CONNECT_TIMEOUT_MS` | `6000` | Per-address connect deadline in the agent downloader |

## Verified

`scripts/56-verify-downloadfix.js` reproduces the exact user scenario
(v6-first resolver order + unreachable IPv6 + working IPv4 mirror):
old code fails at the TCP layer and surfaces the 502; fixed code succeeds -
IPv4-first with zero wasted attempts by default, and via explicit fallback
when the order is forced IPv6-first.
