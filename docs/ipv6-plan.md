# IPv6 (dual-stack firewall) support — plan

Status: planning · Branch: `feat/ipv6` (this document lives on the planning branch until the feature branch is cut)

Azure Firewall can now run in dual-stack mode (IPv4 + IPv6), currently in preview:
<https://learn.microsoft.com/en-us/azure/firewall/deploy-dual-stack-firewall>

az-firewall-watch has never seen an IPv6 address in a log record. This plan lists what breaks, what to change, and how to verify against the lab firewall.

## What the preview supports (relevant for log content)

| Feature | IPv6 | Log category we will see |
| --- | --- | --- |
| Network rules | yes | `AZFWNetworkRule`, legacy `AzureFirewallNetworkRuleLog` |
| DNS proxy | yes | `AZFWDnsQuery`, legacy `AzureFirewallDnsProxyLog` |
| Flow trace / fat flow | unknown, probably | `AZFWFlowTrace`, `AZFWFatFlow` |
| Application rules, DNAT | **no** | none |
| Threat Intel, IDPS, IP Groups | **no** | none |

So the realistic scope is NetworkRule, DnsQuery, FlowTrace, FatFlow with IPv6 `SourceIp` / `DestinationIp`. Outbound traffic is SNATed to the firewall's IPv6 address unless the destination is ULA (`fc00::/7`).

## Where the code assumes IPv4

### 1. Legacy parser splits `host:port` on the first colon — breaks completely

`fw_parser.py`, `_parse_legacy`:

- `AzureFirewallNetworkRuleLog`: `src_str.split(":")` → for `fd00::1:1234` yields `["fd00", "", "1", "1234"]`; source becomes `fd00`, port becomes an empty string.
- `AzureFirewallNatRuleLog`: `words[3].split(":")`, same problem (DNAT is not IPv6-capable in the preview, low priority).
- `AzureFirewallDnsProxyLog`: `words[2].split(":")`, same problem.

Open question that decides the fix: does Azure write `[fd00::1]:1234` (bracketed) or `fd00::1:1234` (ambiguous) in legacy messages? We need real records from the lab before coding this. Plan for both:

- bracketed → strip `[`/`]` and `rsplit(":", 1)`;
- unbracketed → `rsplit(":", 1)` and validate the head with `ipaddress.ip_address`; if that fails, treat the whole token as address without port.

A single helper `split_endpoint(token) -> (ip, port)` replaces the three ad-hoc splits, with tests for IPv4, bracketed IPv6, unbracketed IPv6, and no port (ICMP).

### 2. Structured parser — works, but only by accident

`SourceIp`, `DestinationIp` are plain strings and are passed through unchanged. Nothing to fix for parsing, but tests must cover IPv6 values for `AZFWNetworkRule`, `AZFWDnsQuery`, `AZFWFlowTrace`, `AZFWFatFlow`, and `QueryType=AAAA`.

### 3. Rendering `ip:port` — ambiguous for IPv6

- `viewer/app.py` `_source_text` renders `sourceip + ":" + srcport`.
- `dialogs.py` detail dialog renders `f"{row.sourceip}:{row.srcport}"` and the same for the destination.

For IPv6 this reads `fd00::1:1234`, which is indistinguishable from an address. Add `format_endpoint(ip, port)` in `helpers.py` that produces `[fd00::1]:1234` for IPv6 and `10.0.0.1:1234` otherwise, and use it in both places. Destination cells show only the IP (port is its own column) and need no change.

### 4. Column width

IPv6 addresses are up to 39 characters, plus brackets and port up to 47. The Source column currently sizes itself on IPv4 content. Check DataTable auto-width behaviour with mixed rows; if the table becomes unreadable on narrow terminals, abbreviate the address with `ipaddress.IPv6Address.compressed` (Azure may already emit compressed form; verify with lab data).

### 5. Filters

`_matches` does a case-insensitive substring match on `sourceip` / `targetip`. That works for IPv6 as-is, but the user experience is poor:

- Typing `fd00:c1d0:3f1f:2::10` will not match if Azure emits the uncompressed form (or the other way round). Normalise both sides with `ipaddress.ip_address(...).compressed` when the value parses as an address; fall back to substring otherwise.
- Prefix filtering: accept a CIDR (`fd00:c1d0::/32`, also `10.0.0.0/8`) in the Source and Dest filters and match with `ipaddress.ip_network(..., strict=False)`. This is the one genuinely new feature in the branch and is useful for IPv4 too.

Filter placeholder texts stay as they are.

### 6. Setup wizard

`setup/` only deals with Event Hub, diagnostic settings and categories. No IP handling, nothing to change. The wizard's category list already contains every category IPv6 traffic can appear in.

### 7. Docs

- README: note that dual-stack firewalls are supported, which categories carry IPv6 in the preview, and the CIDR filter syntax.
- CHANGELOG `Unreleased`: Added (IPv6 endpoints, CIDR filter), Fixed (legacy parser on IPv6).

## Work breakdown

Ordered so each step is independently mergeable and testable without lab access, except the last one.

1. **Endpoint helpers + tests** — `split_endpoint`, `format_endpoint` in `helpers.py` (or a small `netutil.py`), pure functions, full test coverage for IPv4/IPv6/bracketed/no-port.
2. **Legacy parser on helpers** — replace the three `split(":")` sites; tests with synthetic IPv6 messages in both candidate formats. Mark the unverified format in a test comment until lab records exist.
3. **Structured parser tests** — IPv6 fixtures for NetworkRule, DnsQuery (AAAA, IPv6 source), FlowTrace, FatFlow. No code change expected.
4. **Rendering** — `_source_text` and detail dialog via `format_endpoint`; snapshot-style assertions in `test_app_filtering.py` / `test_dialogs.py`.
5. **Filter normalisation + CIDR** — `_matches` gains address-aware matching; tests for compressed vs. expanded input, CIDR v4/v6, and plain substring fallback (FQDNs in Dest).
6. **Docs + changelog.**
7. **Lab verification** — run against `fw-hub-gwc` once it is dual-stack: confirm legacy format, confirm which categories actually emit IPv6, capture the raw records into `tests/` fixtures, and fix whatever step 2 guessed wrong.

Steps 1–6 can start now; step 7 waits for the lab.

## Lab prerequisites (handed to the CC-AzureLab session)

- Hub VNet + `AzureFirewallSubnet` get an IPv6 prefix, firewall gets an IPv6 public IP as second ip-config.
- One dual-stack spoke with a VM and a `::/0` UDR to the firewall's private IPv6 address.
- IPv6 network rules (allow + targeted deny) and DNS proxy over IPv6.
- Diagnostic settings unchanged; both Event Hubs (`firewall-logs`, `firewall-logs-legacy`) receive the records.
- The upgrade to dual-stack cannot be reverted in the preview; Christoph approves the `terraform plan` explicitly before apply.

Deliverable from the lab: raw JSON records (structured and legacy) with IPv6 addresses, to be checked into `tests/` as fixtures.

## Out of scope

- IPv6 for the Event Hub connection itself (SDK concern, works today over whatever the OS offers).
- App rule / DNAT / IDPS / Threat Intel records with IPv6 — the service does not produce them yet. Revisit when the preview widens.
- IP Group resolution or reverse DNS.
