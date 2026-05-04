# DolosPy — Summary

## How the Attack Works

A transparent Layer 2 bridge is placed inline between a victim device (laptop/printer) and the network switch. Two Ethernet cables: one from the switch port, one from the victim, both plugged into the Pi.

1. **Bridge passthrough** — all traffic flows through unmodified. The switch sees no link change, the victim sees no disruption. 802.1X EAPOL frames pass through so the victim's NAC authentication stays valid.

2. **Passive discovery** — ARP packets are sniffed to build a MAC→IP table. When an IP packet's Ethernet source MAC maps to a *different* IP than the IP header claims, that's the gateway forwarding someone else's traffic. This identifies both the gateway (MAC/IP) and the client (MAC/IP) without sending a single packet.

3. **Identity spoofing** — ebtables SNAT rewrites all outbound frames from the Pi to use the client's MAC toward the switch and the gateway's MAC toward the client. iptables SNAT rewrites IP source addresses. The Pi effectively becomes invisible — all its traffic looks like it comes from the legitimate client.

4. **Remote access** — LTE USB tethering + Tailscale SSH provides an out-of-band management path that doesn't touch the target network. Tailscale is optional — the core bridge works without it.

---

## Fixes vs DolosJS

### Detection Bugs

| Issue | What Was Wrong | Fix |
|-------|---------------|-----|
| **Wrong client detected on busy VLANs** | Gateway forwarding traffic to other devices on the VLAN triggered ARP mismatch before the real client's traffic arrived. DolosJS had the same issue but was less likely to hit it due to timing. | Added `_on_different_bridge_ports()` — validates both MACs are learned on different bridge ports via `brctl showmacs`. If a MAC isn't physically attached to the bridge, the mismatch is rejected. |
| **"wpad" / LLMNR as hostname** | LLMNR queries contain names the client is *resolving* (wpad, isatap), not its own hostname. DolosJS didn't do hostname detection at all. | Removed LLMNR as a hostname source entirely. |
| **NBNS query names as hostname** | NBNS outbound queries (dport=137) capture lookup targets, not the client's own name. | Only use NBNS responses (sport=137) which contain the client's registered name. |
| **mDNS query names as hostname** | mDNS queries (QR=0) capture names being looked up. Also captured service types like `_ipps._tcp.local`. | Only use mDNS response announcements (QR=1). Skip names starting with `_`. |
| **"foobar" as hostname** | Our own DHCP probe sends hostname "foobar" which was captured as the client's name. | Filter out "foobar" in DHCP request parser. |
| **VM hostname overwrites host** | VMs using host's MAC pass the client_mac guard, their DHCP requests overwrite the real hostname. | DHCP hostname uses first-write-wins. Manual "Lookup Hostname" (reverse DNS) can always overwrite. |
| **Domain/DNS not populating** | `_dns_search` only ran in phase 3. DHCP replies carrying domain/DNS info arrive during phase 1 (gateway_search) and were missed. | `_dns_search` now runs on every packet regardless of phase. |
| **DNS log spam** | `log.info("DNS server found")` fired on every DNS packet, not just new discoveries. | Removed per-packet logging; `_update_dns` already logs new discoveries. |

### Routing / Networking Bugs

| Issue | What Was Wrong | Fix |
|-------|---------------|-----|
| **DNS lookups failing** | DNS servers outside RFC 1918 ranges (e.g., 129.178.2.1) had no route through the bridge when `replace_default_route=false`. | `update_dns()` adds `ip route replace <dns>/32 via virtual_gw dev mibr` for each discovered DNS server. |
| **resolv.conf overwritten by Tailscale** | Tailscale's MagicDNS (`--accept-dns`, on by default) overwrites `/etc/resolv.conf` immediately after we write discovered DNS servers. | `--accept-dns=false` on Tailscale. Also `chattr +i /etc/resolv.conf` after writing to prevent any service from overwriting. |
| **Pi DNS leaked to corp network** | Discovered DNS servers were written directly to `/etc/resolv.conf`, causing all Pi system traffic (Tailscale, dhclient, etc.) to resolve via corp DNS — visible in DNS logs. | `/etc/resolv.conf` defaults to `8.8.8.8` (via LTE). Discovered corp DNS is saved to `discovered_dns.conf` only. Hostname lookups use `dig @<corp_dns>` directly without changing the system resolver. "Apply DNS" / "Restore DNS" buttons allow manual override with opsec warning. Flush & Shutdown auto-restores to `8.8.8.8`. |
| **DHCP probe missing domain option** | `param_req_list` only requested subnet/router/DNS/MTU/NTP. Didn't ask for option 15 (domain name) or 119 (domain search). | Added options 15 and 119 to the request list. |

### OPSEC / Safety

| Issue | What Was Wrong | Fix |
|-------|---------------|-----|
| **IPv6 link-local leak** | `autoconf=0` and `accept_ra=0` don't prevent kernel from creating `fe80::` link-local addresses. Bridge broadcasts IPv6 neighbor discovery — fingerprintable by IDS. | Added `disable_ipv6=1` on all bridge interfaces. Added `ip6tables -P OUTPUT DROP`. |
| **STP BPDU risk** | Linux bridge STP defaults to off but could be enabled. Enterprise switches with BPDU Guard shut down the port instantly on receiving a BPDU. | Explicit `brctl stp mibr off`. |
| **Gateway ARP expiry when client sleeps** | Sleeping client can't respond to gateway ARP requests. Gateway drops the ARP entry, return traffic stops flowing. | Gratuitous ARP keepalive every 30s on the gateway-facing interface, spoofing the client's MAC/IP. |
| **Tailscale killed on dolospy stop** | `ExecStop` in systemd service ran `tailscale down`, killing remote access. | Removed `tailscale down` from ExecStop. Tailscale runs independently as `tailscaled`. |
| **NTP leaking onto bridge** | `systemd-timesyncd` runs by default and sends NTP queries — after `resolv.conf` rewrite these resolved via corp DNS and routed through the bridge. | `systemd-timesyncd` disabled during setup. |
| **apt auto-updates leaking** | `apt-daily.timer` and `unattended-upgrades` periodically download package metadata — visible as HTTP/HTTPS traffic from the client IP. | `apt-daily.timer`, `apt-daily-upgrade.timer`, and `unattended-upgrades` disabled during setup. |
| **DHCP probe hostname fingerprint** | DHCP Discover included `hostname=foobar` — visible to DHCP servers and packet captures. | Hostname option removed entirely from the DHCP Discover. The server doesn't need it to respond. |
| **Web UI exposed on bridge** | Uvicorn bound to `0.0.0.0:4444`, exposing the FastAPI web UI on the bridge IP (`169.254.66.77`) to the corp network. | Web UI binds to Tailscale IP (`100.x.x.x`) if available, otherwise `127.0.0.1`. Never binds `0.0.0.0`. |

### Code Quality / Stability

| Issue | What Was Wrong | Fix |
|-------|---------------|-----|
| **`once()` double-fire risk** | Wrapper was removed *after* calling the callback. If callback triggered another emit, wrapper could fire again. | Remove wrapper *before* calling callback. |
| **ARP event flood** | `new_arp` was dead code in dolosjs (event name mismatch). DolosPy wired it correctly, causing constant subprocess calls and UI spam for every ARP packet. | `_seen_arp` set deduplicates by `MAC:IP` key. |
| **`network_update` not wired to UI** | `search_domain`, `client_name`, etc. discoveries never pushed to the UI in real time. Only visible on page refresh. | Wired `network_update` → `bridge_update(type=network_info)` → UI `applyNetworkInfo()`. |
| **`lookup_hostname` no UI update** | Set `client_name` directly without emitting `network_update`. UI didn't update until 10s poll. | Emit `network_update` after resolving. |
| **Sniff crash** | Scapy `sniff()` exceptions crashed the sniffer thread silently. | `try/except` around `sniff()` with logging. |
| **2-minute boot delay** | `dhclient` and `tailscale up` blocked in systemd ExecStartPre. | Backgrounded both with `&` and `-timeout 10`. |
