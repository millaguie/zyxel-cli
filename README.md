# zyxel-cli

CLI tool for managing the **Zyxel AX7501-B0** router (Digi ISP) via the DAL API.

## Credits

The authentication flow (AES-256-CBC + RSA hybrid encryption) is based on the
reverse-engineering work from the **ha-zyxel** project:
- https://github.com/zulufoxtrot/ha-zyxel

## Requirements

- Python 3.8+
- `requests`
- `pycryptodome`

```bash
pip install requests pycryptodome
```

## Configuration

Set environment variables or use command-line flags:

| Variable | Flag | Default |
|----------|------|---------|
| `ZYXEL_HOST` | `--host` | `192.168.1.1` |
| `ZYXEL_USER` | `--user` | `user` |
| `ZYXEL_PASS` | `--password` | `user` |

## Usage

### System status

```bash
zyxel-cli status
```

Shows model, firmware, serial number, uptime, CPU/RAM usage, and active ports.

### DNS management

```bash
zyxel-cli dns list
zyxel-cli dns add trenes.millaguie.net 192.168.1.7
zyxel-cli dns delete trenes.millaguie.net
zyxel-cli dns delete --index 5
```

### Static DHCP leases

```bash
zyxel-cli dhcp list
zyxel-cli dhcp add AA:BB:CC:DD:EE:FF 192.168.1.100
zyxel-cli dhcp delete AA:BB:CC:DD:EE:FF
zyxel-cli dhcp delete --index 3
```

### NAT / port forwarding

```bash
zyxel-cli nat list
zyxel-cli nat add "Web Server" 80 192.168.1.10 80 --proto tcp
zyxel-cli nat add "Game" 27015 192.168.1.50 27015 --proto udp
zyxel-cli nat add "Range" 8000 192.168.1.10 8000 --ext-port-end 8010 --int-port-end 8010
zyxel-cli nat delete "Web Server"
zyxel-cli nat delete --index 2
```

### WAN / public IP

```bash
zyxel-cli wan
```

Shows IP address, gateway, DNS servers, encapsulation, VLAN, PPP info, and IPv6.

### WiFi information

```bash
zyxel-cli wifi
```

Shows all SSIDs with band, channel, bandwidth, security mode, and visibility.

### Raw OID query

```bash
zyxel-cli raw lan
zyxel-cli raw firewall
zyxel-cli raw gpon
```

Queries any DAL OID and prints the raw JSON response. Useful for exploring
undocumented features.

## DAL API — Known OIDs

The Zyxel DAL (Device Abstraction Layer) API exposes data via OIDs queried at:

```
GET /cgi-bin/DAL?oid=<OID>&sessionkey=<KEY>
```

All requests and responses are AES-256-CBC encrypted.

### OIDs with data (tested on AX7501-B0, firmware V5.17)

| OID | Description | Managed by zyxel-cli |
|-----|-------------|---------------------|
| `status` | System dashboard (model, firmware, uptime, CPU, RAM, ports) | `status` |
| `dns` | DNS host overrides (split-horizon) | `dns` |
| `static_dhcp` | Static DHCP reservations | `dhcp` |
| `nat` | NAT / port forwarding rules | `nat` |
| `wan` | WAN interfaces (IP, gateway, DNS, PPP, IPv6) | `wan` |
| `wlan` | WiFi SSIDs and radio settings | `wifi` |
| `lan` | LAN interfaces and DHCP server config | `raw lan` |
| `firewall` | Firewall rules and levels | `raw firewall` |
| `macfilter` | MAC address filtering | `raw macfilter` |
| `qos` | QoS settings | `raw qos` |
| `ddns` | Dynamic DNS configuration | `raw ddns` |
| `time` | NTP and timezone settings | `raw time` |
| `gpon` | GPON/fiber stats (Rx/Tx power, ONU state) | `raw gpon` |
| `wps` | WPS settings | `raw wps` |
| `snmp` | SNMP configuration | `raw snmp` |

### OIDs tested but empty/error

The following OIDs were tested and returned no data or errors. They may work
on other firmware versions or with different configurations:

```
acl, account, auto_provision, bandwidth_mgmt, cellular, certificate,
classfy, content_filter, dhcpv6, disk, dns_route, dsl, dyndns, email,
ethwan, ftpd, guest_wifi, home_auto, httpd, ipsec, ipv6, log, loopback,
mcast, mesh, nat_passthrough, network_map, noti, openvpn, parental,
port_trigger, pptp, ripd, routing, schedulerule, skin, sshd, storage,
switch, tr069, trust_domain, upnp, url_filter, usb, voip, vpn,
wifisonc, wlan_macfilter, wlan_scheduler, wwan, zebra
```

### Discovering new OIDs

1. Use `zyxel-cli raw <oid>` to query any OID
2. The response includes a `result` field: `ZCFG_SUCCESS` means the OID exists
3. Data is in the `Object` field (list of entries or a single dict)
4. The router web UI can also reveal OIDs — inspect network requests in
   browser DevTools (the DAL endpoint paths contain the OID names)
5. POST to create entries, DELETE with `&Index=N` to remove them
