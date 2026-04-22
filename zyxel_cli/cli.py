"""
zyxel-cli — CLI tool for the Zyxel AX7501-B0 router (Digi).

Manage DNS, DHCP static leases, NAT/port forwarding, and query
system status, WAN, and WiFi information via the Zyxel DAL API.

Authentication uses AES-256-CBC + RSA hybrid encryption, based on
the flow documented by the ha-zyxel project:
  https://github.com/zulufoxtrot/ha-zyxel
"""

import argparse
import base64
import json
import os
import sys

import requests
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad


# ---------------------------------------------------------------------------
# Router API client
# ---------------------------------------------------------------------------

class ZyxelRouter:
    """Client for the Zyxel AX7501-B0 DAL API with AES+RSA encryption."""

    def __init__(self, host, username, password):
        self.url = f"http://{host}"
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.aes_key = None
        self.sessionkey = None

    # -- Auth ---------------------------------------------------------------

    def login(self):
        # Step 1: Get session cookie
        self.session.get(f"{self.url}/GetInfoNoLogin", timeout=10)

        # Step 2: Get RSA public key
        r = self.session.get(f"{self.url}/getRSAPublickKey", timeout=10)
        rsa_key_pem = r.json()["RSAPublicKey"]

        # Step 3: Generate AES key and IV
        self.aes_key = os.urandom(32)
        iv = os.urandom(32)

        # Step 4: Build login payload (password is base64-encoded)
        password_b64 = base64.b64encode(self.password.encode("utf-8")).decode("utf-8")
        login_params = {
            "Input_Account": self.username,
            "Input_Passwd": password_b64,
            "currLang": "en",
            "RememberPassword": 0,
        }

        # AES encrypt the login payload
        json_body = json.dumps(login_params, separators=(",", ":")).encode("utf-8")
        cipher_aes = AES.new(self.aes_key, AES.MODE_CBC, iv[:16])
        ciphertext = cipher_aes.encrypt(pad(json_body, 16))

        # RSA encrypt the AES key
        rsa_key_obj = RSA.import_key(rsa_key_pem.encode("utf-8"))
        cipher_rsa = PKCS1_v1_5.new(rsa_key_obj)
        encrypted_aes_key = cipher_rsa.encrypt(base64.b64encode(self.aes_key))

        encrypted_payload = json.dumps({
            "content": base64.b64encode(ciphertext).decode(),
            "key": base64.b64encode(encrypted_aes_key).decode(),
            "iv": base64.b64encode(iv).decode(),
        })

        # Step 5: POST login
        r = self.session.post(
            f"{self.url}/UserLogin",
            data=encrypted_payload.encode("utf-8"),
            headers={"Content-Type": "application/json"},
            timeout=10,
        )

        login_result = self._decrypt_response(r.json())
        if login_result.get("result") != "ZCFG_SUCCESS":
            print(f"Login failed: {login_result.get('result', 'unknown error')}", file=sys.stderr)
            sys.exit(1)

        self.sessionkey = login_result["sessionkey"]

    def logout(self):
        if self.sessionkey:
            try:
                self.session.get(
                    f"{self.url}/cgi-bin/UserLogout?sessionkey={self.sessionkey}",
                    timeout=5,
                )
            except Exception:
                pass

    # -- Crypto -------------------------------------------------------------

    def _decrypt_response(self, resp_json):
        resp_iv = base64.b64decode(resp_json["iv"])[:16]
        cipher = AES.new(self.aes_key, AES.MODE_CBC, resp_iv)
        decrypted = cipher.decrypt(base64.b64decode(resp_json["content"]))
        pad_len = decrypted[-1]
        return json.loads(decrypted[:-pad_len])

    def _encrypt_request(self, data):
        json_body = json.dumps(data, separators=(",", ":")).encode("utf-8")
        new_iv = os.urandom(32)
        cipher = AES.new(self.aes_key, AES.MODE_CBC, new_iv[:16])
        ciphertext = cipher.encrypt(pad(json_body, 16))
        return json.dumps({
            "content": base64.b64encode(ciphertext).decode(),
            "iv": base64.b64encode(new_iv).decode(),
        })

    # -- DAL primitives -----------------------------------------------------

    def _dal_get(self, oid):
        r = self.session.get(
            f"{self.url}/cgi-bin/DAL?oid={oid}&sessionkey={self.sessionkey}",
            timeout=10,
        )
        return self._decrypt_response(r.json())

    def _dal_post(self, oid, data):
        encrypted = self._encrypt_request(data)
        r = self.session.post(
            f"{self.url}/cgi-bin/DAL?oid={oid}&sessionkey={self.sessionkey}",
            data=encrypted.encode("utf-8"),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "CSRFToken": self.sessionkey,
                "If-Modified-Since": "Thu, 01 Jun 1970 00:00:00 GMT",
            },
            timeout=10,
        )
        if r.status_code == 403:
            print("Error: 403 Forbidden (insufficient permissions?)", file=sys.stderr)
            sys.exit(1)
        if not r.text.strip():
            print("Error: empty response from router", file=sys.stderr)
            sys.exit(1)
        return self._decrypt_response(r.json())

    def _dal_delete(self, oid, index):
        encrypted = self._encrypt_request({})
        r = self.session.request(
            "DELETE",
            f"{self.url}/cgi-bin/DAL?oid={oid}&sessionkey={self.sessionkey}&Index={index}",
            data=encrypted.encode("utf-8"),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "CSRFToken": self.sessionkey,
                "If-Modified-Since": "Thu, 01 Jun 1970 00:00:00 GMT",
            },
            timeout=10,
        )
        if r.status_code == 403:
            print("Error: 403 Forbidden", file=sys.stderr)
            sys.exit(1)
        if not r.text.strip():
            print("Error: empty response from router", file=sys.stderr)
            sys.exit(1)
        return self._decrypt_response(r.json())

    # -- Status -------------------------------------------------------------

    def get_status(self):
        objects = self._dal_get("status").get("Object", [])
        return objects[0] if objects else {}

    # -- DNS ----------------------------------------------------------------

    def get_dns_entries(self):
        return self._dal_get("dns").get("Object", [])

    def add_dns_entry(self, hostname, ip):
        result = self._dal_post("dns", {"HostName": hostname, "IPv4Address": ip})
        return result.get("result") == "ZCFG_SUCCESS"

    def delete_dns_entry(self, index):
        result = self._dal_delete("dns", index)
        return result.get("result") == "ZCFG_SUCCESS"

    # -- DHCP static leases -------------------------------------------------

    def get_dhcp_leases(self):
        return self._dal_get("static_dhcp").get("Object", [])

    def add_dhcp_lease(self, mac, ip):
        result = self._dal_post("static_dhcp", {
            "Enable": True,
            "MACAddr": mac,
            "IPAddr": ip,
        })
        return result.get("result") == "ZCFG_SUCCESS"

    def delete_dhcp_lease(self, index):
        result = self._dal_delete("static_dhcp", index)
        return result.get("result") == "ZCFG_SUCCESS"

    # -- NAT / port forwarding ----------------------------------------------

    def get_nat_rules(self):
        return self._dal_get("nat").get("Object", [])

    def add_nat_rule(self, description, ext_port_start, ext_port_end,
                     int_ip, int_port_start, int_port_end, protocol):
        result = self._dal_post("nat", {
            "Enable": True,
            "Description": description,
            "Protocol": protocol,
            "ExternalPortStart": ext_port_start,
            "ExternalPortEnd": ext_port_end,
            "InternalClient": int_ip,
            "InternalPortStart": int_port_start,
            "InternalPortEnd": int_port_end,
        })
        return result.get("result") == "ZCFG_SUCCESS"

    def delete_nat_rule(self, index):
        result = self._dal_delete("nat", index)
        return result.get("result") == "ZCFG_SUCCESS"

    # -- WAN ----------------------------------------------------------------

    def get_wan_info(self):
        return self._dal_get("wan").get("Object", [])

    # -- WiFi ---------------------------------------------------------------

    def get_wifi_info(self):
        return self._dal_get("wlan").get("Object", [])

    # -- Raw OID query ------------------------------------------------------

    def dal_raw(self, oid):
        return self._dal_get(oid)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def humanize_uptime(seconds):
    """Convert seconds to a human-readable string."""
    seconds = int(seconds)
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    if not parts:
        parts.append(f"{seconds}s")
    return " ".join(parts)


def humanize_bytes(b):
    """Convert bytes to human-readable MB/GB."""
    b = int(b)
    if b >= 1024 * 1024 * 1024:
        return f"{b / (1024**3):.1f} GB"
    if b >= 1024 * 1024:
        return f"{b / (1024**2):.1f} MB"
    if b >= 1024:
        return f"{b / 1024:.1f} KB"
    return f"{b} B"


# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------

# -- status -----------------------------------------------------------------

def cmd_status(router, _args):
    status = router.get_status()
    dev = status.get("DeviceInfo", {})
    sys_info = status.get("SystemInfo", {})

    print(f"Model:       {dev.get('Manufacturer', '?')} {dev.get('ModelName', '?')}")
    print(f"Firmware:    {dev.get('SoftwareVersion', '?')}")
    print(f"Serial:      {dev.get('SerialNumber', '?')}")
    print(f"Hostname:    {sys_info.get('HostName', '?')}")
    print(f"Uptime:      {humanize_uptime(dev.get('UpTime', 0))}")

    cpu = sys_info.get("CPUUsage")
    if cpu is not None:
        print(f"CPU:         {cpu}%")

    ram_total = sys_info.get("Total")
    ram_free = sys_info.get("Free")
    if ram_total and ram_free:
        ram_total_kb = int(ram_total)
        ram_free_kb = int(ram_free)
        ram_used_pct = round((1 - ram_free_kb / ram_total_kb) * 100, 1)
        print(f"RAM:         {ram_used_pct}% used ({humanize_bytes(ram_free_kb * 1024)} free of {humanize_bytes(ram_total_kb * 1024)})")

    wan_lan = status.get("WanLanInfo", [])
    if wan_lan:
        up_ifaces = [i.get("Name", "?") for i in wan_lan if i.get("Status") == "Up"]
        if up_ifaces:
            print(f"Interfaces:  {', '.join(up_ifaces)}")

    lan_ports = status.get("LanPortInfo", [])
    if lan_ports:
        up_ports = [p.get("portName", "?") for p in lan_ports if p.get("status") == "Up"]
        if up_ports:
            print(f"LAN ports:   {', '.join(up_ports)}")


# -- dns --------------------------------------------------------------------

def cmd_dns_list(router, _args):
    entries = router.get_dns_entries()
    if not entries:
        print("No DNS entries found.")
        return

    idx_w = max(len(str(e["Index"])) for e in entries)
    host_w = max(len(e["HostName"]) for e in entries)

    print(f"{'#':<{idx_w}}  {'Hostname':<{host_w}}  IP Address")
    print(f"{'-' * idx_w}  {'-' * host_w}  {'-' * 15}")
    for e in entries:
        print(f"{e['Index']:<{idx_w}}  {e['HostName']:<{host_w}}  {e['IPv4Address']}")
    print(f"\n{len(entries)} entries total.")


def cmd_dns_add(router, args):
    entries = router.get_dns_entries()
    for e in entries:
        if e["HostName"] == args.hostname:
            print(f"Entry for '{args.hostname}' already exists (#{e['Index']} -> {e['IPv4Address']})")
            if e["IPv4Address"] == args.ip:
                return
            print("Delete it first if you want to change the IP.", file=sys.stderr)
            sys.exit(1)

    if router.add_dns_entry(args.hostname, args.ip):
        print(f"Added: {args.hostname} -> {args.ip}")
    else:
        print("Failed to add DNS entry.", file=sys.stderr)
        sys.exit(1)


def cmd_dns_delete(router, args):
    if args.index is not None:
        if router.delete_dns_entry(args.index):
            print(f"Deleted entry #{args.index}")
        else:
            print(f"Failed to delete entry #{args.index}", file=sys.stderr)
            sys.exit(1)
    else:
        entries = router.get_dns_entries()
        for e in entries:
            if e["HostName"] == args.hostname:
                if router.delete_dns_entry(e["Index"]):
                    print(f"Deleted: {e['HostName']} -> {e['IPv4Address']} (#{e['Index']})")
                else:
                    print(f"Failed to delete entry for '{args.hostname}'", file=sys.stderr)
                    sys.exit(1)
                return
        print(f"No entry found for '{args.hostname}'", file=sys.stderr)
        sys.exit(1)


def cmd_dns(router, args):
    {"list": cmd_dns_list, "add": cmd_dns_add, "delete": cmd_dns_delete}[args.dns_command](router, args)


# -- dhcp -------------------------------------------------------------------

def cmd_dhcp_list(router, _args):
    leases = router.get_dhcp_leases()
    if not leases:
        print("No static DHCP leases found.")
        return

    idx_w = max(len(str(e["Index"])) for e in leases)
    mac_w = max(len(e.get("MACAddr", "")) for e in leases)

    print(f"{'#':<{idx_w}}  {'MAC Address':<{mac_w}}  {'IP Address':<15}  Enabled")
    print(f"{'-' * idx_w}  {'-' * mac_w}  {'-' * 15}  {'-' * 7}")
    for e in leases:
        enabled = "yes" if e.get("Enable") else "no"
        print(f"{e['Index']:<{idx_w}}  {e.get('MACAddr', ''):<{mac_w}}  {e.get('IPAddr', ''):<15}  {enabled}")
    print(f"\n{len(leases)} leases total.")


def cmd_dhcp_add(router, args):
    mac = args.mac.upper()
    leases = router.get_dhcp_leases()
    for e in leases:
        if e.get("MACAddr", "").upper() == mac:
            print(f"Lease for {mac} already exists (#{e['Index']} -> {e.get('IPAddr', '?')})")
            if e.get("IPAddr") == args.ip:
                return
            print("Delete it first if you want to change the IP.", file=sys.stderr)
            sys.exit(1)

    if router.add_dhcp_lease(mac, args.ip):
        print(f"Added: {mac} -> {args.ip}")
    else:
        print("Failed to add DHCP lease.", file=sys.stderr)
        sys.exit(1)


def cmd_dhcp_delete(router, args):
    if args.index is not None:
        if router.delete_dhcp_lease(args.index):
            print(f"Deleted lease #{args.index}")
        else:
            print(f"Failed to delete lease #{args.index}", file=sys.stderr)
            sys.exit(1)
    else:
        mac = args.mac.upper()
        leases = router.get_dhcp_leases()
        for e in leases:
            if e.get("MACAddr", "").upper() == mac:
                if router.delete_dhcp_lease(e["Index"]):
                    print(f"Deleted: {e['MACAddr']} -> {e.get('IPAddr', '?')} (#{e['Index']})")
                else:
                    print(f"Failed to delete lease for '{mac}'", file=sys.stderr)
                    sys.exit(1)
                return
        print(f"No lease found for '{mac}'", file=sys.stderr)
        sys.exit(1)


def cmd_dhcp(router, args):
    {"list": cmd_dhcp_list, "add": cmd_dhcp_add, "delete": cmd_dhcp_delete}[args.dhcp_command](router, args)


# -- nat --------------------------------------------------------------------

def cmd_nat_list(router, _args):
    rules = router.get_nat_rules()
    if not rules:
        print("No NAT rules found.")
        return

    idx_w = max(len(str(e["Index"])) for e in rules)
    desc_w = max(len(e.get("Description", "")) for e in rules)
    desc_w = max(desc_w, 11)  # min width for header

    print(f"{'#':<{idx_w}}  {'Description':<{desc_w}}  {'Proto':<9}  {'External':<11}  {'Internal':<21}  On")
    print(f"{'-' * idx_w}  {'-' * desc_w}  {'-' * 9}  {'-' * 11}  {'-' * 21}  {'-' * 3}")
    for e in rules:
        ext_start = e.get("ExternalPortStart", "")
        ext_end = e.get("ExternalPortEnd", "")
        ext = str(ext_start) if ext_start == ext_end else f"{ext_start}-{ext_end}"

        int_start = e.get("InternalPortStart", "")
        int_end = e.get("InternalPortEnd", "")
        int_port = str(int_start) if int_start == int_end else f"{int_start}-{int_end}"
        int_full = f"{e.get('InternalClient', '?')}:{int_port}"

        enabled = "yes" if e.get("Enable") else "no"
        proto = e.get("Protocol", "?")

        print(f"{e['Index']:<{idx_w}}  {e.get('Description', ''):<{desc_w}}  {proto:<9}  {ext:<11}  {int_full:<21}  {enabled}")
    print(f"\n{len(rules)} rules total.")


def cmd_nat_add(router, args):
    ext_start = args.ext_port
    ext_end = args.ext_port_end if args.ext_port_end is not None else ext_start
    int_start = args.int_port
    int_end = args.int_port_end if args.int_port_end is not None else int_start

    proto_map = {"tcp": "TCP", "udp": "UDP", "both": "TCP+UDP"}
    protocol = proto_map[args.proto]

    if router.add_nat_rule(args.description, ext_start, ext_end,
                           args.int_ip, int_start, int_end, protocol):
        ext = str(ext_start) if ext_start == ext_end else f"{ext_start}-{ext_end}"
        int_p = str(int_start) if int_start == int_end else f"{int_start}-{int_end}"
        print(f"Added: {args.description} ({protocol}) :{ext} -> {args.int_ip}:{int_p}")
    else:
        print("Failed to add NAT rule.", file=sys.stderr)
        sys.exit(1)


def cmd_nat_delete(router, args):
    if args.index is not None:
        if router.delete_nat_rule(args.index):
            print(f"Deleted rule #{args.index}")
        else:
            print(f"Failed to delete rule #{args.index}", file=sys.stderr)
            sys.exit(1)
    else:
        rules = router.get_nat_rules()
        for e in rules:
            if e.get("Description", "") == args.description:
                if router.delete_nat_rule(e["Index"]):
                    print(f"Deleted: {e['Description']} (#{e['Index']})")
                else:
                    print(f"Failed to delete rule '{args.description}'", file=sys.stderr)
                    sys.exit(1)
                return
        print(f"No rule found with description '{args.description}'", file=sys.stderr)
        sys.exit(1)


def cmd_nat(router, args):
    {"list": cmd_nat_list, "add": cmd_nat_add, "delete": cmd_nat_delete}[args.nat_command](router, args)


# -- wan --------------------------------------------------------------------

def cmd_wan(router, _args):
    interfaces = router.get_wan_info()
    if not interfaces:
        print("No WAN interfaces found.")
        return

    for iface in interfaces:
        name = iface.get("Name", "?")
        print(f"--- {name} ---")
        print(f"  IP:           {iface.get('IPAddress', '?')}")
        print(f"  Subnet:       {iface.get('SubnetMask', '?')}")
        print(f"  Gateway:      {iface.get('GatewayIPAddress', '?')}")
        print(f"  DNS:          {iface.get('DNSServer', '?')}")
        print(f"  Encapsulation:{iface.get('Encapsulation', '?')}")

        vlan = iface.get("VLANID")
        if vlan:
            print(f"  VLAN:         {vlan}")

        ppp_user = iface.get("pppUsername")
        if ppp_user:
            print(f"  PPP user:     {ppp_user}")

        ipv6 = iface.get("IPv6")
        if ipv6:
            print(f"  IPv6:         {ipv6}")

        ip_mode = iface.get("ipMode")
        if ip_mode:
            print(f"  IP mode:      {ip_mode}")

        nat = iface.get("NatEnable")
        if nat is not None:
            print(f"  NAT:          {'enabled' if nat else 'disabled'}")
        print()


# -- wifi -------------------------------------------------------------------

def cmd_wifi(router, _args):
    networks = router.get_wifi_info()
    if not networks:
        print("No WiFi networks found.")
        return

    ssid_w = max(len(e.get("SSID", "")) for e in networks)
    ssid_w = max(ssid_w, 4)

    print(f"{'#':<3}  {'SSID':<{ssid_w}}  {'Band':<6}  {'Ch':<4}  {'BW':<6}  {'Security':<16}  {'Hidden':<6}  On")
    print(f"{'-' * 3}  {'-' * ssid_w}  {'-' * 6}  {'-' * 4}  {'-' * 6}  {'-' * 16}  {'-' * 6}  {'-' * 3}")
    for e in networks:
        enabled = "yes" if e.get("wlEnable") else "no"
        hidden = "yes" if e.get("wlHide") else "no"
        ch = str(e.get("channel", "auto"))
        if e.get("AutoChannelEnable"):
            ch = "auto"
        print(
            f"{e.get('Index', '?'):<3}  "
            f"{e.get('SSID', ''):<{ssid_w}}  "
            f"{e.get('band', '?'):<6}  "
            f"{ch:<4}  "
            f"{e.get('bandwidth', '?'):<6}  "
            f"{e.get('SecurityMode', '?'):<16}  "
            f"{hidden:<6}  "
            f"{enabled}"
        )
    print(f"\n{len(networks)} networks total.")


# -- raw --------------------------------------------------------------------

def cmd_raw(router, args):
    result = router.dal_raw(args.oid)
    print(json.dumps(result, indent=2, ensure_ascii=False))


# ---------------------------------------------------------------------------
# CLI argument parser
# ---------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        prog="zyxel-cli",
        description="CLI tool for the Zyxel AX7501-B0 router (Digi)",
    )
    parser.add_argument("--host", default=os.environ.get("ZYXEL_HOST", "192.168.1.1"))
    parser.add_argument("--user", default=os.environ.get("ZYXEL_USER", "user"))
    parser.add_argument("--password", default=os.environ.get("ZYXEL_PASS", "user"))

    sub = parser.add_subparsers(dest="command", required=True)

    # status
    sub.add_parser("status", help="System status dashboard")

    # dns
    dns_parser = sub.add_parser("dns", help="Manage DNS entries")
    dns_sub = dns_parser.add_subparsers(dest="dns_command", required=True)

    dns_sub.add_parser("list", help="List DNS entries")

    dns_add = dns_sub.add_parser("add", help="Add a DNS entry")
    dns_add.add_argument("hostname", help="Hostname (e.g. trenes.millaguie.net)")
    dns_add.add_argument("ip", help="IPv4 address (e.g. 192.168.1.7)")

    dns_del = dns_sub.add_parser("delete", help="Delete a DNS entry")
    dns_del.add_argument("hostname", nargs="?", help="Hostname to delete")
    dns_del.add_argument("--index", type=int, help="Delete by index number")

    # dhcp
    dhcp_parser = sub.add_parser("dhcp", help="Manage static DHCP leases")
    dhcp_sub = dhcp_parser.add_subparsers(dest="dhcp_command", required=True)

    dhcp_sub.add_parser("list", help="List static DHCP leases")

    dhcp_add = dhcp_sub.add_parser("add", help="Add a static DHCP lease")
    dhcp_add.add_argument("mac", help="MAC address (e.g. AA:BB:CC:DD:EE:FF)")
    dhcp_add.add_argument("ip", help="IPv4 address (e.g. 192.168.1.100)")

    dhcp_del = dhcp_sub.add_parser("delete", help="Delete a static DHCP lease")
    dhcp_del.add_argument("mac", nargs="?", help="MAC address to delete")
    dhcp_del.add_argument("--index", type=int, help="Delete by index number")

    # nat
    nat_parser = sub.add_parser("nat", help="Manage NAT/port forwarding rules")
    nat_sub = nat_parser.add_subparsers(dest="nat_command", required=True)

    nat_sub.add_parser("list", help="List NAT rules")

    nat_add = nat_sub.add_parser("add", help="Add a NAT rule")
    nat_add.add_argument("description", help="Rule description")
    nat_add.add_argument("ext_port", type=int, help="External port start")
    nat_add.add_argument("int_ip", help="Internal IP address")
    nat_add.add_argument("int_port", type=int, help="Internal port start")
    nat_add.add_argument("--ext-port-end", type=int, help="External port end (default: same as start)")
    nat_add.add_argument("--int-port-end", type=int, help="Internal port end (default: same as start)")
    nat_add.add_argument("--proto", choices=["tcp", "udp", "both"], default="both",
                         help="Protocol (default: both)")

    nat_del = nat_sub.add_parser("delete", help="Delete a NAT rule")
    nat_del.add_argument("description", nargs="?", help="Rule description to delete")
    nat_del.add_argument("--index", type=int, help="Delete by index number")

    # wan
    sub.add_parser("wan", help="Show WAN / public IP info")

    # wifi
    sub.add_parser("wifi", help="Show WiFi SSIDs and settings")

    # raw
    raw_parser = sub.add_parser("raw", help="Query any DAL OID (raw JSON output)")
    raw_parser.add_argument("oid", help="OID name (e.g. lan, firewall, gpon)")

    return parser


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = build_parser()
    args = parser.parse_args()

    # Validate delete commands that need either a name or --index
    if args.command == "dns" and args.dns_command == "delete":
        if not args.hostname and args.index is None:
            parser.error("dns delete requires either a hostname or --index")
    if args.command == "dhcp" and args.dhcp_command == "delete":
        if not args.mac and args.index is None:
            parser.error("dhcp delete requires either a MAC address or --index")
    if args.command == "nat" and args.nat_command == "delete":
        if not args.description and args.index is None:
            parser.error("nat delete requires either a description or --index")

    dispatch = {
        "status": cmd_status,
        "dns": cmd_dns,
        "dhcp": cmd_dhcp,
        "nat": cmd_nat,
        "wan": cmd_wan,
        "wifi": cmd_wifi,
        "raw": cmd_raw,
    }

    router = ZyxelRouter(args.host, args.user, args.password)
    try:
        router.login()
        dispatch[args.command](router, args)
    finally:
        router.logout()


if __name__ == "__main__":
    main()
