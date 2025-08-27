#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import ipaddress
import subprocess
import qrcode
from pathlib import Path
from xml.dom import minidom
from suds.client import Client

#########################################################################################
#                                  Configuration                                        #
#########################################################################################

class Configuration:
    def __init__(self, ServerId, ServerIP, SecretKey, IpPrefix, Port, SaveDir, ApiUrl):
        self.ServerId = ServerId
        self.ServerIP = ServerIP
        self.SecretKey = SecretKey
        self.IpPrefix = IpPrefix
        self.Port = Port
        self.SaveDir = SaveDir
        self.ApiUrl = ApiUrl

    def LoadConfiguration():
        filedir = os.path.dirname(os.path.realpath(__file__))
        doc = minidom.parse(filedir + "/config.xml")
        config = doc.getElementsByTagName("config")[0]
        serverId = config.getElementsByTagName("ServerId")[0].firstChild.data
        serverIP = config.getElementsByTagName("ServerIP")[0].firstChild.data
        secretKey = config.getElementsByTagName("SecretKey")[0].firstChild.data
        ipPrefix = config.getElementsByTagName("IpPrefix")[0].firstChild.data
        port = config.getElementsByTagName("Port")[0].firstChild.data
        saveDir = config.getElementsByTagName("SaveDir")[0].firstChild.data
        apiUrl = config.getElementsByTagName("APIUrl")[0].firstChild.data
        return Configuration(serverId, serverIP, secretKey, ipPrefix, port, saveDir, apiUrl)

#########################################################################################
#                                     Models                                            #
#########################################################################################

class KeyInfo:
    def __init__(self, TicketId, KeyName, Email):
        self.TicketId = TicketId
        self.KeyName = KeyName
        self.Email = Email

#########################################################################################
#                                  Constants                                            #
#########################################################################################

WG_INTERFACE = "wg0"
CLIENT_DNS = "1.1.1.1"
CLIENT_ALLOWED_IPS = "0.0.0.0/0, ::/0"
PERSISTENT_KEEPALIVE = 25

#########################################################################################
#                                  Helpers                                              #
#########################################################################################

def run(cmd, capture=False):
    if capture:
        return subprocess.check_output(cmd, shell=True, text=True).strip()
    return subprocess.call(cmd, shell=True)

def ensure_dir(p):
    Path(p).mkdir(parents=True, exist_ok=True)

def wg_show_dump():
    try:
        return run(f"wg show {WG_INTERFACE} dump", capture=True)
    except subprocess.CalledProcessError:
        return ""

def list_used_ips():
    dump = wg_show_dump()
    used = set()
    if not dump:
        return used
    for line in dump.splitlines():
        parts = line.split('\t')
        if len(parts) < 5:
            continue
        allowed = parts[4]
        for cidr in allowed.split(','):
            try:
                net = ipaddress.ip_network(cidr.strip(), strict=False)
                if isinstance(net, ipaddress.IPv4Network) and net.prefixlen == 32:
                    used.add(str(net.network_address))
            except ValueError:
                pass
    return used

def next_available_ip(ip_prefix: str) -> str:
    used = list_used_ips()
    base = ip_prefix.rstrip('.')
    for last in range(2, 255):
        candidate = f"{base}{last}"
        if candidate not in used:
            return candidate
    raise RuntimeError("No free IP available")

def server_public_key():
    return run(f"wg show {WG_INTERFACE} public-key", capture=True)

#########################################################################################
#                                  API                                                  #
#########################################################################################

def GetTicketInfo(requestInfo):
    client = Client(API_URL)
    result = client.service.GetInstructionInfoList(AUTH_INFO, requestInfo)
    ticketInfoLst = []
    if not result.InstructionList:
        return ticketInfoLst
    for instList in result.InstructionList:
        for inst in instList[1]:
            ticketId = inst[0]
            keyName = inst[2]
            email = inst[3]
            ticketInfoLst.append(KeyInfo(ticketId, keyName, email))
    return ticketInfoLst

def UpdateTicketInfo(ticketInfo):
    client = Client(API_URL)
    client.service.CompleteInstructionTicket(AUTH_INFO, ticketInfo.TicketId, SERVER_ID)
    print('Updated')

def ReadConfig(path):
    with open(path, 'r') as f:
        return f.read()

def SendKey(ticketInfo, conf_path, qr_path=None):
    print('Sending to API...')

    # read .conf file content
    conf_content = ReadConfig(conf_path)

    keyfiles = [
        {
            'KeyContent': conf_content,
            'KeyName': os.path.basename(conf_path)
        }
    ]

    # if QR code exists, attach it as binary (convert to base64 if API expects text)
    if qr_path and os.path.exists(qr_path):
        with open(qr_path, "rb") as f:
            qr_bytes = f.read()
        keyfiles.append({
            'KeyContent': qr_bytes.decode("latin1"),   # or use base64.b64encode(qr_bytes).decode()
            'KeyName': os.path.basename(qr_path)
        })

    # prepare payload
    emailSendInfo = {
        'ServerID': SERVER_ID,
        'Email': ticketInfo.Email,
        'Subject': 'WireGuard by IT-Solution',
        'KeyFiles': keyfiles
    }

    # send to API
    client = Client(API_URL)
    client.service.SendMultipleKey(AUTH_INFO, emailSendInfo)

    print('Complete...')

#########################################################################################
#                                  WG Operations                                        #
#########################################################################################

def revoke_peer(name: str, peers_dir: Path):
    peer_dir = peers_dir / name
    if not peer_dir.exists():
        return
    pub_path = peer_dir / "pubkey"
    if pub_path.exists():
        pubkey = pub_path.read_text().strip()
        run(f"wg set {WG_INTERFACE} peer {pubkey} remove")
    run(f"wg-quick save {WG_INTERFACE}")
    for f in peer_dir.glob("*"):
        f.unlink(missing_ok=True)
    peer_dir.rmdir()

def generate_peer(ticketInfo):
    name = ticketInfo.KeyName
    peers_dir = Path(HOME_DIR)
    ensure_dir(peers_dir)
    peer_dir = peers_dir / name
    ensure_dir(peer_dir)

    privkey = run("wg genkey", capture=True)
    pubkey = run(f"echo '{privkey}' | wg pubkey", capture=True)
    psk = run("wg genpsk", capture=True)

    (peer_dir / "privkey").write_text(privkey + "\n")
    (peer_dir / "pubkey").write_text(pubkey + "\n")
    (peer_dir / "psk").write_text(psk + "\n")

    client_ip = next_available_ip(IP_PREFIX)
    (peer_dir / "ip").write_text(client_ip + "\n")

    run(f"wg set {WG_INTERFACE} peer {pubkey} preshared-key {peer_dir/'psk'} allowed-ips {client_ip}/32")
    run(f"wg-quick save {WG_INTERFACE}")

    server_pub = server_public_key()
    endpoint = f"{SERVER_IP}:{SERVER_PORT}"
    client_conf = f"""[Interface]
PrivateKey = {privkey}
Address = {client_ip}/32
DNS = {CLIENT_DNS}

[Peer]
PublicKey = {server_pub}
PresharedKey = {psk}
AllowedIPs = {CLIENT_ALLOWED_IPS}
Endpoint = {endpoint}
PersistentKeepalive = {PERSISTENT_KEEPALIVE}
"""

    conf_filename = f"WG-{name}.conf"
    conf_path = str(Path(HOME_DIR) / conf_filename)
    with open(conf_path, "w") as f:
        f.write(client_conf)

    qr_path = str(Path(HOME_DIR) / f"WG-{name}.png")
    img = qrcode.make(client_conf)
    img.save(qr_path)

    print(f"Generated {conf_path} and QR {qr_path}")
    return conf_path, qr_path

#########################################################################################
#                                  Processes                                            #
#########################################################################################

def StartRegistrationProcess():
    ticketInfoLst = GetTicketInfo(REGISTER_REQ_INFO)
    for ticketInfo in ticketInfoLst:
        conf_path, qr_path = generate_peer(ticketInfo)
        UpdateTicketInfo(ticketInfo)
        SendKey(ticketInfo, conf_path, qr_path)

def StartDeleteProcess():
    ticketInfoLst = GetTicketInfo(DELETE_REQ_INFO)
    for ticketInfo in ticketInfoLst:
        revoke_peer(ticketInfo.KeyName, Path(HOME_DIR))
        UpdateTicketInfo(ticketInfo)
        print('Deleted')

#########################################################################################
#                                  Entry Point                                          #
#########################################################################################

config = Configuration.LoadConfiguration()
SERVER_ID = config.ServerId
SERVER_IP = config.ServerIP
SECRET_KEY = config.SecretKey
IP_PREFIX = config.IpPrefix
SERVER_PORT = config.Port
HOME_DIR = config.SaveDir
API_URL = config.ApiUrl

AUTH_INFO = {'UserID': 'APIUser', 'Password': '2017hacker'}
REGISTER_REQ_INFO = {'ServerID': SERVER_ID, 'CommandCode': 101}
DELETE_REQ_INFO   = {'ServerID': SERVER_ID, 'CommandCode': 103}

if __name__ == "__main__":
    StartRegistrationProcess()
    StartDeleteProcess()
