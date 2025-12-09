#!/usr/bin/env python3
#   cloudflare-ddns.py
#   Summary: Access your home network remotely via a custom domain name without a static IP!
#   Description: Access your home network remotely via a custom domain
#                Access your home network remotely via a custom domain
#                A small, 🕵️ privacy centric, and ⚡
#                lightning fast multi-architecture Docker image for self hosting projects.

__version__ = "1.0.2"

import json
import os
import signal
import sys
import threading
import time
import requests
import logging

# Add project root to the Python path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, PROJECT_ROOT)

from scripts.config import load_config

# Set up logging
LOG_DIR = os.path.join(PROJECT_ROOT, 'logs')
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
log_file = os.path.join(LOG_DIR, 'ddns.log')

file_handler = logging.FileHandler(log_file)
file_handler.setFormatter(log_formatter)

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(log_formatter)

logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.addHandler(file_handler)
logger.addHandler(console_handler)


class GracefulExit:
    def __init__(self):
        self.kill_now = threading.Event()
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)

    def exit_gracefully(self, signum, frame):
        logger.info("🛑 Stopping main thread...")
        self.kill_now.set()


def deleteEntries(type):
    for option in config["cloudflare"]:
        answer = cf_api(
            "zones/" + option['zone_id'] +
            "/dns_records?per_page=100&type=" + type,
            "GET", option)
        if answer is None or answer["result"] is None:
            time.sleep(5)
            return
        for record in answer["result"]:
            identifier = str(record["id"])
            cf_api(
                "zones/" + option['zone_id'] + "/dns_records/" + identifier,
                "DELETE", option)
            logger.info(f"🗑️ Deleted stale record {identifier}")


def getIPs():
    a = None
    aaaa = None
    global ipv4_enabled
    global ipv6_enabled
    global purgeUnknownRecords
    if ipv4_enabled:
        try:
            a = requests.get(
                "https://1.1.1.1/cdn-cgi/trace").text.split("\n")
            a.pop()
            a = dict(s.split("=") for s in a)["ip"]
        except Exception:
            logger.warning("🧩 IPv4 not detected via 1.1.1.1, trying 1.0.0.1")
            try:
                a = requests.get(
                    "https://1.0.0.1/cdn-cgi/trace").text.split("\n")
                a.pop()
                a = dict(s.split("=") for s in a)["ip"]
            except Exception:
                logger.warning("🧩 IPv4 not detected via 1.0.0.1. Verify your ISP or DNS provider isn't blocking Cloudflare's IPs.")
                if purgeUnknownRecords:
                    deleteEntries("A")
    if ipv6_enabled:
        try:
            aaaa = requests.get(
                "https://[2606:4700:4700::1111]/cdn-cgi/trace").text.split("\n")
            aaaa.pop()
            aaaa = dict(s.split("=") for s in aaaa)["ip"]
        except Exception:
            logger.warning("🧩 IPv6 not detected via 1.1.1.1, trying 1.0.0.1")
            try:
                aaaa = requests.get(
                    "https://[2606:4700:4700::1001]/cdn-cgi/trace").text.split("\n")
                aaaa.pop()
                aaaa = dict(s.split("=") for s in aaaa)["ip"]
            except Exception:
                logger.warning("🧩 IPv6 not detected via 1.0.0.1. Verify your ISP or DNS provider isn't blocking Cloudflare's IPs.")
                if purgeUnknownRecords:
                    deleteEntries("AAAA")
    ips = {}
    if (a is not None):
        ips["ipv4"] = {
            "type": "A",
            "ip": a
        }
    if (aaaa is not None):
        ips["ipv6"] = {
            "type": "AAAA",
            "ip": aaaa
        }
    return ips


def commitRecord(ip):
    global ttl
    for option in config["cloudflare"]:
        subdomains = option["subdomains"]
        response = cf_api("zones/" + option['zone_id'], "GET", option)
        if response is None or response["result"]["name"] is None:
            time.sleep(5)
            return
        base_domain_name = response["result"]["name"]
        for subdomain in subdomains:
            try:
                name = subdomain["name"].lower().strip()
                proxied = subdomain["proxied"]
            except:
                name = subdomain
                proxied = option["proxied"]
            fqdn = base_domain_name
            if name != '' and name != '@':
                fqdn = name + "." + base_domain_name
            record = {
                "type": ip["type"],
                "name": fqdn,
                "content": ip["ip"],
                "proxied": proxied,
                "ttl": ttl
            }
            dns_records = cf_api(
                "zones/" + option['zone_id'] +
                "/dns_records?per_page=100&type=" + ip["type"],
                "GET", option)
            identifier = None
            modified = False
            duplicate_ids = []
            if dns_records is not None:
                for r in dns_records["result"]:
                    if (r["name"] == fqdn):
                        if identifier:
                            if r["content"] == ip["ip"]:
                                duplicate_ids.append(identifier)
                                identifier = r["id"]
                            else:
                                duplicate_ids.append(r["id"])
                        else:
                            identifier = r["id"]
                            if r['content'] != record['content'] or r['proxied'] != record['proxied']:
                                modified = True
            if identifier:
                if modified:
                    logger.info(f"📡 Updating record: {record['type']} {record['name']} -> {record['content']}")
                    cf_api(
                        "zones/" + option['zone_id'] +
                        "/dns_records/" + identifier,
                        "PUT", option, {}, record)
            else:
                logger.info(f"➕ Adding new record: {record['type']} {record['name']} -> {record['content']}")
                cf_api(
                    "zones/" + option['zone_id'] + "/dns_records", "POST", option, {}, record)
            if purgeUnknownRecords:
                for id_to_delete in duplicate_ids:
                    id_to_delete = str(id_to_delete)
                    logger.info(f"🗑️ Deleting stale record {id_to_delete}")
                    cf_api(
                        "zones/" + option['zone_id'] +
                        "/dns_records/" + id_to_delete,
                        "DELETE", option)
    return True


def cf_api(endpoint, method, config, headers={}, data=False):
    auth = config.get('authentication', {})
    api_token = auth.get('api_token')
    
    headers = headers.copy()
    if api_token and api_token != 'api_token_here':
        headers["Authorization"] = "Bearer " + api_token
    elif 'api_key' in auth:
        headers["X-Auth-Email"] = auth['api_key'].get('account_email')
        headers["X-Auth-Key"] = auth['api_key'].get('api_key')

    try:
        url = "https://api.cloudflare.com/client/v4/" + endpoint
        if data:
            response = requests.request(method, url, headers=headers, json=data)
        else:
            response = requests.request(method, url, headers=headers)

        if response.ok:
            return response.json()
        else:
            logger.error(f"😡 Error sending '{method}' request to '{response.url}':")
            logger.error(response.text)
            return None
    except Exception as e:
        logger.error(f"😡 An exception occurred: {e}")
        return None


def updateIPs(ips):
    for ip in ips.values():
        commitRecord(ip)


if __name__ == '__main__':
    ipv4_enabled = True
    ipv6_enabled = True
    purgeUnknownRecords = False
    ttl = 300

    if sys.version_info < (3, 5):
        logger.critical("🐍 This script requires Python 3.5+")
        sys.exit(1)

    config = load_config()
    if not config:
        logger.error("😡 Error reading configuration.")
        time.sleep(10)
        sys.exit(1)

    ipv4_enabled = config.get("a", True)
    ipv6_enabled = config.get("aaaa", True)
    purgeUnknownRecords = config.get("purgeUnknownRecords", False)
    ttl = int(config.get("ttl", 300))

    if ttl < 30:
        ttl = 1
        logger.info("⚙️ TTL is too low - defaulting to 1 (auto)")

    if len(sys.argv) > 1 and sys.argv[1] == "--repeat":
        logger.info(f"🕰️ Updating records every {ttl} seconds (IPv4: {ipv4_enabled}, IPv6: {ipv6_enabled})")
        killer = GracefulExit()
        while not killer.kill_now.wait(ttl):
            updateIPs(getIPs())
    else:
        updateIPs(getIPs())
