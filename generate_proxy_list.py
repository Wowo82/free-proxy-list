#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""原版抓取脚本的最小改动版：只把「能使用的」纯代理地址写入 proxy.txt。

相对原版的改动：
1. 不再写入「入库时间」，也不再拼接 [机房] / [家宽] / [原生IP] 等地区描述；
   proxy.txt 每行只有一个 协议://IP:端口；
2. 过滤脱敏 IP（含 X / *）、非法端口、私有/保留地址、非白名单协议，并去重；
3. 可选 --check 做 TCP / SOCKS5 存活探测，只写探测成功的节点；
4. 原子写入；抓取失败或零结果时保留原有 proxy.txt，不清空列表。

用法：
    python generate_proxy_list_legacy.py
    python generate_proxy_list_legacy.py --check
    python generate_proxy_list_legacy.py --url=https://proxy-socks5.com/
"""

import ipaddress
import os
import re
import socket
import sys
from pathlib import Path

import requests
from bs4 import BeautifulSoup

URL = "https://tomcat1235.nyc.mn/proxy_list"
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )
}
PROTOCOLS = {"socks5", "socks4", "http", "https"}
MASK_RE = re.compile(r"(?i)(?<![a-z0-9])[x*?]{1,3}(?![a-z0-9])|…|\.{3}|隐藏|脱敏")
NOISE_RE = re.compile(r"(?i)已?复制|copied!?|点击复制|copy")
FULL_URL_RE = re.compile(r"^(socks5|socks4|https?)://([^:/\s]+):(\d+)$", re.I)


def is_usable(protocol: str, ip: str, port: str) -> bool:
    """判断一条记录是否是「能使用的」节点。"""
    if protocol not in PROTOCOLS or not port.isdigit():
        return False
    if not 1 <= int(port) <= 65535:
        return False
    if MASK_RE.search(ip):          # 178.207.X.214 这类脱敏地址不可用
        return False
    try:
        addr = ipaddress.ip_address(ip.strip("[]"))
    except ValueError:
        return False
    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
        return False
    return True


def probe(proxy: str, timeout: float = 2.0) -> bool:
    """TCP 连通性；SOCKS5 额外做无认证握手。"""
    m = re.match(r"^(\w+)://([^:]+):(\d+)$", proxy)
    if not m:
        return False
    scheme, host, port = m.group(1), m.group(2), int(m.group(3))
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if scheme.startswith("socks"):
                sock.sendall(b"\x05\x01\x00")
                reply = sock.recv(2)
                return len(reply) >= 2 and reply[0] == 0x05
            return True
    except (OSError, socket.timeout, ValueError):
        return False


class ProxyListScraper:
    def __init__(self, url: str = URL):
        self.url = url

    def scrape_proxy_list(self):
        """抓取代理列表，返回纯地址字符串列表。"""
        try:
            print(f"正在抓取代理列表: {self.url}")
            response = requests.get(self.url, headers=HEADERS, timeout=(5, 20))
            response.raise_for_status()
            response.encoding = "utf-8"

            soup = BeautifulSoup(response.text, "html.parser")
            proxies, seen = [], set()

            # 页面可能有多张表，逐张扫描，避免取到国家统计表
            for table in soup.find_all("table"):
                for row in table.find_all("tr"):
                    cells = row.find_all("td")
                    if len(cells) < 3:
                        continue

                    protocol = cells[0].get_text(strip=True).lower()
                    ip = NOISE_RE.sub("", cells[1].get_text(" ", strip=True)).strip()
                    port = cells[2].get_text(strip=True)

                    # 兼容整串 URL 写在单个单元格里的表格
                    m = FULL_URL_RE.match(ip)
                    if m:
                        protocol, ip, port = m.group(1).lower(), m.group(2), m.group(3)

                    if not is_usable(protocol, ip, port):
                        continue
                    proxy = f"{protocol}://{ip}:{port}"   # 不带任何描述
                    if proxy in seen:
                        continue
                    seen.add(proxy)
                    proxies.append(proxy)

            print(f"成功抓取到 {len(proxies)} 个可用代理")
            return proxies

        except requests.RequestException as e:
            print(f"网络请求错误: {e}")
            return []
        except Exception as e:
            print(f"抓取错误: {e}")
            return []

    def save_to_file(self, proxies, filename="proxy.txt"):
        """只写纯地址，一行一个；无入库时间、无描述、无注释头。"""
        try:
            path = Path(filename)
            tmp = path.with_name(path.name + ".tmp")
            tmp.write_text("\n".join(proxies) + "\n", encoding="utf-8")
            os.replace(tmp, path)
            print(f"已写入 {len(proxies)} 个可用节点到 {filename}")
            return True
        except Exception as e:
            print(f"保存文件错误: {e}")
            return False


def main():
    check = "--check" in sys.argv
    url = next((a.split("=", 1)[1] for a in sys.argv if a.startswith("--url=")), URL)
    scraper = ProxyListScraper(url)
    proxies = scraper.scrape_proxy_list()

    if check and proxies:
        alive = [p for p in proxies if probe(p)]
        print(f"存活探测: {len(alive)}/{len(proxies)} 个可用")
        proxies = alive

    if proxies:
        # 空结果时不写文件，保留上一次成功的列表
        scraper.save_to_file(proxies)
        print("代理列表抓取完成！")
    else:
        print("未能获取到可用代理，保留原有 proxy.txt")


if __name__ == "__main__":
    main()
