import requests
import re
import json
from urllib.parse import urlparse
from datetime import datetime
import os

# 定义广告过滤器URL列表
URL_LIST = [
"https://raw.githubusercontent.com/cabrata/blacklist-hosts/refs/heads/main/hosts/porn/stevenblack-hosts.txt",
"https://raw.githubusercontent.com/cabrata/blacklist-hosts/refs/heads/main/hosts/fakenews/stevenblack-hosts.txt",
"https://raw.githubusercontent.com/cabrata/blacklist-hosts/refs/heads/main/hosts/gambling/stevenblack-hosts.txt",
"https://raw.githubusercontent.com/cabrata/blacklist-hosts/refs/heads/main/hosts/ads-track/adguard.txt",
"https://raw.githubusercontent.com/NotaInutilis/Super-SEO-Spam-Suppressor/refs/heads/main/adblock.txt",
"https://raw.githubusercontent.com/execute-darker/darkerADS/refs/heads/main/data/rules/adblock.txt",
"https://raw.githubusercontent.com/taichikuji/youtube-ads-4-adaway/refs/heads/main/hosts",
"https://raw.githubusercontent.com/eternity5/ChinaList-For-AdguardHome/refs/heads/main/ChinaList.txt",
"https://raw.githubusercontent.com/rcz0315/AdBlock-list-backup/refs/heads/master/merged_abp_filters.txt",
"https://raw.githubusercontent.com/nero-dv/adguard_combined_lists/refs/heads/main/adguard_combined_list.txt",
"https://raw.githubusercontent.com/MkQtS/MyAdList/refs/heads/main/urlparam.txt",
"https://raw.githubusercontent.com/MkQtS/MyAdList/refs/heads/main/ubolist.txt",
"https://raw.githubusercontent.com/MkQtS/MyAdList/refs/heads/main/moblist.txt",
"https://raw.githubusercontent.com/MkQtS/MyAdList/refs/heads/main/easyrules.txt",
"https://raw.githubusercontent.com/MkQtS/MyAdList/refs/heads/main/dnsblock.txt",
"https://raw.githubusercontent.com/jhassine/server-ip-addresses/refs/heads/master/data/datacenters.txt",
"https://raw.githubusercontent.com/peter9811/ad_filter2hosts/refs/heads/main/hosts_filtered.txt",
"https://raw.githubusercontent.com/hyder365/combined-dns-list/refs/heads/master/combined.txt",
"https://raw.githubusercontent.com/HyRespt/AD-List-Merger/refs/heads/main/duplicate_addresses.txt",
"https://raw.githubusercontent.com/HyRespt/AD-List-Merger/refs/heads/main/combined_blocklist.txt",
"https://raw.githubusercontent.com/zhiyuan1i/adblock_list/refs/heads/master/adblock_privacy.txt",
"https://raw.githubusercontent.com/caleee/adguardhome_filter_list/refs/heads/main/filters/filter.txt",
"https://raw.githubusercontent.com/ppfeufer/adguard-filter-list/refs/heads/master/blocklist",
"https://raw.githubusercontent.com/AristonPost/AdList/refs/heads/main/fake-news-hosts",
"https://raw.githubusercontent.com/az4399/ad_list/refs/heads/main/ad.txt",
"https://raw.githubusercontent.com/hululu1068/AdGuard-Rule/refs/heads/main/rule/all.txt",
"https://raw.githubusercontent.com/5whys-adblock/AdGuardHome-rules/refs/heads/main/rules/output_super.txt",
"https://raw.githubusercontent.com/BlueSkyXN/AdGuardHomeRules/refs/heads/master/all.txt",
"https://raw.githubusercontent.com/caidiekeji/adguard-auto-rules/refs/heads/main/adguard-rules.txt",
"https://raw.githubusercontent.com/siankatabg/FuFu-AdGuard-blacklist/refs/heads/master/fufu-adguard-blacklist.txt",
"https://raw.githubusercontent.com/IMAiCool/AdGuardHome-rules/refs/heads/main/output/BlackList.txt",
"https://raw.githubusercontent.com/DevShubam/Filters/refs/heads/main/gambling/gambling-combined-part1.txt",
"https://raw.githubusercontent.com/DevShubam/Filters/refs/heads/main/gambling/gambling-combined.txt",
"https://raw.githubusercontent.com/DevShubam/Filters/refs/heads/main/nsfw/nsfw_combined.txt",
"https://raw.githubusercontent.com/DevShubam/Filters/refs/heads/main/nsfw/nsfw_combined-part4.txt",
"https://raw.githubusercontent.com/DevShubam/Filters/refs/heads/main/nsfw/nsfw_combined-part3.txt",
"https://raw.githubusercontent.com/DevShubam/Filters/refs/heads/main/nsfw/nsfw_combined-part2.txt",
"https://raw.githubusercontent.com/DevShubam/Filters/refs/heads/main/nsfw/nsfw_combined-part1.txt",
"https://raw.githubusercontent.com/KnightmareVIIVIIXC/AIO-Firebog-Blocklists/main/lists/aiofirebog.txt",
"https://objects.githubusercontent.com/github-production-release-asset-2e65be/485397099/e9d2ecf2-565e-4979-91a8-1806801975bb?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=releaseassetproduction%2F20250709%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250709T162558Z&X-Amz-Expires=1800&X-Amz-Signature=8f06cfb0b86df06f91be3a4840e1aeb1493509afcc7abce0900aaca9f08d7b5d&X-Amz-SignedHeaders=host&response-content-disposition=attachment%3B%20filename%3DCherrygram-9.4.0-TG-11.13.0-arm64-v8a.apk&response-content-type=application%2Fvnd.android.package-archive",
"https://raw.githubusercontent.com/KnightmareVIIVIIXC/Personal-List/refs/heads/main/dns_disallowed_clients.txt",
"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
"https://raw.githubusercontent.com/aarakh/hosts/refs/heads/master/hosts",
"https://raw.githubusercontent.com/skyhigh24/BlockList/refs/heads/main/GravityExport.txt",
"https://raw.githubusercontent.com/r0xd4n3t/pihole-adblock-lists/refs/heads/main/pihole_adlists.txt",
"https://raw.githubusercontent.com/Max-Pare/pihole-adlist-merged/refs/heads/main/merged.txt",
"https://raw.githubusercontent.com/DiegoRamil/pihole-blocklist/refs/heads/main/ads.txt",
"https://media.githubusercontent.com/media/UninvitedActivity/PiHoleLists/refs/heads/main/NRD/NRD-07_All.nrd",
"https://raw.githubusercontent.com/jtbrough/pihole-hosts/refs/heads/main/firebog-ticked-hosts",
"https://raw.githubusercontent.com/musdx/blist/refs/heads/master/blocklist.txt",
"https://raw.githubusercontent.com/FreeZoneAT/pihole-blocklist/refs/heads/main/smartblock_part3.txt",
"https://raw.githubusercontent.com/FreeZoneAT/pihole-blocklist/refs/heads/main/smartblock_part2.txt",
"https://raw.githubusercontent.com/FreeZoneAT/pihole-blocklist/refs/heads/main/smartblock_part1.txt",
"https://raw.githubusercontent.com/Bastiaantjuhh/hostfile-merge/refs/heads/main/hostfiles/blacklist.txt",
"https://objects.githubusercontent.com/github-production-release-asset-2e65be/882358246/c0dd6b55-d5a2-4520-acfd-df1b783946df?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=releaseassetproduction%2F20250709%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250709T121535Z&X-Amz-Expires=1800&X-Amz-Signature=ec115f97eb3dd11623d89cb0177ef137961688bb7e3024ca6358aaa31301e695&X-Amz-SignedHeaders=host&response-content-disposition=attachment%3B%20filename%3DPiHoleClient_1.4.0_Android.apk&response-content-type=application%2Fvnd.android.package-archive",
"https://raw.githubusercontent.com/Melting-Core-Studios/Blocklists/refs/heads/main/AdBlocking/adblock.txt",
"https://raw.githubusercontent.com/Melting-Core-Studios/Blocklists/refs/heads/main/Tracking_blocklist/full_anti_track.txt",
"https://objects.githubusercontent.com/github-production-release-asset-2e65be/722153127/89c25b46-4c0b-458e-999f-3670e92a04ce?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=releaseassetproduction%2F20250708%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250708T171417Z&X-Amz-Expires=1800&X-Amz-Signature=5ece31761b9debb27ce3e12ab9f08270ca46031b82f559c9eb2f2a239843b7cc&X-Amz-SignedHeaders=host&response-content-disposition=attachment%3B%20filename%3DAdGuardHomeForRoot_arm64.zip&response-content-type=application%2Foctet-stream",
"https://raw.githubusercontent.com/zhiyuan1i/adblock_list/refs/heads/master/adblock_privacy.txt",
"https://raw.githubusercontent.com/zhiyuan1i/adblock_list/refs/heads/master/adblock_plus.txt",
"https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/dns.txt",
"https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/all.txt",
"https://raw.githubusercontent.com/Chaniug/FilterFusion/main/dist/adblock-main.txt",
"https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/gambling.txt",
"https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/ultimate.txt",
"https://raw.githubusercontent.com/Aloazny/Aloazny_Adblock/main/Rules/Adblock_Chinese.txt"

]

# 日志文件路径
LOG_FILE = "adblock_log.txt"
OUTPUT_FILE = "adblock_reject6.yaml"  # Mihomo 使用的 YAML 格式

def is_valid_dns_domain(domain):
    """验证域名是否符合DNS规范"""
    if len(domain) > 253:
        return False
    
    labels = domain.split('.')
    for label in labels:
        if not label or len(label) > 63:
            return False
        if not re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$", label):
            return False
    
    tld = labels[-1]
    if not re.match(r"^[a-zA-Z]{2,}$", tld):
        return False
    
    return True

def download_rules(url):
    """下载规则并返回内容"""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }
    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        return response.text
    except Exception as e:
        log_message(f"处理 {url} 时出错: {str(e)}")
        return None

def log_message(message):
    """记录日志信息"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_line = f"[{timestamp}] {message}\n"
    print(log_line.strip())
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(log_line)

def process_rules():
    """处理所有规则并生成 Mihomo 兼容的规则集"""
    unique_rules = set()
    excluded_domains = set()

    for url in URL_LIST:
        log_message(f"正在处理: {url}")
        content = download_rules(url)
        if not content:
            continue

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('!'):
                continue

            # 处理白名单规则 (@@)
            if line.startswith('@@'):
                domains = re.sub(r'^@@', '', line)
                domains = re.findall(r'[\w.-]+\.[a-zA-Z]{2,}', domains)
                for domain in domains:
                    if is_valid_dns_domain(domain):
                        excluded_domains.add(domain.lower())
                continue

            # 匹配 Adblock/Easylist 格式的规则
            if re.match(r'^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^$', line):
                domain = re.match(r'^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^$', line).group(1)
                if is_valid_dns_domain(domain):
                    unique_rules.add(domain.lower())
                continue

            # 匹配 Hosts 文件格式的 IPv4 规则
            if re.match(r'^(0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$', line):
                domain = re.match(r'^(0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$', line).group(2)
                if is_valid_dns_domain(domain):
                    unique_rules.add(domain.lower())
                continue

            # 匹配 Hosts 文件格式的 IPv6 规则
            if re.match(r'^::(1)?\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$', line):
                domain = re.match(r'^::(1)?\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$', line).group(2)
                if is_valid_dns_domain(domain):
                    unique_rules.add(domain.lower())
                continue

            # 匹配 Dnsmasq address=/域名/格式的规则
            if re.match(r'^address=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$', line):
                domain = re.match(r'^address=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$', line).group(1)
                if is_valid_dns_domain(domain):
                    unique_rules.add(domain.lower())
                continue

            # 匹配 Dnsmasq server=/域名/的规则
            if re.match(r'^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$', line):
                domain = re.match(r'^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$', line).group(1)
                if is_valid_dns_domain(domain):
                    unique_rules.add(domain.lower())
                continue

            # 处理纯域名行
            if re.match(r'^([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$', line):
                domain = line
                if is_valid_dns_domain(domain):
                    unique_rules.add(domain.lower())
                continue

    # 排除白名单中的域名
    final_rules = [domain for domain in unique_rules if domain not in excluded_domains]
    final_rules = sorted(final_rules)

    # 生成 Mihomo 兼容的 YAML 规则集
    mihomo_ruleset = {
        "payload": final_rules
    }

    # 写入 YAML 文件
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("# Title: AdBlock Rule For Mihomo\n")
        f.write("# Description: 适用于Mihomo的域名拦截规则集\n")
        f.write("# Generated: {}\n".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        f.write("# Rule Count: {}\n".format(len(final_rules)))
        f.write("payload:\n")
        for domain in final_rules:
            f.write(f"  - '{domain}'\n")

    log_message(f"生成的有效规则总数: {len(final_rules)}")
    log_message(f"规则集已保存到: {os.path.abspath(OUTPUT_FILE)}")

if __name__ == "__main__":
    # 初始化日志文件
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        f.write("AdBlock Rule Generator Log\n")
        f.write(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
    
    process_rules()
