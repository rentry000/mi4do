import requests
import re
import json
from urllib.parse import urlparse
from datetime import datetime
import os

# 定义广告过滤器URL列表
URL_LIST = [
"https://raw.githubusercontent.com/ghostnetic/adblock-filter-compiler/refs/heads/main/blocklist.txt",
"https://raw.githubusercontent.com/keanugithub/sp-filters/refs/heads/main/blocklists.txt",
"https://raw.githubusercontent.com/peter9811/ad_filter2hosts/refs/heads/main/hosts_filtered.txt",
"https://raw.githubusercontent.com/1stfine/open_clash/master/rule_provider/rule_porn.yaml",
"https://raw.githubusercontent.com/4skinSkywalker/Anti-Porn-HOSTS-File/refs/heads/master/HOSTS.txt",
"https://raw.githubusercontent.com/ajayyy/easylist/master/easylist_adult/adult_adservers.txt",
"https://raw.githubusercontent.com/alexsannikov/adguardhome-filters/master/porn.txt",
"https://raw.githubusercontent.com/ameshkov/easylist/master/easylist_adult/adult_adservers.txt",
"https://raw.githubusercontent.com/blocklistproject/Lists/master/alt-version/porn-nl.txt",
"https://raw.githubusercontent.com/brijrajparmar27/host-sources/master/Porn/hosts",
"https://raw.githubusercontent.com/Castle67/CastleAds/main/extensions/porn/sinfonietta/hosts.txt",
"https://raw.githubusercontent.com/Castle67/CastleAds/main/NakedSite.lst",
"https://raw.githubusercontent.com/DHCW-Operational-Security/TI/master/BlockedDomains_Porn.txt",
"https://raw.githubusercontent.com/diwasatreya/bad-websites/master/separated/nsfw.json",
"https://raw.githubusercontent.com/edmond-nader/MyPiHoleLists/main/PiPornList.txt",
"https://raw.githubusercontent.com/edwdch/domain-yaml-community/master/yaml/category-porn.txt",
"https://raw.githubusercontent.com/elbkr/bad-websites/main/separated/nsfw.json",
"https://raw.githubusercontent.com/emiliodallatorre/adult-hosts-list/main/list.txt",
"https://raw.githubusercontent.com/funilrys/pornhosts/master/submit_here/hosts.txt",
"https://raw.githubusercontent.com/go2engineering/pihole-blocklists/main/pihole_blocklist_adult.list",
"https://raw.githubusercontent.com/insightbrowser/scripts/master/top_1m_porn_hosts.txt",
"https://raw.githubusercontent.com/LittleCordines/pfsense-hosts-file/master/PornBlocklists",
"https://raw.githubusercontent.com/lonecale/Rules/master/Geosite/rules/category-porn.txt",
"https://raw.githubusercontent.com/madcow05/Scam-Blocklist/master/lists/adblock/nsfw.txt",
"https://raw.githubusercontent.com/madi10/MANTANKODE/master/AdGuard/pornlist.txt",
"https://raw.githubusercontent.com/moose84/list/master/listaPI.txt",
"https://raw.githubusercontent.com/mssvpn/block/master/porn.txt",
"https://raw.githubusercontent.com/mssvpn/domain-list-community/master/data/category-porn",
"https://raw.githubusercontent.com/mullvad/dns-blocklists/main/lists/relay/adult/oisd-nsfw",
"https://raw.githubusercontent.com/nizekun/adguardhome-blocklist/main/alexsannikov-pornlist.txt",
"https://raw.githubusercontent.com/nizekun/adguardhome-blocklist/main/chadmayfieldporn_all1.txt",
"https://raw.githubusercontent.com/nizekun/adguardhome-blocklist/main/chadmayfieldporn_all2.txt",
"https://raw.githubusercontent.com/nizekun/adguardhome-blocklist/main/chadmayfieldporn_all3.txt",
"https://raw.githubusercontent.com/MoisesJMorais/AdGuard-DNS-Filters/refs/heads/main/porn-filter.txt",
"https://raw.githubusercontent.com/MoisesJMorais/AdGuard-DNS-Filters/refs/heads/main/fraud-filter.txt",
"https://raw.githubusercontent.com/MoisesJMorais/AdGuard-DNS-Filters/refs/heads/main/abuse-filter.txt",
"https://raw.githubusercontent.com/MoisesJMorais/AdGuard-DNS-Filters/refs/heads/main/malware-filter.txt",
"https://raw.githubusercontent.com/spydisec/spydithreatintel/refs/heads/main/domainlist/spam/spamscamabuse_domains.txt",
"https://raw.githubusercontent.com/spydisec/spydithreatintel/refs/heads/main/domainlist/malicious/domain_ioc_maltrail_new.txt",
"https://raw.githubusercontent.com/spydisec/spydithreatintel/refs/heads/main/domainlist/ads/advtracking_domains.txt",
"https://raw.githubusercontent.com/miriquidi/domain-blocklists/refs/heads/main/block.txt",
"https://raw.githubusercontent.com/sol1/blocklist-domains/refs/heads/main/outputs/hosts.txt",
"https://raw.githubusercontent.com/person9876/blocklist/refs/heads/main/domainlist.txt",
"https://raw.githubusercontent.com/dmachard/blocklist-domains/data/hosts.txt"

]

# 日志文件路径
LOG_FILE = "adblock_log.txt"
OUTPUT_FILE = "adblock_reject3.yaml"  # Mihomo 使用的 YAML 格式

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
