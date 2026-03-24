#!/usr/bin/env python3
"""
har2list.py - 从 HAR 文件夹生成 Quantumult X 分流规则集

用法:
    python har2list.py <har文件夹> [选项]

    # 从零生成
    python har2list.py ./har/doubao --name Doubao --policy Proxy

    # 基于现有 list 补充
    python har2list.py ./har/bilibili --base BiliBili.list --policy BiliBili
"""

import json
import re
import argparse
import ipaddress
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlparse
from collections import defaultdict

import tldextract


def is_ip_address(host: str) -> bool:
    """判断是否为 IP 地址"""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def extract_from_har(har_path: Path) -> tuple[set[str], set[str]]:
    """
    从单个 HAR 文件中提取所有 hostname 和 IP 地址。

    提取来源：
    - request.url（主请求）
    - response.redirectURL（重定向目标）
    - response.headers 中的 Location（重定向头）
    - serverIPAddress（服务器 IP）
    """
    with open(har_path, encoding="utf-8") as f:
        har = json.load(f)

    hosts = set()
    ips = set()

    for entry in har["log"]["entries"]:
        # 1. 主请求 URL
        req_host = urlparse(entry["request"]["url"]).hostname
        if req_host:
            req_host = req_host.lower()
            if is_ip_address(req_host):
                ips.add(req_host)
            else:
                hosts.add(req_host)

        # 2. 重定向目标 URL
        redirect_url = entry.get("response", {}).get("redirectURL", "")
        if redirect_url:
            redir_host = urlparse(redirect_url).hostname
            if redir_host:
                redir_host = redir_host.lower()
                if is_ip_address(redir_host):
                    ips.add(redir_host)
                else:
                    hosts.add(redir_host)

        # 3. 响应头中的 Location
        for header in entry.get("response", {}).get("headers", []):
            if header["name"].lower() == "location":
                loc_host = urlparse(header["value"]).hostname
                if loc_host:
                    loc_host = loc_host.lower()
                    if is_ip_address(loc_host):
                        ips.add(loc_host)
                    else:
                        hosts.add(loc_host)

        # 4. 服务器 IP
        server_ip = entry.get("serverIPAddress", "")
        if server_ip:
            # 去除可能带的端口号或 IPv6 方括号
            server_ip = server_ip.strip("[]")
            if ":" in server_ip and "." in server_ip:
                # 可能是 ip:port 格式
                server_ip = server_ip.rsplit(":", 1)[0]
            try:
                ipaddress.ip_address(server_ip)
                ips.add(server_ip)
            except ValueError:
                pass

    return hosts, ips


def get_root_domain(hostname: str) -> str:
    """使用 tldextract 提取注册域名（eTLD+1），正确处理 .com.cn 等复合后缀"""
    ext = tldextract.extract(hostname)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return hostname


def parse_list_file(list_path: Path) -> tuple[list[str], set[str], set[str], list[ipaddress.IPv4Network | ipaddress.IPv6Network]]:
    """
    解析现有 .list 文件。

    返回:
        (原始规则行列表, HOST 精确域名集合, HOST-SUFFIX 后缀集合, IP-CIDR 网段列表)
    """
    host_exact = set()
    host_suffix = set()
    ip_networks = []
    rule_lines = []

    for line in list_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        rule_lines.append(stripped)
        parts = stripped.split(",")
        if len(parts) < 2:
            continue
        rule_type = parts[0].upper()
        value = parts[1].lower()
        if rule_type == "HOST":
            host_exact.add(value)
        elif rule_type == "HOST-SUFFIX":
            host_suffix.add(value)
        elif rule_type in ("IP-CIDR", "IP-CIDR6"):
            try:
                ip_networks.append(ipaddress.ip_network(value, strict=False))
            except ValueError:
                pass

    return rule_lines, host_exact, host_suffix, ip_networks


def is_host_covered(hostname: str, host_exact: set[str], host_suffix: set[str]) -> bool:
    """检查域名是否已被现有规则覆盖"""
    hostname = hostname.lower()
    if hostname in host_exact:
        return True
    # HOST-SUFFIX 匹配：域名本身或其任意上级后缀在集合中
    parts = hostname.split(".")
    for i in range(len(parts)):
        suffix = ".".join(parts[i:])
        if suffix in host_suffix:
            return True
    return False


def is_ip_covered(ip_str: str, ip_networks: list) -> bool:
    """检查 IP 是否已被现有 IP-CIDR 规则覆盖"""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in ip_networks)
    except ValueError:
        return False


def build_rules(
    all_hosts: set[str],
    all_ips: set[str],
    suffix_threshold: int,
    exclude_patterns: list[str],
) -> tuple[list[str], list[str], list[str]]:
    """
    生成规则列表。

    返回 (host_rules, suffix_rules, ip_cidr_rules)
    """
    # 编译排除正则
    exclude_res = [re.compile(p, re.IGNORECASE) for p in exclude_patterns]

    def is_excluded(domain: str) -> bool:
        return any(r.search(domain) for r in exclude_res)

    # 过滤掉排除域名和 localhost 等
    filtered_hosts = {
        h
        for h in all_hosts
        if not is_excluded(h) and h not in ("localhost", "127.0.0.1", "[::1]")
    }

    # 按根域名分组
    root_to_hosts = defaultdict(set)
    for h in filtered_hosts:
        root_to_hosts[get_root_domain(h)].add(h)

    host_rules = []
    suffix_rules = []

    for root, hosts in sorted(root_to_hosts.items()):
        if len(hosts) >= suffix_threshold:
            suffix_rules.append(root)
        else:
            for h in sorted(hosts):
                host_rules.append(h)

    # IP-CIDR 规则（/32 精确匹配）
    ip_cidr_rules = []
    for ip in sorted(all_ips):
        if is_excluded(ip):
            continue
        addr = ipaddress.ip_address(ip)
        if isinstance(addr, ipaddress.IPv6Address):
            ip_cidr_rules.append(f"{ip}/128")
        else:
            ip_cidr_rules.append(f"{ip}/32")

    return sorted(host_rules), sorted(suffix_rules), ip_cidr_rules


def generate_list(
    har_folder: Path,
    name: str,
    policy: str,
    output: Path,
    author: str,
    suffix_threshold: int,
    exclude_patterns: list[str],
    include_ip: bool,
):
    har_files = sorted(har_folder.glob("*.har"))
    if not har_files:
        print(f"错误：{har_folder} 中没有找到 .har 文件")
        return

    print(f"找到 {len(har_files)} 个 HAR 文件：")
    all_hosts: set[str] = set()
    all_ips: set[str] = set()
    for f in har_files:
        try:
            hosts, ips = extract_from_har(f)
            print(f"  {f.name}: {len(hosts)} 个域名, {len(ips)} 个 IP")
            all_hosts.update(hosts)
            all_ips.update(ips)
        except (json.JSONDecodeError, KeyError) as e:
            print(f"  {f.name}: 解析失败，跳过（{e}）")

    print(f"\n合并后共 {len(all_hosts)} 个唯一域名, {len(all_ips)} 个唯一 IP")

    host_rules, suffix_rules, ip_cidr_rules = build_rules(
        all_hosts, all_ips, suffix_threshold, exclude_patterns
    )

    if not include_ip:
        ip_cidr_rules = []

    updated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    total = len(host_rules) + len(suffix_rules) + len(ip_cidr_rules)

    lines = [
        f"# NAME: {name}",
        f"# AUTHOR: {author}",
        f"# UPDATED: {updated}",
    ]
    if host_rules:
        lines.append(f"# HOST: {len(host_rules)}")
    if suffix_rules:
        lines.append(f"# HOST-SUFFIX: {len(suffix_rules)}")
    if ip_cidr_rules:
        lines.append(f"# IP-CIDR: {len(ip_cidr_rules)}")
    lines.append(f"# TOTAL: {total}")

    for h in host_rules:
        lines.append(f"HOST,{h},{policy}")
    for s in suffix_rules:
        lines.append(f"HOST-SUFFIX,{s},{policy}")
    for ip in ip_cidr_rules:
        lines.append(f"IP-CIDR,{ip},{policy}")

    output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"\n已生成：{output}")
    print(f"  HOST        : {len(host_rules)} 条")
    print(f"  HOST-SUFFIX : {len(suffix_rules)} 条")
    print(f"  IP-CIDR     : {len(ip_cidr_rules)} 条")
    print(f"  合计        : {total} 条")


def supplement_list(
    har_folder: Path,
    base_path: Path,
    policy: str,
    output: Path,
    suffix_threshold: int,
    exclude_patterns: list[str],
    include_ip: bool,
):
    """基于现有 .list 文件，用 HAR 中的新域名进行补充"""
    # 1. 解析现有规则
    base_rules, host_exact, host_suffix, ip_networks = parse_list_file(base_path)
    print(f"已有规则 ({base_path.name})：")
    print(f"  HOST        : {len(host_exact)} 条")
    print(f"  HOST-SUFFIX : {len(host_suffix)} 条")
    print(f"  IP-CIDR     : {len(ip_networks)} 条")
    print(f"  总规则行    : {len(base_rules)} 条\n")

    # 2. 从 HAR 提取域名
    har_files = sorted(har_folder.glob("*.har"))
    if not har_files:
        print(f"错误：{har_folder} 中没有找到 .har 文件")
        return

    print(f"找到 {len(har_files)} 个 HAR 文件：")
    all_hosts: set[str] = set()
    all_ips: set[str] = set()
    for f in har_files:
        try:
            hosts, ips = extract_from_har(f)
            print(f"  {f.name}: {len(hosts)} 个域名, {len(ips)} 个 IP")
            all_hosts.update(hosts)
            all_ips.update(ips)
        except (json.JSONDecodeError, KeyError) as e:
            print(f"  {f.name}: 解析失败，跳过（{e}）")

    print(f"\nHAR 合并后共 {len(all_hosts)} 个唯一域名, {len(all_ips)} 个唯一 IP")

    # 3. 过滤已覆盖的域名/IP
    new_hosts = {h for h in all_hosts if not is_host_covered(h, host_exact, host_suffix)}
    new_ips = {ip for ip in all_ips if not is_ip_covered(ip, ip_networks)}

    covered_hosts = len(all_hosts) - len(new_hosts)
    covered_ips = len(all_ips) - len(new_ips)
    print(f"已被现有规则覆盖：{covered_hosts} 个域名, {covered_ips} 个 IP")
    print(f"新发现：{len(new_hosts)} 个域名, {len(new_ips)} 个 IP")

    if not new_hosts and (not new_ips or not include_ip):
        print("\n没有需要补充的新规则。")
        return

    # 4. 构建新规则
    new_host_rules, new_suffix_rules, new_ip_rules = build_rules(
        new_hosts, new_ips, suffix_threshold, exclude_patterns
    )
    if not include_ip:
        new_ip_rules = []

    # 5. 读取原始文件内容，保留头部和已有规则
    original_lines = base_path.read_text(encoding="utf-8").splitlines()
    header_lines = []
    body_lines = []
    for line in original_lines:
        if line.startswith("#"):
            header_lines.append(line)
        else:
            body_lines.append(line)

    # 6. 更新头部中的计数和时间
    updated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    new_total = len(base_rules) + len(new_host_rules) + len(new_suffix_rules) + len(new_ip_rules)

    # 更新或追加头部字段
    def update_header(lines: list[str], key: str, value: str) -> list[str]:
        pattern = f"# {key}:"
        for i, line in enumerate(lines):
            if line.startswith(pattern):
                lines[i] = f"# {key}: {value}"
                return lines
        # 在 TOTAL 行之前插入，如果没有 TOTAL 就追加到末尾
        for i, line in enumerate(lines):
            if line.startswith("# TOTAL:"):
                lines.insert(i, f"# {key}: {value}")
                return lines
        lines.append(f"# {key}: {value}")
        return lines

    total_host = len(host_exact) + len(new_host_rules)
    total_suffix = len(host_suffix) + len(new_suffix_rules)
    total_ip = len(ip_networks) + len(new_ip_rules)

    header_lines = update_header(header_lines, "UPDATED", updated)
    if total_host:
        header_lines = update_header(header_lines, "HOST", str(total_host))
    if total_suffix:
        header_lines = update_header(header_lines, "HOST-SUFFIX", str(total_suffix))
    if total_ip:
        header_lines = update_header(header_lines, "IP-CIDR", str(total_ip))
    header_lines = update_header(header_lines, "TOTAL", str(new_total))

    # 7. 组装输出
    out_lines = header_lines + body_lines
    if new_host_rules or new_suffix_rules or new_ip_rules:
        out_lines.append(f"# --- 以下为 HAR 补充规则 ({updated}) ---")
        for h in new_host_rules:
            out_lines.append(f"HOST,{h},{policy}")
        for s in new_suffix_rules:
            out_lines.append(f"HOST-SUFFIX,{s},{policy}")
        for ip in new_ip_rules:
            out_lines.append(f"IP-CIDR,{ip},{policy}")

    output.write_text("\n".join(out_lines) + "\n", encoding="utf-8")
    print(f"\n已生成：{output}")
    print(f"  新增 HOST        : {len(new_host_rules)} 条")
    print(f"  新增 HOST-SUFFIX : {len(new_suffix_rules)} 条")
    print(f"  新增 IP-CIDR     : {len(new_ip_rules)} 条")
    print(f"  总规则数         : {new_total} 条")


def main():
    parser = argparse.ArgumentParser(
        description="将 HAR 文件夹转换为 Quantumult X 分流规则集"
    )
    parser.add_argument("folder", help="存放 HAR 文件的文件夹路径")
    parser.add_argument("--name", default=None, help="规则集名称（默认：文件夹名）")
    parser.add_argument("--policy", default=None, help="QX 策略名（默认：同 name）")
    parser.add_argument("--output", default=None, help="输出文件路径（默认：<name>.list）")
    parser.add_argument("--author", default="Gwen", help="作者名（默认：Gwen）")
    parser.add_argument(
        "--threshold",
        type=int,
        default=2,
        help="同一根域名下几个子域名时改用 HOST-SUFFIX（默认：2）",
    )
    parser.add_argument(
        "--exclude",
        nargs="*",
        default=[],
        help="排除匹配的域名（正则表达式），例如：--exclude 'google' 'cdn\\.jsdelivr'",
    )
    parser.add_argument(
        "--no-ip",
        action="store_true",
        help="不生成 IP-CIDR 规则",
    )
    parser.add_argument(
        "--base",
        default=None,
        help="基于现有 .list 文件补充（补充模式）",
    )
    args = parser.parse_args()

    har_folder = Path(args.folder).resolve()
    if not har_folder.is_dir():
        print(f"错误：{har_folder} 不是有效的文件夹")
        return

    # 默认输出到项目根目录下的 list/ 文件夹
    script_dir = Path(__file__).resolve().parent
    list_dir = script_dir / "list"
    list_dir.mkdir(exist_ok=True)

    if args.base:
        # 补充模式
        base_path = Path(args.base).resolve()
        if not base_path.is_file():
            print(f"错误：{base_path} 不存在")
            return
        name = args.name or base_path.stem
        policy = args.policy or name
        output = Path(args.output) if args.output else list_dir / f"{name}_supplemented.list"
        supplement_list(
            har_folder, base_path, policy, output,
            args.threshold, args.exclude, not args.no_ip,
        )
    else:
        # 全新生成模式
        name = args.name or har_folder.name
        policy = args.policy or name
        output = Path(args.output) if args.output else list_dir / f"{name}.list"
        generate_list(
            har_folder, name, policy, output, args.author,
            args.threshold, args.exclude, not args.no_ip,
        )


if __name__ == "__main__":
    main()
