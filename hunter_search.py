#!/usr/bin/env python3
"""
鹰图 Hunter (https://hunter.qianxin.com/) 数据获取脚本

功能：
  - 通过 Hunter API 搜索网络资产
  - 每次搜索固定返回 10 条（硬限制，除非 --override 明确覆盖）
  - 支持多页翻页
  - 自动处理配额

用法：
  export HUNTER_API_KEY="your_api_key_here"
  python3 hunter_search.py -q 'app="nps"'
  python3 hunter_search.py -q 'app="nps"' -p 3
  python3 hunter_search.py -k "your_key" -q 'ip="1.1.1.1"'
  python3 hunter_search.py -q 'app="nps"' -o result.json -f json
  python3 hunter_search.py -q 'app="nps"' --size 50 --override

注意：
  - 每次搜索默认 10 条，这是硬限制，保护你的 500 条配额
"""

import argparse
import json
import os
import sys
import time
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime

HUNTER_BASE_URL = "https://hunter.qianxin.com/openApi/search"
DEFAULT_SIZE = 10
ALLOWED_PAGE_SIZE = [5, 10, 20, 50, 100]


def search_hunter(api_key, query, page=1, page_size=DEFAULT_SIZE):
    params = {
        "api-key": api_key,
        "search": query,
        "page": page,
        "page_size": page_size,
        "is_web": 1,
        "start_time": "",
        "end_time": "",
    }
    params = {k: v for k, v in params.items() if v != ""}
    url = HUNTER_BASE_URL + "?" + urllib.parse.urlencode(params)

    try:
        req = urllib.request.Request(url)
        req.add_header("Accept", "application/json")
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
            return resp.status, json.loads(body)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")
        return e.code, json.loads(body) if body else {"error": str(e)}
    except Exception as e:
        return 0, {"error": str(e)}


def print_results(response, page=1):
    data = response.get("data") if isinstance(response, dict) else None
    if response.get("code") != 200 or data is None:
        msg = response.get("message", response.get("error", "未知错误"))
        print("  [!] API 错误:", msg)
        return

    total = data.get("total", 0)
    arr = data.get("arr", [])
    consume_quota = data.get("consume_quota", 0)
    rest_quota = data.get("rest_quota", 0)

    print("\n" + "=" * 60)
    print("  [第 %d 页] 总匹配: %s 条 | 本页: %d 条" % (page, total, len(arr)))
    print("  消耗配额: %s | 剩余配额: %s" % (consume_quota, rest_quota))
    print("=" * 60)

    for i, asset in enumerate(arr, 1):
        url = asset.get("url", "") or ""
        ip = asset.get("ip", "") or ""
        port = asset.get("port", "") or ""
        protocol = asset.get("protocol", "") or ""
        title = asset.get("web_title", "") or "-"
        domain = asset.get("domain", "") or "-"
        status_code = asset.get("status_code", "") or ""
        country = asset.get("country", "") or ""
        province = asset.get("province", "") or ""
        city = asset.get("city", "") or ""
        is_web = "W" if asset.get("is_web") == 1 else "N"
        banner = (asset.get("banner", "") or "")[:80]
        addr = url if url else (ip + ":" + port)

        print("\n  %2d. [%s] %s" % (i, is_web, addr))
        print("       IP: %-15s  端口: %-5s  协议: %s" % (ip, port, protocol))
        print("       域名: %-30s  状态码: %s" % (domain, status_code))
        print("       标题: %s" % title)
        print("       位置: %s %s %s" % (country, province, city))
        if banner:
            print("       Banner: %s..." % banner)

    print("\n" + "=" * 60 + "\n")


def save_results(all_results, query, output_file, fmt="text"):
    if fmt == "json":
        output = {
            "query": query,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total": len(all_results),
            "results": all_results,
        }
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2, ensure_ascii=False)
        print("[+] 已保存 %d 条结果到 %s (JSON)" % (len(all_results), output_file))
    else:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(output_file, "w", encoding="utf-8") as f:
            f.write("鹰图 Hunter 搜索结果\n")
            f.write("查询: %s\n" % query)
            f.write("时间: %s\n" % timestamp)
            f.write("总数: %d 条\n" % len(all_results))
            f.write("=" * 70 + "\n\n")
            for i, asset in enumerate(all_results, 1):
                url = asset.get("url", "") or ""
                ip = asset.get("ip", "") or ""
                port = asset.get("port", "") or ""
                title = asset.get("web_title", "") or "-"
                domain = asset.get("domain", "") or "-"
                protocol = asset.get("protocol", "") or ""
                country = asset.get("country", "") or ""
                province = asset.get("province", "") or ""
                city = asset.get("city", "") or ""
                banner = (asset.get("banner", "") or "")[:80]
                addr = url if url else (ip + ":" + port)
                f.write("%d. %s\n" % (i, addr))
                f.write("   IP: %s  端口: %s  协议: %s\n" % (ip, port, protocol))
                f.write("   域名: %s  状态码: %s\n" % (domain, asset.get("status_code", "")))
                f.write("   标题: %s\n" % title)
                f.write("   位置: %s %s %s\n" % (country, province, city))
                if banner:
                    f.write("   Banner: %s...\n" % banner)
                f.write("-" * 40 + "\n")
        print("[+] 已保存 %d 条结果到 %s (Text)" % (len(all_results), output_file))


def get_api_key(args):
    if args.api_key:
        return args.api_key
    env_key = os.environ.get("HUNTER_API_KEY")
    if env_key:
        return env_key
    return None


def main():
    parser = argparse.ArgumentParser(
        description="鹰图 Hunter 资产搜索工具（每次默认 10 条，保护配额）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-k", "--api-key", help="Hunter API Key")
    parser.add_argument("-q", "--query", required=True, help='搜索语法，如 app="nps"')
    parser.add_argument("-p", "--pages", type=int, default=1, help="翻页数（默认 1 页，每页 10 条）")
    parser.add_argument("--size", type=int, default=DEFAULT_SIZE, help="每页条数（默认 10，需 --override）")
    parser.add_argument("--override", action="store_true", help="覆盖 10 条限制")
    parser.add_argument("-o", "--output", help="输出文件路径")
    parser.add_argument("-f", "--format", choices=["text", "json"], default="text", help="输出格式")
    parser.add_argument("--delay", type=float, default=0.5, help="翻页间隔秒数")
    parser.add_argument("--quota", action="store_true", help="仅查询剩余配额，不搜索")

    args = parser.parse_args()

    if args.quota:
        api_key = get_api_key(args)
        if not api_key:
            print("[!] 请提供 API Key")
            sys.exit(1)
        code, resp = search_hunter(api_key, args.query, page=1, page_size=1)
        print("[i] HTTP 状态码:", code)
        print("[i] 完整响应:", json.dumps(resp, ensure_ascii=False, indent=2))
        data = resp.get("data") if isinstance(resp, dict) else None
        if data is None:
            sys.exit(1)
        print("[i] 剩余配额:", data.get("rest_quota", "未知"))
        print("[i] 匹配总数:", data.get("total", "未知"))
        return

    api_key = get_api_key(args)
    if not api_key:
        print("[!] 请提供 API Key")
        sys.exit(1)

    page_size = args.size
    if page_size != DEFAULT_SIZE and not args.override:
        print("[!] 默认每页只能搜 %d 条，加 --override 覆盖" % DEFAULT_SIZE)
        sys.exit(1)

    if page_size not in ALLOWED_PAGE_SIZE:
        print("[!] 每页条数必须是: %s" % ALLOWED_PAGE_SIZE)
        sys.exit(1)

    total_pages = args.pages
    print("[*] 搜索: %s" % args.query)
    print("[*] %d 条 x %d 页 = 预计 %d 配额" % (page_size, total_pages, page_size * total_pages))

    all_results = []
    for page in range(1, total_pages + 1):
        print("\n[*] 第 %d 页..." % page)
        code, resp = search_hunter(api_key, args.query, page=page, page_size=page_size)

        if code != 200:
            print("[!] HTTP %d: %s" % (code, resp.get("msg", resp.get("error", "未知"))))
            break

        data = resp.get("data") if isinstance(resp, dict) else None
        if resp.get("code") != 200 or data is None:
            print("[!] API 异常:", json.dumps(resp, ensure_ascii=False, indent=2))
            break

        arr = data.get("arr", [])
        all_results.extend(arr)
        print_results(resp, page)
        print("[*] 剩余配额:", data.get("rest_quota", 0))

        if not arr or len(arr) < page_size:
            if page < total_pages:
                print("[*] 没有更多数据，提前结束")
            break
        if page < total_pages:
            time.sleep(args.delay)

    print("\n" + "=" * 60)
    print("完成！共获取 %d 条" % len(all_results))
    print("=" * 60)

    if args.output and all_results:
        save_results(all_results, args.query, args.output, args.format)
    if not args.output:
        print("\n提示: 加 -o <文件名> 可保存结果")


if __name__ == "__main__":
    main()
