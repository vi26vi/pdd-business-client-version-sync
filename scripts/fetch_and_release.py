#!/usr/bin/env python3
"""
拼多多商家客户端自动同步脚本
- 调用拼多多内部 API 获取所有客户端的最新版本信息
- 下载各平台客户端安装包
- 通过 GitHub API 创建/更新 Release 并上传 Assets
"""

import os
import sys
import json
import time
import hashlib
import requests
from datetime import datetime, timezone, timedelta
from pathlib import Path

# ──────────────────────────────────────────
# 常量配置
# ──────────────────────────────────────────

PDD_API_URL = "https://mms.pinduoduo.com/earth/api/pack/queryPackList"
PDD_REFERER = "https://mms.pinduoduo.com/other/download_app"

GITHUB_TOKEN = os.environ["GITHUB_TOKEN"]
GITHUB_REPO  = os.environ["GITHUB_REPO"]   # owner/repo

PLATFORM_MAP = {
    1: {"name": "Android",  "ext": ".apk",  "emoji": "📱"},
    2: {"name": "iOS",      "ext": "",      "emoji": "🍎"},   # App Store 链接，不下载
    3: {"name": "Windows",  "ext": ".exe",  "emoji": "🖥️"},
    4: {"name": "macOS",    "ext": ".dmg",  "emoji": "🍏"},
}

RESULT_FILE = "/tmp/pdd_sync_result.txt"
DOWNLOAD_DIR = Path("/tmp/pdd_downloads")
DOWNLOAD_DIR.mkdir(exist_ok=True)

CST = timezone(timedelta(hours=8))

# ──────────────────────────────────────────
# 工具函数
# ──────────────────────────────────────────

def log(msg: str):
    ts = datetime.now(CST).strftime("%Y-%m-%d %H:%M:%S CST")
    print(f"[{ts}] {msg}", flush=True)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def format_size(size_bytes: int) -> str:
    for unit in ["B", "KB", "MB", "GB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} GB"


# ──────────────────────────────────────────
# 步骤 1：获取客户端信息
# ──────────────────────────────────────────

def fetch_pack_list() -> list[dict]:
    log("正在请求拼多多 API …")
    resp = requests.post(
        PDD_API_URL,
        json={},
        headers={
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/125.0.0.0 Safari/537.36"
            ),
            "Accept": "application/json",
            "Referer": PDD_REFERER,
            "Content-Type": "application/json",
        },
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    if not data.get("success"):
        raise RuntimeError(f"API 返回失败: {data}")
    packs = data["result"]["packList"]
    log(f"获取到 {len(packs)} 个客户端包信息")
    return packs


# ──────────────────────────────────────────
# 步骤 2：下载安装包
# ──────────────────────────────────────────

def download_file(url: str, dest: Path, timeout: int = 120) -> bool:
    """流式下载，显示进度。返回是否成功。"""
    log(f"下载: {url}")
    try:
        with requests.get(url, stream=True, timeout=timeout,
                          headers={"User-Agent": "Mozilla/5.0"}) as r:
            r.raise_for_status()
            total = int(r.headers.get("content-length", 0))
            downloaded = 0
            with open(dest, "wb") as f:
                for chunk in r.iter_content(chunk_size=1024 * 256):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
            log(f"  ✅ 下载完成: {format_size(downloaded)}")
            return True
    except Exception as e:
        log(f"  ❌ 下载失败: {e}")
        return False


# ──────────────────────────────────────────
# 步骤 3：GitHub Release 操作
# ──────────────────────────────────────────

GH_API = "https://api.github.com"
GH_HEADERS = {
    "Authorization": f"Bearer {GITHUB_TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}


def get_or_create_release(tag: str, release_name: str, body: str) -> dict:
    """获取已存在的 Release，或创建新的。"""
    url = f"{GH_API}/repos/{GITHUB_REPO}/releases/tags/{tag}"
    r = requests.get(url, headers=GH_HEADERS, timeout=15)
    if r.status_code == 200:
        log(f"Release 已存在，将更新: {tag}")
        release = r.json()
        # 更新 body（changelog）
        patch_url = f"{GH_API}/repos/{GITHUB_REPO}/releases/{release['id']}"
        requests.patch(patch_url, json={"body": body}, headers=GH_HEADERS, timeout=15)
        return release
    elif r.status_code == 404:
        log(f"创建新 Release: {tag}")
        create_url = f"{GH_API}/repos/{GITHUB_REPO}/releases"
        payload = {
            "tag_name": tag,
            "name": release_name,
            "body": body,
            "draft": False,
            "prerelease": False,
            "make_latest": "true",
        }
        resp = requests.post(create_url, json=payload, headers=GH_HEADERS, timeout=15)
        resp.raise_for_status()
        return resp.json()
    else:
        r.raise_for_status()


def list_release_assets(release_id: int) -> dict[str, dict]:
    """返回 {asset_name: asset_info} 字典。"""
    url = f"{GH_API}/repos/{GITHUB_REPO}/releases/{release_id}/assets"
    r = requests.get(url, headers=GH_HEADERS, timeout=15)
    r.raise_for_status()
    return {a["name"]: a for a in r.json()}


def delete_asset(asset_id: int):
    url = f"{GH_API}/repos/{GITHUB_REPO}/releases/assets/{asset_id}"
    requests.delete(url, headers=GH_HEADERS, timeout=15)


def upload_asset(release: dict, file_path: Path, asset_name: str):
    """上传 Asset，若同名已存在则先删除再上传。"""
    upload_url = release["upload_url"].replace("{?name,label}", "")
    existing = list_release_assets(release["id"])
    if asset_name in existing:
        log(f"  旧 Asset 已存在，先删除: {asset_name}")
        delete_asset(existing[asset_name]["id"])

    log(f"  上传 Asset: {asset_name} ({format_size(file_path.stat().st_size)})")
    with open(file_path, "rb") as f:
        headers = {**GH_HEADERS, "Content-Type": "application/octet-stream"}
        r = requests.post(
            f"{upload_url}?name={asset_name}",
            headers=headers,
            data=f,
            timeout=300,
        )
    r.raise_for_status()
    log(f"  ✅ 上传成功: {r.json().get('browser_download_url', '')}")
    return r.json()


# ──────────────────────────────────────────
# 步骤 4：上传 JSON 索引
# ──────────────────────────────────────────

def upload_index_json(release: dict, packs: list[dict], extra_info: list[dict]):
    """将完整的客户端信息索引作为 JSON Asset 上传。"""
    index = {
        "generated_at": datetime.now(CST).isoformat(),
        "source_api": PDD_API_URL,
        "clients": extra_info,
    }
    index_path = DOWNLOAD_DIR / "pdd_clients_index.json"
    index_path.write_text(json.dumps(index, ensure_ascii=False, indent=2), encoding="utf-8")
    upload_asset(release, index_path, "pdd_clients_index.json")


# ──────────────────────────────────────────
# 主流程
# ──────────────────────────────────────────

def main():
    results = []
    run_time = datetime.now(CST)

    # 1. 获取客户端信息
    packs = fetch_pack_list()

    # 2. 整理信息，构建 Release tag / body
    client_infos = []
    changelog_lines = [
        f"## 拼多多商家客户端最新版本",
        f"",
        f"> 自动同步时间：{run_time.strftime('%Y年%m月%d日 %H:%M')} (CST)",
        f"> 数据来源：[拼多多商家后台]({PDD_REFERER})",
        f"",
        f"| 平台 | 版本 | 更新日期 | 更新内容 |",
        f"|------|------|----------|----------|",
    ]

    # 取版本最高的 Win 版本号作为 tag（或所有版本拼接）
    tag_parts = []
    for pack in packs:
        t = pack["type"]
        meta = PLATFORM_MAP.get(t, {"name": f"type{t}", "ext": "", "emoji": "📦"})
        updated_at = datetime.fromtimestamp(pack["updatedAt"] / 1000, tz=CST)
        date_str = updated_at.strftime("%Y-%m-%d")
        tag_parts.append(f"{meta['name'].lower()}-{pack['version']}")
        content = pack.get("content", "").strip()
        changelog_lines.append(
            f"| {meta['emoji']} {meta['name']} | `{pack['version']}` "
            f"| {date_str} | {content} |"
        )
        client_infos.append({
            "type": t,
            "platform": meta["name"],
            "version": pack["version"],
            "url": pack["url"],
            "content": content,
            "updated_at": updated_at.isoformat(),
        })

    # Release tag 格式：pdd-clients-YYYYMMDD-HHmm
    tag = f"pdd-clients-{run_time.strftime('%Y%m%d-%H%M')}"
    release_name = f"拼多多商家客户端 · {run_time.strftime('%Y-%m-%d %H:%M')} CST"

    changelog_lines += [
        "",
        "---",
        "",
        "### 📥 文件说明",
        "",
        "| 文件名 | 说明 |",
        "|--------|------|",
        "| `*.apk` | Android 安装包 |",
        "| `*.exe` | Windows 安装程序 |",
        "| `*.dmg` | macOS 安装包 |",
        "| `pdd_clients_index.json` | 完整版本信息索引（含原始下载地址） |",
        "",
        "> **iOS** 版本通过 App Store 分发，无独立安装包，请直接前往 App Store 下载。",
    ]
    body = "\n".join(changelog_lines)

    # 3. 创建/获取 Release
    release = get_or_create_release(tag, release_name, body)
    release_id = release["id"]
    log(f"Release ID: {release_id}, URL: {release.get('html_url', '')}")

    # 4. 遍历下载 & 上传
    for pack in packs:
        t = pack["type"]
        meta = PLATFORM_MAP.get(t, {"name": f"type{t}", "ext": "", "emoji": "📦"})

        # iOS 使用 App Store，不下载
        if t == 2:
            log(f"[iOS] App Store 链接: {pack['url']} — 跳过下载")
            results.append(f"[iOS] App Store: {pack['url']} (版本 {pack['version']})")
            continue

        version = pack["version"]
        ext = meta["ext"]
        asset_name = f"pdd-merchant-{meta['name'].lower()}-{version}{ext}"
        dest = DOWNLOAD_DIR / asset_name

        ok = download_file(pack["url"], dest)
        if ok:
            sha = sha256_file(dest)
            log(f"  SHA256: {sha}")
            upload_asset(release, dest, asset_name)
            # 同时上传 sha256 校验文件
            sha_path = DOWNLOAD_DIR / f"{asset_name}.sha256"
            sha_path.write_text(f"{sha}  {asset_name}\n")
            upload_asset(release, sha_path, f"{asset_name}.sha256")
            results.append(f"[{meta['name']}] v{version} ✅ 已上传")
        else:
            results.append(f"[{meta['name']}] v{version} ❌ 下载失败")

    # 5. 上传索引 JSON
    upload_index_json(release, packs, client_infos)
    results.append("[INDEX] pdd_clients_index.json ✅ 已上传")

    # 6. 写入结果文件
    summary = "\n".join([
        f"执行时间: {run_time.strftime('%Y-%m-%d %H:%M:%S CST')}",
        f"Release: {release.get('html_url', '')}",
        "",
        *results,
    ])
    Path(RESULT_FILE).write_text(summary, encoding="utf-8")
    log("=" * 50)
    log(summary)
    log("=" * 50)


if __name__ == "__main__":
    main()
