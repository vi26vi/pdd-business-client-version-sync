#!/usr/bin/env python3
"""
拼多多商家客户端自动同步脚本
- 调用拼多多内部 API 获取所有客户端的最新版本信息
- 下载各平台客户端安装包
- 上传/查询 VirusTotal 扫描报告
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
GITHUB_REPO = os.environ["GITHUB_REPO"]

VT_API_KEY = os.environ.get("VT_API_KEY", "")
VT_API_URL = "https://www.virustotal.com/api/v3"
VT_UPLOAD_LIMIT = 32 * 1024 * 1024   # 32MB 免费 API 上传限制
VT_POLL_INTERVAL = 15   # 轮询间隔（秒）
VT_POLL_TIMEOUT = 180   # 最长等待（秒）

PLATFORM_MAP = {
    1: {"name": "android", "ext": ".apk",  "emoji": "📱", "label": "Android"},
    2: {"name": "ios",     "ext": "",      "emoji": "🍎", "label": "iOS"},
    3: {"name": "windows", "ext": ".exe",  "emoji": "🖥️", "label": "Windows"},
    4: {"name": "macos",   "ext": ".dmg",  "emoji": "🍏", "label": "macOS"},
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


def vt_headers() -> dict:
    return {"x-apikey": VT_API_KEY, "Accept": "application/json"}


# ──────────────────────────────────────────
# VirusTotal 操作
# ──────────────────────────────────────────

def vt_get_report(sha256: str):
    """通过 SHA256 查询 VirusTotal 已有报告。返回报告 data 或 None。"""
    log(f"  [VT] 查询已有报告: {sha256[:16]}...")
    try:
        r = requests.get(
            f"{VT_API_URL}/files/{sha256}",
            headers=vt_headers(),
            timeout=30,
        )
        if r.status_code == 200:
            log("  [VT] ✅ 找到已有报告")
            return r.json()["data"]
        elif r.status_code == 404:
            log("  [VT] 无已有报告（404）")
            return None
        else:
            log(f"  [VT] 查询失败: {r.status_code} {r.text[:100]}")
            return None
    except Exception as e:
        log(f"  [VT] 查询异常: {e}")
        return None


def vt_upload_file(file_path: Path):
    """
    上传文件到 VirusTotal，返回 analysis_id。
    仅在文件 ≤ 32MB 时调用。
    """
    log(f"  [VT] 上传文件: {file_path.name} ({format_size(file_path.stat().st_size)})")
    try:
        with open(file_path, "rb") as f:
            r = requests.post(
                f"{VT_API_URL}/files",
                headers={"x-apikey": VT_API_KEY},
                files={"file": (file_path.name, f, "application/octet-stream")},
                timeout=120,
            )
        r.raise_for_status()
        analysis_id = r.json()["data"]["id"]
        log(f"  [VT] 上传成功，analysis_id: {analysis_id[:30]}...")
        return analysis_id
    except Exception as e:
        log(f"  [VT] 上传失败: {e}")
        return None


def vt_poll_analysis(analysis_id: str):
    """轮询分析状态，完成后返回报告 data。"""
    url = f"{VT_API_URL}/analyses/{analysis_id}"
    deadline = time.time() + VT_POLL_TIMEOUT
    while time.time() < deadline:
        try:
            r = requests.get(url, headers=vt_headers(), timeout=30)
            if r.status_code == 200:
                data = r.json()["data"]
                status = data["attributes"]["status"]
                log(f"  [VT] 分析状态: {status}")
                if status == "completed":
                    sha256 = data["meta"]["file_info"]["sha256"]
                    return vt_get_report(sha256)
                elif status == "failed":
                    log("  [VT] 分析失败")
                    return None
            else:
                log(f"  [VT] 轮询失败: {r.status_code}")
        except Exception as e:
            log(f"  [VT] 轮询异常: {e}")
        time.sleep(VT_POLL_INTERVAL)

    log("  [VT] ⚠️ 轮询超时")
    return None


def vt_process_file(file_path: Path, sha256: str):
    """
    处理单个文件：
    1. 查已有报告 → 有则返回报告 URL
    2. 无报告且文件 ≤ 32MB → 上传并等待结果
    3. 无报告且文件 > 32MB → 返回 None
    """
    # 步骤1：查已有报告
    report = vt_get_report(sha256)
    if report:
        return f"https://www.virustotal.com/gui/file/{sha256}/detection"

    # 步骤2：无报告，尝试上传（仅 ≤ 32MB）
    file_size = file_path.stat().st_size
    if file_path.exists() and file_size <= VT_UPLOAD_LIMIT:
        log(f"  [VT] 文件 {format_size(file_size)} ≤ 32MB，开始上传...")
        analysis_id = vt_upload_file(file_path)
        if analysis_id:
            report = vt_poll_analysis(analysis_id)
            if report:
                return f"https://www.virustotal.com/gui/file/{sha256}/detection"
    elif not file_path.exists():
        # iOS 没有文件，只查报告
        pass
    else:
        log(f"  [VT] ⚠️ 文件 {format_size(file_size)} > 32MB，免费 API 无法上传")
        log(f"  [VT]   请在 VirusTotal 网站手动上传，或等待社区上传")

    return None


def vt_make_badge(report_url: str | None, sha256: str) -> str:
    """生成 VirusTotal 报告链接的 Markdown。"""
    if report_url:
        return f"[查看报告]({report_url})"
    else:
        return f"暂无报告 (`{sha256[:8]}...`)"


# ──────────────────────────────────────────
# 步骤1：获取客户端信息
# ──────────────────────────────────────────

def fetch_pack_list():
    log("正在请求拼多多 API ...")
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
# 步骤2：下载安装包
# ──────────────────────────────────────────

def download_file(url: str, dest: Path, timeout: int = 300) -> bool:
    """流式下载，返回是否成功。"""
    log(f"下载: {url}")
    try:
        with requests.get(url, stream=True, timeout=timeout,
                          headers={"User-Agent": "Mozilla/5.0"}) as r:
            r.raise_for_status()
            with open(dest, "wb") as f:
                for chunk in r.iter_content(chunk_size=1024 * 256):
                    if chunk:
                        f.write(chunk)
            log(f"  ✅ 下载完成: {format_size(dest.stat().st_size)}")
            return True
    except Exception as e:
        log(f"  ❌ 下载失败: {e}")
        return False


# ──────────────────────────────────────────
# 步骤3：GitHub Release 操作
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


def list_release_assets(release_id: int) -> dict:
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
    log("  ✅ 上传成功")
    return r.json()


# ──────────────────────────────────────────
# 步骤4：上传 JSON 索引
# ──────────────────────────────────────────

def upload_index_json(release: dict, extra_info: list):
    index = {
        "generated_at": datetime.now(CST).isoformat(),
        "source_api": PDD_API_URL,
        "virustotal_api_enabled": True,
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
    vt_results = {}   # {platform_type: report_url or None}
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
        f"> VirusTotal 扫描报告由社区 API 自动查询/上传",
        f"",
        f"| 平台 | 版本 | 更新日期 | 更新内容 | VirusTotal 报告 |",
        f"|------|------|----------|----------|-----------------|",
    ]

    # 第一遍：计算文件名，下载，VT 扫描
    file_meta = []  # (pack, meta, asset_name, dest, sha256, vt_url)
    for pack in packs:
        t = pack["type"]
        meta = PLATFORM_MAP.get(t, {"name": f"type{t}", "ext": "", "emoji": "📦", "label": f"type{t}"})
        updated_at = datetime.fromtimestamp(pack["updatedAt"] / 1000, tz=CST)
        date_str = updated_at.strftime("%Y-%m-%d")
        content = pack.get("content", "").strip()
        version = pack["version"]
        ext = meta["ext"]

        # 文件名：pdd-business-client-{platform}-{version}{ext}
        asset_name = f"pdd-business-client-{meta['name']}-{version}{ext}"
        dest = DOWNLOAD_DIR / asset_name

        vt_url = None
        sha256 = None

        if t == 2:
            # iOS：无文件，仅记录 App Store 链接，尝试用 URL 查 VT
            log(f"[iOS] App Store 链接: {pack['url']} — 跳过下载")
            # iOS 没有文件哈希可查，VT 不支持 URL 直接查询 App Store
            results.append(f"[iOS] App Store: {pack['url']} (版本 {version})")
        else:
            # 下载文件
            ok = download_file(pack["url"], dest)
            if ok:
                sha256 = sha256_file(dest)
                log(f"  SHA256: {sha256}")
                # 上传 .sha256 校验文件
                sha_path = DOWNLOAD_DIR / f"{asset_name}.sha256"
                sha_path.write_text(f"{sha256}  {asset_name}\n")
                # VirusTotal 处理
                log(f"  [VT] 开始处理 VirusTotal ...")
                vt_url = vt_process_file(dest, sha256)
                if vt_url:
                    log(f"  [VT] ✅ 报告链接: {vt_url}")
                else:
                    log(f"  [VT] ⚠️ 暂无报告")
                results.append(f"[{meta['label']}] v{version} ✅ 已下载")
            else:
                results.append(f"[{meta['label']}] v{version} ❌ 下载失败")

        # 记录到 file_meta
        file_meta.append({
            "pack": pack,
            "meta": meta,
            "asset_name": asset_name,
            "dest": dest,
            "sha256": sha256,
            "vt_url": vt_url,
            "date_str": date_str,
            "content": content,
            "version": version,
        })

        # 记录到 client_infos（用于 JSON 索引）
        client_infos.append({
            "type": t,
            "platform": meta["label"],
            "version": version,
            "url": pack["url"],
            "content": content,
            "updated_at": updated_at.isoformat(),
            "sha256": sha256,
            "virustotal_url": vt_url,
        })

    # 构建表格行
    for fm in file_meta:
        pack = fm["pack"]
        meta = fm["meta"]
        vt_badge = vt_make_badge(fm["vt_url"], fm["sha256"]) if fm["sha256"] else "N/A（iOS App Store）"
        changelog_lines.append(
            f"| {meta['emoji']} {meta['label']} | `{fm['version']}` "
            f"| {fm['date_str']} | {fm['content']} | {vt_badge} |"
        )

    # Release tag 格式：pdd-clients-YYYYMMDD-HHMM
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
        "| `pdd-business-client-android-*.apk` | Android 安装包 |",
        "| `pdd-business-client-windows-*.exe` | Windows 安装程序 |",
        "| `pdd-business-client-macos-*.dmg` | macOS 安装包 |",
        "| `*.sha256` | SHA256 校验文件 |",
        "| `pdd_clients_index.json` | 完整版本信息索引（含原始下载地址、SHA256、VT报告链接） |",
        "",
        "> **iOS** 版本通过 App Store 分发，无独立安装包，请直接前往 App Store 下载。",
        "",
        "---",
        "",
        "### 🛡️ VirusTotal 安全扫描",
        "",
        "- 所有安装包均通过 VirusTotal API 自动查询/上传扫描",
        "- 报告链接如上表「VirusTotal 报告」列",
        "- 若显示「暂无报告」，表示该文件尚未被 VirusTotal 社区收录，或文件大于 32MB（免费 API 限制）",
        "- 可在 [VirusTotal 官网](https://www.virustotal.com) 手动上传查询",
    ]
    body = "\n".join(changelog_lines)

    # 3. 创建/获取 Release
    release = get_or_create_release(tag, release_name, body)
    release_id = release["id"]
    log(f"Release ID: {release_id}, URL: {release.get('html_url', '')}")

    # 4. 遍历上传 Assets
    for fm in file_meta:
        t = fm["pack"]["type"]
        if t == 2:
            continue  # iOS 无文件

        dest = fm["dest"]
        asset_name = fm["asset_name"]

        if dest.exists():
            upload_asset(release, dest, asset_name)
            # 上传 sha256 校验文件
            sha_path = DOWNLOAD_DIR / f"{asset_name}.sha256"
            if sha_path.exists():
                upload_asset(release, sha_path, f"{asset_name}.sha256")

    # 5. 上传索引 JSON
    upload_index_json(release, client_infos)
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
