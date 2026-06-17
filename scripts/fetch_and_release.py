#!/usr/bin/env python3
"""
拼多多商家客户端自动同步脚本
- 调用拼多多内部 API 获取所有客户端的最新版本信息
- 与 GitHub 最新 Release 中的版本号比对，无更新则跳过
- 有更新时下载各平台客户端安装包
- 上传/查询 VirusTotal 扫描报告（支持 >32MB 大文件，通过 upload_url API）
- 通过 GitHub API 创建新 Release 并上传 Assets
"""

import os
import re
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
GITHUB_REPO  = os.environ["GITHUB_REPO"]

VT_API_KEY       = os.environ.get("VT_API_KEY", "")
VT_API_URL       = "https://www.virustotal.com/api/v3"
VT_POLL_INTERVAL = 15   # 轮询间隔（秒）
VT_POLL_TIMEOUT  = 300  # 最长等待（秒），大文件扫描时间更长

PLATFORM_MAP = {
    1: {"name": "android", "ext": ".apk",  "emoji": "📱", "label": "Android"},
    2: {"name": "ios",     "ext": "",      "emoji": "🍎", "label": "iOS"},
    3: {"name": "windows", "ext": ".exe",  "emoji": "🖥️", "label": "Windows"},
    4: {"name": "macos",   "ext": ".dmg",  "emoji": "🍏", "label": "macOS"},
}

RESULT_FILE  = "/tmp/pdd_sync_result.txt"
DOWNLOAD_DIR = Path("/tmp/pdd_downloads")
DOWNLOAD_DIR.mkdir(exist_ok=True)

CST = timezone(timedelta(hours=8))

GH_API     = "https://api.github.com"
GH_HEADERS = {
    "Authorization": f"Bearer {GITHUB_TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}


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
# 版本比对：从最新 Release 提取已记录的版本号
# ──────────────────────────────────────────

def get_latest_release_versions() -> dict:
    """
    从 GitHub 最新 Release 的 body 或 Assets 文件名中解析各平台已发布版本号。
    返回格式：{platform_type_int: "version_string", ...}
    例如：{1: "7.3.6", 2: "7.3.6", 3: "3.6.6", 4: "1.0.18"}
    若无 Release，返回空 dict。
    """
    log("正在获取 GitHub 最新 Release 版本信息...")
    url = f"{GH_API}/repos/{GITHUB_REPO}/releases/latest"
    try:
        r = requests.get(url, headers=GH_HEADERS, timeout=15)
        if r.status_code == 404:
            log("  尚无任何 Release，本次将全量发布")
            return {}
        r.raise_for_status()
        release = r.json()
    except Exception as e:
        log(f"  获取 Release 失败: {e}，将视为全量发布")
        return {}

    versions = {}

    # 优先从 pdd_clients_index.json 的 Asset 内容中解析
    for asset in release.get("assets", []):
        if asset["name"] == "pdd_clients_index.json":
            try:
                download_url = asset["browser_download_url"]
                resp = requests.get(
                    download_url,
                    headers={"Authorization": f"Bearer {GITHUB_TOKEN}"},
                    timeout=15,
                )
                resp.raise_for_status()
                index = resp.json()
                for client in index.get("clients", []):
                    t = client.get("type")
                    v = client.get("version")
                    if t and v:
                        versions[t] = v
                if versions:
                    log(f"  从 index.json 解析到版本: {versions}")
                    return versions
            except Exception as e:
                log(f"  解析 index.json 失败: {e}，降级到文件名解析")
            break

    # 降级：从 Assets 文件名解析版本号
    # 文件名格式：PddWorkbenchSetup-{platform}-{version}{ext}
    name_to_type = {v["name"]: k for k, v in PLATFORM_MAP.items()}
    for asset in release.get("assets", []):
        name = asset["name"]
        # 例：PddWorkbenchSetup-android-7.3.6.apk
        m = re.match(r"PddWorkbenchSetup-(\w+)-([\d.]+)\.\w+$", name)
        if m:
            platform_name = m.group(1)
            version_str   = m.group(2)
            t = name_to_type.get(platform_name)
            if t:
                versions[t] = version_str

    # iOS 版本从 Release body 中提取（iOS 无文件，只在表格里）
    body = release.get("body", "")
    ios_m = re.search(r"iOS.*?`([\d.]+)`", body)
    if ios_m:
        versions[2] = ios_m.group(1)

    log(f"  从文件名解析到版本: {versions}")
    return versions


# ──────────────────────────────────────────
# VirusTotal 操作（支持大文件）
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
            log("  [VT] 无已有报告（404），需要上传")
            return None
        else:
            log(f"  [VT] 查询失败: {r.status_code} {r.text[:100]}")
            return None
    except Exception as e:
        log(f"  [VT] 查询异常: {e}")
        return None


def vt_get_upload_url() -> str | None:
    """
    获取大文件上传专用 URL（/api/v3/files/upload_url）。
    每个 URL 仅限使用一次。
    """
    log("  [VT] 获取大文件上传 URL ...")
    try:
        r = requests.get(
            f"{VT_API_URL}/files/upload_url",
            headers=vt_headers(),
            timeout=30,
        )
        r.raise_for_status()
        url = r.json()["data"]
        log("  [VT] 获取到上传 URL（将于首次使用后失效）")
        return url
    except Exception as e:
        log(f"  [VT] 获取上传 URL 失败: {e}")
        return None


def vt_upload_file(file_path: Path):
    """
    上传文件到 VirusTotal，自动选择上传方式：
    - ≤ 32MB：直接 POST /files
    - > 32MB：先 GET /files/upload_url，再 POST 到返回的上传 URL
    返回 analysis_id。
    """
    file_size = file_path.stat().st_size
    log(f"  [VT] 上传文件: {file_path.name} ({format_size(file_size)})")

    try:
        if file_size <= 32 * 1024 * 1024:
            log("  [VT] 使用直接上传（≤ 32MB）...")
            with open(file_path, "rb") as f:
                r = requests.post(
                    f"{VT_API_URL}/files",
                    headers={"x-apikey": VT_API_KEY},
                    files={"file": (file_path.name, f, "application/octet-stream")},
                    timeout=120,
                )
            r.raise_for_status()
            analysis_id = r.json()["data"]["id"]
            log(f"  [VT] ✅ 上传成功，analysis_id: {analysis_id[:30]}...")
            return analysis_id
        else:
            log("  [VT] 使用 upload_url 上传（> 32MB）...")
            upload_url = vt_get_upload_url()
            if not upload_url:
                log("  [VT] ❌ 无法获取上传 URL，中止上传")
                return None
            with open(file_path, "rb") as f:
                r = requests.post(
                    upload_url,
                    headers={"x-apikey": VT_API_KEY},
                    files={"file": (file_path.name, f, "application/octet-stream")},
                    timeout=600,
                )
            r.raise_for_status()
            analysis_id = r.json()["data"]["id"]
            log(f"  [VT] ✅ 大文件上传成功，analysis_id: {analysis_id[:30]}...")
            return analysis_id

    except Exception as e:
        log(f"  [VT] ❌ 上传失败: {e}")
        return None


def vt_poll_analysis(analysis_id: str):
    """轮询分析状态，完成后返回报告 data。"""
    url      = f"{VT_API_URL}/analyses/{analysis_id}"
    deadline = time.time() + VT_POLL_TIMEOUT
    while time.time() < deadline:
        try:
            r = requests.get(url, headers=vt_headers(), timeout=30)
            if r.status_code == 200:
                data   = r.json()["data"]
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

    log(f"  [VT] ⚠️ 轮询超时（{VT_POLL_TIMEOUT}s）")
    return None


def vt_process_file(file_path: Path, sha256: str):
    """
    处理单个文件：
    1. 查已有报告 → 有则直接返回报告 URL
    2. 无报告    → 上传文件（自动适配大小），等待扫描完成
    """
    report = vt_get_report(sha256)
    if report:
        return f"https://www.virustotal.com/gui/file/{sha256}/detection"

    if file_path.exists():
        log(f"  [VT] 开始上传文件（{format_size(file_path.stat().st_size)}）...")
        analysis_id = vt_upload_file(file_path)
        if analysis_id:
            report = vt_poll_analysis(analysis_id)
            if report:
                return f"https://www.virustotal.com/gui/file/{sha256}/detection"

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
            "Accept":       "application/json",
            "Referer":      PDD_REFERER,
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

def create_release(tag: str, release_name: str, body: str) -> dict:
    """创建新 Release。"""
    log(f"创建新 Release: {tag}")
    url = f"{GH_API}/repos/{GITHUB_REPO}/releases"
    payload = {
        "tag_name":    tag,
        "name":        release_name,
        "body":        body,
        "draft":       False,
        "prerelease":  False,
        "make_latest": "true",
    }
    resp = requests.post(url, json=payload, headers=GH_HEADERS, timeout=15)
    resp.raise_for_status()
    return resp.json()


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
    existing   = list_release_assets(release["id"])
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
            timeout=600,
        )
    r.raise_for_status()
    log("  ✅ 上传成功")
    return r.json()


# ──────────────────────────────────────────
# 步骤4：上传 JSON 索引
# ──────────────────────────────────────────

def upload_index_json(release: dict, client_infos: list):
    index = {
        "generated_at":          datetime.now(CST).isoformat(),
        "source_api":            PDD_API_URL,
        "virustotal_api_enabled": True,
        "clients":               client_infos,
    }
    index_path = DOWNLOAD_DIR / "pdd_clients_index.json"
    index_path.write_text(json.dumps(index, ensure_ascii=False, indent=2), encoding="utf-8")
    upload_asset(release, index_path, "pdd_clients_index.json")


# ──────────────────────────────────────────
# 主流程
# ──────────────────────────────────────────

def main():
    run_time = datetime.now(CST)
    results  = []

    # ── 1. 获取拼多多最新版本信息 ──────────────────────────
    packs = fetch_pack_list()

    # ── 2. 获取 GitHub 最新 Release 中的版本号 ────────────
    latest_versions = get_latest_release_versions()
    # latest_versions: {type_int: "version_str"}

    # ── 3. 比对：找出有版本变化的平台 ─────────────────────
    updated_types = set()
    for pack in packs:
        t       = pack["type"]
        new_ver = pack["version"]
        old_ver = latest_versions.get(t)
        if old_ver != new_ver:
            meta = PLATFORM_MAP.get(t, {})
            log(f"  [{meta.get('label', t)}] 版本有更新: {old_ver or '(无)'} → {new_ver}")
            updated_types.add(t)
        else:
            meta = PLATFORM_MAP.get(t, {})
            log(f"  [{meta.get('label', t)}] 版本无变化: {new_ver}，跳过")

    if not updated_types:
        msg = "所有平台版本均无更新，本次跳过发布"
        log(msg)
        Path(RESULT_FILE).write_text(
            f"执行时间: {run_time.strftime('%Y-%m-%d %H:%M:%S CST')}\n{msg}\n",
            encoding="utf-8",
        )
        return

    log(f"共 {len(updated_types)} 个平台有更新，开始处理...")

    # ── 4. 构建版本表格 & 处理有更新的平台 ────────────────
    client_infos    = []
    file_meta       = []
    changelog_lines = [
        "## 拼多多商家客户端最新版本",
        "",
        f"> 自动同步时间：{run_time.strftime('%Y年%m月%d日 %H:%M')} (CST)",
        f"> 数据来源：[拼多多商家后台]({PDD_REFERER})",
        "> VirusTotal 扫描报告由社区 API 自动查询/上传（支持 ≤650MB 大文件）",
        "",
        "| 平台 | 版本 | 更新状态 | 更新日期 | 更新内容 | VirusTotal 报告 |",
        "|------|------|----------|----------|----------|-----------------|",
    ]

    for pack in packs:
        t          = pack["type"]
        meta       = PLATFORM_MAP.get(
            t, {"name": f"type{t}", "ext": "", "emoji": "📦", "label": f"type{t}"}
        )
        updated_at = datetime.fromtimestamp(pack["updatedAt"] / 1000, tz=CST)
        date_str   = updated_at.strftime("%Y-%m-%d")
        content    = pack.get("content", "").strip()
        version    = pack["version"]
        ext        = meta["ext"]
        is_updated = t in updated_types

        asset_name = f"PddWorkbenchSetup-{meta['name']}-{version}{ext}"
        dest       = DOWNLOAD_DIR / asset_name
        vt_url     = None
        sha256     = None

        if t == 2:
            # iOS：无文件
            log(f"[iOS] App Store 链接: {pack['url']} (版本 {version})")
            results.append(f"[iOS] App Store: {pack['url']} (版本 {version})")
        elif is_updated:
            # 有更新 → 下载 + VT 扫描
            ok = download_file(pack["url"], dest)
            if ok:
                sha256   = sha256_file(dest)
                sha_path = DOWNLOAD_DIR / f"{asset_name}.sha256"
                sha_path.write_text(f"{sha256}  {asset_name}\n")
                log(f"  SHA256: {sha256}")
                log(f"  [VT] 开始处理 VirusTotal ...")
                vt_url = vt_process_file(dest, sha256)
                if vt_url:
                    log(f"  [VT] ✅ 报告链接: {vt_url}")
                else:
                    log("  [VT] ⚠️ 暂无报告")
                results.append(f"[{meta['label']}] v{version} ✅ 已下载（新版本）")
            else:
                results.append(f"[{meta['label']}] v{version} ❌ 下载失败")
        else:
            # 无更新 → 不下载，仅记录
            results.append(f"[{meta['label']}] v{version} — 版本无变化，已跳过")

        # 状态标记
        if t == 2:
            status_badge = "🍎 App Store"
        elif is_updated:
            old_ver = latest_versions.get(t, "")
            status_badge = f"🆕 {old_ver + ' → ' if old_ver else '首次发布 → '}{version}"
        else:
            status_badge = "✅ 无变化"

        file_meta.append({
            "pack":       pack,
            "meta":       meta,
            "asset_name": asset_name,
            "dest":       dest,
            "sha256":     sha256,
            "vt_url":     vt_url,
            "date_str":   date_str,
            "content":    content,
            "version":    version,
            "is_updated": is_updated,
        })

        client_infos.append({
            "type":           t,
            "platform":       meta["label"],
            "version":        version,
            "url":            pack["url"],
            "content":        content,
            "updated_at":     updated_at.isoformat(),
            "sha256":         sha256,
            "virustotal_url": vt_url,
        })

        # 表格行
        if t == 2:
            vt_badge = "N/A（iOS App Store）"
        elif sha256:
            vt_badge = vt_make_badge(vt_url, sha256)
        else:
            vt_badge = "— （版本无变化）"

        changelog_lines.append(
            f"| {meta['emoji']} {meta['label']} "
            f"| `{version}` "
            f"| {status_badge} "
            f"| {date_str} "
            f"| {content} "
            f"| {vt_badge} |"
        )

    # 组装 Release body
    updated_labels = [
        PLATFORM_MAP.get(t, {}).get("label", str(t))
        for t in updated_types
    ]
    changelog_lines += [
        "",
        "---",
        "",
        "### 📥 文件说明",
        "",
        "| 文件名 | 说明 |",
        "|--------|------|",
        "| `PddWorkbenchSetup-android-*.apk` | Android 安装包 |",
        "| `PddWorkbenchSetup-windows-*.exe` | Windows 安装程序 |",
        "| `PddWorkbenchSetup-macos-*.dmg`   | macOS 安装包 |",
        "| `*.sha256`                          | SHA256 校验文件 |",
        "| `pdd_clients_index.json`            | 完整版本信息索引（含原始下载地址、SHA256、VT报告链接） |",
        "",
        "> **iOS** 版本通过 App Store 分发，无独立安装包，请直接前往 App Store 下载。",
        "",
        "---",
        "",
        "### 🛡️ VirusTotal 安全扫描",
        "",
        "- 所有安装包均通过 VirusTotal API 自动查询/上传扫描",
        "- 报告链接如上表「VirusTotal 报告」列",
        "- 免费 API 支持上传最大 **650MB** 的文件（通过 `/files/upload_url` 接口）",
        "- 若显示「暂无报告」，表示该文件尚未被 VirusTotal 社区收录且首次上传后扫描未完成",
        "- 可在 [VirusTotal 官网](https://www.virustotal.com) 手动查看",
        "",
        "---",
        "",
        f"> 本次更新平台：**{'、'.join(updated_labels)}**",
    ]
    body = "\n".join(changelog_lines)

    # ── 5. 创建 Release ─────────────────────────────────
    tag          = f"pdd-clients-{run_time.strftime('%Y%m%d-%H%M')}"
    release_name = f"拼多多商家客户端 · {run_time.strftime('%Y-%m-%d %H:%M')} CST"
    release      = create_release(tag, release_name, body)
    log(f"Release 创建成功: {release.get('html_url', '')}")

    # ── 6. 上传有更新平台的 Assets ───────────────────────
    for fm in file_meta:
        t = fm["pack"]["type"]
        if t == 2 or not fm["is_updated"]:
            continue  # iOS 无文件；无更新平台不上传

        dest       = fm["dest"]
        asset_name = fm["asset_name"]

        if dest.exists():
            upload_asset(release, dest, asset_name)
            sha_path = DOWNLOAD_DIR / f"{asset_name}.sha256"
            if sha_path.exists():
                upload_asset(release, sha_path, f"{asset_name}.sha256")

    # ── 7. 上传索引 JSON ─────────────────────────────────
    upload_index_json(release, client_infos)
    results.append("[INDEX] pdd_clients_index.json ✅ 已上传")

    # ── 8. 写入结果文件 ──────────────────────────────────
    summary = "\n".join([
        f"执行时间: {run_time.strftime('%Y-%m-%d %H:%M:%S CST')}",
        f"更新平台: {', '.join(updated_labels)}",
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
