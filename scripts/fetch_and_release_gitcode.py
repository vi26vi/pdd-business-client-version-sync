#!/usr/bin/env python3
"""
拼多多商家客户端自动同步脚本（GitCode 版）
- 调用拼多多内部 API 获取所有客户端的最新版本信息
- 下载各平台客户端安装包
- 通过 GitCode API（兼容 Gitea）创建 Release 并上传 Assets

环境变量（GitCode CI 自动注入）：
  CI_JOB_TOKEN          Job 临时令牌（仅限读取仓库等操作）
  CI_PROJECT_PATH       项目路径，如 "owner/repo"
  CI_PROJECT_ID          项目数字 ID

需要手动配置的 CI 变量（设置 → DevOps → 变量）：
  GITCODE_TOKEN          个人访问令牌（需要 api + write_repository 权限）
  GITCODE_DOMAIN         可选，GitCode 域名，默认 https://gitcode.com
"""

import os
import sys
import json
import hashlib
import requests
from datetime import datetime, timezone, timedelta
from pathlib import Path

# ──────────────────────────────────────────
# 常量配置
# ──────────────────────────────────────────

PDD_API_URL = "https://mms.pinduoduo.com/earth/api/pack/queryPackList"
PDD_REFERER = "https://mms.pinduoduo.com/other/download_app"

GITCODE_DOMAIN = os.environ.get("GITCODE_DOMAIN", "https://gitcode.com")
PROJECT_PATH = os.environ.get("CI_PROJECT_PATH") or os.environ.get("CI_PROJECT_NAME") or ""
PROJECT_ID   = os.environ.get("CI_PROJECT_ID", "")

# 优先使用用户配置的 PAT，回退到 CI_JOB_TOKEN（后者权限受限）
GITCODE_TOKEN = os.environ.get("GITCODE_TOKEN") or os.environ.get("CI_JOB_TOKEN", "")

API_BASE = f"{GITCODE_DOMAIN}/api/v1"

CST = timezone(timedelta(hours=8))
DOWNLOAD_DIR = Path("/tmp/pdd_downloads")
DOWNLOAD_DIR.mkdir(exist_ok=True)

PLATFORM_MAP = {
    1: {"name": "Android",  "ext": ".apk",  "emoji": "📱"},
    2: {"name": "iOS",      "ext": "",      "emoji": "🍎"},
    3: {"name": "Windows",  "ext": ".exe",  "emoji": "🖥️"},
    4: {"name": "macOS",    "ext": ".dmg",  "emoji": "🍏"},
}

# URL 编码项目路径（替换 / 为 %2F）
def url_encode_project_path(path: str) -> str:
    return path.replace("/", "%2F")


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


def api_headers() -> dict:
    """返回带有认证的请求头。"""
    return {
        "Authorization": f"token {GITCODE_TOKEN}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def api_get(path: str) -> dict:
    r = requests.get(f"{API_BASE}{path}", headers=api_headers(), timeout=30)
    r.raise_for_status()
    return r.json()


def api_post(path: str, data: dict) -> dict:
    r = requests.post(f"{API_BASE}{path}", headers=api_headers(), json=data, timeout=30)
    r.raise_for_status()
    return r.json()


def api_delete(path: str):
    r = requests.delete(f"{API_BASE}{path}", headers=api_headers(), timeout=30)
    r.raise_for_status()


def api_upload(path: str, file_path: Path, file_key: str = "attachment") -> dict:
    """multipart 上传文件。"""
    with open(file_path, "rb") as f:
        headers = {"Authorization": f"token {GITCODE_TOKEN}"}
        r = requests.post(
            f"{API_BASE}{path}",
            headers=headers,
            files={file_key: (file_path.name, f, "application/octet-stream")},
            timeout=300,
        )
    r.raise_for_status()
    return r.json()


# ──────────────────────────────────────────
# 步骤 1：获取拼多多客户端信息
# ──────────────────────────────────────────

def fetch_pack_list() -> list[dict]:
    log("请求拼多多 API …")
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

def download_file(url: str, dest: Path, timeout: int = 300) -> bool:
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
# 步骤 3：GitCode Release 操作（Gitea API）
# ──────────────────────────────────────────

def encode_path(path: str) -> str:
    """将 owner/repo 路径进行 URL 编码。"""
    return path.replace("/", "%2F")


def create_tag(tag_name: str, message: str = "") -> bool:
    """在 GitCode 仓库创建轻量标签。"""
    log(f"创建标签: {tag_name}")
    try:
        payload = {
            "tag_name": tag_name,
            "message": message,
        }
        path = f"/repos/{encode_path(PROJECT_PATH)}/tags"
        api_post(path, payload)
        log(f"  ✅ 标签已创建")
        return True
    except requests.HTTPError as e:
        if e.response.status_code == 409:
            log(f"  ⚠️ 标签已存在，跳过创建")
            return True
        log(f"  ❌ 创建标签失败: {e}")
        return False


def get_release_by_tag(tag_name: str) -> dict | None:
    """通过标签名查找已存在的 Release。"""
    try:
        path = f"/repos/{encode_path(PROJECT_PATH)}/releases/tags/{tag_name}"
        return api_get(path)
    except requests.HTTPError as e:
        if e.response.status_code == 404:
            return None
        raise


def delete_release_by_tag(tag_name: str):
    """删除指定标签的 Release。"""
    release = get_release_by_tag(tag_name)
    if release:
        rel_id = release["id"]
        path = f"/repos/{encode_path(PROJECT_PATH)}/releases/{rel_id}"
        api_delete(path)
        log(f"  ✅ 已删除旧 Release (id={rel_id})")


def create_release(tag_name: str, name: str, body: str) -> dict:
    """创建新的 Release。先删除旧的（如果存在）。"""
    existing = get_release_by_tag(tag_name)
    if existing:
        log(f"  ⚠️ Release 已存在 (tag={tag_name})，将删除并重建")
        delete_release_by_tag(tag_name)

    log(f"创建 Release: {name}")
    payload = {
        "tag_name": tag_name,
        "name": name,
        "body": body,
        "draft": False,
        "prerelease": False,
    }
    path = f"/repos/{encode_path(PROJECT_PATH)}/releases"
    release = api_post(path, payload)
    log(f"  ✅ Release 已创建: id={release['id']}")
    return release


def delete_asset(release_id: int, asset_id: int):
    path = f"/repos/{encode_path(PROJECT_PATH)}/releases/{release_id}/assets/{asset_id}"
    api_delete(path)


def upload_asset(release_id: int, file_path: Path, asset_name: str) -> dict:
    """上传 Asset 到指定 Release。若同名已存在则先删除。"""
    # 先列出已有的 assets，检查同名
    try:
        existing = api_get(f"/repos/{encode_path(PROJECT_PATH)}/releases/{release_id}/assets")
        for a in existing:
            if a.get("name") == asset_name:
                log(f"  旧 Asset 已存在，先删除: {asset_name}")
                delete_asset(release_id, a["id"])
    except Exception:
        pass

    log(f"  上传 Asset: {asset_name} ({format_size(file_path.stat().st_size)})")
    path = f"/repos/{encode_path(PROJECT_PATH)}/releases/{release_id}/assets"
    result = api_upload(path, file_path)
    log(f"  ✅ 上传成功: {result.get('browser_download_url', 'OK')}")
    return result


# ──────────────────────────────────────────
# 步骤 4：上传 JSON 索引
# ──────────────────────────────────────────

def upload_index_json(release_id: int, packs: list[dict], client_infos: list[dict]):
    index = {
        "generated_at": datetime.now(CST).isoformat(),
        "source_api": PDD_API_URL,
        "source_page": PDD_REFERER,
        "clients": client_infos,
    }
    index_path = DOWNLOAD_DIR / "pdd_clients_index.json"
    index_path.write_text(json.dumps(index, ensure_ascii=False, indent=2), encoding="utf-8")
    upload_asset(release_id, index_path, "pdd_clients_index.json")


# ──────────────────────────────────────────
# 主流程
# ──────────────────────────────────────────

def main():
    if not GITCODE_TOKEN:
        log("❌ 致命错误：未配置 GITCODE_TOKEN CI 变量")
        log("  请在 GitCode 项目 → 设置 → DevOps → 变量 → 添加变量")
        log("  变量名: GITCODE_TOKEN")
        log("  变量值: 你的个人访问令牌（需要 api + write_repository 权限）")
        sys.exit(1)

    if not PROJECT_PATH:
        log("❌ 致命错误：无法获取项目路径（CI_PROJECT_PATH 或 CI_PROJECT_NAME）")
        sys.exit(1)

    log(f"GitCode 项目: {PROJECT_PATH} (id={PROJECT_ID})")
    log(f"API 地址: {API_BASE}")

    results = []
    run_time = datetime.now(CST)

    # 1. 获取客户端信息
    packs = fetch_pack_list()

    # 2. 构建 Release 内容
    client_infos = []
    changelog_lines = [
        f"## 🛒 拼多多商家客户端最新版本",
        f"",
        f"> ⏰ 自动同步时间：{run_time.strftime('%Y年%m月%d日 %H:%M')} (CST)",
        f"> 📡 数据来源：[拼多多商家后台]({PDD_REFERER})",
        f"",
        f"| 平台 | 版本 | 更新日期 | 更新内容 |",
        f"|------|------|----------|----------|",
    ]

    for pack in packs:
        t = pack["type"]
        meta = PLATFORM_MAP.get(t, {"name": f"type{t}", "ext": "", "emoji": "📦"})
        updated_at = datetime.fromtimestamp(pack["updatedAt"] / 1000, tz=CST)
        date_str = updated_at.strftime("%Y-%m-%d")
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

    # Release tag: pdd-clients-YYYYMMDD-HHmm
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
        "> **iOS 版本**通过 App Store 分发，无独立安装包。",
        "",
        "> ⚠️ 本项目仅做自动化同步，所有安装包版权归拼多多所有。",
    ]
    body = "\n".join(changelog_lines)

    # 3. 创建标签 + Release
    if not create_tag(tag):
        log("⚠️ 标签创建失败，继续尝试创建 Release …")

    try:
        release = create_release(tag, release_name, body)
        release_id = release["id"]
        log(f"Release ID: {release_id}")
        log(f"Release URL: {GITCODE_DOMAIN}/{PROJECT_PATH}/-/releases/{tag}")
    except Exception as e:
        log(f"❌ 创建 Release 失败: {e}")
        sys.exit(1)

    # 4. 下载并上传各平台安装包
    for pack in packs:
        t = pack["type"]
        meta = PLATFORM_MAP.get(t, {"name": f"type{t}", "ext": "", "emoji": "📦"})

        if t == 2:  # iOS
            log(f"[iOS] App Store: {pack['url']} — 仅记录，跳过下载")
            results.append(
                {"platform": "iOS", "version": pack["version"],
                 "status": "skipped", "url": pack["url"]}
            )
            continue

        version = pack["version"]
        ext = meta["ext"]
        asset_name = f"pdd-merchant-{meta['name'].lower()}-{version}{ext}"
        dest = DOWNLOAD_DIR / asset_name

        ok = download_file(pack["url"], dest)
        if ok:
            sha = sha256_file(dest)
            log(f"  SHA256: {sha}")
            upload_asset(release_id, dest, asset_name)

            # SHA256 校验文件
            sha_path = DOWNLOAD_DIR / f"{asset_name}.sha256"
            sha_path.write_text(f"{sha}  {asset_name}\n", encoding="utf-8")
            upload_asset(release_id, sha_path, f"{asset_name}.sha256")

            results.append(
                {"platform": meta["name"], "version": version,
                 "status": "uploaded", "sha256": sha}
            )
        else:
            results.append(
                {"platform": meta["name"], "version": version,
                 "status": "download_failed"}
            )

    # 5. 上传索引 JSON
    upload_index_json(release_id, packs, client_infos)
    results.append({"platform": "index", "version": "",
                    "status": "uploaded", "file": "pdd_clients_index.json"})

    # 6. 输出结果
    summary = {
        "executed_at": run_time.isoformat(),
        "project": PROJECT_PATH,
        "release_tag": tag,
        "release_url": f"{GITCODE_DOMAIN}/{PROJECT_PATH}/-/releases/{tag}",
        "results": results,
    }

    print("\n" + "=" * 60)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print("=" * 60)

    # 写入 artifacts
    Path("sync_result.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    log("✅ 同步完成")


if __name__ == "__main__":
    main()
