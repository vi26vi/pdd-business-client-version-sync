# 拼多多商家客户端自动同步（GitCode 版）

自动每小时从拼多多商家后台获取最新客户端安装包，并上传至 **GitCode Releases**。

## 工作原理

1. 调用拼多多商家后台内部 API `https://mms.pinduoduo.com/earth/api/pack/queryPackList` 获取所有平台客户端版本信息
2. 下载 Android、Windows、macOS 安装包
3. 计算 SHA256 校验值
4. 通过 GitCode API（Gitea 兼容）创建新 Release 并上传安装包及校验文件
5. 上传完整版本信息索引 `pdd_clients_index.json`

## 支持的客户端平台

| 平台 | 文件类型 | 说明 |
|------|----------|------|
| 📱 Android | `.apk` | 直接下载安装包 |
| 🍎 iOS | — | App Store 链接，仅记录在索引中 |
| 🖥️ Windows | `.exe` | 直接下载安装程序 |
| 🍏 macOS | `.dmg` | 直接下载安装包 |

## 文件结构

```
.
├── .codechina-ci.yml                    # GitCode CI/CD 流水线
├── .github/
│   └── workflows/
│       └── pdd-client-sync.yml          # GitHub Actions 版（保留）
└── scripts/
    ├── fetch_and_release.py             # GitHub 版脚本
    └── fetch_and_release_gitcode.py     # GitCode 版脚本
```

## 使用方法

### 第一步：创建 GitCode 项目

1. 登录 [gitcode.com](https://gitcode.com)，创建新仓库
2. 将本目录所有文件推送到仓库

### 第二步：配置访问令牌

1. GitCode → 右上角头像 → **设置** → **访问令牌**
2. 创建新令牌，勾选 `api` + `write_repository` 权限
3. 复制生成的令牌

### 第三步：配置 CI 变量

进入项目 → **设置** → **DevOps** → **变量** → 添加：

| 变量名 | 值 | 说明 |
|--------|-----|------|
| `GITCODE_TOKEN` | `<你的令牌>` | 必填，用于调用 GitCode API |
| `GITCODE_DOMAIN` | `https://gitcode.com` | 可选，默认值即可 |

### 第四步：创建定时计划

1. 进入项目 → **设置** → **DevOps** → **流水线计划** → **新建计划**

2. 填写表单：

| 字段 | 值 |
|------|-----|
| 描述 | 每小时同步拼多多客户端 |
| 时间表模式 | `0 * * * *`（每小时执行一次） |
| 时间表时区 | `Asia/Shanghai` |
| 目标分支/标签 | `main`（或你的默认分支） |
| 活动 | ✅ 勾选 |

3. 保存后，定时任务立即生效

### 手动触发

进入项目 → **DevOps** → **流水线** → 点击 **运行流水线**。

## Release 命名规则

- **Tag**：`pdd-clients-YYYYMMDD-HHmm`（北京时间）
- **名称**：`拼多多商家客户端 · YYYY-MM-DD HH:MM CST`

## CI 流水线说明

流水线文件 `.codechina-ci.yml` 定义了一个 `sync` 阶段，执行流程如下：

```
Python 3.11 slim 镜像
  → 安装 requests
  → 执行 fetch_and_release_gitcode.py
    → 调用拼多多 API 获取版本信息
    → 下载各平台安装包
    → 创建 GitCode Release（API /repos/{owner}/{repo}/releases）
    → 上传安装包 + SHA256 校验 + 索引 JSON
  → 输出 sync_result.json artifacts
```

## 与 GitHub Actions 版的区别

| 特性 | GitHub Actions | GitCode CI |
|------|---------------|------------|
| 配置文件 | `.github/workflows/pdd-client-sync.yml` | `.codechina-ci.yml` |
| 脚本文件 | `scripts/fetch_and_release.py` | `scripts/fetch_and_release_gitcode.py` |
| API 路径 | `api.github.com/repos/…/releases` | `gitcode.com/api/v1/repos/…/releases` |
| 认证方式 | `GITHUB_TOKEN`（内置） | `GITCODE_TOKEN`（需手动配置） |
| 发布方式 | Releases Assets | Releases Assets（Gitea API） |

## 注意事项

- 本项目仅供学习和研究用途
- 拼多多保留修改 API 或限制访问的权利
- 安装包的版权归拼多多所有
- 确保 CI 令牌至少拥有 `api` 和 `write_repository` 权限
