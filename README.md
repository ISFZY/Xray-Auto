# 🚀 Xray Auto Deployment Script (VLESS-Reality-Vision/xhttp)

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![System](https://img.shields.io/badge/System-Debian%20%7C%20Ubuntu-orange)](https://github.com/accforeve/Xray-Auto)

[中文文档](#chinese) | [English Description](#english)

---

<a name="chinese"></a>
## 🇨🇳 中文说明
这是一个全自动化的 Xray 部署脚本，基于 **VLESS + Reality + XTLS-Vision/(xhttp)** 顶尖流控协议。专为 Debian 和 Ubuntu 系统设计，提供极致的性能优化与安全防护。

* 版本: v0.1
* 核心: Xray-core (VLESS + Reality)
* 协议: TCP-Vision (主力) + xhttp (备用)(v0.2)
 
### ✨ 核心功能

* **⚡️ 极速协议**: 部署最新的 VLESS + Reality + XTLS-Vision/xhttp 流控组合。
* **🧠 智能 SNI 优选**: 自动测试并选择延迟最低的大厂域名（Apple, Microsoft 等）作为伪装目标，拒绝卡顿。
* **🛡️ 独家防火墙策略**: 采用 **白名单模式** (Whitelist)，默认拒绝所有非必要端口，隐藏服务器指纹。
* **🔄 一键回国模式切换**: 独有的 `mode` 指令，支持一键切换 **阻断回国 (Block CN)** 或 **允许回国 (Allow CN)** 流量。
* **⚙️ 系统深度优化**: 
    * 自动开启 BBR + FQ 加速。
    * 智能 Swap 管理（内存 < 2G 时自动创建 1G Swap）。
    * 集成 Fail2ban 防暴力破解，自动适配 SSH 端口。
* **🤖 全自动静默安装**: 完美解决 Ubuntu/Debian 安装过程中的各种弹窗询问，实现真正的无人值守部署。

### 🛑 安装前必读：风险审计与注意事项
>**[!WARNING]**
> 警告：本脚本包含强制性的系统修改操作，请务必在运行前阅读以下风险清单。
> 强烈建议仅在全新的、纯净的 VPS 系统上运行此脚本。
>
**1. 🔥 网络与防火墙风险 (严重)**

| 风险点 | 详细描述 | 后果 |
|---|---|---|
| 暴力重置防火墙 | 脚本会执行 iptables -F 清空所有规则。 | 如果你的服务器上有 Docker、K8s 或自定义的路由转发，网络将立即瘫痪。 |
| 默认拒绝策略 | 仅放行 SSH、443、8443 端口，其余入站流量全部 DROP。 | 如果你修改了 SSH 端口且脚本未检测到，或者使用 VNC/Web面板，你将被锁在服务器外。 |
| 端口强占 | 强制占用 443 和 8443 端口。 | 如果本机已运行 Nginx/Apache/Caddy 占用 443，Xray 将启动失败且原网站无法访问。 |
| 流量限制（BT） | 脚本内置路由规则，强制阻断 BitTorrent 协议。 | 无法使用此节点进行 BT/P2P 下载。（这是为了防止 DMCA 投诉导致 VPS 被商家封锁）。 |

**2. ⚙️ 系统环境风险 (中等)**
 * 强制杀进程：脚本运行初期会执行 killall apt，如果后台正在进行系统更新，可能导致 dpkg 数据库损坏。
 * 强制内核/系统升级：脚本包含 apt-get upgrade，可能会升级内核。对特定内核版本有依赖的环境请勿运行。
 * Swap 创建：会在磁盘强制创建 1GB Swap 文件（如果内存<2G）。

**3. 📱 客户端兼容性 (重要)**
(本脚本部署了两种最新协议，请确保你的客户端支持)：
 * 节点 1 (Vision): 需要 Xray-core v1.8.0+ (如 v2rayN 6.x+, Shadowrocket 最新版)。
 * 节点 2 (xhttp): 极新协议 (Xray v1.8.24+)，目前仅少数最新版客户端（如 v2rayN 预发行版、Nekobox 最新版）支持。

### 🛠️ 安装指南
环境要求:
 * 系统: Debian 10+ / Ubuntu 20.04+
 * 权限: Root 用户
 * 状态: 端口 443/8443 未被占用

**🚀 快速安装**
```
bash <(curl -sL https://raw.githubusercontent.com/accforeve/Xray-Auto/main/install.sh)

```
**🗑️ 卸载**
如果你想移除 Xray 及其相关配置：
```
bash <(curl -sL https://raw.githubusercontent.com/accforeve/Xray-Auto/main/remove.sh)

```
### 常用指令
| 指令 | 说明 |
| ---- | ---- |
| `mode` | 查看当前分流策略状态（阻断/允许回国） |
| `mode c` | 切换模式：在“阻断回国”与“允许回国”之间切换 |

**配置文件路径:**
 * Xray 配置: /usr/local/etc/xray/config.json

### 📝 配置说明 | Configuration Details
安装结束后，脚本会自动输出连接信息，包含：
* 节点配置信息：ip、端口、SNI等，用于手输时使用。
* VLESS 链接：可直接复制导入客户端（如 v2rayN, V2Box, Shadowrocket 等）。
* 二维码：手机扫码直连。


<a name="English"></a>
## 🇺🇸 English Description
An advanced, fully automated deployment script for Xray, featuring VLESS + Reality + XTLS-Vision. Designed for performance, security, and ease of use on Debian and Ubuntu systems.

* Version: v0.1
* Core: Xray-core (VLESS + Reality)  
* Protocols: TCP-Vision (Primary) + xhttp (Secondary/Fallback)（v0.2)

### ✨ Key Features
 * ⚡️ Cutting-edge Protocol: Deploys VLESS + Reality + XTLS-Vision flow control.
 * 🧠 Intelligent SNI Selection: Automatically pings and selects the fastest domain (e.g., Apple, Microsoft) for camouflage to ensure stability.
 * 🛡️ Advanced Security: Uses iptables Whitelist Mode by default, blocking all unauthorized ports to hide server fingerprint.
 * 🔄 One-Key Routing Switch: Exclusive mode command to toggle between Block CN (Block China Traffic) and Allow CN (Allow China Traffic).
 * ⚙️ System Optimization:
   * Enables BBR + FQ congestion control.
   * Smart Swap allocation (Auto-adds 1GB Swap if RAM < 2GB).
   * Fail2ban integration with auto-detection of SSH port.
 * 🤖 Silent Installation: Handles all Debian/Ubuntu prompts automatically for a truly hands-free setup.

### 🛑 READ BEFORE INSTALLATION: Risk Assessment & Audit
> [!WARNING]
> **CRITICAL WARNING: This script performs aggressive system modifications.**
> **It is strongly recommended to run this ONLY on a FRESH, CLEAN VPS installation.**
> 
**1. 🔥 Network & Firewall Risks (High Severity)**
| Risk Item | Description | Potential Consequence |
| :--- | :--- | :--- |
| **Aggressive Firewall Reset** | The script executes `iptables -F` to flush ALL existing rules. | If you are running **Docker**, **Kubernetes**, or custom routing, **your network will break immediately**. |
| **Strict Default Policy** | Sets default input policy to `DROP`. Only SSH, 443, and 8443 are allowed. | If you use a non-standard SSH port (and the script fails to detect it) or a web panel, **you will be locked out**. |
| **Port Conflict (443)** | Forces binding to ports `443` and `8443`. | If **Nginx/Apache/Caddy** is already running on port 443, Xray will fail to start, and your existing websites will go down. |
| **Traffic Restriction (BT)** | **BitTorrent traffic is blocked** by internal routing rules. | You **cannot** use this node for Torrent/P2P downloads. (This is intended to protect your VPS from DMCA bans). |

**2. ⚙️ System Environment Risks (Medium Severity)**
* **Force Kill Processes**: The script executes `killall apt` at startup. If a system update is running in the background, this may corrupt the `dpkg` database.
* **Forced System Upgrade**: Includes `apt-get upgrade`, which may update the kernel. Do not run if your environment depends on a specific kernel version.
* **Swap Creation**: Automatically creates a 1GB Swap file if RAM < 2GB.

**3. 📱 Client Compatibility (Important)**
This script deploys two cutting-edge protocols. Ensure your client supports them:
* **Node 1 (Vision)**: Requires **Xray-core v1.8.0+** (e.g., v2rayN 6.x+, latest Shadowrocket).
* **Node 2 (xhttp)**: **Experimental/New Protocol** (Xray v1.8.24+). Only supported by very recent clients (e.g., v2rayN Pre-release, latest Nekobox).

### 🛠️ Installation Guide

**Prerequisites**:
* **OS**: Debian 10+ / Ubuntu 20.04+
* **User**: Root privileges required
* **Network**: Ports 443 and 8443 must be open and unused.

### 💻 Requirements
 * OS: Debian 10/11/12 or Ubuntu 20.04/22.04/24.04
 * Arch: x86_64 / amd64
 * Auth: Root access required
   
### 🚀 Installation
Replace YourUsername and YourRepo with your actual GitHub username and repository name:
```
bash <(curl -sL https://raw.githubusercontent.com/accforeve/Xray-Auto/main/install.sh)

```
### 🗑️ Uninstall
To remove Xray and its associated configurations:
```
bash <(curl -sL https://raw.githubusercontent.com/accforeve/Xray-Auto/main/remove.sh)

```
### 🛠 Management
After installation, use the following commands:
| Command | Description |
|---|---|
| mode | Check current routing status (Block/Allow CN) |
| mode c | Switch Mode: Toggle between Blocking and Allowing CN traffic |


**Configuration Paths:**
 * Xray Config: /usr/local/etc/xray/config.json

### 📝 Configuration Details
After installation is complete, the script will automatically output connection information, including:
* **Node Configuration**: IP, Port, SNI, etc. (for manual input).
* **VLESS Link**: Can be directly copied and imported into clients (e.g., v2rayN, V2Box, Shadowrocket).
* **QR Code**: Scan with a mobile phone to connect directly.

### ⚠️ 免责声明 | Disclaimer
This script is for educational and technical research purposes only. The author is not responsible for any server data loss, IP bans, or other consequences resulting from the use of this script. Please comply with local laws and regulations.

本脚本仅供学习与技术研究使用。作者不对因使用本脚本造成的服务器数据丢失、IP 被封锁或其他后果负责。请遵守当地法律法规。

[Project maintained by accforeve](https://github.com/accforeve)

