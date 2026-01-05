# 🚀 Xray Auto Deployment Script (VLESS-Reality-Vision)

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![System](https://img.shields.io/badge/System-Debian%20%7C%20Ubuntu-orange)](https://github.com/accforeve/Xray-Auto)

[中文文档](#chinese) | [English Description](#english)

---

<a name="chinese"></a>
## 🇨🇳 中文说明

这是一个全自动化的 Xray 部署脚本，基于 **VLESS + Reality + XTLS-Vision** 顶尖流控协议。专为 Debian 和 Ubuntu 系统设计，提供极致的性能优化与安全防护。

### ✨ 核心功能

* **⚡️ 极速协议**: 部署最新的 VLESS + Reality + XTLS-Vision 流控组合。
* **🧠 智能 SNI 优选**: 自动测试并选择延迟最低的大厂域名（Apple, Microsoft 等）作为伪装目标，拒绝卡顿。
* **🛡️ 独家防火墙策略**: 采用 **白名单模式** (Whitelist)，默认拒绝所有非必要端口，隐藏服务器指纹。
* **🔄 一键回国模式切换**: 独有的 `mode` 指令，支持一键切换 **阻断回国 (Block CN)** 或 **允许回国 (Allow CN)** 流量。
* **⚙️ 系统深度优化**: 
    * 自动开启 BBR + FQ 加速。
    * 智能 Swap 管理（内存 < 2G 时自动创建 1G Swap）。
    * 集成 Fail2ban 防暴力破解，自动适配 SSH 端口。
* **🤖 全自动静默安装**: 完美解决 Ubuntu/Debian 安装过程中的各种弹窗询问，实现真正的无人值守部署。

### 💻 环境要求
* **操作系统**: Debian 10/11/12 或 Ubuntu 20.04/22.04/24.04
* **架构**: x86_64 / amd64
* **权限**: 需要 Root 权限

### 🚀 快速安装
```
bash <(curl -sL https://raw.githubusercontent.com/accforeve/Xray-Auto/main/install.sh)

```

### 🗑️ 卸载 / Uninstall
如果你想移除 Xray 及其相关配置：

```
bash <(curl -sL https://raw.githubusercontent.com/accforeve/Xray-Auto/main/remove.sh)

```

### 常用指令
| 指令 | 说明 |
| ---- | ---- |
| `mode` | 查看当前分流策略状态（阻断/允许回国） |
| `mode c` | 切换模式：在“阻断回国”与“允许回国”之间切换 |

### 📝 配置说明 | Configuration Details
安装结束后，脚本会自动输出连接信息，包含：
* 节点配置信息：ip、端口、SNI等，用于手输时使用。
* VLESS 链接：可直接复制导入客户端（如 v2rayN, V2Box, Shadowrocket 等）。
* 二维码：手机扫码直连。


<a name="English"></a>
## 🇺🇸 English Description
An advanced, fully automated deployment script for Xray, featuring VLESS + Reality + XTLS-Vision. Designed for performance, security, and ease of use on Debian and Ubuntu systems.
✨ Key Features
 * ⚡️ Cutting-edge Protocol: Deploys VLESS + Reality + XTLS-Vision flow control.
 * 🧠 Intelligent SNI Selection: Automatically pings and selects the fastest domain (e.g., Apple, Microsoft) for camouflage to ensure stability.
 * 🛡️ Advanced Security: Uses iptables Whitelist Mode by default, blocking all unauthorized ports to hide server fingerprint.
 * 🔄 One-Key Routing Switch: Exclusive mode command to toggle between Block CN (Block China Traffic) and Allow CN (Allow China Traffic).
 * ⚙️ System Optimization:
   * Enables BBR + FQ congestion control.
   * Smart Swap allocation (Auto-adds 1GB Swap if RAM < 2GB).
   * Fail2ban integration with auto-detection of SSH port.
 * 🤖 Silent Installation: Handles all Debian/Ubuntu prompts automatically for a truly hands-free setup.
   
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

### 📝 Configuration Details
After installation is complete, the script will automatically output connection information, including:
* **Node Configuration**: IP, Port, SNI, etc. (for manual input).
* **VLESS Link**: Can be directly copied and imported into clients (e.g., v2rayN, V2Box, Shadowrocket).
* **QR Code**: Scan with a mobile phone to connect directly.

### ⚠️ 免责声明 | Disclaimer
This script is for educational and research purposes only. The author is not responsible for any consequences arising from the use of this script. Please comply with local laws and regulations.

本脚本仅供学习、测试和科研使用。作者不对使用本脚本产生的任何后果负责。请遵守当地法律法规。

[Project maintained by accforeve](https://github.com/accforeve)

