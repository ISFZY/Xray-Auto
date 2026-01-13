# 🚀 Xray-Auto Installer

![Version](https://img.shields.io/badge/version-1.0-blue?style=flat-square)
![Language](https://img.shields.io/badge/language-Bash-4EAA25?style=flat-square&logo=gnu-bash&logoColor=white)
![Core](https://img.shields.io/badge/core-Xray-0066CC?style=flat-square&logo=telegram&logoColor=white)
![Network](https://img.shields.io/badge/network-IPv4%2FIPv6-orange?style=flat-square)
![License](https://img.shields.io/badge/license-GPL%20v3-blue?style=flat-square)

[🇨🇳 中文说明](#-中文说明) | [🇺🇸 English Guide](#-english-guide)

---

<a name="中文说明"></a>
## 🇨🇳 中文说明

**Xray-Auto Installer** 是一个高度自动化、界面美观且功能强大的 Xray 部署脚本。基于 **VLESS-Reality** 协议，集成 **Vision** 和 **xhttp** 两种流控模式，完美适配 **IPv4 和 IPv6** 双栈环境。

### ✨ 核心特性
* **⚡ 极致性能组合**: 默认部署 **VLESS-Reality**，无需域名和证书。同时开启 **TCP-Vision** (极速) 和 **xhttp** (高隐蔽) 双节点。
* **🌐 智能双栈网络**: v0.4 新增环境自动检测。自动识别 IPv4 Only / IPv6 Only / 双栈环境，并调整路由策略，完美支持纯 IPv6 VPS。
* **🎨 交互式 UI**: 拥有漂亮的 Banner、动态加载动画 (Spinner)、颜色高亮和倒计时交互，告别枯燥的安装过程。
* **🔍 智能 SNI 优选**: 内置大厂域名列表，安装时自动测速，为你选择延迟最低的最佳伪装域名。
* **🛡️ 全方位安全**:
    * 自动配置 `iptables` (v4) 和 `ip6tables` (v6) 防火墙。
    * 集成 `Fail2ban`，防止 SSH 暴力破解。
* **📱 贴心工具箱**:
    * `info`：支持动态 IP 显示，提供**交互式二维码**生成（按需显示，不刷屏）。
    * `ports`：修改 SSH 等端口。
    * `net`：一键切换 **ipv4/ipv6**。

### 🛠️ 环境要求
* **操作系统**: Debian 10+ / Ubuntu 20.04+ (推荐 Debian 11/12)
* **架构**: x86_64 / arm64
* **权限**: 需要 `root` 用户权限
* **网络**: 必须有公网 IP (IPv4 或 IPv6 均可)

### 🚀 快速开始

使用 `root` 用户登录服务器，执行以下命令：

```
bash <(curl -Ls https://raw.githubusercontent.com/ISFZY/Xray-Auto/main/install.sh)

```

**🗑️ 卸载**
如果你想移除 Xray 及其相关配置：
```
bash <(curl -sL https://github.com/ISFZY/Xray-Auto/raw/main/remove.sh)

```

### 🎮 常用命令
安装完成后，直接在终端输入以下命令：
| 指令 | 功能 | 说明 |
| --- | --- | --- |
| `info` | 查询Xray配置信息 | * 查看当前的 IP、端口、UUID、伪装域名等信息。* 运行后输入 `y` 可在终端生成巨大的二维码供手机扫描。|
| `ports` | 修改端口 | 1. SSH 2. Vision 3. xhttp |
| `net` | 切换网络 | 1. **IPv4 优先**: 推荐, 兼容性最好。2. **IPv6 优先**: 适合 IPv6 线路优秀的机器。3. **仅 IPv4**: 强制 Xray 只用 IPv4 。4. **仅 IPv6**: 强制 Xray 只用 IPv6。 |
| `f2b` | 修改防火墙（Fail2ban) | Fail2ban相关参数 |

### 📝 客户端配置参考
| 参数 | 值 (示例) | 说明 |
| :--- | :--- | :--- |
| **地址 (Address)** | `1.2.3.4` 或 `[2001::1]` | 服务器 IP |
| **端口 (Port)** | `443` | 安装时设置的端口 |
| **用户 ID (UUID)** | `de305d54-...` | 输入 `info` 获取 |
| **流控 (Flow)** | `xtls-rprx-vision` | **仅 Vision 节点填写** |
| **传输协议 (Network)**| `tcp` 或 `xhttp` | Vision 选 TCP，xhttp 选 xhttp |
| **伪装域名 (SNI)** | `www.microsoft.com` | 输入 `info` 获取 |
| **指纹 (Fingerprint)**| `chrome` | |
| **Public Key** | `B9s...` | 输入 `info` 获取 |
| **ShortId** | `a1b2...` | 输入 `info` 获取 |
| **路径 (Path)** | `/8d39f310` | **仅 xhttp 节点填写** |



---

<a name="english-guide"></a>
## 🇺🇸 English Guide

**Xray-Auto Installer** is a fully automated, lightweight, and high-performance script for deploying Xray. It integrates the latest **VLESS-Reality** protocol with **Vision** and **xhttp** flow control, optimized for both **IPv4 and IPv6** environments.

### ✨ Features
* **⚡ Dual-Protocol Deployment**: Automatically deploys **VLESS-Reality** with **TCP-Vision** (Speed) and **xhttp** (Obfuscation) nodes.
* **🌐 IPv4/IPv6 Dual-Stack**: Automatically detects network stack. Supports IPv4-only, IPv6-only, and Dual-stack servers perfectly.
* **🎨 Interactive UI**: Beautiful CLI experience with loading spinners, color highlighting, and countdown interactions.
* **🔍 Smart SNI Selection**: Tests latency to major domains (Microsoft, Apple, Tesla, etc.) and auto-selects the best camouflage domain.
* **🛡️ Security Hardened**:
    * Auto-configured `iptables` & `ip6tables`.
    * Integrated `Fail2ban` to prevent SSH brute-force attacks.
* **📱 Handy Tools**:
    * `info`: View config, dynamic IP detection, and generate **QR Codes**.
    * `ports`: Change ports.
    * `net`：One-click switch between **ipv4/ipv6**.

### 🛠️ Requirements
* **OS**: Debian 10+ / Ubuntu 20.04+ (Debian 12 Recommended).
* **Architecture**: x86_64 / arm64.
* **Privilege**: Root access required.
* **Network**: Public IPv4 or IPv6 address.

### 🚀 Quick Start

Run the following command as **root**:

```
bash <(curl -Ls https://raw.githubusercontent.com/ISFZY/Xray-Auto/main/install.sh)

```

### 🗑️ Uninstall
To remove Xray and its associated configurations:
```
bash <(curl -sL https://github.com/ISFZY/Xray-Auto/raw/main/remove.sh)

```
### 🎮 Commands
After installation, you can use these shortcuts:
Here is the English translation of the table you uploaded.
Xray Management Commands
| Command | Function | Description |
|---|---|---|
| 'info' | View Xray Config Info | • View current IP, Port, UUID, Camouflage Domain, etc.• After running, type y to generate a large QR code in the terminal for scanning with a mobile phone. |
| `ports` | change Ports | 1. SSH 2. Vision 3. xhttp |
| 'net' | Switch Network | 1. **IPv4 Priority**: Recommended, best compatibility. 2. **IPv6 Priority**: Suitable for servers with excellent IPv6 connections.3. **IPv4 Only**: Forces Xray to use IPv4 only.4. **IPv6 Only**: Forces Xray to use IPv6 only. |
| `f2b` | Setting Fail2ban) | Fail2ban |

### 📝 Client Configuration Reference
| Parameter | Value (Example) | Note |
| :--- | :--- | :--- |
| **Address** | `1.2.3.4` or `[2001::1]` | Server IP |
| **Port** | `443` | Set during install |
| **UUID** | `de305d54-...` | Get via `info` |
| **Flow** | `xtls-rprx-vision` | **Vision Node Only** |
| **Network** | `tcp` or `xhttp` | Vision uses TCP, xhttp uses xhttp |
| **SNI** | `www.microsoft.com` | Get via `info` |
| **Fingerprint**| `chrome` | |
| **Public Key** | `B9s...` | Get via `info` |
| **ShortId** | `a1b2...` | Get via `info` |
| **Path** | `/8d39f310` | **xhttp Node Only** |

---

## ⚠️ Disclaimer / 免责声明

### 🇺🇸 English
1.  **Educational Use Only**: This project is intended solely for **learning, technical research, and network testing**. It is not intended for any illegal activities.
2.  **User Responsibility**: Users must comply with the laws and regulations of their local jurisdiction and the location of the server. The author assumes no responsibility for any legal consequences arising from the use of this script.
3.  **No Warranty**: This software is provided "AS IS", without warranty of any kind, express or implied. The author disclaims all liability for any damages, data loss, or system instability resulting from its use.
4.  **Third-Party Tools**: This script relies on third-party programs (e.g., Xray-core). The author is not responsible for the security, stability, or content of these external tools.
5.  **GPL v3 License**: This project is licensed under the **GNU General Public License v3.0**. Please review the `LICENSE` file for full terms and conditions.

### 🇨🇳 中文
1.  **仅供科研与学习**: 本项目仅用于**网络技术研究、学习交流及系统测试**。请勿将本脚本用于任何违反国家法律法规的用途。
2.  **法律合规**: 使用本脚本时，请务必遵守您所在国家/地区以及服务器所在地的法律法规。严禁用于涉及政治、宗教、色情、诈骗等非法内容的传播。一切因违规使用产生的法律后果，由使用者自行承担，作者不承担任何连带责任。
3.  **无担保条款**: 本软件按“原样”提供，不提供任何形式的明示或暗示担保。作者不对因使用本脚本而导致的任何直接或间接损失（包括但不限于数据丢失、系统崩溃、IP 被封锁、服务器被服务商暂停等）负责。
4.  **第三方组件**: 本脚本集成了第三方开源程序（如 Xray-core），其版权和责任归原作者所有。本脚本作者不对第三方程序的安全性或稳定性做出保证。
5.  **许可证**: 本项目遵循 **GNU General Public License v3.0** 开源协议，详细条款请参阅仓库内的 `LICENSE` 文件。



[Project maintained by ISFZY](https://github.com/ISFZY)

