# Xray Auto Installer

> 🚀 **VLESS + Reality + Vision + Intelligent SNI + System Optimization** > 一个轻量级、自动化、高稳定性的 Xray 部署脚本。

![License](https://img.shields.io/github/license/accforeve/Xray-Auto)
![Version](https://img.shields.io/badge/version-v0.1-green)
![Shell](https://img.shields.io/badge/language-Bash-blue)

## 📖 简介 | Introduction

本项目是一个专为 **Debian / Ubuntu** 系统设计的 Xray 自动化安装脚本。它采用目前最先进的 **VLESS + Reality + Vision** 协议组合，并集成了多项系统级优化和安全防护功能。

## ✨ 功能特性 | Features

* **⚡ 顶级协议架构**: 部署 VLESS + Reality + Vision (xtls-rprx-vision)，抗封锁能力极强。
* **🌐 智能 SNI 优选**: 自动测试并筛选连接延迟最低的伪装域名（支持 Microsoft, Apple 大厂域名），显著提升连接速度。
* **🛡️ 全方位安全防护**:
    * 集成 `Fail2ban` 防暴力破解。
    * 配置双栈防火墙（IPv4 + IPv6），仅放行必要端口。
    * 自动处理端口占用冲突。
* **⚙️ 系统深度优化**:
    * 开启 BBR 拥塞控制。
    * 自动检测内存，若不足 2GB 自动创建 Swap 交换分区。
    * 优化 TCP 连接参数与文件描述符限制。
* **🛠️ 便捷管理工具**:
    * 内置 `mode` 命令：一键切换 **[阻断回国]** / **[允许回国]** 流量策略。
    * 自动配置 GeoIP/GeoSite 定时更新任务。
    * 提供美观的终端输出与二维码展示。

## 💻 环境要求 | Requirements

* **OS**: Debian 10+
* **Root**: 需要 root 权限运行
* **Network**: 正常的互联网连接

## 🚀 快速开始 | Quick Start

⚠️安装前提醒：会强制清空容器、占用443端口，更改防火墙规则。
使用 `root` 用户登录服务器，执行以下命令即可开始安装：

```bash
wget -N [https://raw.githubusercontent.com/accforeve/Xray-Auto/main/install.sh](https://raw.githubusercontent.com/accforeve/Xray-Auto/main/install.sh) && bash install.sh
```

### 常用指令
| 功能 | 指令 |
| ---- | ---- |
| 查看当前模式状态 | `mode` |
| 切换模式 | `mode c` |
| 查看 Xray 运行状态 | `systemctl status xray` |
| 重启 Xray 服务 | `systemctl restart xray` |
| 查看实时日志 | `journalctl -u xray -f` |
| 卸载脚本 | `xray-uninstal` |

### 📝 配置说明 | Configuration Details

安装结束后，脚本会自动输出连接信息，包含：
* 节点配置信息：ip、端口、SNI等，用于手输时使用。
* VLESS 链接：可直接复制导入客户端（如 v2rayN, V2Box, Shadowrocket 等）。
* 二维码：手机扫码直连。

### ⚠️ 免责声明 | Disclaimer

* 本项目仅供学习、技术研究及科研使用，非盈利目的。请于下载后 24 小时内删除, 不得用作任何商业用途, 文字、数据及图片均有所属版权, 如转载须注明来源。
* 使用本程序必循遵守部署服务器所在地、所在国家和用户所在国家的法律法规，使用本脚本产生的任何后果由用户自行承担。

[Project maintained by accforeve](https://github.com/accforeve)

