#!/bin/bash
# ==============================================================
# Project: Xray Uninstaller
# Author: ISFZY
# Repository: https://github.com/ISFZY/Xray-Auto
# Description: Remove Xray, Configs, and related tools
# ==============================================================

# 颜色定义
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
PLAIN='\033[0m'

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}❌ 错误：请使用 root 权限运行此脚本。${PLAIN}"
    exit 1
fi

clear
echo "=========================================================="
echo -e "${RED}⚠️  警告：即将执行卸载操作！${PLAIN}"
echo "=========================================================="
echo "此操作将执行以下动作："
echo "1. 停止并删除 Xray 服务"
echo "2. 删除所有配置文件 (config.json)"
echo "3. 删除相关的工具 (mode, update_geoip)"
echo ""
echo "系统基础依赖、BBR 加速和 Swap 分区将保留。"
echo "=========================================================="

# --- [新增] 用户交互确认 ---
read -p "是否确任要卸载? 请输入 [y/n]: " answer
if [[ "${answer,,}" != "y" ]]; then
    echo -e "\n${GREEN}已取消卸载操作。${PLAIN}"
    exit 0
fi
# -------------------------

echo -e "\n🗑️ 正在停止并卸载 Xray 服务..."

# 1. 停止并禁用服务
systemctl stop xray >/dev/null 2>&1
systemctl disable xray >/dev/null 2>&1

# 2. 删除 Xray 主程序与资源文件
rm -rf /usr/local/bin/xray
rm -rf /usr/local/share/xray
rm -rf /usr/local/etc/xray

# 3. 删除 Systemd 服务文件
rm -f /etc/systemd/system/xray.service
rm -rf /etc/systemd/system/xray.service.d
systemctl daemon-reload

# 4. 删除附加工具 (mode 指令和自动更新脚本)
rm -f /usr/local/bin/mode
rm -f /usr/local/bin/update_geoip.sh

# 5. 清理定时任务 (Crontab)
# 仅删除包含 update_geoip.sh 的行，保留其他任务
crontab -l 2>/dev/null | grep -v "update_geoip.sh" | crontab -

echo "=========================================================="
echo -e "${GREEN}✅ Xray 已成功卸载${PLAIN}"
echo "=========================================================="
echo "提示："
echo "防火墙规则 (iptables) 未被重置。如果需要恢复默认防火墙，"
echo "请手动执行: iptables -P INPUT ACCEPT && iptables -F"
echo "=========================================================="

