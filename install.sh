#!/bin/bash
# ==============================================================
# Project: Xray Auto Installer
# Author: accforeve
# Repository: https://github.com/accforeve/Xray-Auto
# License: MIT License
# Version: v0.6.1 (TimeFirst)
# Description: VLESS + Reality + Vision + Intelligent SNI + Docker Compatible
# Update: 将时间同步前置到apt之前，解决因时间错误导致源更新失败的问题
# ==============================================================

# --- [Config] 全局环境配置 ---
export DEBIAN_FRONTEND=noninteractive
APT_OPTS="-y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold"
PORT=443  # 默认监听端口

# --- [Style] 终端输出样式定义 ---
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
BLUE='\033[36m'
PLAIN='\033[0m'
BOLD='\033[1m'

# --- [Utils] 核心辅助函数 ---
step() { echo -e "\n${BLUE}➜  $1${PLAIN}"; }
sub()  { echo -e "     ${PLAIN}$1"; }
warn() { echo -e "     ${YELLOW}⚠️  $1${PLAIN}"; }
err()  { echo -e "     ${RED}❌  $1${PLAIN}"; exit 1; }

# --- [Core] 基础环境预检 ---
check_os() {
    [[ $EUID -ne 0 ]] && err "请使用 root 用户运行此脚本！"
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        if [[ "$ID" != "debian" && "$ID" != "ubuntu" ]]; then
            err "本脚本仅支持 Debian 或 Ubuntu 系统，当前检测到: $ID"
        fi
    else
        err "无法检测操作系统版本，请更换 Debian/Ubuntu 系统。"
    fi
}

# --- [Core] 强制时间同步 (无依赖版) ---
# 在 apt 运行前执行，防止因时间偏差导致 SSL 证书验证失败
sync_time_pre() {
    sub "正在校准系统时间与时区..."
    timedatectl set-timezone Asia/Shanghai
    
    # 尝试开启系统自带的 NTP
    timedatectl set-ntp true >/dev/null 2>&1
    
    # [关键] 强制从 Google 获取时间头并写入系统 (容错处理)
    # 即使 apt 坏了装不了 chrony，这里也能保证时间基本正确
    if command -v curl >/dev/null 2>&1; then
        DATE_STR=$(curl -sI --max-time 3 google.com | grep -i '^Date:' | cut -d' ' -f3-6)
        [ -n "$DATE_STR" ] && date -s "$DATE_STR" >/dev/null 2>&1
    elif command -v wget >/dev/null 2>&1; then
        DATE_STR=$(wget -qSO- --max-redirect=0 google.com 2>&1 | grep -i '^Date:' | cut -d' ' -f3-6)
        [ -n "$DATE_STR" ] && date -s "$DATE_STR" >/dev/null 2>&1
    fi
    
    # 再次确认硬件时钟
    hwclock -w >/dev/null 2>&1
}

# --- [Core] 进程锁清理机制 (Tiered Kill) ---
clean_locks() {
    systemctl stop unattended-upgrades.service >/dev/null 2>&1
    systemctl stop apt-daily.service >/dev/null 2>&1
    systemctl stop apt-daily-upgrade.service >/dev/null 2>&1
    
    # 优先杀掉占用锁文件的具体进程
    local lock_pid
    for lock in /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock; do
        fuser -k $lock >/dev/null 2>&1
    done

    # 兜底强制结束所有 apt/dpkg 进程
    killall apt apt-get dpkg >/dev/null 2>&1
    
    rm -f /var/lib/dpkg/lock* /var/lib/apt/lists/lock /var/cache/apt/archives/lock
    dpkg --configure -a >/dev/null 2>&1
}

# --- [Core] APT 安装封装器 ---
run_apt() {
    local cmd="$1"
    local max_retries=5
    local i=0
    while [ $i -lt $max_retries ]; do
        if eval "apt-get $APT_OPTS $cmd"; then return 0; fi
        ((i++))
        warn "操作失败，尝试自动修复 ($i/$max_retries)..."
        sleep 2
        clean_locks
        apt-get -f install $APT_OPTS >/dev/null 2>&1
        dpkg --configure -a >/dev/null 2>&1
        [[ "$cmd" == *"install"* ]] && apt-get update $APT_OPTS >/dev/null 2>&1
    done
    
    echo ""
    warn "apt/dpkg 执行遭遇严重错误！"
    warn "若提示 'newline in field name' 等数据库损坏错误，请手动执行："
    echo -e "${YELLOW}     rm -f /var/lib/dpkg/updates/* && dpkg --configure -a${PLAIN}"
    echo ""
    err "致命错误：无法执行 $cmd"
}

# --- 主程序入口 ---
main() {
    clear
    echo -e "${BOLD}Xray Auto Installer ${PLAIN}${GREEN}v0.6.1 (TimeFirst)${PLAIN}"
    echo -e "--------------------------------------------------"
    
    # 0. 预检
    check_os

    # --- 1. 系统参数初始化 ---
    step "[1/8] 环境初始化与时间同步"
    
    # [Update] 优先执行时间同步，确保后续 apt update 的 SSL 握手正常
    sync_time_pre

    sub "配置系统参数..."
    if [ -f /etc/needrestart/needrestart.conf ]; then
        sed -i "s/#\$nrconf{restart} = 'i';/\$nrconf{restart} = 'a';/" /etc/needrestart/needrestart.conf
        sed -i "s/\$nrconf{restart} = 'i';/\$nrconf{restart} = 'a';/" /etc/needrestart/needrestart.conf
    fi
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections 2>/dev/null
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections 2>/dev/null
    clean_locks

    # --- 2. 依赖安装 ---
    step "[2/8] 系统更新与依赖安装"
    sub "更新软件源 (apt update)..."
    run_apt "update"
    sub "安装基础组件..."
    # chrony 仍然安装，作为长期的后台时间同步服务
    run_apt "install curl wget sudo nano git htop tar unzip socat fail2ban chrony iptables iptables-persistent psmisc ca-certificates qrencode"

    # --- 3. 端口交互逻辑 ---
    step "[3/8] 端口冲突检测"
    
    PID_443=$(fuser 443/tcp 2>/dev/null)
    if [ -n "$PID_443" ]; then
        PROC_NAME=$(ps -p $PID_443 -o comm= | head -n 1)
        warn "检测到 443 端口被占用 (PID: $PID_443, 进程: $PROC_NAME)"
        
        echo -e "     请选择操作:"
        echo -e "     ${GREEN}1)${PLAIN} 强制清理并使用 443 端口 (推荐)"
        echo -e "     ${GREEN}2)${PLAIN} 自定义其他端口"
        echo -ne "     ➜ 请输入选项 [1/2] (默认1): "
        read -r choice
        
        case "$choice" in
            2)
                while true; do
                    echo -ne "     ➜ 请输入新的端口号 (1024-65535): "
                    read -r new_port
                    if [[ "$new_port" =~ ^[0-9]+$ ]] && [ "$new_port" -ge 1024 ] && [ "$new_port" -le 65535 ]; then
                        if fuser "$new_port"/tcp >/dev/null 2>&1; then
                             warn "端口 $new_port 正被其他程序占用，请更换。"
                        else
                             PORT=$new_port
                             sub "端口已确认为: ${YELLOW}$PORT${PLAIN}"
                             break
                        fi
                    else
                        warn "输入无效，请输入 1024 到 65535 之间的数字。"
                    fi
                done
                ;;
            *)
                sub "正在清理 443 端口占用进程..."
                systemctl stop nginx apache2 caddy httpd >/dev/null 2>&1
                fuser -k 443/tcp >/dev/null 2>&1
                sleep 1
                PORT=443
                ;;
        esac
    else
        sub "443 端口空闲，将使用默认配置。"
        PORT=443
    fi

    # --- 4. 内核与系统调优 ---
    step "[4/8] 系统内核优化"
    # 时区已在第一步设置，此处保留内存与TCP优化逻辑

    RAM_MB=$(free -m | grep Mem | awk '{print $2}')
    if [ "$RAM_MB" -lt 2048 ] && ! grep -q "/swapfile" /etc/fstab; then
        sub "内存 < 2G，创建 1GB Swap..."
        fallocate -l 1G /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=1024 status=none
        chmod 600 /swapfile && mkswap /swapfile >/dev/null 2>&1 && swapon /swapfile >/dev/null 2>&1
        echo '/swapfile none swap sw 0 0' >> /etc/fstab
    fi

    if ! grep -q "tcp_congestion_control=bbr" /etc/sysctl.conf; then
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        sysctl -p > /dev/null 2>&1
    fi

    if ! grep -q "SystemMaxUse=200M" /etc/systemd/journald.conf; then
        echo "SystemMaxUse=200M" >> /etc/systemd/journald.conf
        systemctl restart systemd-journald
    fi

    # --- 5. 安全防护 (IPv4 + IPv6) ---
    step "[5/8] 配置双栈防火墙"
    SSH_PORT=$(ss -tlnp | grep sshd | grep LISTEN | awk '{print $4}' | sed 's/.*://' | head -n 1)
    [ -z "$SSH_PORT" ] && SSH_PORT=22
    
    iptables -F; ip6tables -F
    
    for cmd in iptables ip6tables; do
        $cmd -A INPUT -i lo -j ACCEPT
        $cmd -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
        $cmd -A INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT
        $cmd -A INPUT -p tcp --dport "$PORT" -j ACCEPT
        $cmd -A INPUT -p udp --dport "$PORT" -j ACCEPT
        $cmd -P INPUT DROP
        $cmd -P FORWARD DROP
        $cmd -P OUTPUT ACCEPT
    done

    iptables -A INPUT -p icmp -j ACCEPT
    ip6tables -A INPUT -p ipv6-icmp -j ACCEPT
    
    netfilter-persistent save >/dev/null 2>&1

    mkdir -p /etc/fail2ban
    cat > /etc/fail2ban/jail.local << FAIL2BAN_EOF
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1
findtime  = 1d
maxretry = 3
bantime  = 24h
bantime.increment = true
backend = systemd
banaction = iptables-multiport
[sshd]
enabled = true
port    = $SSH_PORT
mode    = aggressive
FAIL2BAN_EOF
    systemctl restart fail2ban >/dev/null 2>&1

    # --- 6. Xray 核心安装 ---
    step "[6/8] 安装 Xray 核心"
    [ -f /usr/local/bin/xray ] && systemctl stop xray
    bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install >/dev/null 2>&1
    
    mkdir -p /usr/local/share/xray/
    dl() { wget -q --timeout=20 --tries=3 -O "$2" "$1" || warn "下载资源失败: $1"; }
    dl "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" "/usr/local/share/xray/geoip.dat"
    dl "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" "/usr/local/share/xray/geosite.dat"

    # --- 7. 配置文件生成 ---
    step "[7/8] 生成配置文件"
    DOMAINS=("www.icloud.com" "www.apple.com" "itunes.apple.com" "learn.microsoft.com" "www.microsoft.com" "www.bing.com")
    BEST_MS=9999
    BEST_DOMAIN=""
    
    echo -ne "\033[?25l"
    for domain in "${DOMAINS[@]}"; do
        echo -ne "     👉 测试 SNI: $domain...\r"
        time_cost=$(LC_NUMERIC=C curl -w "%{time_connect}" -o /dev/null -s --connect-timeout 2 "https://$domain")
        if [ -n "$time_cost" ] && [ "$time_cost" != "0.000" ]; then
            ms=$(LC_NUMERIC=C awk -v t="$time_cost" 'BEGIN { printf "%.0f", t * 1000 }')
            if [ "$ms" -lt "$BEST_MS" ]; then BEST_MS=$ms; BEST_DOMAIN=$domain; fi
        fi
    done
    echo -ne "\033[?25h"
    [ -z "$BEST_DOMAIN" ] && BEST_DOMAIN="www.microsoft.com"
    sub "优选 SNI: ${YELLOW}$BEST_DOMAIN${PLAIN} ($BEST_MS ms)"

    XRAY_BIN="/usr/local/bin/xray"
    UUID=$($XRAY_BIN uuid)
    KEYS=$($XRAY_BIN x25519)
    PRIVATE_KEY=$(echo "$KEYS" | grep -i "Private" | awk -F ': ' '{print $2}' | head -1)
    [ -z "$PRIVATE_KEY" ] && PRIVATE_KEY=$(echo "$KEYS" | grep -i "Private" | awk '{print $2}' | head -1)
    PUBLIC_KEY=$(echo "$KEYS" | grep -iE "Public|Password" | awk -F ': ' '{print $2}' | head -1)
    [ -z "$PUBLIC_KEY" ] && PUBLIC_KEY=$(echo "$KEYS" | grep -iE "Public|Password" | awk '{print $2}' | head -1)
    SHORT_ID=$(openssl rand -hex 8)

    if [[ $BEST_DOMAIN == www.* ]]; then SNI_JSON="\"$BEST_DOMAIN\""; else SNI_JSON="\"$BEST_DOMAIN\", \"www.$BEST_DOMAIN\""; fi

    mkdir -p /usr/local/etc/xray/
    gen_config() {
        local BLOCK_CN=$1
        local GEOIP_RULES='{ "type": "field", "ip": [ "geoip:private" ], "outboundTag": "block" },'
        [ "$BLOCK_CN" == "block" ] && GEOIP_RULES='{ "type": "field", "ip": [ "geoip:private", "geoip:cn" ], "outboundTag": "block" },'
        
        cat <<EOF
{
  "log": { "loglevel": "warning" },
  "dns": { "servers": [ "localhost", "1.1.1.1" ] },
  "inbounds": [
    {
      "port": ${PORT}, "protocol": "vless",
      "settings": { "clients": [ { "id": "${UUID}", "flow": "xtls-rprx-vision" } ], "decryption": "none" },
      "streamSettings": {
        "network": "tcp", "security": "reality",
        "realitySettings": {
          "show": false, "dest": "${BEST_DOMAIN}:443",
          "serverNames": [ ${SNI_JSON} ], "privateKey": "${PRIVATE_KEY}",
          "shortIds": [ "${SHORT_ID}" ], "fingerprint": "chrome"
        }
      },
      "sniffing": { "enabled": true, "destOverride": [ "http", "tls", "quic" ], "routeOnly": true }
    }
  ],
  "outbounds": [ { "protocol": "freedom", "tag": "direct" }, { "protocol": "blackhole", "tag": "block" } ],
  "routing": { "domainStrategy": "IPIfNonMatch", "rules": [ ${GEOIP_RULES} { "type": "field", "protocol": [ "bittorrent" ], "outboundTag": "block" } ] }
}
EOF
    }

    gen_config "block" > /usr/local/etc/xray/config_block.json
    gen_config "allow" > /usr/local/etc/xray/config_allow.json
    cp /usr/local/etc/xray/config_block.json /usr/local/etc/xray/config.json

    # --- 8. 服务封装与工具 ---
    step "[8/8] 封装工具与服务"
    mkdir -p /etc/systemd/system/xray.service.d
    echo -e "[Service]\nLimitNOFILE=infinity\nLimitNPROC=infinity\nTasksMax=infinity\nRestart=on-failure\nRestartSec=5" > /etc/systemd/system/xray.service.d/override.conf
    systemctl daemon-reload

    cat > /usr/local/bin/update_geoip.sh <<EOF
#!/bin/bash
wget -q -O /usr/local/share/xray/geoip.dat https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat
wget -q -O /usr/local/share/xray/geosite.dat https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat
systemctl restart xray
EOF
    chmod +x /usr/local/bin/update_geoip.sh
    rm -f /etc/cron.d/xray-geoip
    echo "0 4 * * 2 root /usr/local/bin/update_geoip.sh" > /etc/cron.d/xray-geoip

    cat > /usr/local/bin/mode << 'MODE_EOF'
#!/bin/bash
GREEN='\033[32m'
WHITE='\033[37m'
YELLOW='\033[33m'
PLAIN='\033[0m'
CONFIG="/usr/local/etc/xray/config.json"
BLOCK_CFG="/usr/local/etc/xray/config_block.json"
ALLOW_CFG="/usr/local/etc/xray/config_allow.json"

if grep -q "geoip:cn" "$CONFIG"; then 
    M1_ICON="${GREEN}●${PLAIN}"; M1_TXT="${GREEN}1. 阻断回国 (Block CN) [当前]${PLAIN}"
    M2_ICON="${WHITE}○${PLAIN}"; M2_TXT="${WHITE}2. 允许回国 (Allow CN)${PLAIN}"
else 
    M1_ICON="${WHITE}○${PLAIN}"; M1_TXT="${WHITE}1. 阻断回国 (Block CN)${PLAIN}"
    M2_ICON="${GREEN}●${PLAIN}"; M2_TXT="${GREEN}2. 允许回国 (Allow CN) [当前]${PLAIN}"
fi

if [ "$1" == "c" ]; then
    echo "🔄 正在切换模式..."
    if grep -q "geoip:cn" "$CONFIG"; then
        cp "$ALLOW_CFG" "$CONFIG"; MSG=">> 已切换为: 允许回国"
    else
        cp "$BLOCK_CFG" "$CONFIG"; MSG=">> 已切换为: 阻断回国"
    fi
    systemctl restart xray && echo -e "${GREEN}${MSG}${PLAIN}"
    exit 0
fi

echo -e ""
echo -e "模式列表 (Mode List):"
echo -e "  $M1_ICON $M1_TXT"
echo -e "  $M2_ICON $M2_TXT"
echo -e ""
echo -e "👉 切换指令: ${YELLOW}mode c${PLAIN}"
echo -e ""
MODE_EOF
    chmod +x /usr/local/bin/mode

    cat > /usr/local/bin/xray-uninstall << 'EOF'
#!/bin/bash
systemctl stop xray; systemctl disable xray >/dev/null 2>&1
rm -rf /etc/systemd/system/xray.service /etc/systemd/system/xray.service.d /usr/local/bin/xray /usr/local/etc/xray /usr/local/share/xray /usr/local/bin/mode /usr/local/bin/update_geoip.sh /etc/cron.d/xray-geoip
iptables -P INPUT ACCEPT
iptables -F
netfilter-persistent save >/dev/null 2>&1
systemctl daemon-reload
echo "Xray 已卸载，防火墙已重置为放行状态。"
rm -f /usr/local/bin/xray-uninstall
EOF
    chmod +x /usr/local/bin/xray-uninstall

    systemctl enable xray >/dev/null 2>&1
    systemctl restart xray

    # --- 最终回显 (UI v0.0 Style) ---
    sub "恢复系统自动更新服务..."
    if systemctl list-unit-files | grep -q unattended-upgrades; then
        systemctl restart unattended-upgrades >/dev/null 2>&1
    fi

    # [Smart IP]
    IPV4=$(curl -s4m8 ip.sb || curl -s4m8 ipinfo.io/ip || curl -s4m8 ifconfig.me)
    if [ -n "$IPV4" ]; then
        FINAL_IP="$IPV4"
        LINK_IP="$IPV4"
    else
        IPV6=$(curl -s6m8 ip.sb || curl -s6m8 ifconfig.co)
        FINAL_IP="$IPV6"
        LINK_IP="[$IPV6]"
    fi
    [ -z "$FINAL_IP" ] && FINAL_IP="IP 获取失败"
    
    HOST_TAG=$(hostname)
    [ -z "$HOST_TAG" ] && HOST_TAG="Xray"
    
    LINK="vless://${UUID}@${LINK_IP}:${PORT}?security=reality&encryption=none&pbk=${PUBLIC_KEY}&headerType=none&fp=chrome&type=tcp&flow=xtls-rprx-vision&sni=${BEST_DOMAIN}&sid=${SHORT_ID}#${HOST_TAG}"

    echo ""
    echo -e "${GREEN}==========================================================${PLAIN}"
    echo -e "${GREEN}🎉  Xray(Auto) v0.6.1 部署成功！${PLAIN}"
    echo -e "${GREEN}==========================================================${PLAIN}"
    echo -e "${BOLD}📋 服务器配置详情 (Server Details)${PLAIN}"
    echo -e "----------------------------------------------------------"
    echo -e " 🔹 地址 (IP)      : ${BLUE}${FINAL_IP}${PLAIN}"
    echo -e " 🔹 端口 (Port)    : ${BLUE}${PORT}${PLAIN}"
    echo -e " 🔹 伪装域名 (SNI) : ${BLUE}${BEST_DOMAIN}${PLAIN}"
    echo -e " 🔹 用户 ID (UUID) : ${BLUE}${UUID}${PLAIN}"
    echo -e " 🔹 短 ID (ShortId): ${BLUE}${SHORT_ID}${PLAIN}"
    echo -e " 🔹 流控 (Flow)    : ${BLUE}xtls-rprx-vision${PLAIN}"
    echo -e " 🔹 公钥 (Public)  : ${YELLOW}${PUBLIC_KEY}${PLAIN}"
    echo -e "----------------------------------------------------------"
    echo -e " 🔸 模式切换       : 输入 ${YELLOW}mode c${PLAIN} 切换 [阻断/允许] 回国"
    echo -e " 🔸 卸载脚本       : 输入 ${RED}xray-uninstall${PLAIN}"
    echo -e " 🔸 查看防火墙     : 输入 ${YELLOW}iptables -L -n${PLAIN}"
    echo -e "----------------------------------------------------------"
    echo ""
    echo -e "${BOLD}👇 通用分享链接 (VLESS Link)${PLAIN}"
    echo -e "${BLUE}${LINK}${PLAIN}"
    echo ""
    echo -e "${BOLD}👇 手机扫码 (QR Code)${PLAIN}"
    qrencode -t ANSIUTF8 "${LINK}"
    echo ""
}

main
