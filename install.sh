#!/bin/bash
# ==============================================================
# Project: Xray Auto Installer
# Author: ISFZY
# Repository: https://github.com/ISFZY/Xray-Auto
# Version: 0.4
# ==============================================================

# --- 1. 全局配置与 UI 定义 ---
RED="\033[31m"; GREEN="\033[32m"; YELLOW="\033[33m"; BLUE="\033[36m"; PURPLE="\033[35m"; PLAIN="\033[0m"
BOLD="\033[1m"
BG_RED="\033[41;37m"; BG_GREEN="\033[42;37m"
ICON_OK="✅"; ICON_ERR="❌"; ICON_WARN="⚠️"; ICON_WAIT="⏳"

# 动画函数
run_with_spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    echo -ne "  "
    while [ "$(ps -p $pid -o pid=)" ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

print_banner() {
    clear
    echo -e "${BLUE}============================================================${PLAIN}"
    echo -e "${BLUE}            __   __  ______    _______  __   __             ${PLAIN}"
    echo -e "${BLUE}           |  |_|  ||    _ |  |   _   ||  | |  |            ${PLAIN}"
    echo -e "${BLUE}           |       ||   | ||  |  |_|  ||  |_|  |            ${PLAIN}"
    echo -e "${BLUE}           |       ||   |_||_ |       ||       |            ${PLAIN}"
    echo -e "${BLUE}           |     | |    __  ||       ||_     _|             ${PLAIN}"
    echo -e "${BLUE}           |   _   ||   |  | ||   _   |  |   |              ${PLAIN}"
    echo -e "${BLUE}           |__| |__||___|  |_||__| |__|  |___|              ${PLAIN}"
    echo -e "${BLUE}============================================================${PLAIN}"
    echo -e "${YELLOW}${BOLD}                      Xray-Auto v0.4               ${PLAIN}"
    echo -e "${BLUE}============================================================${PLAIN}\n"
}

# --- 2. 基础检查与网络侦测 ---
if [[ $EUID -ne 0 ]]; then echo -e "${RED}${ICON_ERR} Error: 请使用 root 权限运行!${PLAIN}"; exit 1; fi
if [ ! -f /etc/debian_version ]; then echo -e "${RED}${ICON_ERR} 仅支持 Debian/Ubuntu 系统!${PLAIN}"; exit 1; fi

pre_flight_check() {
    if ! dpkg --audit >/dev/null 2>&1; then
        echo -e "${YELLOW}${ICON_WARN} 检测到 apt 锁死或损坏，正在尝试自愈...${PLAIN}"
        rm -f /var/lib/apt/lists/lock /var/cache/apt/archives/lock /var/lib/dpkg/lock*
        dpkg --configure -a >/dev/null 2>&1
        echo -e "${GREEN}${ICON_OK} 修复完成。${PLAIN}"
    fi
}

check_net_stack() {
    HAS_V4=false; HAS_V6=false; CURL_OPT=""
    if curl -s4m 2 https://1.1.1.1 >/dev/null 2>&1; then HAS_V4=true; fi
    if curl -s6m 2 https://2606:4700:4700::1111 >/dev/null 2>&1; then HAS_V6=true; fi

    if [ "$HAS_V4" = true ] && [ "$HAS_V6" = true ]; then
        NET_TYPE="Dual-Stack (双栈)"; CURL_OPT="-4"; DOMAIN_STRATEGY="IPIfNonMatch"
    elif [ "$HAS_V4" = true ]; then
        NET_TYPE="IPv4 Only"; CURL_OPT="-4"; DOMAIN_STRATEGY="UseIPv4"
    elif [ "$HAS_V6" = true ]; then
        NET_TYPE="IPv6 Only"; CURL_OPT="-6"; DOMAIN_STRATEGY="UseIPv6"
    else
        echo -e "${RED}${ICON_ERR} 无法连接互联网，请检查网络！${PLAIN}"; exit 1
    fi
    echo -e "${GREEN}${ICON_OK} 网络环境检测: ${NET_TYPE}${PLAIN}"
}

set_sysctl() {
    local param=$1; local value=$2
    if grep -q "^$param" /etc/sysctl.conf; then
        sed -i "s|^$param.*|$param=$value|" /etc/sysctl.conf
    else
        echo "$param=$value" >> /etc/sysctl.conf
    fi
}

wait_with_countdown() {
    local seconds=$1; local message=$2
    read -t 0.1 -n 10000 discard 2>/dev/null
    for ((i=seconds; i>0; i--)); do
echo -ne "\r${GREEN}👉 ${message} ${PLAIN}[Enter 快进 / 其他键修改] (默认: ${YELLOW} ${i} ${PLAIN}${GREEN}s) ${PLAIN}"
        if IFS= read -t 1 -s -n 1 key; then
            if [[ -z "$key" ]]; then echo -e "\n⏩ 使用默认配置。"; return 0;
            else echo -e "\n✏️  切换为手动输入..."; return 1; fi
        fi
    done
    echo -e "\n✅ 倒计时结束，应用默认。"
    return 0
}

# --- 3. 配置阶段 ---
print_banner
pre_flight_check
check_net_stack

echo -e "${BLUE}--- ⚙️  端口配置 ---${PLAIN}"
SSH_CURRENT_PORT=$(echo $SSH_CLIENT | awk '{print $3}')
SSH_CONFIG_PORT=$(grep "^Port" /etc/ssh/sshd_config | head -n 1 | awk '{print $2}')
DEF_SSH=${SSH_CURRENT_PORT:-${SSH_CONFIG_PORT:-22}}

if wait_with_countdown 9 "确认 SSH 管理端口 [${DEF_SSH}]"; then SSH_PORT=$DEF_SSH; else read -p "   请输入 SSH 端口: " U_SSH; SSH_PORT=${U_SSH:-$DEF_SSH}; fi

DEF_V=443
if wait_with_countdown 9 "确认 Vision 端口 (TCP) [${DEF_V}]"; then PORT_VISION=$DEF_V; else read -p "   输入 Vision 端口: " t; PORT_VISION=${t:-$DEF_V}; fi

DEF_X=8443
if wait_with_countdown 9 "确认 xhttp 端口 [${DEF_X}]"; then PORT_XHTTP=$DEF_X; else read -p "   输入 xhttp 端口: " t; PORT_XHTTP=${t:-$DEF_X}; fi


clear
echo -e "${YELLOW}${BOLD}🚀 开始全自动化部署...${PLAIN}"

# --- 1. 系统初始化 ---
timedatectl set-timezone Asia/Shanghai
export DEBIAN_FRONTEND=noninteractive

# 强制抑制 "Service Restart" 粉色弹窗
if [ -f /etc/needrestart/needrestart.conf ]; then
    sed -i "s/#\$nrconf{restart} = 'i';/\$nrconf{restart} = 'a';/" /etc/needrestart/needrestart.conf
fi

echo -ne "${BLUE}📦 更新系统并安装依赖 ${PLAIN}(此过程可能需要几分钟)..."

(
    # apt 更新命令 (静默执行)
    apt-get update -qq >/dev/null 2>&1
    apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" upgrade >/dev/null 2>&1
    
    # 安装核心依赖 (静默执行)
    DEPENDENCIES="curl wget sudo nano git htop tar unzip socat fail2ban rsyslog chrony iptables qrencode"
    apt-get install -y $DEPENDENCIES >/dev/null 2>&1
) &

# 运行动画，直到上面的任务结束
run_with_spinner $!
echo -e "${GREEN} 完成${PLAIN}"

# 二次检查
if ! command -v fail2ban-client &> /dev/null; then
echo -e "\n${RED}❌ 严重错误：软件安装失败。可能是网络源问题，请重试。${PLAIN}"
    exit 1
fi

# 安装 Xray
echo -e "${BLUE}   🚀 下载并安装 Xray Core...${PLAIN}"
bash -c "$(curl -L $CURL_OPT https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

echo -e "${GREEN} Xray Core 安装完成${PLAIN}"

mkdir -p /usr/local/share/xray/
wget -q $CURL_OPT -O /usr/local/share/xray/geoip.dat https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat
wget -q $CURL_OPT -O /usr/local/share/xray/geosite.dat https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat

# --- 2. 防火墙 ---
add_rule() {
    local port=$1; local v4=$2; local v6=$3
    if [ "$v4" = true ]; then
        if ! iptables -C INPUT -p tcp --dport $port -j ACCEPT 2>/dev/null; then
            iptables -A INPUT -p tcp --dport $port -j ACCEPT; iptables -A INPUT -p udp --dport $port -j ACCEPT; fi
    fi
    if [ "$v6" = true ] && [ -f /proc/net/if_inet6 ]; then
        if ! ip6tables -C INPUT -p tcp --dport $port -j ACCEPT 2>/dev/null; then
            ip6tables -A INPUT -p tcp --dport $port -j ACCEPT; ip6tables -A INPUT -p udp --dport $port -j ACCEPT; fi
    fi
}
add_rule $SSH_PORT $HAS_V4 $HAS_V6
add_rule $PORT_VISION $HAS_V4 $HAS_V6
add_rule $PORT_XHTTP $HAS_V4 $HAS_V6
netfilter-persistent save >/dev/null 2>&1

cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1
bantime = 24h
findtime = 1d
maxretry = 3
backend = systemd
[sshd]
enabled = true
port = $SSH_PORT,22
mode = aggressive
EOF
systemctl restart fail2ban >/dev/null 2>&1

# 确保服务启动
systemctl restart rsyslog || echo "Rsyslog restart skipped"
systemctl enable fail2ban >/dev/null 2>&1
systemctl restart fail2ban

echo -ne "${BLUE}   🛠️  执行内核调优 (BBR + Swap)...${PLAIN}"
set_sysctl "net.core.default_qdisc" "fq"
set_sysctl "net.ipv4.tcp_congestion_control" "bbr"
sysctl -p >/dev/null 2>&1
if [ "$(free -m | grep Mem | awk '{print $2}')" -lt 2048 ] && [ "$(swapon --show | wc -l)" -lt 2 ]; then
    fallocate -l 1G /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=1024 status=none
    chmod 600 /swapfile && mkswap /swapfile >/dev/null && swapon /swapfile >/dev/null
    grep -q "/swapfile" /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi
echo -e "${GREEN} 完成 ${PLAIN}"

# --- 3. 智能 SNI 优选 ---
echo -e "\n${BLUE}--- 🔍 智能 SNI 伪装域优选 ---${PLAIN}"
DOMAINS=("www.icloud.com" "www.apple.com" "itunes.apple.com" "learn.microsoft.com" "www.bing.com" "www.tesla.com")
BEST_MS=9999; BEST_INDEX=0
printf "${BG_GREEN} %-4s %-25s %-12s ${PLAIN}\n" "ID" "Domain" "Latency"
for i in "${!DOMAINS[@]}"; do
    domain="${DOMAINS[$i]}"
    time_cost=$(LC_NUMERIC=C curl $CURL_OPT -w "%{time_connect}" -o /dev/null -s --connect-timeout 2 "https://$domain")
    if [ -n "$time_cost" ] && [ "$time_cost" != "0.000" ]; then
        ms=$(LC_NUMERIC=C awk -v t="$time_cost" 'BEGIN { printf "%.0f", t * 1000 }')
        color=$GREEN
        if [ "$ms" -gt 200 ]; then color=$YELLOW; fi
        if [ "$ms" -lt "$BEST_MS" ]; then BEST_MS=$ms; BEST_INDEX=$((i+1)); fi
        printf " %-4s %-25s ${color}%-8s${PLAIN}\n" "$((i+1))" "$domain" "${ms}ms"
    else
        printf " %-4s %-25s ${RED}%-8s${PLAIN}\n" "$((i+1))" "$domain" "Timeout"
    fi
done
DEFAULT_SNI=${DOMAINS[$((BEST_INDEX-1))]}
echo -e "----------------------------------------------"
if wait_with_countdown 9 "优选 SNI [${DEFAULT_SNI}]"; then SNI_HOST="$DEFAULT_SNI"; else
    read -p "   请输入自定义 SNI: " SNI_IN; SNI_HOST="${SNI_IN:-$DEFAULT_SNI}"; fi
echo -e "   ✅ 已选: ${YELLOW}${SNI_HOST}${PLAIN}"

# --- 生成配置 ---
XRAY_BIN="/usr/local/bin/xray"
UUID=$($XRAY_BIN uuid)
KEYS=$($XRAY_BIN x25519)

# 1. 提取密钥
PRIVATE_KEY=$(echo "$KEYS" | grep "Private" | awk '{print $NF}')
PUBLIC_KEY=$(echo "$KEYS" | grep -E "Public|Password" | awk '{print $NF}')

# 2. 生成随机参数
SHORT_ID=$(openssl rand -hex 8)
XHTTP_PATH="/$(openssl rand -hex 4)"

# 3. 验证变量是否生成成功
if [[ -z "$UUID" || -z "$PRIVATE_KEY" || -z "$PUBLIC_KEY" ]]; then
    echo -e "\${RED}❌ 错误：凭证生成不完整，请检查 Xray 是否安装成功。${PLAIN}"
    exit 1
fi

mkdir -p /usr/local/etc/xray/

# --- 写入配置 ---
cat > /usr/local/etc/xray/config.json <<EOF
{
  "log": { "loglevel": "warning" },
  "dns": { "servers": [ "1.1.1.1", "8.8.8.8", "localhost" ] },
  "inbounds": [
    {
      "tag": "vision_node", "port": ${PORT_VISION}, "protocol": "vless",
      "settings": { "clients": [ { "id": "${UUID}", "flow": "xtls-rprx-vision" } ], "decryption": "none" },
      "streamSettings": { "network": "tcp", "security": "reality", "realitySettings": { "show": false, "dest": "${SNI_HOST}:443", "serverNames": [ "${SNI_HOST}" ], "privateKey": "${PRIVATE_KEY}", "shortIds": [ "${SHORT_ID}" ], "fingerprint": "chrome" } },
      "sniffing": { "enabled": true, "destOverride": [ "http", "tls", "quic" ], "routeOnly": true }
    },
    {
      "tag": "xhttp_node", "port": ${PORT_XHTTP}, "protocol": "vless",
      "settings": { "clients": [ { "id": "${UUID}", "flow": "" } ], "decryption": "none" },
      "streamSettings": { "network": "xhttp", "security": "reality", "xhttpSettings": { "path": "${XHTTP_PATH}" }, "realitySettings": { "show": false, "dest": "${SNI_HOST}:443", "serverNames": [ "${SNI_HOST}" ], "privateKey": "${PRIVATE_KEY}", "shortIds": [ "${SHORT_ID}" ], "fingerprint": "chrome" } },
      "sniffing": { "enabled": true, "destOverride": [ "http", "tls", "quic" ], "routeOnly": true }
    }
  ],
  "outbounds": [ { "protocol": "freedom", "tag": "direct" }, { "protocol": "blackhole", "tag": "block" } ],
  "routing": { "domainStrategy": "${DOMAIN_STRATEGY}", "rules": [ { "type": "field", "ip": [ "geoip:private", "geoip:cn" ], "outboundTag": "block" }, { "type": "field", "protocol": [ "bittorrent" ], "outboundTag": "block" } ] }
}
EOF

mkdir -p /etc/systemd/system/xray.service.d
echo -e "[Service]\nLimitNOFILE=infinity\nLimitNPROC=infinity\nTasksMax=infinity" > /etc/systemd/system/xray.service.d/override.conf
systemctl daemon-reload >/dev/null

# --- 5. 生成工具脚本 (Info & Mode) ---
cp /usr/local/etc/xray/config.json /usr/local/etc/xray/config_block.json
sed 's/, "geoip:cn"//g' /usr/local/etc/xray/config_block.json > /usr/local/etc/xray/config_allow.json

# 1. 自动获取主机名
HOST_NAME=$(hostname)

# 2. Info 脚本
# 写入静态变量头
cat > /usr/local/bin/info <<EOF
#!/bin/bash
RED="\033[31m"; GREEN="\033[32m"; YELLOW="\033[33m"; BLUE="\033[36m"; PLAIN="\033[0m"

# --- 核心配置 ---
UUID="${UUID}"
PORT_VISION="${PORT_VISION}"
PORT_XHTTP="${PORT_XHTTP}"
SNI_HOST="${SNI_HOST}"
SHORT_ID="${SHORT_ID}"
XHTTP_PATH="${XHTTP_PATH}"
PRIVATE_KEY="${PRIVATE_KEY}"
PUBLIC_KEY="${PUBLIC_KEY}"
HOST_NAME="${HOST_NAME}"
EOF

# 动态逻辑
cat >> /usr/local/bin/info << 'SCRIPT_EOF'

# --- 动态获取 IP ---
IPV4=$(curl -s4m 2 https://api.ipify.org || curl -s4m 2 https://ifconfig.me)
IPV6=$(curl -s6m 2 https://api64.ipify.org || curl -s6m 2 https://ifconfig.co)
[ -z "$IPV4" ] && IPV4="N/A"
[ -z "$IPV6" ] && IPV6="N/A"
if [[ "$IPV4" != "无 IPv4 地址" ]]; then SHOW_IP=$IPV4; else SHOW_IP="[$IPV6]"; fi

# --- 生成链接 ---
# 节点1备注：主机名_Vision (代表 TCP Reality + Vision流控)
LINK_VISION="vless://${UUID}@${SHOW_IP}:${PORT_VISION}?security=reality&encryption=none&pbk=${PUBLIC_KEY}&headerType=none&fp=chrome&type=tcp&flow=xtls-rprx-vision&sni=${SNI_HOST}&sid=${SHORT_ID}#${HOST_NAME}_Vision"

# 节点2备注：主机名_xhttp (代表 xhttp协议)
LINK_XHTTP="vless://${UUID}@${SHOW_IP}:${PORT_XHTTP}?security=reality&encryption=none&pbk=${PUBLIC_KEY}&headerType=none&fp=chrome&type=xhttp&path=${XHTTP_PATH}&sni=${SNI_HOST}&sid=${SHORT_ID}#${HOST_NAME}_xhttp"

# --- 输出显示 ---
clear
echo -e "=========================================================="
echo -e "${BLUE}🚀 Xray 配置详情 ${PLAIN}"
echo -e "=========================================================="
echo -e "  服务器名     : ${HOST_NAME}"
echo -e "  IPv4 地址    : ${GREEN}${IPV4}${PLAIN}"
echo -e "  IPv6 地址    : ${BLUE}${IPV6}${PLAIN}"
echo -e "  伪装域SNI    : ${YELLOW}${SNI_HOST}${PLAIN}"
echo -e "  UUID         : ${GREEN}${UUID}${PLAIN}"
echo -e "  Short ID     : ${GREEN}${SHORT_ID}${PLAIN}"
echo -e "  Public Key   : ${GREEN}${PUBLIC_KEY}${PLAIN}"
echo -e "  Private Key  : ${RED}${PRIVATE_KEY}${PLAIN} (服务端用)"
echo -e "----------------------------------------------------------"
echo -e "  节点 1 (Vision)  端口: ${GREEN}${PORT_VISION}${PLAIN}    流控: ${GREEN}xtls-rprx-vision${PLAIN}"
echo -e "  节点 2 (xhttp)   端口: ${GREEN}${PORT_XHTTP}${PLAIN}   协议: ${GREEN}xhttp${PLAIN}   路径: ${GREEN}${XHTTP_PATH}${PLAIN}"
echo -e "----------------------------------------------------------"
echo -e "${YELLOW}👇 节点 1 (Vision) 链接:${PLAIN}"
echo -e "${LINK_VISION}"
echo -e ""
echo -e "${YELLOW}👇 节点 2 (xhttp) 链接:${PLAIN}"
echo -e "${LINK_XHTTP}"
echo -e "=========================================================="
echo -e "\n📱 手机扫码功能"
read -p "   是否显示二维码? (y/n) [默认 n]: " CHOICE
if [[ "$CHOICE" == "y" || "$CHOICE" == "Y" ]]; then
    echo -e "\n${YELLOW}>>> 正在生成 Vision 节点二维码...${PLAIN}"
    qrencode -t ANSIUTF8 "${LINK_VISION}"
    echo -e "\n${YELLOW}>>> 正在生成 xhttp 节点二维码...${PLAIN}"
    qrencode -t ANSIUTF8 "${LINK_XHTTP}"
fi
echo ""
SCRIPT_EOF
chmod +x /usr/local/bin/info

# Mode 脚本
cat > /usr/local/bin/mode << 'MODE_EOF'
#!/bin/bash
GREEN='\033[32m'; RED='\033[31m'; YELLOW='\033[33m'; BLUE='\033[36m'; PLAIN='\033[0m'
CONFIG="/usr/local/etc/xray/config.json"
BLOCK_CFG="/usr/local/etc/xray/config_block.json"
ALLOW_CFG="/usr/local/etc/xray/config_allow.json"
if grep -q "geoip:cn" "$CONFIG"; then
    OPT_1="${GREEN}1. 阻断国内流量 (Block CN) [✅ 当前]${PLAIN}"
    OPT_2="2. 允许国内流量 (Allow CN)"
else
    OPT_1="1. 阻断国内流量 (Block CN)"
    OPT_2="${RED}2. 允许国内流量 (Allow CN) [⚠️ 当前]${PLAIN}"
fi
clear
echo -e "============================================"
echo -e "${BLUE}       Xray 路由模式切换 (Mode Switch)${PLAIN}"
echo -e "==========================================="
echo -e "$OPT_1"
echo -e "$OPT_2"
echo -e "-------------------------------------------"
read -p "请输入选项 [1-2] (其他键退出): " choice
case "$choice" in
    1) cp "$BLOCK_CFG" "$CONFIG"; systemctl restart xray; echo -e "\n${GREEN}✅ 已切换为: 阻断国内流量${PLAIN}";;
    2) cp "$ALLOW_CFG" "$CONFIG"; systemctl restart xray; echo -e "\n${RED}⚠️  已切换为: 允许国内流量${PLAIN}";;
    *) echo "已退出，未做更改。"; exit 0;;
esac
MODE_EOF
chmod +x /usr/local/bin/mode

systemctl enable xray >/dev/null 2>&1
if systemctl restart xray; then
    bash /usr/local/bin/info
    echo -e "\n🎉 安装全部完成！"
    echo -e "💡 常用命令: ${YELLOW}info${PLAIN} (查看信息) | ${YELLOW}mode${PLAIN} (切换流控模式)"
else
    echo -e "${RED}${ICON_ERR} Xray 服务启动失败！${PLAIN}"
    echo -e "请运行: systemctl status xray 查看错误日志"
    exit 1
fi
