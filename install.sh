#!/bin/bash
# ==============================================================
# Project: Xray-Auto Installer
# Author: ISFZY
# Repository: https://github.com/ISFZY/Xray-Auto
# Version: v0.3 VLESS+reality-Vision/xhttp
# ==============================================================

# --- 全局颜色定义 ---
RED="\033[31m"; GREEN="\033[32m"; YELLOW="\033[33m"; BLUE="\033[36m"; PLAIN="\033[0m"
BG_RED="\033[41;37m"; BG_YELLOW="\033[43;30m"

# --- 系统环境强制检查 ---
if [ ! -f /etc/debian_version ]; then
    echo -e "\${RED}❌ 错误：本脚本仅支持 Debian 或 Ubuntu 系统！CentOS/RedHat 请勿运行。${PLAIN}"
    exit 1
fi

if [[ $EUID -ne 0 ]]; then echo -e "${RED}Error: 请使用 root 权限!${PLAIN}"; exit 1; fi

# --- 核心工具：动态倒计时 ---
# 返回: 0=使用默认(超时或按回车), 1=手动修改(按其他键)
wait_with_countdown() {
    local seconds=$1
    local message=$2
    
    # 清除输入缓存
    read -t 0.1 -n 10000 discard 2>/dev/null
    
    for ((i=seconds; i>0; i--)); do
        # 动态刷新显示
        echo -ne "\r${YELLOW}👉 ${message} [Enter快进 / 其他键修改] (默认: ${BG_RED} ${i} ${PLAIN}${YELLOW}s) ${PLAIN}"
        
        # 检测按键 (-s不回显, -n1读一个字符, -t1超时1秒)
        # 注意: IFS= 防止 read 去除空格
        if IFS= read -t 1 -s -n 1 key; then
            # 如果 key 为空 (直接回车) -> 0 (默认)
            if [[ -z "$key" ]]; then
                echo -e "\n⏩ 已按 Enter，立即使用默认值。"
                return 0
            else
                echo -e "\n✅ 切换为手动输入模式..."
                return 1
            fi
        fi
    done
    echo -e "\n✅ 倒计时结束，自动应用默认设置。"
    return 0
}

# --- 0. 强力预检与修复 ---
pre_flight_check() {
    if ! dpkg --audit >/dev/null 2>&1; then
        echo -e "${BG_RED} ⚠️  检测到系统数据库损坏，正在自愈... ${PLAIN}"
        killall apt apt-get dpkg 2>/dev/null
        rm -f /var/lib/apt/lists/lock /var/cache/apt/archives/lock /var/lib/dpkg/lock*
        rm -rf /var/lib/dpkg/updates/*
        dpkg --configure -a
        apt-get clean && apt-get update -qq
        echo -e "${GREEN}✅ 修复完成。${PLAIN}\n"
    fi
}

clear
echo -e "${GREEN}🚀 开始部署 v0.3 ...${PLAIN}"

pre_flight_check
if ! command -v ss >/dev/null 2>&1; then apt-get install -y iproute2 net-tools >/dev/null; fi

# ==============================================================
# 1. 统一端口管理器
# ==============================================================
echo -e "\n${BLUE}==========================================================${PLAIN}"
echo -e "${BLUE}    ⚙️  全局端口配置 (按 Enter 快速确认默认值)${PLAIN}"
echo -e "${BLUE}==========================================================${PLAIN}"

# --- SSH 端口 ---
SSH_CONF=$(grep "^Port" /etc/ssh/sshd_config | head -n 1 | awk '{print $2}')
SSH_PROC=$(ss -tlnp | grep sshd | grep LISTEN | head -n 1 | awk '{print $4}' | sed 's/.*://')
DEF_SSH=${SSH_PROC:-${SSH_CONF:-22}}

echo -e "\n${YELLOW}[1/3] SSH 管理端口${PLAIN}"
if wait_with_countdown 10 "确认 SSH 端口 [${DEF_SSH}]"; then
    SSH_PORT=$DEF_SSH
else
    read -p "   ✏️  请输入新的 SSH 端口: " U_SSH
    SSH_PORT=${U_SSH:-$DEF_SSH}
fi
echo -e "   ✅ 最终 SSH: ${BLUE}${SSH_PORT}${PLAIN}"

# --- Vision 端口 ---
DEF_V=443
echo -e "\n${YELLOW}[2/3] Vision 节点端口 (TCP)${PLAIN}"
ss -tuln | grep -q ":${DEF_V} " && echo -e "   当前状态: ${BG_RED} 被占用 ${PLAIN}" || echo -e "   当前状态: ${GREEN} 空闲 ${PLAIN}"

if wait_with_countdown 10 "确认 Vision 端口 [${DEF_V}]"; then
    PORT_VISION=$DEF_V
else
    read -p "   ✏️  请输入 Vision 端口: " U_V
    PORT_VISION=${U_V:-$DEF_V}
fi
echo -e "   ✅ 最终 Vision: ${BLUE}${PORT_VISION}${PLAIN}"

# --- xhttp 端口 ---
DEF_X=8443
echo -e "\n${YELLOW}[3/3] xhttp 节点端口${PLAIN}"
ss -tuln | grep -q ":${DEF_X} " && echo -e "   当前状态: ${BG_RED} 被占用 ${PLAIN}" || echo -e "   当前状态: ${GREEN} 空闲 ${PLAIN}"

if wait_with_countdown 10 "确认 xhttp 端口 [${DEF_X}]"; then
    PORT_XHTTP=$DEF_X
else
    read -p "   ✏️  请输入 xhttp 端口: " U_X
    PORT_XHTTP=${U_X:-$DEF_X}
fi
echo -e "   ✅ 最终 xhttp: ${BLUE}${PORT_XHTTP}${PLAIN}"

echo -e "\n配置已锁定，准备安装..."
sleep 1

# ==============================================================
# 2. 系统安装
# ==============================================================
echo "📦 更新系统并安装依赖..."
timedatectl set-timezone Asia/Shanghai
export DEBIAN_FRONTEND=noninteractive
DEPS="curl wget sudo nano git htop tar unzip socat fail2ban rsyslog chrony iptables qrencode iptables-persistent"

if ! apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" $DEPS; then
    pre_flight_check
    if ! apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" $DEPS; then
        echo -e "${RED}❌ 依赖安装失败。${PLAIN}"; exit 1
    fi
fi

echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections

# 3. 优化
if [ "$(free -m | grep Mem | awk '{print $2}')" -lt 2048 ] && [ "$(swapon --show | wc -l)" -lt 2 ]; then
    fallocate -l 1G /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=1024 status=none
    chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
    echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi
if ! grep -q "tcp_congestion_control=bbr" /etc/sysctl.conf; then
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    sysctl -p >/dev/null 2>&1
fi

# 4. 安装 Xray
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
mkdir -p /usr/local/share/xray/
wget -q -O /usr/local/share/xray/geoip.dat https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat
wget -q -O /usr/local/share/xray/geosite.dat https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat

# ==============================================================
# 5. 智能 SNI 优选
# ==============================================================
echo -e "\n${BLUE}==========================================================${PLAIN}"
echo -e "${BLUE}    🔍  智能 SNI 伪装域优选 (Smart SNI Selection)${PLAIN}"
echo -e "${BLUE}==========================================================${PLAIN}"

DOMAINS=("www.icloud.com" "www.apple.com" "itunes.apple.com" "learn.microsoft.com" "www.microsoft.com" "www.bing.com" "www.tesla.com")
BEST_MS=9999
BEST_INDEX=0

echo -e "正在测试握手延迟..."
# 使用 %-10s 而不是 %-10b
printf "%-4s %-22s %-10s\n" "ID" "Domain" "Latency"
echo "----------------------------------------"

for i in "${!DOMAINS[@]}"; do
    domain="${DOMAINS[$i]}"
    time_cost=$(LC_NUMERIC=C curl -4 -w "%{time_connect}" -o /dev/null -s --connect-timeout 2 "https://$domain")
    
    if [ -n "$time_cost" ] && [ "$time_cost" != "0.000" ]; then
        ms=$(LC_NUMERIC=C awk -v t="$time_cost" 'BEGIN { printf "%.0f", t * 1000 }')
    else
        ms="Timeout"
    fi
    
    if [ "$ms" == "Timeout" ]; then
        printf "%-4s %-22s %-10b\n" "$((i+1))" "$domain" "${RED}Timeout${PLAIN}"
    else
        printf "%-4s %-22s %-10b\n" "$((i+1))" "$domain" "${GREEN}${ms}ms${PLAIN}"
        if [ "$ms" -lt "$BEST_MS" ]; then BEST_MS=$ms; BEST_INDEX=$((i+1)); fi
    fi
done

if [ "$BEST_MS" == "9999" ]; then BEST_INDEX=1; fi
DEFAULT_DOMAIN=${DOMAINS[$((BEST_INDEX-1))]}

echo "----------------------------------------"
echo -e "0   自定义输入 (Custom Input)"
echo "----------------------------------------"
echo -e "🚀 自动推荐: [${GREEN}${BEST_INDEX}${PLAIN}] ${DEFAULT_DOMAIN} (延迟最低)"

if wait_with_countdown 10 "选择 SNI 序号 [推荐: ${BEST_INDEX}]"; then
    SNI_HOST="$DEFAULT_DOMAIN"
    echo -e "   ✅ 已自动选择: ${BLUE}${SNI_HOST}${PLAIN}"
else
    read -p "   ✏️  请输入选择 (0-${#DOMAINS[@]}): " SNI_CHOICE
    
    if [ -z "$SNI_CHOICE" ]; then
        SNI_HOST="$DEFAULT_DOMAIN"
    elif [ "$SNI_CHOICE" == "0" ]; then
        read -p "   ✏️  请输入自定义域名: " CUSTOM_DOMAIN
        SNI_HOST="${CUSTOM_DOMAIN:-$DEFAULT_DOMAIN}"
    elif [[ "$SNI_CHOICE" =~ ^[0-9]+$ ]] && [ "$SNI_CHOICE" -ge 1 ] && [ "$SNI_CHOICE" -le "${#DOMAINS[@]}" ]; then
        SNI_HOST="${DOMAINS[$((SNI_CHOICE-1))]}"
    else
        SNI_HOST="$DEFAULT_DOMAIN"
    fi
    echo -e "   ✅ 最终选择: ${BLUE}${SNI_HOST}${PLAIN}"
fi

# ==============================================================
# 后续配置
# ==============================================================
XRAY_BIN="/usr/local/bin/xray"
UUID=$($XRAY_BIN uuid)
KEYS=$($XRAY_BIN x25519)
PRIVATE_KEY=$(echo "$KEYS" | grep "Private" | awk '{print $2}')
PUBLIC_KEY=$(echo "$KEYS" | grep -E "Public|Password" | awk '{print $2}')
SHORT_ID=$(openssl rand -hex 8)
XHTTP_PATH="/req"

mkdir -p /usr/local/etc/xray/
cat > /usr/local/etc/xray/config.json <<CONFIG_EOF
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
  "routing": { "domainStrategy": "IPIfNonMatch", "rules": [ { "type": "field", "ip": [ "geoip:private", "geoip:cn" ], "outboundTag": "block" }, { "type": "field", "protocol": [ "bittorrent" ], "outboundTag": "block" } ] }
}
CONFIG_EOF

mkdir -p /etc/systemd/system/xray.service.d
echo -e "[Service]\nLimitNOFILE=infinity\nLimitNPROC=infinity\nTasksMax=infinity\nRestart=on-failure\nRestartSec=5" > /etc/systemd/system/xray.service.d/override.conf
systemctl daemon-reload

iptables -F
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT
iptables -A INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT
if [ "$SSH_PORT" != "22" ]; then iptables -A INPUT -p tcp --dport 22 -j ACCEPT; fi
iptables -A INPUT -p tcp -m multiport --dports ${PORT_VISION},${PORT_XHTTP} -j ACCEPT
iptables -A INPUT -p udp -m multiport --dports ${PORT_VISION},${PORT_XHTTP} -j ACCEPT
iptables -P INPUT DROP; iptables -P FORWARD DROP; iptables -P OUTPUT ACCEPT

if [ -f /proc/net/if_inet6 ]; then
    ip6tables -F
    ip6tables -A INPUT -i lo -j ACCEPT
    ip6tables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    ip6tables -A INPUT -p ipv6-icmp -j ACCEPT
    ip6tables -A INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT
    if [ "$SSH_PORT" != "22" ]; then ip6tables -A INPUT -p tcp --dport 22 -j ACCEPT; fi
    ip6tables -A INPUT -p tcp -m multiport --dports ${PORT_VISION},${PORT_XHTTP} -j ACCEPT
    ip6tables -A INPUT -p udp -m multiport --dports ${PORT_VISION},${PORT_XHTTP} -j ACCEPT
    ip6tables -P INPUT DROP; ip6tables -P FORWARD DROP; ip6tables -P OUTPUT ACCEPT
fi
netfilter-persistent save

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
port    = $SSH_PORT,22
mode    = aggressive
FAIL2BAN_EOF
systemctl restart rsyslog; systemctl enable fail2ban; systemctl restart fail2ban

# Mode & Info
cp /usr/local/etc/xray/config.json /usr/local/etc/xray/config_block.json
sed 's/, "geoip:cn"//g' /usr/local/etc/xray/config_block.json > /usr/local/etc/xray/config_allow.json
cat > /usr/local/bin/mode << 'MODE_EOF'
#!/bin/bash
GREEN='\033[32m'; RED='\033[31m'; WHITE='\033[37m'; PLAIN='\033[0m'
CONFIG="/usr/local/etc/xray/config.json"
BLOCK_CFG="/usr/local/etc/xray/config_block.json"
ALLOW_CFG="/usr/local/etc/xray/config_allow.json"
set_block() { cp "$BLOCK_CFG" "$CONFIG"; systemctl restart xray; echo -e "✅ 已切换为: ${GREEN}阻断回国 (Block CN)${PLAIN}"; }
set_allow() { cp "$ALLOW_CFG" "$CONFIG"; systemctl restart xray; echo -e "✅ 已切换为: ${RED}允许回国 (Allow CN)${PLAIN}"; }
if grep -q "geoip:cn" "$CONFIG"; then
    OPT_1="${GREEN} 1. 阻断回国 (Block CN) [当前]${PLAIN}"
    OPT_2="${WHITE} 2. 允许回国 (Allow CN)${PLAIN}"
else
    OPT_1="${WHITE} 1. 阻断回国 (Block CN)${PLAIN}"
    OPT_2="${GREEN} 2. 允许回国 (Allow CN) [当前]${PLAIN}"
fi
clear
echo "=============================="; echo "    Xray 模式切换 (Mode)"; echo "=============================="
echo -e "$OPT_1"; echo -e "$OPT_2"; echo "------------------------------"
read -p "请选择 [1-2] (输入其他任意键退出): " choice
case "$choice" in 1) set_block ;; 2) set_allow ;; *) echo "已退出。"; exit 0 ;; esac
MODE_EOF
chmod +x /usr/local/bin/mode
systemctl enable xray && systemctl restart xray

cat > /usr/local/bin/info <<EOF
#!/bin/bash
RED="\033[31m"; GREEN="\033[32m"; YELLOW="\033[33m"; BLUE="\033[36m"; PLAIN="\033[0m"
UUID="${UUID}"; PUBLIC_KEY="${PUBLIC_KEY}"; SHORT_ID="${SHORT_ID}"; SNI_HOST="${SNI_HOST}"
XHTTP_PATH="${XHTTP_PATH}"; SSH_PORT="${SSH_PORT}"
PORT_VISION="${PORT_VISION}"; PORT_XHTTP="${PORT_XHTTP}"

IPV4=\$(curl -s4m 5 https://1.1.1.1/cdn-cgi/trace | grep "ip=" | cut -d= -f2)
if [ -z "\$IPV4" ]; then IPV4=\$(curl -s4m 5 https://api.ipify.org); fi
HOST_TAG=\$(hostname | tr ' ' '.')
[ -z "\$HOST_TAG" ] && HOST_TAG="XrayServer"

LINK_VISION="vless://\${UUID}@\${IPV4}:\${PORT_VISION}?security=reality&encryption=none&pbk=\${PUBLIC_KEY}&headerType=none&fp=chrome&type=tcp&flow=xtls-rprx-vision&sni=\${SNI_HOST}&sid=\${SHORT_ID}#\${HOST_TAG}_Vision"
LINK_XHTTP="vless://\${UUID}@\${IPV4}:\${PORT_XHTTP}?security=reality&encryption=none&pbk=\${PUBLIC_KEY}&headerType=none&fp=chrome&type=xhttp&path=\${XHTTP_PATH}&sni=\${SNI_HOST}&sid=\${SHORT_ID}#\${HOST_TAG}_xhttp"
clear
echo -e "\${GREEN}Xray 配置信息 (Xray Configuration)\${PLAIN}"
echo "=========================================================="
echo -e "\${YELLOW}代理配置:\${PLAIN}"
echo "----------------------------------------------------------"
# --- 对齐修正 (Precise Alignment) ---
# 基准: Public Key (10字符)
# 地址 (IP) : 视觉宽约9字符 -> 补1个空格
echo -e "  地址 (IP)  : \${BLUE}\${IPV4}\${PLAIN}"
# 优选 SNI  : 视觉宽约8字符 -> 补2个空格
echo -e "  优选 SNI   : \${YELLOW}\${SNI_HOST}\${PLAIN}"
# UUID      : 视觉宽4字符   -> 补6个空格
echo -e "  UUID       : \${BLUE}\${UUID}\${PLAIN}"
# Public Key: 视觉宽10字符  -> 补0个空格
echo -e "  Public Key : \${BLUE}\${PUBLIC_KEY}\${PLAIN}"
echo "----------------------------------------------------------"
# 对齐修正 (Precise Alignment)
printf "  节点 1 %-8s : 端口: \${BLUE}%-5s\${PLAIN} 协议: \${BLUE}TCP/Reality\${PLAIN}\n" "(Vision)" "\${PORT_VISION}"
printf "  节点 2 %-8s : 端口: \${BLUE}%-5s\${PLAIN} 协议: \${BLUE}xhttp/Reality\${PLAIN} 路径: \${BLUE}\${XHTTP_PATH}\${PLAIN}\n" "(xhttp)" "\${PORT_XHTTP}"
echo "----------------------------------------------------------"
echo -e "  管理端口 (SSH) : \${BLUE}\${SSH_PORT}\${PLAIN}"
echo "----------------------------------------------------------"
echo -e "\${YELLOW}👇 节点1 链接 (Vision):\${PLAIN}"
echo -e "\${GREEN}\${LINK_VISION}\${PLAIN}"
echo ""
echo -e "\${YELLOW}👇 节点2 链接 (xhttp):\${PLAIN}"
echo -e "\${GREEN}\${LINK_XHTTP}\${PLAIN}"
echo "----------------------------------------------------------"
echo -e "\${YELLOW}👇 节点1 二维码 (Vision):\${PLAIN}"
qrencode -t ANSIUTF8 "\${LINK_VISION}"
echo ""
echo -e "\${YELLOW}👇 节点2 二维码 (xhttp):\${PLAIN}"
qrencode -t ANSIUTF8 "\${LINK_XHTTP}"
echo ""
EOF
chmod +x /usr/local/bin/info

# 完成
bash /usr/local/bin/info
echo -e ""
echo -e "🎉 \033[32m安装完成！\033[0m"
echo -e "💡 命令：\033[33minfo\033[0m (查看信息) | \033[33mmode\033[0m (切换模式)"

