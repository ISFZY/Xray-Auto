#!/bin/bash
# ==============================================================
# Project: Xray Auto Installer
# Author: ISFZY
# Repository: https://github.com/ISFZY/Xray-Auto
# Version: 0.4
# ==============================================================

RED="\033[31m"; GREEN="\033[32m"; YELLOW="\033[33m"; BLUE="\033[36m"; PURPLE="\033[35m"; PLAIN="\033[0m"
BOLD="\033[1m"; BG_RED="\033[41;37m"; BG_GREEN="\033[42;37m"
ICON_OK="✅"; ICON_ERR="❌"; ICON_WARN="⚠️"; ICON_WAIT="⏳"

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
    echo -e "${BLUE}           |__| |__||___|  |_||__| |__|  |___|  By ISFZY    ${PLAIN}"
    echo -e "${BLUE}============================================================${PLAIN}"
    echo -e "${YELLOW}${BOLD}                      Xray-Auto v0.4               ${PLAIN}"
    echo -e "${BLUE}============================================================${PLAIN}\n"
}

if [[ $EUID -ne 0 ]]; then echo -e "${RED}${ICON_ERR} Error: 请使用 root 权限运行!${PLAIN}"; exit 1; fi
if [ ! -f /etc/debian_version ]; then echo -e "${RED}${ICON_ERR} 仅支持 Debian/Ubuntu 系统!${PLAIN}"; exit 1; fi

pre_flight_check() {
    if ! pgrep -x apt >/dev/null && ! pgrep -x dpkg >/dev/null && dpkg --audit >/dev/null 2>&1; then
        return 0
    fi

    echo -e "正在检查环境..."

    local timeout=120
    local max_ticks=$((timeout * 2)) 
    local ticks=0
    
    local spin='-\|/'
    local i=0

    while pgrep -x apt >/dev/null || pgrep -x dpkg >/dev/null; do
        if [ $ticks -ge $max_ticks ]; then
            printf "\r\033[K" 
            echo -e "${RED}${ICON_ERR} 等待超时！apt/dpkg 占用时间过长。${PLAIN}"
            exit 1
        fi

        local sec=$((ticks / 2))
        
        i=$(( (i+1) % 4 ))
        printf "\r${YELLOW}[%s] 系统正忙，请稍候... (%ds/${timeout}s)${PLAIN}" "${spin:$i:1}" "$sec"
        
        sleep 0.5
        ((ticks++))
    done

    printf "\r\033[K"

    if ! dpkg --audit >/dev/null 2>&1; then
        echo -e "${YELLOW}尝试修复被中断的安装...${PLAIN}"

        dpkg --configure -a >/dev/null 2>&1
        if ! dpkg --audit >/dev/null 2>&1; then
             echo -e "${RED}修复失败，请手动检查。${PLAIN}"
             exit 1
        fi
        echo -e "${GREEN}修复完成。${PLAIN}"
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

timedatectl set-timezone Asia/Shanghai
export DEBIAN_FRONTEND=noninteractive

if [ -f /etc/needrestart/needrestart.conf ]; then
    sed -i "s/#\$nrconf{restart} = 'i';/\$nrconf{restart} = 'a';/" /etc/needrestart/needrestart.conf
fi

echo -ne "${BLUE}📦 更新系统并安装依赖 ${PLAIN}(此过程可能需要几分钟)..."

(
    apt-get update -qq >/dev/null 2>&1
    apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" upgrade >/dev/null 2>&1
    
    DEPENDENCIES="curl wget sudo nano git htop tar unzip socat fail2ban rsyslog chrony iptables qrencode"
    apt-get install -y $DEPENDENCIES >/dev/null 2>&1
) &

run_with_spinner $!
echo -e "${GREEN} 完成${PLAIN}"

if ! command -v fail2ban-client &> /dev/null; then
echo -e "\n${RED}❌ 严重错误：软件安装失败。可能是网络源问题，请重试。${PLAIN}"
    exit 1
fi

echo -ne "${BLUE}   🚀 下载并安装 Xray Core...${PLAIN}"

install_xray_core() {
    bash -c "$(curl -L $CURL_OPT https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install >/dev/null 2>&1
}

(install_xray_core) &
pid=$!
run_with_spinner $pid
wait $pid
status=$?

if [ $status -ne 0 ]; then
    echo -e "\n${YELLOW}⚠️  安装被中断 (可能是 apt 被占用)，正在尝试自动修复...${PLAIN}"
    
    pre_flight_check
    
    echo -ne "${BLUE}   🔄 锁已释放，正在重试安装 Xray Core...${PLAIN}"
    (install_xray_core) &
    pid=$!
    run_with_spinner $pid
    wait $pid
    
    if [ $? -ne 0 ]; then
        echo -e "\n${RED}❌ 严重错误：重试安装失败！请检查网络连接。${PLAIN}"
        exit 1
    fi
fi

echo -e "${GREEN} 完成${PLAIN}"

mkdir -p /usr/local/share/xray/
wget -q $CURL_OPT -O /usr/local/share/xray/geoip.dat https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat
wget -q $CURL_OPT -O /usr/local/share/xray/geosite.dat https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat

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

echo -e "\n${BLUE}--- 🔍 智能 SNI 伪装域优选 ---${PLAIN}"
DOMAINS=("www.icloud.com" "www.apple.com" "itunes.apple.com" "learn.microsoft.com" "www.bing.com" "www.tesla.com")
BEST_MS=9999; BEST_INDEX=1

printf "${BG_GREEN} %-4s %-25s %-12s ${PLAIN}\n" "ID" "Domain" "Latency"

for i in "${!DOMAINS[@]}"; do
    domain="${DOMAINS[$i]}"
    display_index=$((i+1))
    
    time_cost=$(LC_NUMERIC=C curl $CURL_OPT -w "%{time_connect}" -o /dev/null -s --connect-timeout 2 "https://$domain")
    if [ -n "$time_cost" ] && [ "$time_cost" != "0.000" ]; then
        ms=$(LC_NUMERIC=C awk -v t="$time_cost" 'BEGIN { printf "%.0f", t * 1000 }')
        color=$GREEN
        if [ "$ms" -gt 200 ]; then color=$YELLOW; fi

        if [ "$ms" -lt "$BEST_MS" ]; then BEST_MS=$ms; BEST_INDEX=$display_index; fi
        printf " %-4s %-25s ${color}%-8s${PLAIN}\n" "$display_index" "$domain" "${ms}ms"
    else
        printf " %-4s %-25s ${RED}%-8s${PLAIN}\n" "$display_index" "$domain" "Timeout"
    fi
done

printf " %-4s %-25s ${BLUE}%-8s${PLAIN}\n" "0" "自定义输入 (Custom)" "-"
echo -e "----------------------------------------------"

DEFAULT_SNI=${DOMAINS[$((BEST_INDEX-1))]}

echo -ne "${GREEN}👉 请选择 SNI ID [0-6] ${PLAIN}(默认: ${YELLOW}${BEST_INDEX}. ${DEFAULT_SNI}${PLAIN}): "
read -t 10 -p "" SELECTION || SELECTION=""
echo "" # 换行

if [[ -z "$SELECTION" ]]; then
    SNI_HOST="$DEFAULT_SNI"
    echo -e "⏩ 使用推荐配置: ${GREEN}${SNI_HOST}${PLAIN}"

elif [[ "$SELECTION" == "0" ]]; then
    while true; do
        read -p "⌨️  请输入自定义 SNI 域名: " CUSTOM_INPUT
        if [[ "$CUSTOM_INPUT" =~ ^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]]; then
            SNI_HOST="$CUSTOM_INPUT"
            break
        else
            echo -e "${RED}❌ 格式错误！请输入有效的域名 (例如: www.google.com)${PLAIN}"
        fi
    done

elif [[ "$SELECTION" =~ ^[1-6]$ ]]; then
    SNI_HOST=${DOMAINS[$((SELECTION-1))]}
    echo -e "👉 您选择了: ${GREEN}${SNI_HOST}${PLAIN}"

else
    SNI_HOST="$DEFAULT_SNI"
    echo -e "${YELLOW}⚠️  输入无效，自动使用推荐: ${GREEN}${SNI_HOST}${PLAIN}"
fi

echo -e "✅ 最终 SNI: ${YELLOW}${SNI_HOST}${PLAIN}"

XRAY_BIN="/usr/local/bin/xray"
UUID=$($XRAY_BIN uuid)
KEYS=$($XRAY_BIN x25519)

PRIVATE_KEY=$(echo "$KEYS" | grep "Private" | awk '{print $NF}')
PUBLIC_KEY=$(echo "$KEYS" | grep -E "Public|Password" | awk '{print $NF}')

SHORT_ID=$(openssl rand -hex 8)
XHTTP_PATH="/$(openssl rand -hex 4)"

if [[ -z "$UUID" || -z "$PRIVATE_KEY" || -z "$PUBLIC_KEY" ]]; then
    echo -e "\${RED}❌ 错误：凭证生成不完整，请检查 Xray 是否安装成功。${PLAIN}"
    exit 1
fi

mkdir -p /usr/local/etc/xray/

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

cp /usr/local/etc/xray/config.json /usr/local/etc/xray/config_block.json
sed 's/, "geoip:cn"//g' /usr/local/etc/xray/config_block.json > /usr/local/etc/xray/config_allow.json

HOST_NAME=$(hostname)

cat > /usr/local/bin/info <<EOF
#!/bin/bash
RED="\033[31m"; GREEN="\033[32m"; YELLOW="\033[33m"; BLUE="\033[36m"; PLAIN="\033[0m"

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

cat >> /usr/local/bin/info << 'SCRIPT_EOF'

IPV4=$(curl -s4m 2 https://api.ipify.org || curl -s4m 2 https://ifconfig.me)
IPV6=$(curl -s6m 2 https://api64.ipify.org || curl -s6m 2 https://ifconfig.co)
[ -z "$IPV4" ] && IPV4="N/A"
[ -z "$IPV6" ] && IPV6="N/A"
if [[ "$IPV4" != "N/A" ]]; then SHOW_IP=$IPV4; else SHOW_IP="[$IPV6]"; fi

LINK_VISION="vless://${UUID}@${SHOW_IP}:${PORT_VISION}?security=reality&encryption=none&pbk=${PUBLIC_KEY}&headerType=none&fp=chrome&type=tcp&flow=xtls-rprx-vision&sni=${SNI_HOST}&sid=${SHORT_ID}#${HOST_NAME}_Vision"

LINK_XHTTP="vless://${UUID}@${SHOW_IP}:${PORT_XHTTP}?security=reality&encryption=none&pbk=${PUBLIC_KEY}&headerType=none&fp=chrome&type=xhttp&path=${XHTTP_PATH}&sni=${SNI_HOST}&sid=${SHORT_ID}#${HOST_NAME}_xhttp"

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
echo -e "${BLUE}👇 节点 1 (Vision) 链接:${PLAIN}"
echo -e "${LINK_VISION}"
echo -e ""
echo -e "${BLUE}👇 节点 2 (xhttp) 链接:${PLAIN}"
echo -e "${LINK_XHTTP}"
echo -e "=========================================================="
echo -e "\n${BLUE}📱 手机扫码功能${PLAIN}"
echo -ne "${YELLOW}   是否显示二维码? (y/n) [默认 n]: ${PLAIN}"
read CHOICE

if [[ "$CHOICE" == "y" || "$CHOICE" == "Y" ]]; then
    echo -e "\n${BLUE}>>> 正在生成 Vision 节点二维码...${PLAIN}"
    qrencode -t ANSIUTF8 "${LINK_VISION}"
    echo -e "\n${BLUE}>>> 正在生成 xhttp 节点二维码...${PLAIN}"
    qrencode -t ANSIUTF8 "${LINK_XHTTP}"
fi
echo ""
SCRIPT_EOF
chmod +x /usr/local/bin/info

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
