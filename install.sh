#!/bin/bash
# ==================================================================
# Project: Xray Auto Installer
# Author: ISFZY
# Repository: https://github.com/ISFZY/Xray-Auto
# ==================================================================

# ------------------------------------------------------------------
# 一、全局配置与 UI 定义 (Global Settings & UI)
# ------------------------------------------------------------------

# 1.1 基础颜色配置
RED="\033[31m"; GREEN="\033[32m"; YELLOW="\033[33m"; BLUE="\033[36m"; PURPLE="\033[35m"; GRAY="\033[90m"; PLAIN="\033[0m"
BOLD="\033[1m"

# 1.2 标准化状态标签 (Standard Tags)
OK="${GREEN}[OK]${PLAIN}"
ERR="${RED}[ERR]${PLAIN}"
WARN="${YELLOW}[WARN]${PLAIN}"
INFO="${BLUE}[INFO]${PLAIN}"
STEP="${PURPLE}==>${PLAIN}"

# 1.3 简单的旋转动画
# Linux 等待动画： | / - \
UI_SPINNER_FRAMES=("|" "/" "-" "\\")
# 截取日志长度
UI_LOG_WIDTH=50

# 1.4 锁文件配置 (Prevent Duplicate Run)
LOCK_DIR="/tmp/xray_installer_lock"
PID_FILE="$LOCK_DIR/pid"

# 1.5 交互超时设置 (Interaction Timeouts)
UI_TIMEOUT_SHORT=30   # 简单询问 (如: BBR, 时区)
UI_TIMEOUT_LONG=30    # 复杂操作 (如: 端口, 选域名)

# ------------------------------------------------------------------
# 二、核心函数定义 (Core Functions Definition)
# ------------------------------------------------------------------

# --- 锁释放与清理 ---
cleanup() {
  rm -f "/tmp/xray_install_step.log"
  # 释放锁：删除目录
  rm -rf "$LOCK_DIR" 2>/dev/null
}
trap cleanup EXIT INT TERM

# --- 锁获取 (单实例检查) ---
lock_acquire() {
  # 尝试创建目录作为原子锁
  if mkdir "$LOCK_DIR" 2>/dev/null; then
    echo "$$" > "$PID_FILE"
    return 0
  fi

  # 如果锁存在，检查持有锁的进程是否还活着
  if [ -f "$PID_FILE" ]; then
    local old_pid=$(cat "$PID_FILE" 2>/dev/null)
    if [ -n "$old_pid" ] && ! kill -0 "$old_pid" 2>/dev/null; then
      # 进程已死 (Stale Lock)，强制接管
      rm -rf "$LOCK_DIR"
      mkdir "$LOCK_DIR" 2>/dev/null || return 1
      echo "$$" > "$PID_FILE"
      return 0
    fi
  fi
  
  return 1
}

# --- 日志封装函数 ---
log_info() { echo -e "${INFO} $*"; }
log_warn() { echo -e "${WARN} $*"; }
log_err()  { echo -e "${ERR} $*" >&2; }

# --- 核心：统一倒计时交互函数 ---
# 用法: read_with_timeout "提示语" "默认值" "超时时间"
# 结果存储在全局变量 $USER_INPUT 中
read_with_timeout() {
    local prompt="$1"
    local default="$2"
    local timeout="$3"
    local input_char=""
    
    # 清空之前的输入残留
    USER_INPUT=""

    for ((t=timeout; t>0; t--)); do
        # 交互 UI： 提示语 [默认: X] [ 10s ] :
        echo -ne "\r${YELLOW}${prompt} [默认: ${default}] [ ${RED}${t}s${YELLOW} ] : ${PLAIN}"
        
        # -n 1 读取一个字符，-t 1 等待一秒
        read -t 1 -n 1 input_char
        if [ $? -eq 0 ]; then
            # 用户按下了键
            echo "" # 换行
            # 如果用户直接按回车(输入为空)，则使用默认值
            if [ -z "$input_char" ]; then
                USER_INPUT="$default"
            else
                USER_INPUT="$input_char"
            fi
            return 0
        fi
    done

    # 超时处理
    echo -e "\n${INFO} 倒计时结束，使用默认值: ${default}"
    USER_INPUT="$default"
}

# --- 核心：旋转光标监控 (Standard Spinner) [修复版] ---
monitor_task_inline() {
    local pid=$1
    local logfile=$2
    local desc=$3
    local i=0
    
    # 隐藏光标
    tput civis
    
    while kill -0 $pid 2>/dev/null; do
        # 获取日志摘要
        if [ -f "$logfile" ]; then
            local raw_log=$(tail -n 1 "$logfile" 2>/dev/null)
            # 1. 去除颜色代码
            # 2. 去除 \r 回车符
             local clean_log=$(echo "$raw_log" | sed 's/\x1b\[[0-9;]*m//g' | tr -d '\r' | cut -c 1-$UI_LOG_WIDTH)
        else
            local clean_log=""
        fi

        if [ -z "$clean_log" ]; then clean_log="..."; fi
        
        i=$(( (i+1) % ${#UI_SPINNER_FRAMES[@]} ))
        
        # 打印状态
        printf "\r ${BLUE}[ %s ]${PLAIN} %-35s ${GRAY}(%s)${PLAIN}\033[K" \
            "${UI_SPINNER_FRAMES[$i]}" "$desc" "$clean_log"
            
        sleep 0.1
    done
    
    tput cnorm
}

# --- 核心：任务执行包装器 ---
execute_task() {
    local cmd="$1"
    local desc="$2"
    local current_step=$3 
    local total_steps=$4
    
    local log_file="/tmp/xray_install_step.log"
    local max_retries=3
    local attempt=1

    while true; do
        echo "" > "$log_file"
        bash -c "$cmd" > "$log_file" 2>&1 &
        local pid=$!
        
        monitor_task_inline $pid "$log_file" "$desc"
        
        wait $pid
        local status=$?

        # 清除当前行
        echo -ne "\r\033[K"

        if [ $status -eq 0 ]; then
            # 成功后显示： [OK] 任务描述
            echo -e "${OK}   ${desc}"
            return 0
        fi

        # 失败后显示： [ERR] 任务描述
        echo -e "${ERR}  ${desc}"
        
        echo -e "${RED}=== 错误日志 ===${PLAIN}"
        tail -n 5 "$log_file" | sed "s/^/   /g"
        
        if [ $attempt -ge $max_retries ]; then
            echo -e "${RED}多次重试失败。${PLAIN}"
            while true; do
                read -p "选项: (y=重试 / n=退出 / l=查看日志) [y]: " choice
                choice=${choice:-y}
                case "$choice" in
                    y|Y) echo -e "${INFO} 正在重试..."; attempt=0; break ;;
                    n|N) exit 1 ;;
                    l|L) more "$log_file"; echo ""; ;;
                    *) echo "输入错误";;
                esac
            done
        fi
        ((attempt++))
        sleep 2
    done
}

# ==================================================================
# 三、业务逻辑执行区 (Main Execution)
# ==================================================================

# 0. 单实例检查
if ! lock_acquire; then
    echo -e "${ERR} 脚本已经在运行中，请勿重复执行！(Another instance is running)"
    exit 1
fi

print_banner() {
    clear
    echo -e "${BLUE}============================================================${PLAIN}"
    echo -e "${BLUE} Xray Auto Installer                                        ${PLAIN}"
    echo -e "${BLUE}============================================================${PLAIN}\n"
}

pre_flight_check() {
    # 检测包管理器锁
    is_package_manager_running() {
        pgrep -x apt >/dev/null || pgrep -x apt-get >/dev/null || pgrep -x dpkg >/dev/null || pgrep -f "unattended-upgr" >/dev/null
    }

    local desc="环境检查 (Environment Check)"
    local max_ticks=300 # 300秒超时
    local ticks=0
    
    # 1. 如果占用，显示等待 Spinner
    if is_package_manager_running; then
        echo -e "${INFO} 检测到系统更新进程正在运行，正在等待释放锁..."
        # 隐藏光标
        tput civis 
        while is_package_manager_running; do
            if [ $ticks -ge $max_ticks ]; then
                tput cnorm
                echo -e "\n${WARN} 等待超时！用户可选择手动杀进程或继续等待。"
                read -p "是否强制终止占用进程? (y/n) [n]: " kill_choice
                if [[ "$kill_choice" == "y" ]]; then
                    killall apt apt-get 2>/dev/null
                    rm -f /var/lib/apt/lists/lock /var/cache/apt/archives/lock /var/lib/dpkg/lock*
                    break
                else
                    echo -e "${ERR} 用户取消，安装终止。"; exit 1
                fi
            fi
            
            # 简单的转圈动画
            local frame=${UI_SPINNER_FRAMES[$((ticks % 4))]}
            printf "\r ${BLUE}[ %s ]${PLAIN} System busy... (${ticks}s)" "$frame"
            
            sleep 0.5
            ((ticks++))
        done
        tput cnorm
        echo -ne "\r\033[K" # 清除等待行
    fi

    # 2. 检查 dpkg 状态
    if ! dpkg --audit >/dev/null 2>&1; then
        echo -e "${ERR} 检测到 dpkg 数据库状态异常！"
        echo -e "${YELLOW}建议执行: 'dpkg --configure -a' 修复系统。${PLAIN}"
        exit 1
    fi
    
    echo -e "${OK}   ${desc}"
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
        echo -e "${ERR} 无法连接互联网，请检查网络！"; exit 1
    fi
    
    echo -e "${OK}   网络检测: ${GREEN}${NET_TYPE}${PLAIN}"
}

# --- 时区检测与自动校准 ---
check_timezone() {
    local current_tz=$(timedatectl show -p Timezone --value)
    
    echo -e "\n${BLUE}--- 0. 时区设置 (Timezone) ---${PLAIN}"
    echo -e "   当前: ${YELLOW}${current_tz}${PLAIN}"
    
    # 交互询问    
    read_with_timeout "时区是否修改为上海? (y/n)" "n" "$UI_TIMEOUT_SHORT"
    local tz_choice="$USER_INPUT"

    if [[ "$tz_choice" =~ ^[yY]$ ]]; then
        execute_task "timedatectl set-timezone Asia/Shanghai" "设置时区为 Asia/Shanghai"
    else
        execute_task "timedatectl set-timezone UTC" "设置时区为 UTC"
    fi

    execute_task "timedatectl set-ntp true" "同步系统时间"
}

# --- 执行初始化 ---
print_banner
pre_flight_check
check_net_stack
check_timezone

# --- 2. 安装流程 ---
echo -e "\n${STEP} 开始安装核心组件..."

export DEBIAN_FRONTEND=noninteractive
mkdir -p /etc/needrestart/conf.d
echo "\$nrconf{restart} = 'a';" > /etc/needrestart/conf.d/99-xray-auto.conf

# === 1. 系统级更新 ===
# 修复潜在的包管理锁问题
rm -f /var/lib/apt/lists/lock /var/cache/apt/archives/lock /var/lib/dpkg/lock*
execute_task "apt-get update -qq"  "刷新软件源"
execute_task "DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' upgrade" "系统升级"

# === 2. 依赖安装 (安装后立即验证) ===
DEPENDENCIES=("curl" "tar" "unzip" "fail2ban" "rsyslog" "chrony" "iptables" "iptables-persistent" "qrencode" "jq" "cron" "python3-systemd")

echo -e "${INFO} 正在检查并安装依赖..."
for pkg in "${DEPENDENCIES[@]}"; do
    # 预检查：如果 dpkg 数据库里已经有了，就不浪费时间apt了
    if dpkg -s "$pkg" &>/dev/null; then
        echo -e "${OK}   依赖已就绪: $pkg"
        continue
    fi

    # 初次安装
    execute_task "apt-get install -y $pkg" "安装依赖: $pkg"
    
    # [关键步骤] 安装后验证：apt 虽然返回0，但可能包坏了
    if ! dpkg -s "$pkg" &>/dev/null; then
        echo -e "${WARN} 依赖 $pkg 校验失败！尝试修复源并重试..."
        apt-get update -qq --fix-missing
        execute_task "apt-get install -y $pkg" "重试安装: $pkg"
        
        # 熔断机制：二次重试还不行，直接报错退出
        if ! dpkg -s "$pkg" &>/dev/null; then
            echo -e "${ERR} [FATAL] 无法安装系统依赖: $pkg"
            echo -e "${YELLOW}请手动运行 'apt-get install $pkg' 查看具体报错。${PLAIN}"
            exit 1
        fi
    fi
done

# === 3. Xray 核心安装 (二进制验证 + 循环重试) ===
install_xray_robust() {
    local max_tries=3
    local count=0
    local bin_path="/usr/local/bin/xray"
    
    mkdir -p /usr/local/share/xray/

    while [ $count -lt $max_tries ]; do
        # 执行官方安装脚本
        CMD_XRAY='bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --without-geodata'
        
        if [ $count -gt 0 ]; then
            desc="安装 Xray Core (第 $((count+1)) 次尝试)"
        else
            desc="安装 Xray Core"
        fi
        execute_task "$CMD_XRAY" "$desc"
        
        # [关键步骤] 验证：不仅检查文件存在，还要试运行一次看版本
        if [ -f "$bin_path" ] && "$bin_path" version &>/dev/null; then
            local ver=$("$bin_path" version | head -n 1 | awk '{print $2}')
            echo -e "${OK}   Xray 核心校验通过: ${GREEN}${ver}${PLAIN}"
            return 0
        fi
        
        echo -e "${WARN} Xray 安装校验失败 (文件损坏或无法运行)，清理环境重试..."
        # 删除可能损坏的二进制文件
        rm -rf "$bin_path" "/usr/local/share/xray/"
        ((count++))
        sleep 2
    done
    
    echo -e "${ERR} [FATAL] Xray Core 安装最终失败！"
    echo -e "${YELLOW}可能原因：GitHub 连接被墙或网络极不稳定。${PLAIN}"
    exit 1
}

install_xray_robust

# === 4. GeoIP 数据库下载 (校验 + 自动更新) ===
install_geoip_robust() {
    local file="/usr/local/share/xray/geoip.dat"
    local url="https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"
    
    # --- 1. 下载 ---
    execute_task "curl -L $CURL_OPT -o $file $url" "下载 GeoIP 规则库"
    
    # --- 2. 校验 (验证文件是否存在且大小正常) ---
    local fsize=$(du -k "$file" 2>/dev/null | awk '{print $1}')
    if [ ! -f "$file" ] || [ "$fsize" -lt 500 ]; then
        echo -e "${WARN} GeoIP 文件似乎不完整 (Size: ${fsize}KB)，正在重试下载..."
        rm -f "$file"
        execute_task "curl -L $CURL_OPT -o $file $url" "重试下载 GeoIP"
        
        # 二次检查
        if [ ! -f "$file" ]; then
            echo -e "${WARN} GeoIP 下载失败，将跳过 (不影响核心功能)。"
            return 1
        fi
    fi

    # --- 3. 配置自动更新 (Crontab) ---
    # 定义更新命令
    local update_cmd="curl -L $CURL_OPT -o $file $url && systemctl restart xray"
    local cron_job="0 4 * * 0 $update_cmd >/dev/null 2>&1"

    # 确保 cron 已安装
    if ! command -v crontab &>/dev/null; then apt-get install -y cron &>/dev/null; fi
    
    # 写入任务 (先删旧的，再加新的)
    (crontab -l 2>/dev/null | grep -v 'geoip.dat'; echo "$cron_job") | crontab -
    
    echo -e "${OK}   geoip 自动更新任务 (每周日 4:00)"
}

install_geoip_robust

echo -e "${OK}   基础组件安装完毕 (已通过完整性自检)。\n"

# --- 3. 安全与防火墙配置 ---

_add_fw_rule() {
    local port=$1; local v4=$2; local v6=$3
    if [ "$v4" = true ]; then
        iptables -C INPUT -p tcp --dport $port -j ACCEPT 2>/dev/null || iptables -A INPUT -p tcp --dport $port -j ACCEPT
        iptables -C INPUT -p udp --dport $port -j ACCEPT 2>/dev/null || iptables -A INPUT -p udp --dport $port -j ACCEPT
    fi
    if [ "$v6" = true ] && [ -f /proc/net/if_inet6 ]; then
        ip6tables -C INPUT -p tcp --dport $port -j ACCEPT 2>/dev/null || ip6tables -A INPUT -p tcp --dport $port -j ACCEPT
        ip6tables -C INPUT -p udp --dport $port -j ACCEPT 2>/dev/null || ip6tables -A INPUT -p udp --dport $port -j ACCEPT
    fi
}

setup_firewall_and_security() {
    echo -e "${BLUE}--- 2. 端口与安全配置 (Security) ---${PLAIN}"
    
    # 自动检测 SSH 端口
    local current_ssh_port=$(grep "^Port" /etc/ssh/sshd_config | head -n 1 | awk '{print $2}' | tr -d '\r')
    if [ -z "$current_ssh_port" ]; then current_ssh_port=22; fi
    
    SSH_PORT=$current_ssh_port
    PORT_VISION=443
    PORT_XHTTP=8443

    echo -e "   SSH    端口 : ${GREEN}$SSH_PORT${PLAIN}"
    echo -e "   Vision 端口 : ${GREEN}$PORT_VISION${PLAIN}"
    echo -e "   XHTTP  端口 : ${GREEN}$PORT_XHTTP${PLAIN}"

    # 交互询问
    read_with_timeout "是否自定义端口? (y/n)" "n" "$UI_TIMEOUT_LONG"
    local port_choice="$USER_INPUT"

    if [[ "$port_choice" =~ ^[yY]$ ]]; then
        
        # === 1. SSH 端口配置 ===
        clear
        echo -e "${RED}################################################################${PLAIN}"
        echo -e "${RED}#                      高风险操作警告 (WARNING)                #${PLAIN}"
        echo -e "${RED}################################################################${PLAIN}"
        echo -e "${RED}#${PLAIN}                                                              ${RED}#${PLAIN}"
        echo -e "${RED}#${PLAIN}  1. 云服务器用户 (阿里云/腾讯云/AWS等)：                     ${RED}#${PLAIN}"
        echo -e "${RED}#${PLAIN}     即将配置 SSH 端口。如果修改端口，必须先在                ${RED}#${PLAIN}"
        echo -e "${RED}#${PLAIN}     网页控制台的【安全组/防火墙】放行新端口！                ${RED}#${PLAIN}"
        echo -e "${RED}#${PLAIN}                                                              ${RED}#${PLAIN}"
        echo -e "${RED}#${PLAIN}  2. 此时修改端口后，【绝对不要】关闭当前窗口！               ${RED}#${PLAIN}"
        echo -e "${RED}#${PLAIN}     请新开一个 SSH 窗口测试连接。如果失败，                  ${RED}#${PLAIN}"
        echo -e "${RED}#${PLAIN}     你需要通过云控制台 VNC 救砖或重装系统。                  ${RED}#${PLAIN}"
        echo -e "${RED}#${PLAIN}                                                              ${RED}#${PLAIN}"
        echo -e "${RED}################################################################${PLAIN}"
        echo ""

        # 强制确认
        read -p "我已知晓风险，是否修改 SSH 端口? (y=修改 / n=保持默认 $SSH_PORT): " ssh_confirm
        
        if [[ "$ssh_confirm" =~ ^[yY]$ ]]; then
            while true; do
                read -p "请输入新的 SSH 端口: " input_ssh
                # 校验数字
                if [[ ! "$input_ssh" =~ ^[0-9]+$ ]] || [ "$input_ssh" -lt 1 ] || [ "$input_ssh" -gt 65535 ]; then
                    echo -e "${RED}错误: 端口必须是 1-65535 之间的数字！${PLAIN}"
                    continue
                fi
                # 确认修改
                SSH_PORT="$input_ssh"
                break
            done
        else
            echo -e "${INFO} SSH 端口保持默认: ${GREEN}$SSH_PORT${PLAIN}"
        fi

        # === 2. Vision / XHTTP 端口设置 ===
        echo -e "\n${BLUE}--- 继续配置 Xray 端口 ---${PLAIN}"
        read -p "请输入 Vision 端口 [443]: " input_vision
        PORT_VISION=${input_vision:-443}
        
        read -p "请输入 XHTTP  端口 [8443]: " input_xhttp
        PORT_XHTTP=${input_xhttp:-8443}
        
        # === 3. 应用 SSH 修改 ===
        if [ "$SSH_PORT" != "$current_ssh_port" ]; then
            sed -i "s/^Port.*/Port $SSH_PORT/" /etc/ssh/sshd_config
            if ! grep -q "^Port" /etc/ssh/sshd_config; then echo "Port $SSH_PORT" >> /etc/ssh/sshd_config; fi
            
            echo -e "${WARN} 正在重启 SSH 服务，请务必放行端口 $SSH_PORT !"
            systemctl restart ssh || systemctl restart sshd
        fi
    fi

    # --- 最终配置回显 ---
    echo -e "\n${INFO} 端口配置确认 (Configuration Confirmed):"
    echo -e "${OK} SSH    端口 : ${GREEN}$SSH_PORT${PLAIN}"
    echo -e "${OK} Vision 端口 : ${GREEN}$PORT_VISION${PLAIN}"
    echo -e "${OK} XHTTP  端口 : ${GREEN}$PORT_XHTTP${PLAIN}\n"

    # Fail2ban 配置 (开启指数封禁)
    cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1
bantime = 1d
bantime.increment = true
bantime.factor = 1
bantime.maxtime = 30d
findtime = 1d
maxretry = 3
# 改为 auto，让它自动兼容日志文件和systemd，防止崩溃
backend = auto

[sshd]
enabled = true
port = $SSH_PORT,22
# 如果 aggressive 模式导致无法启动，可改为 normal
mode = aggressive
EOF
    execute_task "systemctl restart rsyslog && systemctl enable fail2ban && systemctl restart fail2ban" "配置 Fail2ban 防护(开启指数封禁)"

    # 防火墙规则
    _add_fw_rule $SSH_PORT $HAS_V4 $HAS_V6
    _add_fw_rule $PORT_VISION $HAS_V4 $HAS_V6
    _add_fw_rule $PORT_XHTTP $HAS_V4 $HAS_V6
    execute_task "netfilter-persistent save" "持久化防火墙规则"
}

setup_kernel_optimization() {
    echo -e "\n${BLUE}--- 3. 内核优化 (Kernel Opt) ---${PLAIN}"
    
    # --- 1. BBR 配置 ---
    read_with_timeout "是否启用 BBR 加速? (y/n)" "y" "$UI_TIMEOUT_SHORT"
    local bbr_choice="$USER_INPUT"
    
    if [[ "${bbr_choice:-y}" =~ ^[yY]$ ]]; then
        execute_task 'echo "net.core.default_qdisc=fq" > /etc/sysctl.d/99-xray-bbr.conf && echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.d/99-xray-bbr.conf && sysctl --system' "启用 BBR"
    else
        echo -e "${INFO} 跳过 BBR 配置。"
    fi

    # --- 2. Swap 智能配置 ---
    local ram_size=$(free -m | awk '/Mem:/ {print $2}')
    if [ "$ram_size" -lt 2048 ]; then
        # 先检查 Swap 是否已经启用
        if grep -q "/swapfile" /proc/swaps; then
            echo -e "${OK}   检测到 Swap 已启用，跳过创建。"
        else
            echo -e "${WARN} 内存少于 2GB，正在自动配置 Swap..."
            
            # 使用 dd 作为 fallocate 的备用方案（兼容性更好），并包裹在复合命令中
            # 逻辑：先删残余 -> 尝试 fallocate -> 失败则用 dd -> 设置权限 -> 格式化 -> 挂载 -> 写入 fstab
            local cmd_swap='
                swapoff /swapfile 2>/dev/null; rm -f /swapfile;
                if ! fallocate -l 1024M /swapfile 2>/dev/null; then
                    dd if=/dev/zero of=/swapfile bs=1M count=1024;
                fi;
                chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile && 
                if ! grep -q "/swapfile" /etc/fstab; then echo "/swapfile none swap sw 0 0" >> /etc/fstab; fi
            '
            execute_task "$cmd_swap" "启用 1GB Swap"
        fi
    fi
}

# --- 执行配置 ---
setup_firewall_and_security
setup_kernel_optimization

# --- SNI 优选 ---
echo -e "\n${BLUE}--- 5. SNI 伪装域优选 ---${PLAIN}"
RAW_DOMAINS=("www.icloud.com" "www.apple.com" "itunes.apple.com" "learn.microsoft.com" "www.bing.com" "www.tesla.com")
TEMP_FILE=$(mktemp)

echo -e "${INFO} 正在检测域名延迟..."
tput civis
for domain in "${RAW_DOMAINS[@]}"; do
    printf "\r   Ping: %-25s" "${domain}..."
    time_cost=$(LC_NUMERIC=C curl $CURL_OPT -w "%{time_connect}" -o /dev/null -s --connect-timeout 2 "https://$domain")
    if [ -n "$time_cost" ] && [ "$time_cost" != "0.000" ]; then
        ms=$(LC_NUMERIC=C awk -v t="$time_cost" 'BEGIN { printf "%.0f", t * 1000 }')
        echo "$ms $domain" >> "$TEMP_FILE"
    else
        echo "999999 $domain" >> "$TEMP_FILE"
    fi
done
tput cnorm
echo -ne "\r\033[K"

SORTED_DOMAINS=() 
index=1
echo -e "   结果清单:"
echo -e "   0 . 自定义域名 (Custom Input)"

while read ms domain; do
    SORTED_DOMAINS+=("$domain")
    if [ "$ms" == "999999" ]; then d_ms="Fail"; else d_ms="${ms}ms"; fi
    
    # 绿色推荐标签
    if [ "$index" -eq 1 ]; then tag="${GREEN}[推荐]${PLAIN}"; else tag=""; fi
    
    # 格式化对齐输出
    printf "   %-2d. %-28s %-8s %b\n" "$index" "$domain" "$d_ms" "$tag"
    ((index++))
done < <(sort -n "$TEMP_FILE")
rm -f "$TEMP_FILE"

# --- 交互选择 ---
read_with_timeout "请输入序号选择 (0=自定义)" "1" "$UI_TIMEOUT_LONG"
sel="$USER_INPUT"

SNI_HOST=${SORTED_DOMAINS[0]} # 初始化默认值

if [ "$sel" == "0" ]; then
    # 用户选择自定义，需要重新读取完整字符串
    echo ""
    read -p "   请输入自定义域名 (如 www.google.com): " custom_domain
    if [ -n "$custom_domain" ]; then
        SNI_HOST="$custom_domain"
    else
        echo -e "${WARN} 输入为空，已回退到默认推荐域名。"
    fi
elif [[ "$sel" =~ ^[0-9]+$ ]] && [ "$sel" -le "${#SORTED_DOMAINS[@]}" ] && [ "$sel" -gt 0 ]; then
    # 用户选择了列表中的序号
    SNI_HOST=${SORTED_DOMAINS[$((sel-1))]}
fi

echo -e "${OK}   已选伪装域: ${GREEN}${SNI_HOST}${PLAIN}\n"

# --- 生成最终配置 ---
# 1. 强制创建配置目录 (防止目录不存在导致写入失败)
mkdir -p /usr/local/etc/xray

XRAY_BIN="/usr/local/bin/xray"

# 2. 核心文件熔断检查
if [ ! -f "$XRAY_BIN" ]; then
    echo -e "${RED}==========================================================${PLAIN}"
    echo -e "${RED} [FATAL] 严重错误：Xray 核心文件未安装成功！               ${PLAIN}"
    echo -e "${RED}==========================================================${PLAIN}"
    echo -e "原因分析："
    echo -e "1. GitHub 连接超时，导致安装脚本下载失败。"
    echo -e "2. 纯 IPv6 机器未正确通过代理连接 GitHub。"
    echo -e ""
    echo -e "${YELLOW}建议：请检查服务器网络，或重新运行脚本。${PLAIN}"
    exit 1
fi

UUID=$($XRAY_BIN uuid)
KEYS=$($XRAY_BIN x25519)
PRIVATE_KEY=$(echo "$KEYS" | grep "Private" | awk '{print $NF}')
PUBLIC_KEY=$(echo "$KEYS" | grep -E "Public|Password" | awk '{print $NF}')
SHORT_ID=$(openssl rand -hex 8)
XHTTP_PATH="/$(openssl rand -hex 4)"

# 3. 密钥生成失败检查
if [ -z "$UUID" ] || [ -z "$PRIVATE_KEY" ]; then
    echo -e "${ERR} 密钥生成失败，无法写入配置！"
    exit 1
fi

# 写入 Config
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
  "routing": { "domainStrategy": "${DOMAIN_STRATEGY}", "rules": [ { "type": "field", "ip": [ "geoip:private" ], "outboundTag": "block" }, { "type": "field", "protocol": [ "bittorrent" ], "outboundTag": "block" } ] }
}
EOF

# Systemd 覆盖
mkdir -p /etc/systemd/system/xray.service.d
echo -e "[Service]\nLimitNOFILE=infinity\nLimitNPROC=infinity\nTasksMax=infinity" > /etc/systemd/system/xray.service.d/override.conf

# ==================================================================
# 四、脚本管理区 (Script Management Area)
# ==================================================================

# --- 1. Info 脚本 ---
cat > /usr/local/bin/info << 'EOF'
#!/bin/bash
RED="\033[31m"; GREEN="\033[32m"; YELLOW="\033[33m"; BLUE="\033[36m"; PLAIN="\033[0m"

# 配置文件路径
CONFIG_FILE="/usr/local/etc/xray/config.json"
SSH_CONFIG="/etc/ssh/sshd_config"
XRAY_BIN="/usr/local/bin/xray"

# 检查依赖
if ! command -v jq &> /dev/null; then
    echo -e "${RED}Error: 缺少 jq 依赖，无法解析配置。请运行 apt install jq${PLAIN}"
    exit 1
fi

# --- 1. 基础信息提取 ---
SSH_PORT=$(grep "^Port" "$SSH_CONFIG" | head -n 1 | awk '{print $2}')
[ -z "$SSH_PORT" ] && SSH_PORT=22

HOST_NAME=$(hostname)

# 使用 jq 提取关键配置
UUID=$(jq -r '.inbounds[0].settings.clients[0].id' "$CONFIG_FILE")
PRIVATE_KEY=$(jq -r '.inbounds[0].streamSettings.realitySettings.privateKey' "$CONFIG_FILE")
SHORT_ID=$(jq -r '.inbounds[0].streamSettings.realitySettings.shortIds[0]' "$CONFIG_FILE")
SNI_HOST=$(jq -r '.inbounds[0].streamSettings.realitySettings.serverNames[0]' "$CONFIG_FILE")
PORT_VISION=$(jq -r '.inbounds[] | select(.tag=="vision_node") | .port' "$CONFIG_FILE")
PORT_XHTTP=$(jq -r '.inbounds[] | select(.tag=="xhttp_node") | .port' "$CONFIG_FILE")
XHTTP_PATH=$(jq -r '.inbounds[] | select(.tag=="xhttp_node") | .streamSettings.xhttpSettings.path' "$CONFIG_FILE")

# --- 2. 公钥反推与熔断机制 ---

PUBLIC_KEY=""
if [ -n "$PRIVATE_KEY" ] && [ "$PRIVATE_KEY" != "null" ] && [ -x "$XRAY_BIN" ]; then
    # 1. 获取完整输出
    RAW_OUTPUT=$($XRAY_BIN x25519 -i "$PRIVATE_KEY")
    
    # 2. 兼容性提取：
    #    grep -iE "Public|Password": 同时匹配 Public, public, Password
    #    head -n 1: 防止匹配多行，只取第一行
    PUBLIC_KEY=$(echo "$RAW_OUTPUT" | grep -iE "Public|Password" | head -n 1 | awk -F':' '{print $2}' | tr -d ' \r\n')
fi

# [熔断检查]：如果算不出公钥，说明配置已废，禁止生成链接
if [ -z "$PUBLIC_KEY" ] || [ "$PUBLIC_KEY" == "null" ]; then
    clear
    echo -e "${RED}=======================================================${PLAIN}"
    echo -e "${RED}   [FATAL] 严重错误：无法获取 Public Key (公钥)         ${PLAIN}"
    echo -e "${RED}=======================================================${PLAIN}"
    echo -e "原因分析："
    echo -e "1. 配置文件中的 Private Key 可能损坏或为空。"
    echo -e "2. Xray 核心未能正确执行 x25519 指令。"
    echo -e ""
    echo -e "当前提取到的私钥: ${YELLOW}${PRIVATE_KEY}${PLAIN}"
    echo -e "Xray 原始输出参考: \n${RAW_OUTPUT}"
    echo -e "${RED}脚本已终止，未生成无效链接。请检查 /usr/local/etc/xray/config.json${PLAIN}"
    exit 1
fi

# --- 3. 生成展示逻辑 ---

# 获取公网 IP
IPV4=$(curl -s4m 1 https://api.ipify.org || echo "N/A")
IPV6=$(curl -s6m 1 https://api64.ipify.org || echo "N/A")
if [[ "$IPV4" != "N/A" ]]; then SHOW_IP=$IPV4; else SHOW_IP="[$IPV6]"; fi

# 拼接链接
LINK_VISION="vless://${UUID}@${SHOW_IP}:${PORT_VISION}?security=reality&encryption=none&pbk=${PUBLIC_KEY}&headerType=none&fp=chrome&type=tcp&flow=xtls-rprx-vision&sni=${SNI_HOST}&sid=${SHORT_ID}#${HOST_NAME}_Vision"
LINK_XHTTP="vless://${UUID}@${SHOW_IP}:${PORT_XHTTP}?security=reality&encryption=none&pbk=${PUBLIC_KEY}&headerType=none&fp=chrome&type=xhttp&path=${XHTTP_PATH}&sni=${SNI_HOST}&sid=${SHORT_ID}#${HOST_NAME}_xhttp"

# 界面输出
clear
echo -e "${BLUE}===================================================================${PLAIN}"
echo -e "${BLUE}       Xray 配置详情 (Dynamic Info)     ${PLAIN}"
echo -e "${BLUE}===================================================================${PLAIN}"
echo -e "  SSH 端口    : ${RED}${SSH_PORT}${PLAIN}"
echo -e "  IPv4 地址   : ${GREEN}${IPV4}${PLAIN}"
echo -e "  IPv6 地址   : ${GREEN}${IPV6}${PLAIN}"
echo -e "  SNI 伪装域  : ${YELLOW}${SNI_HOST}${PLAIN}"
echo -e "  UUID        : ${BLUE}${UUID}${PLAIN}"
echo -e "  Short ID    : ${BLUE}${SHORT_ID}${PLAIN}"
echo -e "  Public Key  : ${YELLOW}${PUBLIC_KEY}${PLAIN} (客户端)"
echo -e "  Private Key : ${RED}${PRIVATE_KEY}${PLAIN} (服务端)"
echo -e "-------------------------------------------------------------------"
echo -e "  ${YELLOW}节点 1${PLAIN} (Vision)  端口: ${GREEN}${PORT_VISION}${PLAIN}    流控: ${GREEN}xtls-rprx-vision${PLAIN}"
echo -e "  ${YELLOW}节点 2${PLAIN}(xhttp)    端口: ${GREEN}${PORT_XHTTP}${PLAIN}   协议: ${GREEN}xhttp${PLAIN}   路径: ${GREEN}${XHTTP_PATH}${PLAIN}"
echo -e "==================================================================="
echo -e "${YELLOW}>> 节点 1 (Vision) 链接:${PLAIN}"
echo -e "${LINK_VISION}\n"
echo -e "${YELLOW}>> 节点 2 (xhttp) 链接:${PLAIN}"
echo -e "${LINK_XHTTP}\n"

read -n 1 -p "是否生成二维码? (y/n): " CHOICE
echo ""
if [[ "$CHOICE" =~ ^[yY]$ ]]; then
    echo -e "\n${BLUE}--- Vision Node ---${PLAIN}"
    qrencode -t ANSIUTF8 "${LINK_VISION}"
    echo -e "\n${BLUE}--- xhttp Node ---${PLAIN}"
    qrencode -t ANSIUTF8 "${LINK_XHTTP}"
fi

# 底部常用命令提示
echo -e "\n------------------------------------------------------------------"
echo -e " 常用工具: ${YELLOW}info${PLAIN}  (信息) | ${YELLOW}net${PLAIN} (网络)"
echo -e " 运维命令: ${YELLOW}ports${PLAIN} (端口) | ${YELLOW}f2b${PLAIN} (防火墙) | ${YELLOW}journalctl -u xray -f${PLAIN} (日志)"
echo -e "------------------------------------------------------------------"
echo ""
EOF
chmod +x /usr/local/bin/info

# --- 2. Net 脚本 ---
cat > /usr/local/bin/net << 'EOF'
#!/bin/bash
RED="\033[31m"; GREEN="\033[32m"; YELLOW="\033[33m"; BLUE="\033[36m"; PLAIN="\033[0m"

CONFIG_FILE="/usr/local/etc/xray/config.json"
GAI_CONF="/etc/gai.conf"

# 检查依赖
if ! command -v jq &> /dev/null; then
    echo -e "${RED}错误: 缺少 jq 依赖，无法解析配置。${PLAIN}"; exit 1
fi

# --- 核心逻辑 ---

# 1. 设置系统级优先级 (gai.conf)
# v4 = 添加 precedence 行; v6 = 删除该行
set_system_prio() {
    [ ! -f "$GAI_CONF" ] && touch "$GAI_CONF"
    if [ "$1" == "v4" ]; then
        if ! grep -q "^precedence ::ffff:0:0/96  100" "$GAI_CONF"; then
            echo "precedence ::ffff:0:0/96  100" >> "$GAI_CONF"
        fi
    else
        sed -i '/^precedence ::ffff:0:0\/96  100/d' "$GAI_CONF"
    fi
}

# 2. 设置 Xray 策略并应用
apply_strategy() {
    local sys_prio=$1      # v4 或 v6
    local xray_strategy=$2 # IPIfNonMatch, UseIPv4, UseIPv6
    local desc=$3
    
    echo -e "${BLUE}正在配置: ${desc}...${PLAIN}"
    
    # 修改系统
    set_system_prio "$sys_prio"
    
    # 修改 Xray 配置
    jq --arg s "$xray_strategy" '.routing.domainStrategy = $s' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    
    echo -e "${INFO} 重启 Xray 服务..."
    systemctl restart xray
    echo -e "${GREEN}设置成功！当前状态: ${desc}${PLAIN}"
    read -n 1 -s -r -p "按任意键继续..."
}

# 3. 状态检测函数
get_current_status() {
    # 读取 Xray 配置
    if [ -f "$CONFIG_FILE" ]; then
        CURRENT_STRATEGY=$(jq -r '.routing.domainStrategy // "Unknown"' "$CONFIG_FILE")
    else
        CURRENT_STRATEGY="Error"
    fi

    # 读取系统配置
    if grep -q "^precedence ::ffff:0:0/96  100" "$GAI_CONF" 2>/dev/null; then
        SYS_PRIO="IPv4 优先"
    else
        SYS_PRIO="IPv6 优先"
    fi
    
    # 综合判断
    if [ "$CURRENT_STRATEGY" == "UseIPv4" ]; then
        STATUS_TEXT="${YELLOW}仅 IPv4 (IPv4 Only)${PLAIN}"
        MARK_3="${GREEN}●${PLAIN}"; MARK_1=" "; MARK_2=" "; MARK_4=" "
    elif [ "$CURRENT_STRATEGY" == "UseIPv6" ]; then
        STATUS_TEXT="${YELLOW}仅 IPv6 (IPv6 Only)${PLAIN}"
        MARK_4="${GREEN}●${PLAIN}"; MARK_1=" "; MARK_2=" "; MARK_3=" "
    else
        # 双栈模式
        if [ "$SYS_PRIO" == "IPv4 优先" ]; then
            STATUS_TEXT="${GREEN}双栈 - IPv4 优先${PLAIN}"
            MARK_1="${GREEN}●${PLAIN}"; MARK_2=" "; MARK_3=" "; MARK_4=" "
        else
            STATUS_TEXT="${GREEN}双栈 - IPv6 优先${PLAIN}"
            MARK_2="${GREEN}●${PLAIN}"; MARK_1=" "; MARK_3=" "; MARK_4=" "
        fi
    fi
}

# --- 交互菜单 ---

while true; do
    get_current_status
    clear
    echo -e "${BLUE}===================================================${PLAIN}"
    echo -e "${BLUE}          网络优先级切换 (Network Priority)       ${PLAIN}"
    echo -e "${BLUE}===================================================${PLAIN}"
    echo -e "当前状态: ${STATUS_TEXT}"
    echo -e "---------------------------------------------------"
    echo -e "  ${MARK_1} 1. IPv4 优先 (推荐)   ${GRAY}- 双栈环境，v4 流量优先${PLAIN}"
    echo -e "  ${MARK_2} 2. IPv6 优先          ${GRAY}- 双栈环境，v6 流量优先${PLAIN}"
    echo -e "  ${MARK_3} 3. 仅 IPv4            ${GRAY}- 强制 Xray 只用 IPv4${PLAIN}"
    echo -e "  ${MARK_4} 4. 仅 IPv6            ${GRAY}- 强制 Xray 只用 IPv6${PLAIN}"
    echo -e "---------------------------------------------------"
    echo -e "  0. 退出 (Exit)"
    echo -e ""
    read -p "请输入选项 [0-4]: " choice

    case "$choice" in
        1) apply_strategy "v4" "IPIfNonMatch" "IPv4 优先 (双栈)" ;;
        2) apply_strategy "v6" "IPIfNonMatch" "IPv6 优先 (双栈)" ;;
        3) apply_strategy "v4" "UseIPv4"      "仅 IPv4 (Disable v6)" ;;
        4) apply_strategy "v6" "UseIPv6"      "仅 IPv6 (Disable v4)" ;;
        0) exit 0 ;;
        *) echo -e "${RED}输入无效${PLAIN}"; sleep 1 ;;
    esac
done
EOF
chmod +x /usr/local/bin/net

# --- 3. Ports 脚本 ---
cat > /usr/local/bin/ports << 'EOF'
#!/bin/bash
RED="\033[31m"; GREEN="\033[32m"; YELLOW="\033[33m"; BLUE="\033[36m"; GRAY="\033[90m"; PLAIN="\033[0m"

# 配置文件路径
CONFIG_FILE="/usr/local/etc/xray/config.json"
SSH_CONFIG="/etc/ssh/sshd_config"

# 检查依赖
if ! command -v jq &> /dev/null; then
    echo -e "${RED}错误: 缺少 jq 依赖，无法解析配置。${PLAIN}"; exit 1
fi

# --- 辅助函数 ---

check_status() {
    local port=$1
    if ss -tulpn | grep -q ":${port} "; then
        echo -e "${GREEN}运行中${PLAIN}"
    else
        echo -e "${RED}未运行${PLAIN}"
    fi
}

open_port() {
    local port=$1
    iptables -I INPUT -p tcp --dport $port -j ACCEPT
    iptables -I INPUT -p udp --dport $port -j ACCEPT
    if [ -f /proc/net/if_inet6 ]; then
        ip6tables -I INPUT -p tcp --dport $port -j ACCEPT 2>/dev/null
        ip6tables -I INPUT -p udp --dport $port -j ACCEPT 2>/dev/null
    fi
    netfilter-persistent save 2>/dev/null
}

get_ports() {
    CURRENT_SSH=$(grep "^Port" "$SSH_CONFIG" | head -n 1 | awk '{print $2}')
    [ -z "$CURRENT_SSH" ] && CURRENT_SSH=22
    
    if [ -f "$CONFIG_FILE" ]; then
        CURRENT_VISION=$(jq -r '.inbounds[] | select(.tag=="vision_node") | .port' "$CONFIG_FILE")
        CURRENT_XHTTP=$(jq -r '.inbounds[] | select(.tag=="xhttp_node") | .port' "$CONFIG_FILE")
    else
        CURRENT_VISION="N/A"; CURRENT_XHTTP="N/A"
    fi
}

validate_port() {
    if [[ ! "$1" =~ ^[0-9]+$ ]] || [ "$1" -lt 1 ] || [ "$1" -gt 65535 ]; then
        echo -e "${RED}错误: 端口必须是 1-65535 之间的数字！${PLAIN}"
        return 1
    fi
    return 0
}

# --- 修改逻辑 ---

change_ssh() {
    # === 红色警示框开始 ===
    clear
    echo -e "${RED}################################################################${PLAIN}"
    echo -e "${RED}#                    高风险操作警告 (WARNING)                  #${PLAIN}"
    echo -e "${RED}################################################################${PLAIN}"
    echo -e "${RED}#${PLAIN}                                                              ${RED}#${PLAIN}"
    echo -e "${RED}#${PLAIN}  1. 云服务器用户 (阿里云/腾讯云/AWS等)：                     ${RED}#${PLAIN}"
    echo -e "${RED}#${PLAIN}     必须先在网页控制台的【安全组/防火墙】放行新端口！        ${RED}#${PLAIN}"
    echo -e "${RED}#${PLAIN}     (脚本只能修改系统内部防火墙，无法修改云平台安全组)       ${RED}#${PLAIN}"
    echo -e "${RED}#${PLAIN}                                                              ${RED}#${PLAIN}"
    echo -e "${RED}#${PLAIN}  2. 修改后【绝对不要】关闭当前窗口！                         ${RED}#${PLAIN}"
    echo -e "${RED}#${PLAIN}     请新开一个 SSH 窗口测试连接。如果失败，                  ${RED}#${PLAIN}"
    echo -e "${RED}#${PLAIN}     请立即利用当前窗口改回原端口 ($CURRENT_SSH)。                    ${RED}#${PLAIN}"
    echo -e "${RED}#${PLAIN}                                                              ${RED}#${PLAIN}"
    echo -e "${RED}################################################################${PLAIN}"
    echo ""
    
    read -p "我已知晓风险，确认继续修改? (y/n): " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        echo -e "${YELLOW}>>> 操作已取消。${PLAIN}"; sleep 1; return
    fi
    # === 红色警示框结束 ===

    echo ""
    read -p "请输入新的 SSH 端口 [当前: $CURRENT_SSH]: " new_port
    validate_port "$new_port" || return
    
    echo -e "${BLUE}正在修改 SSH 端口...${PLAIN}"
    sed -i "s/^Port.*/Port $new_port/" "$SSH_CONFIG"
    if ! grep -q "^Port" "$SSH_CONFIG"; then echo "Port $new_port" >> "$SSH_CONFIG"; fi
    
    open_port "$new_port"
    
    echo -e "${INFO} 重启 SSH 服务..."
    systemctl restart ssh || systemctl restart sshd
    echo -e "${GREEN}修改成功！请务必新开窗口测试端口 $new_port 。${PLAIN}"
    read -n 1 -s -r -p "按任意键继续..."
}

change_vision() {
    read -p "请输入新的 Vision 端口 [当前: $CURRENT_VISION]: " new_port
    validate_port "$new_port" || return

    echo -e "${BLUE}正在修改 Vision 端口...${PLAIN}"
    jq --argjson port $new_port '(.inbounds[] | select(.tag=="vision_node").port) |= $port' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    
    open_port "$new_port"
    
    echo -e "${INFO} 重启 Xray 服务..."
    systemctl restart xray
    echo -e "${GREEN}修改成功！${PLAIN}"
    read -n 1 -s -r -p "按任意键继续..."
}

change_xhttp() {
    read -p "请输入新的 XHTTP 端口 [当前: $CURRENT_XHTTP]: " new_port
    validate_port "$new_port" || return

    echo -e "${BLUE}正在修改 XHTTP 端口...${PLAIN}"
    jq --argjson port $new_port '(.inbounds[] | select(.tag=="xhttp_node").port) |= $port' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    
    open_port "$new_port"
    
    echo -e "${INFO} 重启 Xray 服务..."
    systemctl restart xray
    echo -e "${GREEN}修改成功！${PLAIN}"
    read -n 1 -s -r -p "按任意键继续..."
}

# --- 主循环菜单 ---

while true; do
    get_ports
    clear
    echo -e "${BLUE}===================================================${PLAIN}"
    echo -e "${BLUE}          端口管理面板 (Port Manager)             ${PLAIN}"
    echo -e "${BLUE}===================================================${PLAIN}"
    echo -e "  服务            端口          状态"
    echo -e "---------------------------------------------------"
    printf "  1. SSH          ${YELLOW}%-12s${PLAIN}  %s\n" "$CURRENT_SSH" "$(check_status $CURRENT_SSH)"
    printf "  2. Vision       ${YELLOW}%-12s${PLAIN}  %s\n" "$CURRENT_VISION" "$(check_status $CURRENT_VISION)"
    printf "  3. XHTTP        ${YELLOW}%-12s${PLAIN}  %s\n" "$CURRENT_XHTTP" "$(check_status $CURRENT_XHTTP)"
    echo -e "---------------------------------------------------"
    echo -e "  0. 退出 (Exit)"
    echo -e ""
    read -p "请输入选项 [0-3]: " choice

    case "$choice" in
        1) change_ssh ;;
        2) change_vision ;;
        3) change_xhttp ;;
        0) exit 0 ;;
        *) echo -e "${RED}输入无效${PLAIN}"; sleep 1 ;;
    esac
done
EOF
chmod +x /usr/local/bin/ports

# --- 4. Fail2ban 管理脚本 ---
cat > /usr/local/bin/f2b << 'EOF'
#!/bin/bash
RED="\033[31m"; GREEN="\033[32m"; YELLOW="\033[33m"; BLUE="\033[36m"; GRAY="\033[90m"; PLAIN="\033[0m"

JAIL_FILE="/etc/fail2ban/jail.local"

# 0. 启动即清屏
clear

if [ "$EUID" -ne 0 ]; then echo -e "${RED}请使用 sudo 运行此脚本！${PLAIN}"; exit 1; fi

# --- 核心辅助函数 ---

get_conf() {
    local key=$1
    # 提取 value
    grep "^${key}\s*=" "$JAIL_FILE" | awk -F'=' '{print $2}' | tr -d ' '
}

set_conf() {
    local key=$1; local val=$2
    if grep -q "^${key}\s*=" "$JAIL_FILE"; then
        sed -i "s/^${key}\s*=.*/${key} = ${val}/" "$JAIL_FILE"
    else
        sed -i "2i ${key} = ${val}" "$JAIL_FILE"
    fi
}

restart_f2b() {
    echo -e "${INFO} 正在重载配置..."
    systemctl restart fail2ban
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}配置已生效！${PLAIN}"
    else
        echo -e "${RED}Fail2ban 重启失败，请检查配置！${PLAIN}"
    fi
    read -n 1 -s -r -p "按任意键继续..."
}

get_status() {
    if systemctl is-active fail2ban >/dev/null 2>&1; then
        local count=$(fail2ban-client status sshd 2>/dev/null | grep "Currently banned" | grep -o "[0-9]*")
        echo -e "${GREEN}运行中 (Active)${PLAIN} | 当前封禁: ${RED}${count:-0}${PLAIN} IP"
    else
        echo -e "${RED}已停止 (Stopped)${PLAIN}"
    fi
}

# --- 校验函数 ---

# 校验时间格式 (支持纯数字 或 10s/10m/10h/10d/1w)
validate_time() {
    local input=$1
    if [[ "$input" =~ ^[0-9]+[smhdw]?$ ]]; then return 0; else return 1; fi
}

# 校验纯数字
validate_int() {
    local input=$1
    if [[ "$input" =~ ^[0-9]+$ ]]; then return 0; else return 1; fi
}

# --- 功能模块 ---

change_param() {
    local name=$1; local key=$2; local type=$3 # time or int
    local current=$(get_conf "$key")
    
    echo -e "\n${BLUE}正在修改: ${name}${PLAIN}"
    echo -e "当前值: ${GREEN}${current}${PLAIN}"
    if [ "$type" == "time" ]; then
        echo -e "${GRAY}(格式说明: 纯数字=秒, 或加单位 s/m/h/d. 例: 30m, 1h, 7d)${PLAIN}"
    else
        echo -e "${GRAY}(格式说明: 仅允许输入纯数字)${PLAIN}"
    fi

    while true; do
        read -p "请输入新值 (留空取消): " new_val
        if [ -z "$new_val" ]; then echo "取消修改。"; read -n 1 -s -r; return; fi

        # 执行校验
        if [ "$type" == "time" ]; then
            validate_time "$new_val" && break
            echo -e "${RED}错误: 格式不正确！请使用如 600, 1h, 1d 等格式。${PLAIN}"
        elif [ "$type" == "int" ]; then
            validate_int "$new_val" && break
            echo -e "${RED}错误: 必须输入纯数字！${PLAIN}"
        fi
    done
    
    set_conf "$key" "$new_val"
    restart_f2b
}

toggle_service() {
    echo -e "\n${BLUE}--- 服务开关 ---${PLAIN}"
    if systemctl is-active fail2ban >/dev/null 2>&1; then
        echo -e "当前状态: ${GREEN}运行中${PLAIN}"
        read -p "是否停止并禁用 Fail2ban? (y/n): " confirm
        if [[ "$confirm" == "y" ]]; then
            systemctl stop fail2ban
            systemctl disable fail2ban
            echo -e "${RED}服务已停止。${PLAIN}"
        fi
    else
        echo -e "当前状态: ${RED}已停止${PLAIN}"
        read -p "是否启用并启动 Fail2ban? (y/n): " confirm
        if [[ "$confirm" == "y" ]]; then
            systemctl enable fail2ban
            systemctl start fail2ban
            echo -e "${GREEN}服务已启动。${PLAIN}"
        fi
    fi
    read -n 1 -s -r -p "按任意键继续..."
}

unban_ip() {
    echo -e "\n${BLUE}--- 手动解封 IP ---${PLAIN}"
    read -p "请输入 IP: " target_ip
    [ -z "$target_ip" ] && return
    # 简单校验 IP 格式 (包含点和数字)
    if [[ ! "$target_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo -e "${RED}IP 格式看似不正确，跳过。${PLAIN}"; sleep 1; return
    fi
    fail2ban-client set sshd unbanip "$target_ip"
    echo -e "${GREEN}指令已发送。${PLAIN}"
    read -n 1 -s -r -p "按任意键继续..."
}

add_whitelist() {
    echo -e "\n${BLUE}--- 添加白名单 ---${PLAIN}"
    read -p "输入 IP (回车自动添加当前IP): " input_ip
    if [ -z "$input_ip" ]; then
        input_ip=$(echo $SSH_CLIENT | awk '{print $1}')
    fi
    if [ -z "$input_ip" ]; then echo "无法获取 IP"; sleep 1; return; fi
    
    local old_line=$(grep "^ignoreip" "$JAIL_FILE")
    if echo "$old_line" | grep -q "$input_ip"; then
        echo -e "${YELLOW}已存在于白名单。${PLAIN}"; sleep 1; return
    fi
    
    sed -i "/^ignoreip/ s/$/ ${input_ip}/" "$JAIL_FILE"
    restart_f2b
}

view_logs() {
    clear; echo -e "${BLUE}=== 封禁日志 (最近20条) ===${PLAIN}"
    grep "Ban" /var/log/fail2ban.log 2>/dev/null | tail -n 20 || echo "暂无日志"
    read -n 1 -s -r -p "按任意键退出..."
}

menu_exponential() {
    while true; do
        clear
        local inc=$(get_conf "bantime.increment")
        local fac=$(get_conf "bantime.factor")
        local max=$(get_conf "bantime.maxtime")
        
        [ "$inc" == "true" ] && S_INC="${GREEN}ON${PLAIN}" || S_INC="${RED}OFF${PLAIN}"

        echo -e "${BLUE}=== 指数封禁设置 (Recidivism) ===${PLAIN}"
        echo -e "  1. 递增模式开关   [${S_INC}]"
        echo -e "  2. 修改增长系数   [${YELLOW}${fac}${PLAIN}] (Factor)"
        echo -e "  3. 修改封禁上限   [${YELLOW}${max}${PLAIN}] (MaxTime)"
        echo -e "---------------------------------"
        echo -e "  0. 返回"
        echo -e ""
        read -p "请选择: " sc
        case "$sc" in
            1) 
                [ "$inc" == "true" ] && ns="false" || ns="true"
                set_conf "bantime.increment" "$ns"; restart_f2b ;;
            2) change_param "增长系数" "bantime.factor" "int" ;;
            3) change_param "封禁上限" "bantime.maxtime" "time" ;;
            0) return ;;
        esac
    done
}

# --- 主循环 ---

while true; do
    clear
    VAL_MAX=$(get_conf "maxretry"); VAL_BAN=$(get_conf "bantime"); VAL_FIND=$(get_conf "findtime")
    
    echo -e "${BLUE}===================================================${PLAIN}"
    echo -e "${BLUE}         Fail2ban 防火墙管理 (F2B Panel)           ${PLAIN}"
    echo -e "${BLUE}===================================================${PLAIN}"
    echo -e "  状态: $(get_status)"
    echo -e "---------------------------------------------------"
    echo -e "  1. 修改 最大重试次数 [${YELLOW}${VAL_MAX}${PLAIN}]  (MaxRetry)"
    echo -e "  2. 修改 初始封禁时长 [${YELLOW}${VAL_BAN}${PLAIN}] (BanTime)"
    echo -e "  3. 修改 监测时间窗口 [${YELLOW}${VAL_FIND}${PLAIN}] (FindTime)"
    echo -e "---------------------------------------------------"
    echo -e "  4. ${GREEN}手动解封 IP${PLAIN}  (Unban)"
    echo -e "  5. ${GREEN}添加白名单${PLAIN}   (Whitelist)"
    echo -e "  6. 查看封禁日志 (Logs)"
    echo -e "  7. ${YELLOW}指数封禁设置${PLAIN} (Advanced) ->"
    echo -e "---------------------------------------------------"
    echo -e "  8. 开启/停止 Fail2ban 服务 (On/Off)"
    echo -e "  0. 退出"
    echo -e ""
    read -p "请输入选项 [0-8]: " choice

    case "$choice" in
        1) change_param "最大重试次数" "maxretry" "int" ;;
        2) change_param "初始封禁时长" "bantime"  "time" ;;
        3) change_param "监测时间窗口" "findtime" "time" ;;
        4) unban_ip ;;
        5) add_whitelist ;;
        6) view_logs ;;
        7) menu_exponential ;;
        8) toggle_service ;;
        0) clear; exit 0 ;;
        *) ;;
    esac
done
EOF
chmod +x /usr/local/bin/f2b

# ==================================================================
# 五、服务启动与收尾 (Service Start & Finalize)
# ==================================================================

echo -e "\n${STEP} 正在启动服务..."

# 1. 重新加载并启动
CMD_START="systemctl daemon-reload && systemctl enable xray && systemctl restart xray"

# 使用新的 execute_task (无返回值显示，靠内部[OK]显示)
if execute_task "$CMD_START" "启动 Xray 服务 (Start Service)"; then
    
    # --- 成功 ---
    echo -e "\n${OK} ${GREEN}安装全部完成 (Installation Complete)${PLAIN}"
    
    # 自动执行一次 info 显示结果
    if [ -f "/usr/local/bin/info" ]; then
        bash /usr/local/bin/info
    fi
else
    # --- 失败 ---
    echo -e "\n${ERR} ${RED}Xray 服务启动失败！${PLAIN}"
    echo -e "${YELLOW}>>> 最后 20 行日志 (Journalctl):${PLAIN}"
    journalctl -u xray --no-pager -n 20
    exit 1
fi
