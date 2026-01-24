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
read_with_timeout() {
    local prompt="$1"
    local default="$2"
    local timeout="$3"
    local input_char=""
    
    # 1. 清空之前的输入残留 (关键修复：防止幽灵回车导致秒过)
    while read -r -t 0; do read -r -n 1; done
    
    USER_INPUT=""
    
    # 2. 设定截止时间戳 (锚定未来时刻)
    local start_time=$(date +%s)
    local end_time=$((start_time + timeout))
    local current_time
    local remaining

    while true; do
        current_time=$(date +%s)
        remaining=$((end_time - current_time))
        
        # 如果时间到了，退出循环
        if [ "$remaining" -le 0 ]; then
            break
        fi
        
        # 交互 UI： 提示语 [默认: X] [ 10s ] :
        # 这里的 $remaining 是真实剩余秒数，不会忽快忽慢
        echo -ne "\r${YELLOW}${prompt} [默认: ${default}] [ ${RED}${remaining}s${YELLOW} ] : ${PLAIN}"
        
        # -t 1 等待一秒，但我们只关心是否按键
        read -t 1 -n 1 input_char
        if [ $? -eq 0 ]; then
            # 用户按下了键
            echo "" # 换行
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

# --- 核心：旋转光标监控 (Standard Spinner) ---
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

# === 3. Xray 核心安装 (支持版本锁定) ===
install_xray_robust() {
    local max_tries=3
    local count=0
    local bin_path="/usr/local/bin/xray"
    
    # [设置] 版本锁定
    # 留空 "" = 始终安装最新版 (Latest)
    # 填值 "v00.00.00" = 锁定特定版本
    # 目前 XHTTP 需要较新版本，暂时不锁
    local FIXED_VER="" 
    
    # 构造版本参数
    local VER_ARG=""
    if [ -n "$FIXED_VER" ]; then
        VER_ARG="--version $FIXED_VER"
        echo -e "${INFO} 已启用版本锁定: ${YELLOW}${FIXED_VER}${PLAIN}"
    fi
    
    mkdir -p /usr/local/share/xray/

    while [ $count -lt $max_tries ]; do
        # 注：在 install 后面加上了 $VER_ARG
        CMD_XRAY='bash -c "$(curl -L -o /dev/null -s -w %{url_effective} https://github.com/XTLS/Xray-install/raw/main/install-release.sh | xargs curl -L)" @ install --without-geodata '"$VER_ARG"
        
        if [ $count -gt 0 ]; then
            desc="安装 Xray Core (第 $((count+1)) 次尝试)"
        else
            desc="安装 Xray Core"
        fi
        
        # 执行安装
        execute_task "$CMD_XRAY" "$desc"
        
        # 验证
        if [ -f "$bin_path" ] && "$bin_path" version &>/dev/null; then
            local ver=$("$bin_path" version | head -n 1 | awk '{print $2}')
            echo -e "${OK}   Xray 核心校验通过: ${GREEN}${ver}${PLAIN}"
            return 0
        fi
        
        echo -e "${WARN} 安装校验失败，清理重试..."
        rm -rf "$bin_path" "/usr/local/share/xray/"
        ((count++))
        sleep 2
    done
    
    echo -e "${ERR} [FATAL] Xray Core 安装最终失败！"
    exit 1
}

install_xray_robust

# === 4. GeoData 核心数据库安装 (IP + 域名) ===
install_geodata_robust() {
    local share_dir="/usr/local/share/xray"
    local bin_dir="/usr/local/bin"
    mkdir -p "$share_dir"
    
    # 定义下载目标
    declare -A files
    files["geoip.dat"]="https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"
    files["geosite.dat"]="https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"

    echo -e "${INFO} 开始下载核心数据库 (GeoIP + Geosite)..."

    for name in "${!files[@]}"; do
        local url="${files[$name]}"
        local file_path="$share_dir/$name"
        local link_path="$bin_dir/$name"

        # 1. 下载
        execute_task "curl -L -o $file_path $url" "下载 $name"

        # 2. 校验 (必须存在且大于 500KB)
        local fsize=$(du -k "$file_path" 2>/dev/null | awk '{print $1}')
        if [ ! -f "$file_path" ] || [ "$fsize" -lt 500 ]; then
            echo -e "${WARN} $name 文件校验失败 (Size: ${fsize}KB)，尝试重试..."
            rm -f "$file_path"
            execute_task "curl -L -o $file_path $url" "重试下载 $name"
            
            # 二次校验
            if [ ! -f "$file_path" ]; then
                echo -e "${ERR} [FATAL] $name 下载失败，分流功能将无法使用！"
            fi
        fi

        # 3. 建立软链接 (关键修复：解决 Xray 找不到文件的问题)
        # Xray 默认会在运行目录(/usr/local/bin)查找 dat 文件
        ln -sf "$file_path" "$link_path"
        echo -e "${OK}   已建立链接: $link_path"
    done

    # --- 4. 配置双库自动更新 (Crontab) ---
    # 每周日 4:00 同时更新 geoip 和 geosite，并重启 Xray
    local update_cmd="curl -L -o $share_dir/geoip.dat ${files[geoip.dat]} && curl -L -o $share_dir/geosite.dat ${files[geosite.dat]} && systemctl restart xray"
    local cron_job="0 4 * * 0 $update_cmd >/dev/null 2>&1"

    if ! command -v crontab &>/dev/null; then apt-get install -y cron &>/dev/null; fi
    
    # 写入任务 (先清理旧的 geoip/geosite 任务，再写入新的)
    (crontab -l 2>/dev/null | grep -v 'geoip.dat' | grep -v 'geosite.dat'; echo "$cron_job") | crontab -
    
    echo -e "${OK}   已添加 GeoData 自动更新任务 (每周日 4:00)"
}

install_geodata_robust

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
findtime = 7d
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
  "dns": { "servers": [ "localhost" ] },
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

# --- 1. Info 脚本 (info) ---
cat > /usr/local/bin/info << 'EOF'
#!/bin/bash
RED="\033[31m"; GREEN="\033[32m"; YELLOW="\033[33m"; BLUE="\033[36m"; PLAIN="\033[0m"

CONFIG_FILE="/usr/local/etc/xray/config.json"
SSH_CONFIG="/etc/ssh/sshd_config"
XRAY_BIN="/usr/local/bin/xray"

if ! command -v jq &> /dev/null; then echo -e "${RED}Error: 缺少 jq 依赖。${PLAIN}"; exit 1; fi

# --- 1. 基础信息提取 ---
SSH_PORT=$(grep "^Port" "$SSH_CONFIG" | head -n 1 | awk '{print $2}')
[ -z "$SSH_PORT" ] && SSH_PORT=22
HOST_NAME=$(hostname)

# 提取 Config
UUID=$(jq -r '.inbounds[0].settings.clients[0].id' "$CONFIG_FILE")
PRIVATE_KEY=$(jq -r '.inbounds[0].streamSettings.realitySettings.privateKey' "$CONFIG_FILE")
SHORT_ID=$(jq -r '.inbounds[0].streamSettings.realitySettings.shortIds[0]' "$CONFIG_FILE")
SNI_HOST=$(jq -r '.inbounds[0].streamSettings.realitySettings.serverNames[0]' "$CONFIG_FILE")
PORT_VISION=$(jq -r '.inbounds[] | select(.tag=="vision_node") | .port' "$CONFIG_FILE")
PORT_XHTTP=$(jq -r '.inbounds[] | select(.tag=="xhttp_node") | .port' "$CONFIG_FILE")
XHTTP_PATH=$(jq -r '.inbounds[] | select(.tag=="xhttp_node") | .streamSettings.xhttpSettings.path' "$CONFIG_FILE")

# 计算公钥
if [ -n "$PRIVATE_KEY" ] && [ -x "$XRAY_BIN" ]; then
    RAW_OUTPUT=$($XRAY_BIN x25519 -i "$PRIVATE_KEY")
    PUBLIC_KEY=$(echo "$RAW_OUTPUT" | grep -iE "Public|Password" | head -n 1 | awk -F':' '{print $2}' | tr -d ' \r\n')
fi
if [ -z "$PUBLIC_KEY" ]; then echo -e "${RED}严重错误：无法计算公钥！${PLAIN}"; exit 1; fi

# --- 2. IP 检测与链接生成 ---

IPV4=$(curl -s4m 1 https://api.ipify.org || echo "N/A")
IPV6=$(curl -s6m 1 https://api64.ipify.org || echo "N/A")

# 生成 IPv4 链接
LINK_V4_VIS=""
LINK_V4_XHT=""
if [[ "$IPV4" != "N/A" ]]; then
    LINK_V4_VIS="vless://${UUID}@${IPV4}:${PORT_VISION}?security=reality&encryption=none&pbk=${PUBLIC_KEY}&headerType=none&fp=chrome&type=tcp&flow=xtls-rprx-vision&sni=${SNI_HOST}&sid=${SHORT_ID}#${HOST_NAME}_Vision_v4"
    LINK_V4_XHT="vless://${UUID}@${IPV4}:${PORT_XHTTP}?security=reality&encryption=none&pbk=${PUBLIC_KEY}&headerType=none&fp=chrome&type=xhttp&path=${XHTTP_PATH}&sni=${SNI_HOST}&sid=${SHORT_ID}#${HOST_NAME}_xhttp_v4"
fi

# 生成 IPv6 链接
LINK_V6_VIS=""
LINK_V6_XHT=""
if [[ "$IPV6" != "N/A" ]]; then
    LINK_V6_VIS="vless://${UUID}@[${IPV6}]:${PORT_VISION}?security=reality&encryption=none&pbk=${PUBLIC_KEY}&headerType=none&fp=chrome&type=tcp&flow=xtls-rprx-vision&sni=${SNI_HOST}&sid=${SHORT_ID}#${HOST_NAME}_Vision_v6"
    LINK_V6_XHT="vless://${UUID}@[${IPV6}]:${PORT_XHTTP}?security=reality&encryption=none&pbk=${PUBLIC_KEY}&headerType=none&fp=chrome&type=xhttp&path=${XHTTP_PATH}&sni=${SNI_HOST}&sid=${SHORT_ID}#${HOST_NAME}_xhttp_v6"
fi

# --- 3. 界面展示 ---
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

# 节点名称黄色高亮，视觉更清晰
if [[ -n "$LINK_V4_VIS" ]]; then
    echo -e "${GREEN}>> IPv4 节点 (通用):${PLAIN}"
    echo -e "${YELLOW}Vision${PLAIN}: ${LINK_V4_VIS}"
    echo -e "${YELLOW}XHTTP ${PLAIN}: ${LINK_V4_XHT}"
    echo ""
fi

if [[ -n "$LINK_V6_VIS" ]]; then
    echo -e "${GREEN}>> IPv6 节点 (专用):${PLAIN} ${GRAY}(需支持 v6 网络)${PLAIN}"
    echo -e "${YELLOW}Vision${PLAIN}: ${LINK_V6_VIS}"
    echo -e "${YELLOW}XHTTP ${PLAIN}: ${LINK_V6_XHT}"
    echo ""
fi

# 补全所有协议的二维码
read -n 1 -p "是否生成二维码? (y/n): " CHOICE
echo ""
if [[ "$CHOICE" =~ ^[yY]$ ]]; then
    if [[ -n "$LINK_V4_VIS" ]]; then
        echo -e "\n${BLUE}--- IPv4 Vision ---${PLAIN}"
        qrencode -t ANSIUTF8 "${LINK_V4_VIS}"
        echo -e "\n${BLUE}--- IPv4 XHTTP ---${PLAIN}"
        qrencode -t ANSIUTF8 "${LINK_V4_XHT}"
    fi
    
    # 为了防止刷屏，IPv6 二维码依然需要二次确认
    if [[ -n "$LINK_V6_VIS" ]]; then
        echo ""
        read -n 1 -p "是否继续生成 IPv6 二维码? (y/n): " CHOICE_V6
        echo ""
        if [[ "$CHOICE_V6" =~ ^[yY]$ ]]; then
            echo -e "\n${BLUE}--- IPv6 Vision ---${PLAIN}"
            qrencode -t ANSIUTF8 "${LINK_V6_VIS}"
            echo -e "\n${BLUE}--- IPv6 XHTTP ---${PLAIN}"
            qrencode -t ANSIUTF8 "${LINK_V6_XHT}"
        fi
    fi
fi

echo -e "\n------------------------------------------------------------------"
echo -e " 常用工具: ${YELLOW}info${PLAIN}  (信息) | ${YELLOW}net${PLAIN} (网络) | ${YELLOW}swap${PLAIN} (内存) | ${YELLOW}f2b${PLAIN} (防火墙)"
echo -e " 运维命令: ${YELLOW}ports${PLAIN} (端口) | ${YELLOW}bbr${PLAIN} (内核) | ${YELLOW}bt${PLAIN}   (封禁) | ${YELLOW}xw${PLAIN}  (WARP分流) | ${YELLOW}journalctl -u xray -f${PLAIN} (日志)"
echo -e "------------------------------------------------------------------"
echo ""
EOF
chmod +x /usr/local/bin/info

# --- 2. Net 脚本 (net) ---
cat > /usr/local/bin/net << 'EOF'
#!/bin/bash
RED="\033[31m"; GREEN="\033[32m"; YELLOW="\033[33m"; BLUE="\033[36m"; PLAIN="\033[0m"

CONFIG_FILE="/usr/local/etc/xray/config.json"
GAI_CONF="/etc/gai.conf"
SYSCTL_CONF="/etc/sysctl.conf"

if ! command -v jq &> /dev/null; then echo -e "${RED}错误: 缺少 jq。${PLAIN}"; exit 1; fi

# --- 核心辅助函数 ---

# 1. 连通性自检 (防止配置错误导致失联)
check_connectivity() {
    local target_ver=$1
    echo -e "${BLUE}正在检测 ${target_ver} 连通性...${PLAIN}"
    if [ "$target_ver" == "v4" ]; then
        if curl -s4m 2 https://1.1.1.1 >/dev/null 2>&1; then return 0; fi
    elif [ "$target_ver" == "v6" ]; then
        if curl -s6m 2 https://2606:4700:4700::1111 >/dev/null 2>&1; then return 0; fi
    fi
    return 1
}

# 2. 检查当前 SSH 连接方式 (防自杀核心)
check_ssh_connection() {
    # 获取当前 SSH 连接的客户端 IP
    local client_ip=$(echo $SSH_CLIENT | awk '{print $1}')
    if [[ "$client_ip" =~ : ]]; then
        echo "v6" # 当前是 IPv6 连接
    else
        echo "v4" # 当前是 IPv4 连接
    fi
}

# 3. 内核级 IPv6 开关
toggle_system_ipv6() {
    local state=$1 # on 或 off
    
    if [ "$state" == "off" ]; then
        # [安全检查] 如果当前 SSH 是 v6 连进来的，禁止关闭 v6！
        if [ "$(check_ssh_connection)" == "v6" ]; then
            echo -e "${RED}[危险操作拦截]${PLAIN}"
            echo -e "${YELLOW}检测到您当前正在通过 IPv6 连接 SSH！${PLAIN}"
            echo -e "${YELLOW}若此时系统级禁用 IPv6，您将立即断开连接且无法重连！${PLAIN}"
            echo -e "${RED}操作已取消。请切换到 IPv4 网络连接 SSH 后再试。${PLAIN}"
            read -n 1 -s -r -p "按任意键返回..."
            return 1
        fi

        echo -e "${YELLOW}正在系统级禁用 IPv6 (sysctl)...${PLAIN}"
        sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null
        sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null
        # 持久化
        sed -i '/net.ipv6.conf.all.disable_ipv6/d' "$SYSCTL_CONF"
        echo "net.ipv6.conf.all.disable_ipv6 = 1" >> "$SYSCTL_CONF"
    else
        echo -e "${GREEN}正在恢复系统级 IPv6...${PLAIN}"
        sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null
        sysctl -w net.ipv6.conf.default.disable_ipv6=0 >/dev/null
        # 移除持久化屏蔽
        sed -i '/net.ipv6.conf.all.disable_ipv6/d' "$SYSCTL_CONF"
    fi
    return 0
}

# 4. 设置系统优先级 (gai.conf)
set_system_prio() {
    [ ! -f "$GAI_CONF" ] && touch "$GAI_CONF"
    sed -i '/^precedence ::ffff:0:0\/96  100/d' "$GAI_CONF"
    if [ "$1" == "v4" ]; then echo "precedence ::ffff:0:0/96  100" >> "$GAI_CONF"; fi
}

# 5. 应用策略总控
apply_strategy() {
    local sys_action=$1    # v4_only, v6_only, v4_prio, v6_prio
    local xray_strategy=$2 # IPIfNonMatch, UseIPv4, UseIPv6
    local desc=$3

    # --- 1. 执行系统级变更 ---
    if [ "$sys_action" == "v4_only" ]; then
        # 尝试关闭系统 IPv6，如果被安全拦截则停止
        if ! toggle_system_ipv6 "off"; then return; fi
        set_system_prio "v4"
        
    elif [ "$sys_action" == "v6_only" ]; then
        # 警告：不能关闭系统 v4
        echo -e "${WARN} 提示：为防止 SSH 失联，系统级 IPv4 将保持开启，仅在 Xray 层强制 IPv6。${PLAIN}"
        toggle_system_ipv6 "on" # 确保 v6 是开的
        set_system_prio "v6"    # 让系统偏好 v6
        
    else
        # 双栈模式：确保 v6 是开的
        toggle_system_ipv6 "on"
        if [ "$sys_action" == "v4_prio" ]; then set_system_prio "v4"; else set_system_prio "v6"; fi
    fi

    # --- 2. 连通性复查 ---
    # 如果强制 v4，但机器根本没有 v4 (ping不通)，则回滚
    if [ "$xray_strategy" == "UseIPv4" ] && ! check_connectivity "v4"; then
        echo -e "${RED}错误：本机无法连接 IPv4 网络，无法执行纯 IPv4 策略！${PLAIN}"
        toggle_system_ipv6 "on" # 回滚
        read -n 1 -s -r; return
    fi

    # --- 3. 修改 Xray 配置 ---
    echo -e "${BLUE}正在配置 Xray 策略...${PLAIN}"
    jq --arg s "$xray_strategy" '.routing.domainStrategy = $s' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    
    echo -e "${INFO} 重启 Xray 服务..."
    systemctl restart xray
    
    if systemctl is-active --quiet xray; then
        echo -e "${GREEN}设置成功！当前运行模式: ${YELLOW}${desc}${PLAIN}"
    else
        echo -e "${RED}Xray 重启失败！正在自动回滚到默认模式...${PLAIN}"
        toggle_system_ipv6 "on"
        jq '.routing.domainStrategy = "IPIfNonMatch"' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
        systemctl restart xray
    fi
    read -n 1 -s -r -p "按任意键继续..."
}

# 4. 状态显示
get_current_status() {
    # 1. 获取 Xray 策略
    if [ -f "$CONFIG_FILE" ]; then CURRENT_STRATEGY=$(jq -r '.routing.domainStrategy // "Unknown"' "$CONFIG_FILE"); else CURRENT_STRATEGY="Error"; fi
    
    # 2. 获取内核 IPv6 状态 (0=开启, 1=禁用)
    local sys_v6_val=$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null)
    # 容错处理：如果获取不到，默认为 0 (开启)
    [ -z "$sys_v6_val" ] && sys_v6_val=0

    if [ "$sys_v6_val" -eq 1 ]; then
        SYS_V6_STATUS="${RED}已禁用${PLAIN}"
        IS_V6_DISABLED=true
    else
        SYS_V6_STATUS="${GREEN}启用${PLAIN}"
        IS_V6_DISABLED=false
    fi

    # 3. 状态映射逻辑 (引入“半生效”状态检测)
    MARK_1=" "; MARK_2=" "; MARK_3=" "; MARK_4=" "
    
    case "$CURRENT_STRATEGY" in
        "UseIPv4")
            # [逻辑修复] 只有当 Xray=UseIPv4 且 系统v6=禁用 时，才算完美的选项 3
            if [ "$IS_V6_DISABLED" = true ]; then
                STATUS_TEXT="${YELLOW}仅 IPv4 (纯净模式)${PLAIN}"
                MARK_3="${GREEN}●${PLAIN}" 
            else
                # 否则说明是“安装后的初始混合态”
                STATUS_TEXT="${YELLOW}仅 IPv4${PLAIN} (系统 IPv6: ${SYS_V6_STATUS} - ${RED}未生效${PLAIN})"
                MARK_3="${YELLOW}●${PLAIN}" # 使用黄色圆点提示差异
            fi
            ;;
        "UseIPv6")
            STATUS_TEXT="${YELLOW}仅 IPv6${PLAIN} (系统 IPv4: 保持启用)"
            MARK_4="${GREEN}●${PLAIN}" 
            ;;
        *)
            if grep -q "^precedence ::ffff:0:0/96  100" "$GAI_CONF" 2>/dev/null; then
                STATUS_TEXT="${GREEN}双栈 - v4 优先${PLAIN}"
                MARK_1="${GREEN}●${PLAIN}"
            else
                STATUS_TEXT="${GREEN}双栈 - v6 优先${PLAIN}"
                MARK_2="${GREEN}●${PLAIN}"
            fi 
            ;;
    esac
}

# --- 交互菜单 ---
while true; do
    get_current_status
    clear
    echo -e "${BLUE}===================================================${PLAIN}"
    echo -e "${BLUE}          网络优先级切换 (Network Priority)       ${PLAIN}"
    echo -e "${BLUE}===================================================${PLAIN}"
    echo -e "  当前状态: ${STATUS_TEXT}"
    echo -e "---------------------------------------------------"
    echo -e "  [双栈模式 - 系统级排序]"
    echo -e "  ${MARK_1} 1. IPv4 优先   ${GRAY}- 推荐，系统 IPv6 保持开启${PLAIN}"
    echo -e "  ${MARK_2} 2. IPv6 优先   ${GRAY}- 系统 IPv4 保持开启${PLAIN}"
    echo -e "---------------------------------------------------"
    echo -e "  [强制模式 - 系统级开关]"
    echo -e "  ${MARK_3} 3. 仅 IPv4     ${GRAY}- ${RED}彻底禁用系统 IPv6${GRAY} + Xray 仅 v4${PLAIN}"
    echo -e "  ${MARK_4} 4. 仅 IPv6     ${GRAY}- 系统 v4 保持开启 + Xray 仅 v6${PLAIN}"
    echo -e "---------------------------------------------------"
    echo -e "  0. 退出"
    echo -e ""
    read -p "请输入选项 [0-4]: " choice

    case "$choice" in
        1) apply_strategy "v4_prio" "IPIfNonMatch" "IPv4 优先 (双栈)" ;;
        2) apply_strategy "v6_prio" "IPIfNonMatch" "IPv6 优先 (双栈)" ;;
        3) apply_strategy "v4_only" "UseIPv4"      "纯 IPv4 模式 (系统级禁用 v6)" ;;
        4) apply_strategy "v6_only" "UseIPv6"      "纯 IPv6 模式 (Xray 强制)" ;;
        0) exit 0 ;;
        *) echo -e "${RED}输入无效${PLAIN}"; sleep 1 ;;
    esac
done
EOF
chmod +x /usr/local/bin/net

# --- 3. Ports 脚本 (ports) ---
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
    printf "  1. 修改 SSH          ${YELLOW}%-12s${PLAIN}  %s\n" "$CURRENT_SSH" "$(check_status $CURRENT_SSH)"
    printf "  2. 修改 Vision       ${YELLOW}%-12s${PLAIN}  %s\n" "$CURRENT_VISION" "$(check_status $CURRENT_VISION)"
    printf "  3. 修改 XHTTP        ${YELLOW}%-12s${PLAIN}  %s\n" "$CURRENT_XHTTP" "$(check_status $CURRENT_XHTTP)"
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

# --- 4. Fail2ban 管理脚本 (f2b) ---
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
validate_time() {
    if [[ "$1" =~ ^[0-9]+[smhdw]?$ ]]; then return 0; else return 1; fi
}
validate_int() {
    if [[ "$1" =~ ^[0-9]+$ ]]; then return 0; else return 1; fi
}

# --- 功能模块 ---

change_param() {
    local name=$1; local key=$2; local type=$3
    local current=$(get_conf "$key")
    echo -e "\n${BLUE}正在修改: ${name}${PLAIN}"
    echo -e "当前值: ${GREEN}${current}${PLAIN}"
    
    while true; do
        read -p "请输入新值 (留空取消): " new_val
        if [ -z "$new_val" ]; then echo "取消修改。"; read -n 1 -s -r; return; fi
        if [ "$type" == "time" ]; then validate_time "$new_val" && break; fi
        if [ "$type" == "int" ]; then validate_int "$new_val" && break; fi
        echo -e "${RED}格式错误，请重试。${PLAIN}"
    done
    
    set_conf "$key" "$new_val"
    restart_f2b
}

toggle_service() {
    echo -e "\n${BLUE}--- 服务开关 ---${PLAIN}"
    if systemctl is-active fail2ban >/dev/null 2>&1; then
        read -p "是否停止并禁用 Fail2ban? (y/n): " confirm
        if [[ "$confirm" == "y" ]]; then systemctl stop fail2ban; systemctl disable fail2ban; echo -e "${RED}服务已停止。${PLAIN}"; fi
    else
        read -p "是否启用并启动 Fail2ban? (y/n): " confirm
        if [[ "$confirm" == "y" ]]; then systemctl enable fail2ban; systemctl start fail2ban; echo -e "${GREEN}服务已启动。${PLAIN}"; fi
    fi
    read -n 1 -s -r -p "按任意键继续..."
}

unban_ip() {
    echo -e "\n${BLUE}--- 手动解封 IP (Unban Manager) ---${PLAIN}"
    
    # 获取被封禁列表
    # 原始输出包含 "Banned IP list: IP1 IP2 ...", 我们提取冒号后面的部分
    local banned_list=$(fail2ban-client status sshd 2>/dev/null | grep "Banned IP list" | awk -F':' '{print $2}' | sed 's/^[ \t]*//')
    
    # 如果列表为空或全是空格
    if [ -z "$banned_list" ] || [ "$banned_list" == " " ]; then
        banned_list="无 (None)"
    fi

    echo -e "当前被封禁 IP (Banned List):"
    echo -e "${RED}${banned_list}${PLAIN}"
    echo -e "---------------------------------------------------"
    
    read -p "请输入要解封的 IP (留空取消): " target_ip
    [ -z "$target_ip" ] && return
    
    fail2ban-client set sshd unbanip "$target_ip"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}指令已发送。${PLAIN}"
    else
        echo -e "${RED}操作失败 (可能是服务未运行或 IP 未被封禁)。${PLAIN}"
    fi
    read -n 1 -s -r -p "按任意键继续..."
}

add_whitelist() {
    echo -e "\n${BLUE}--- 添加白名单 (Whitelist Manager) ---${PLAIN}"
    
    # 获取白名单列表
    local current_list=$(grep "^ignoreip" "$JAIL_FILE" | awk -F'=' '{print $2}' | sed 's/^[ \t]*//;s/[ \t]*$//')
    
    echo -e "当前已放行 IP (Current List):"
    echo -e "${YELLOW}${current_list:-无}${PLAIN}"
    echo -e "---------------------------------------------------"
    
    local current_ip=$(echo $SSH_CLIENT | awk '{print $1}')
    read -p "输入 IP (回车自动添加本机 ${current_ip}): " input_ip
    
    if [ -z "$input_ip" ]; then input_ip="$current_ip"; fi
    if [ -z "$input_ip" ]; then echo -e "${RED}无法获取 IP。${PLAIN}"; sleep 1; return; fi
    
    if echo "$current_list" | grep -Fq "$input_ip"; then
        echo -e "${YELLOW}该 IP 已存在。${PLAIN}"; sleep 1; return
    fi
    
    sed -i "/^ignoreip/ s/$/ ${input_ip}/" "$JAIL_FILE"
    restart_f2b
}

view_logs() {
    clear
    echo -e "${BLUE}=== 系统封禁/解封历史 (Audit Log) ===${PLAIN}"
    echo -e "日志来源: ${GRAY}/var/log/fail2ban.log${PLAIN}"
    echo -e "---------------------------------------------------"

    if [ ! -f /var/log/fail2ban.log ]; then
        echo -e "${YELLOW}暂无日志文件 (服务可能刚安装)。${PLAIN}"
    else
        # [核心优化] 使用 awk 进行格式化对齐
        # 1. sprintf("%9s", $4): 将第4列(PID)强制设为9个字符宽，并右对齐。
        #    这样 [123]: 和 [12345]: 中的冒号就会上下垂直对齐。
        # 2. gsub: 给关键词上色。
        
        grep -E "(Ban|Unban)" /var/log/fail2ban.log 2>/dev/null | tail -n 20 | \
        awk '{
            # 1. 颜色高亮 (先上色，避免影响对齐逻辑)
            gsub(/Unban/, "\033[32m&\033[0m");
            gsub(/Ban/, "\033[31m&\033[0m");
            
            # 2. 对齐 PID 字段 (识别类似 [12345]: 的列)
            if ($4 ~ /^\[.*\]:$/) {
                # 右对齐，宽度设为 9 (PID通常5-6位，9足够容纳)
                $4 = sprintf("%9s", $4)
            }
            
            # 3. 打印重组后的行 (awk 会自动用整齐的空格连接各列)
            print
        }'
    fi
    
    echo -e "---------------------------------------------------"
    read -n 1 -s -r -p "按任意键退出..."
}

menu_exponential() {
    while true; do
        clear
        local inc=$(get_conf "bantime.increment")
        local fac=$(get_conf "bantime.factor")
        local max=$(get_conf "bantime.maxtime")
        [ "$inc" == "true" ] && S_INC="${GREEN}ON${PLAIN}" || S_INC="${RED}OFF${PLAIN}"

        echo -e "${BLUE}=== 指数封禁设置 ===${PLAIN}"
        echo -e "  1. 递增模式开关   [${S_INC}]"
        echo -e "  2. 修改增长系数   [${YELLOW}${fac}${PLAIN}]"
        echo -e "  3. 修改封禁上限   [${YELLOW}${max}${PLAIN}]"
        echo -e "---------------------------------"
        echo -e "  0. 返回"
        echo -e ""
        read -p "请选择: " sc
        case "$sc" in
            1) [ "$inc" == "true" ] && ns="false" || ns="true"; set_conf "bantime.increment" "$ns"; restart_f2b ;;
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
    echo -e "${BLUE}         Fail2ban 防火墙管理 (F2B Panel)          ${PLAIN}"
    echo -e "${BLUE}===================================================${PLAIN}"
    echo -e "  状态: $(get_status)"
    echo -e "---------------------------------------------------"
    echo -e "  1. 修改 最大重试次数 [${YELLOW}${VAL_MAX}${PLAIN}]"
    echo -e "  2. 修改 初始封禁时长 [${YELLOW}${VAL_BAN}${PLAIN}]"
    echo -e "  3. 修改 监测时间窗口 [${YELLOW}${VAL_FIND}${PLAIN}]"
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

# --- 5. BBR 管理脚本 (bbr) ---
cat > /usr/local/bin/bbr << 'EOF'
#!/bin/bash
RED="\033[31m"; GREEN="\033[32m"; YELLOW="\033[33m"; BLUE="\033[36m"; GRAY="\033[90m"; PLAIN="\033[0m"

SYSCTL_CONF="/etc/sysctl.d/99-xray-bbr.conf"

# 0. 启动即清屏
clear
if [ "$EUID" -ne 0 ]; then echo -e "${RED}请使用 sudo 运行此脚本！${PLAIN}"; exit 1; fi

# --- 核心函数 ---

get_status() {
    # 读取内核当前生效的配置
    local cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    local qd=$(sysctl -n net.core.default_qdisc 2>/dev/null)
    
    # 判断 BBR 状态
    if [[ "$cc" == "bbr" ]]; then
        STATUS_BBR="${GREEN}已开启 (BBR)${PLAIN}"
    else
        STATUS_BBR="${YELLOW}未开启 ($cc)${PLAIN}"
    fi

    # 判断队列状态
    if [[ "$qd" == "fq" ]]; then
        STATUS_QDISC="${GREEN}FQ${PLAIN}"
    else
        STATUS_QDISC="${YELLOW}$qd${PLAIN}"
    fi
    
    # 判断是否应用了额外优化 (检查配置文件是否存在且行数够多)
    if [ -f "$SYSCTL_CONF" ] && [ $(wc -l < "$SYSCTL_CONF") -gt 5 ]; then
        STATUS_OPT="${GREEN}已应用高性能参数${PLAIN}"
    else
        STATUS_OPT="${GRAY}默认参数${PLAIN}"
    fi
}

apply_sysctl() {
    echo -e "${INFO} 正在刷新内核参数..."
    sysctl --system >/dev/null 2>&1
    echo -e "${GREEN}设置已生效！${PLAIN}"
    read -n 1 -s -r -p "按任意键继续..."
}

# --- 功能模块 ---

enable_bbr() {
    echo -e "\n${BLUE}正在开启 BBR 加速...${PLAIN}"
    # 写入基础 BBR 配置
    cat > "$SYSCTL_CONF" <<CONF
# Xray Auto - BBR Base
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
CONF
    apply_sysctl
}

disable_bbr() {
    echo -e "\n${BLUE}正在关闭 BBR (恢复 CUBIC)...${PLAIN}"
    # 恢复系统默认 (通常是 fq_codel + cubic)
    cat > "$SYSCTL_CONF" <<CONF
# Xray Auto - BBR Disabled
net.core.default_qdisc = fq_codel
net.ipv4.tcp_congestion_control = cubic
CONF
    apply_sysctl
}

# 高级优化：调整 TCP 窗口和缓冲区，适合大流量 VPS
optimize_tcp() {
    echo -e "\n${BLUE}正在应用 TCP 高性能参数 (Buffer Optimization)...${PLAIN}"
    # 先保留当前的 CC 算法
    local current_cc=$(sysctl -n net.ipv4.tcp_congestion_control)
    local current_qd=$(sysctl -n net.core.default_qdisc)
    
    cat > "$SYSCTL_CONF" <<CONF
# Xray Auto - Advanced TCP Optimization
net.core.default_qdisc = $current_qd
net.ipv4.tcp_congestion_control = $current_cc

# TCP 缓冲区优化 (针对大带宽)
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

# 低延迟与并发优化
net.ipv4.tcp_low_latency = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_notsent_lowat = 16384
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_syncookies = 1
CONF
    apply_sysctl
}

reset_tcp() {
    echo -e "\n${BLUE}正在重置为保守参数...${PLAIN}"
    # 只保留最基础的 BBR/Cubic 设置，清除缓冲区优化
    local current_cc=$(sysctl -n net.ipv4.tcp_congestion_control)
    local current_qd=$(sysctl -n net.core.default_qdisc)
    
    cat > "$SYSCTL_CONF" <<CONF
# Xray Auto - Base Config
net.core.default_qdisc = $current_qd
net.ipv4.tcp_congestion_control = $current_cc
CONF
    apply_sysctl
}

switch_qdisc() {
    echo -e "\n${BLUE}切换队列调度算法 (Queue Discipline)${PLAIN}"
    echo "1. FQ (Fair Queue) - BBR 的最佳拍档"
    echo "2. FQ_CODEL - 通用性更好，适合 CUBIC"
    read -p "请选择 [1-2]: " q_choice
    
    local target_q=""
    case "$q_choice" in
        1) target_q="fq" ;;
        2) target_q="fq_codel" ;;
        *) return ;;
    esac
    
    # 替换配置文件中的 qdisc 设置
    if grep -q "net.core.default_qdisc" "$SYSCTL_CONF"; then
        sed -i "s/^net.core.default_qdisc.*/net.core.default_qdisc = $target_q/" "$SYSCTL_CONF"
    else
        echo "net.core.default_qdisc = $target_q" >> "$SYSCTL_CONF"
    fi
    apply_sysctl
}

# --- 主循环 ---

while true; do
    get_status
    clear
    echo -e "${BLUE}===================================================${PLAIN}"
    echo -e "${BLUE}          内核与网络优化 (BBR Manager)            ${PLAIN}"
    echo -e "${BLUE}===================================================${PLAIN}"
    echo -e "  拥塞算法 : ${STATUS_BBR}"
    echo -e "  队列调度 : ${STATUS_QDISC}"
    echo -e "  高级优化 : ${STATUS_OPT}"
    echo -e "---------------------------------------------------"
    echo -e "  1. ${GREEN}开启 BBR${PLAIN} (Enable BBR + FQ)"
    echo -e "  2. ${YELLOW}关闭 BBR${PLAIN} (Disable -> Cubic)"
    echo -e "---------------------------------------------------"
    echo -e "  3. 应用 TCP 大窗口优化 (Boost Throughput)"
    echo -e "  4. 重置 TCP 缓冲区参数 (Reset to Default)"
    echo -e "  5. 切换队列算法 (FQ / FQ_CODEL)"
    echo -e "---------------------------------------------------"
    echo -e "  0. 退出 (Exit)"
    echo -e ""
    read -p "请输入选项 [0-5]: " choice

    case "$choice" in
        1) enable_bbr ;;
        2) disable_bbr ;;
        3) optimize_tcp ;;
        4) reset_tcp ;;
        5) switch_qdisc ;;
        0) clear; exit 0 ;;
        *) ;;
    esac
done
EOF
chmod +x /usr/local/bin/bbr

# --- 6. Swap 管理脚本 (swap) ---
cat > /usr/local/bin/swap << 'EOF'
#!/bin/bash
RED="\033[31m"; GREEN="\033[32m"; YELLOW="\033[33m"; BLUE="\033[36m"; PLAIN="\033[0m"

# 0. 权限检测
if [ "$EUID" -ne 0 ]; then echo -e "${RED}请使用 sudo 运行此脚本！${PLAIN}"; exit 1; fi

# --- 核心功能 ---

# 获取当前状态
get_status() {
    # Swap 大小
    SWAP_TOTAL=$(free -m | grep Swap | awk '{print $2}')
    if [ "$SWAP_TOTAL" -eq 0 ]; then
        STATUS_SWAP="${RED}未启用${PLAIN}"
    else
        STATUS_SWAP="${GREEN}已启用 (${SWAP_TOTAL}MB)${PLAIN}"
    fi

    # Swappiness 值
    SWAPPINESS=$(cat /proc/sys/vm/swappiness)
}

# 添加 Swap
add_swap() {
    echo -e "\n${BLUE}正在创建 Swap 分区...${PLAIN}"
    read -p "请输入 Swap 大小 (单位 MB，推荐 1024 或 2048): " swap_size
    [ -z "$swap_size" ] && swap_size=1024

    # 清理旧的
    if [ -f /swapfile ]; then swapoff /swapfile 2>/dev/null; rm -f /swapfile; fi

    # 创建新的
    fallocate -l ${swap_size}M /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile

    # 写入 fstab (持久化)
    if ! grep -q "/swapfile" /etc/fstab; then
        echo '/swapfile none swap sw 0 0' >> /etc/fstab
    fi

    echo -e "${GREEN}成功创建 ${swap_size}MB Swap！${PLAIN}"
    read -n 1 -s -r -p "按任意键继续..."
}

# 删除 Swap
del_swap() {
    echo -e "\n${YELLOW}正在删除 Swap...${PLAIN}"
    swapoff /swapfile 2>/dev/null
    rm -f /swapfile
    # 从 fstab 移除
    sed -i '/\/swapfile/d' /etc/fstab
    echo -e "${GREEN}Swap 已删除。${PLAIN}"
    read -n 1 -s -r -p "按任意键继续..."
}

# [新功能] 调整 Swappiness
set_swappiness() {
    echo -e "\n${BLUE}当前亲和度 (Swappiness): ${YELLOW}${SWAPPINESS}${PLAIN}"
    echo -e "说明: 值越小(0-10)，越倾向于使用物理内存(速度快)。"
    echo -e "      值越大(60-100)，越倾向于使用硬盘交换(适合内存极小的情况)。"
    echo -e "------------------------------------------------"
    
    # 默认值是 60
    read -p "请输入新的值 [0-100] (默认: 60): " new_val

    # 核心逻辑：若直接回车(变量为空)，则赋值为 60
    [ -z "$new_val" ] && new_val=60

    if [[ ! "$new_val" =~ ^[0-9]+$ ]] || [ "$new_val" -lt 0 ] || [ "$new_val" -gt 100 ]; then
        echo -e "${RED}输入错误，请输入 0-100 之间的数字。${PLAIN}"
    else
        # 临时生效
        sysctl -w vm.swappiness=$new_val >/dev/null
        
        # 永久生效 (修改 /etc/sysctl.conf)
        if grep -q "vm.swappiness" /etc/sysctl.conf; then
            sed -i "s/^vm.swappiness.*/vm.swappiness = $new_val/" /etc/sysctl.conf
        else
            echo "vm.swappiness = $new_val" >> /etc/sysctl.conf
        fi
        echo -e "${GREEN}设置成功！当前亲和度已改为: ${new_val}${PLAIN}"
    fi
    read -n 1 -s -r -p "按任意键继续..."
}

# --- 主菜单 ---
while true; do
    clear
    get_status
    echo -e "${BLUE}===================================================${PLAIN}"
    echo -e "${BLUE}           虚拟内存管理 (Swap Manager)            ${PLAIN}"
    echo -e "${BLUE}===================================================${PLAIN}"
    echo -e "  Swap 状态   : ${STATUS_SWAP}"
    echo -e "  Swappiness  : ${YELLOW}${SWAPPINESS}${PLAIN} (亲和度)"
    echo -e "---------------------------------------------------"
    echo -e "  1. 添加 / 修改 Swap 容量"
    echo -e "  2. 关闭 / 删除 Swap"
    echo -e "---------------------------------------------------"
    echo -e "  3. 调整 Swappiness 亲和度 ${GRAY}(性能优化)${PLAIN}"
    echo -e "---------------------------------------------------"
    echo -e "  0. 退出"
    echo -e ""
    read -p "请输入选项 [0-3]: " choice

    case "$choice" in
        1) add_swap ;;
        2) del_swap ;;
        3) set_swappiness ;;
        0) clear; exit 0 ;;
        *) ;;
    esac
done
EOF
chmod +x /usr/local/bin/swap

# --- 7. BT 管理脚本 (bt) ---
cat > /usr/local/bin/bt << 'EOF'
#!/bin/bash
RED="\033[31m"; GREEN="\033[32m"; YELLOW="\033[33m"; BLUE="\033[36m"; GRAY="\033[90m"; PLAIN="\033[0m"

CONFIG_FILE="/usr/local/etc/xray/config.json"

# 0. 启动即清屏
clear
if [ "$EUID" -ne 0 ]; then echo -e "${RED}请使用 sudo 运行此脚本！${PLAIN}"; exit 1; fi
if ! command -v jq &> /dev/null; then echo -e "${RED}错误: 缺少 jq 依赖。${PLAIN}"; exit 1; fi

# --- 核心函数 ---

get_status() {
    # 1. 检测 BT 封禁
    if jq -e '.routing.rules[] | select(.outboundTag=="block" and (.protocol | index("bittorrent")))' "$CONFIG_FILE" >/dev/null; then
        STATUS_BT="${GREEN}已封禁 (Blocked)${PLAIN}"
        IS_BT_BLOCKED=true
    else
        STATUS_BT="${RED}已允许 (Allowed)${PLAIN}"
        IS_BT_BLOCKED=false
    fi

    # 2. 检测私有 IP 封禁
    if jq -e '.routing.rules[] | select(.outboundTag=="block" and (.ip | index("geoip:private")))' "$CONFIG_FILE" >/dev/null; then
        STATUS_PRIVATE="${GREEN}已封禁 (Blocked)${PLAIN}"
        IS_PRIVATE_BLOCKED=true
    else
        STATUS_PRIVATE="${RED}已允许 (Allowed)${PLAIN}"
        IS_PRIVATE_BLOCKED=false
    fi
}

apply_changes() {
    echo -e "${INFO} 正在重启 Xray 服务以应用规则..."
    systemctl restart xray
    echo -e "${GREEN}规则已生效！${PLAIN}"
    read -n 1 -s -r -p "按任意键继续..."
}

# --- 功能模块 ---

toggle_bt() {
    echo -e "\n${BLUE}切换 BT/P2P 下载拦截状态${PLAIN}"
    if [ "$IS_BT_BLOCKED" = true ]; then
        echo -e "操作: ${RED}解除封禁${PLAIN} (允许 BT 下载)"
        jq 'del(.routing.rules[] | select(.outboundTag=="block" and (.protocol | index("bittorrent"))))' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    else
        echo -e "操作: ${GREEN}开启封禁${PLAIN} (禁止 BT 下载)"
        local new_rule='{"type": "field", "protocol": ["bittorrent"], "outboundTag": "block"}'
        jq --argjson rule "$new_rule" '.routing.rules = [$rule] + .routing.rules' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    fi
    apply_changes
}

toggle_private() {
    echo -e "\n${BLUE}切换私有 IP (局域网) 拦截状态${PLAIN}"
    if [ "$IS_PRIVATE_BLOCKED" = true ]; then
        echo -e "操作: ${RED}解除封禁${PLAIN} (允许访问内网 IP)"
        jq 'del(.routing.rules[] | select(.outboundTag=="block" and (.ip | index("geoip:private"))))' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    else
        echo -e "操作: ${GREEN}开启封禁${PLAIN} (禁止访问内网 IP)"
        local new_rule='{"type": "field", "ip": ["geoip:private"], "outboundTag": "block"}'
        jq --argjson rule "$new_rule" '.routing.rules = [$rule] + .routing.rules' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    fi
    apply_changes
}

# --- 主菜单 ---

while true; do
    get_status
    clear
    echo -e "${BLUE}===================================================${PLAIN}"
    echo -e "${BLUE}          流量拦截管理 (Traffic Blocker)          ${PLAIN}"
    echo -e "${BLUE}===================================================${PLAIN}"
    echo -e "  BT / P2P 下载   : ${STATUS_BT}"
    echo -e "  私有 IP (局域网): ${STATUS_PRIVATE}"
    echo -e "---------------------------------------------------"
    echo -e "  1. 开启/关闭 ${YELLOW}BT 下载封禁${PLAIN}"
    echo -e "  2. 开启/关闭 ${YELLOW}私有 IP 封禁${PLAIN}"
    echo -e "---------------------------------------------------"
    echo -e "  0. 退出 (Exit)"
    echo -e ""
    read -p "请输入选项 [0-2]: " choice

    case "$choice" in
        1) toggle_bt ;;
        2) toggle_private ;;
        0) clear; exit 0 ;;
        *) ;;
    esac
done
EOF
chmod +x /usr/local/bin/bt

# --- 8. WARP 管理脚本 (xw) ---
cat > /usr/local/bin/xw << 'EOF'
#!/bin/bash
RED="\033[31m"; GREEN="\033[32m"; YELLOW="\033[33m"; BLUE="\033[36m"; GRAY="\033[90m"; PLAIN="\033[0m"

CONFIG_FILE="/usr/local/etc/xray/config.json"
WARP_PORT=40000

# 0. 启动即清屏
clear
if [ "$EUID" -ne 0 ]; then echo -e "${RED}请使用 sudo 运行此脚本！${PLAIN}"; exit 1; fi

# --- 核心检测函数 ---
check_warp_socket() {
    (echo > /dev/tcp/127.0.0.1/$WARP_PORT) >/dev/null 2>&1
}

wait_for_port() {
    echo -ne "${INFO} 正在等待 WARP 服务启动..."
    for i in {1..15}; do
        if check_warp_socket; then
            echo -e "\r${OK} WARP 服务响应正常 (127.0.0.1:$WARP_PORT)    "
            return 0
        fi
        echo -ne "."
        sleep 1
    done
    echo -e "\r${WARN} WARP 服务响应超时，请检查日志。    "
    return 1
}

check_xray_outbound() {
    if jq -e '.outbounds[] | select(.tag=="warp_proxy")' "$CONFIG_FILE" >/dev/null; then return 0; else return 1; fi
}

check_rule_ui() {
    local site=$1 
    if jq -e --arg site "$site" '.routing.rules[] | select(.outboundTag=="warp_proxy" and (.domain | index($site)))' "$CONFIG_FILE" >/dev/null; then
        # 绿色
        echo -e "${GREEN}WARP 托管${PLAIN}"
    else
        # 黄色，或直连符号
        echo -e "${YELLOW}默认直连${PLAIN}"
    fi
}

apply_changes() {
    echo -e "${INFO} 正在重启 Xray 服务..."
    systemctl restart xray
    echo -e "${GREEN}配置已更新！${PLAIN}"
    read -n 1 -s -r -p "按任意键继续..."
}

# --- Xray 配置修改 ---
ensure_outbound() {
    if check_xray_outbound; then return; fi
    echo -e "${INFO} 添加 Xray 出口 (Socks5:$WARP_PORT)..."
    local out_obj='{"tag": "warp_proxy", "protocol": "socks", "settings": {"servers": [{"address": "127.0.0.1", "port": '$WARP_PORT'}]}}'
    jq --argjson obj "$out_obj" '.outbounds += [$obj]' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
}

remove_outbound() {
    echo -e "${INFO} 移除 Xray 出口..."
    jq 'del(.outbounds[] | select(.tag=="warp_proxy"))' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    jq 'del(.routing.rules[] | select(.outboundTag=="warp_proxy"))' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
}

toggle_rule() {
    local name=$1; local sites_json=$2 
    ensure_outbound
    if ! check_warp_socket; then
        echo -e "${WARN} WARP 未运行！请先执行选项 1 安装。"
        read -n 1 -s -r; return
    fi
    local first_site=$(echo "$sites_json" | jq -r '.[0]')
    local is_enabled=false
    if jq -e --arg site "$first_site" '.routing.rules[] | select(.outboundTag=="warp_proxy" and (.domain | index($site)))' "$CONFIG_FILE" >/dev/null; then is_enabled=true; fi

    if [ "$is_enabled" = true ]; then
        echo -e "操作: ${YELLOW}关闭 $name 分流${PLAIN}"
        jq --argjson sites "$sites_json" 'del(.routing.rules[] | select(.outboundTag=="warp_proxy" and (.domain == $sites)))' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    else
        echo -e "操作: ${GREEN}开启 $name 分流${PLAIN}"
        local new_rule="{\"type\": \"field\", \"domain\": $sites_json, \"outboundTag\": \"warp_proxy\"}"
        jq --argjson rule "$new_rule" '.routing.rules = [$rule] + .routing.rules' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    fi
    apply_changes
}

# --- 功能模块 ---
install_warp() {
    echo -e "\n${BLUE}正在安装 WARP (Socks5 模式)...${PLAIN}"
    wget -N https://gitlab.com/fscarmen/warp/-/raw/main/menu.sh && bash menu.sh c
    echo -e "\n${INFO} 检查服务状态..."
    if wait_for_port; then
        ensure_outbound; systemctl restart xray
        echo -e "${OK} 安装成功！Xray 已自动对接。"
    else
        echo -e "${ERR} 安装可能失败，请查看上方报错。"
    fi
    read -n 1 -s -r -p "按任意键继续..."
}

uninstall_warp() {
    echo -e "\n${RED}正在卸载 WARP...${PLAIN}"
    if command -v warp &>/dev/null; then warp u; else wget -N https://gitlab.com/fscarmen/warp/-/raw/main/menu.sh && bash menu.sh u; fi
    remove_outbound; systemctl restart xray
    echo -e "${GREEN}卸载清理完毕。${PLAIN}"
    read -n 1 -s -r -p "按任意键继续..."
}

menu_brush_ip() {
    echo -e "\n${BLUE}调用优选 IP 工具...${PLAIN}"
    if command -v warp &>/dev/null; then warp i; else wget -N https://gitlab.com/fscarmen/warp/-/raw/main/menu.sh && bash menu.sh i; fi
    read -n 1 -s -r -p "按任意键继续..."
}

# --- 主菜单 ---
while true; do
    clear
    # 状态栏使用图标，更直观
    if check_warp_socket; then STATUS_SOCK="${GREEN}● 运行中${PLAIN}"; else STATUS_SOCK="${RED}● 未运行${PLAIN}"; fi
    if check_xray_outbound; then STATUS_XRAY="${GREEN}● 已连接${PLAIN}"; else STATUS_XRAY="${YELLOW}● 未连接${PLAIN}"; fi
    
    # 规则检测 (UI函数)
    STATUS_NF=$(check_rule_ui "geosite:netflix")
    STATUS_AI=$(check_rule_ui "geosite:openai")

    echo -e "${BLUE}===================================================${PLAIN}"
    echo -e "${BLUE}           WARP 分流管理面板 (Xray Warp)          ${PLAIN}"
    echo -e "${BLUE}===================================================${PLAIN}"
    echo -e "  WARP 服务: ${STATUS_SOCK}    Xray 接口: ${STATUS_XRAY}"
    echo -e "---------------------------------------------------"
    echo -e "  1. 安装 / 重装 WARP   ${GRAY}(自动配置 Socks5 端口 40000)${PLAIN}"
    echo -e "  2. 彻底卸载 WARP      ${GRAY}(卸载并清理残留规则)${PLAIN}"
    echo -e "  3. 优选 WARP IP       ${GRAY}(当 Netflix 依然看不了时使用)${PLAIN}"
    echo -e "---------------------------------------------------"
    echo -e "  [分流策略控制台]"
    # 使用 printf 进行对齐，或者手动使用点阵线
    echo -e "  4. Netflix 媒体库 ....... [ ${STATUS_NF} ]"
    echo -e "  5. 全能 AI 分流包 ....... [ ${STATUS_AI} ]"
    echo -e "     ${GRAY}(含 OpenAI, Claude, Grok)${PLAIN}"
    echo -e "---------------------------------------------------"
    echo -e "  0. 退出 (Exit)"
    echo -e ""
    read -p "请输入选项 [0-5]: " choice
    case "$choice" in
        1) install_warp ;;
        2) uninstall_warp ;;
        3) menu_brush_ip ;;
        4) toggle_rule "Netflix" '["geosite:netflix"]' ;;
        5) toggle_rule "AI Services" '["geosite:openai","geosite:anthropic","geosite:twitter"]' ;;
        0) clear; exit 0 ;;
        *) ;;
    esac
done
EOF
chmod +x /usr/local/bin/xw

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
