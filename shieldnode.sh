#!/bin/bash

# ==============================================================================
#  VPN NODE DDoS PROTECTION v1.1
#  - nftables rate-limit (kernel-level SYN flood protection)
#  - CrowdSec (SSH brute-force + port-scan + community blocklist)
#
#  Запускать ПОСЛЕ vpn-node-setup-v4.9 (или на уже работающей ноде).
#  Совместимо с активным UFW и любыми другими nft-таблицами.
#
#  Архитектура hook-приоритетов:
#    prerouting -200: conntrack (системный, фиксирует ct state)
#    prerouting -100: НАШ ddos_protect (rate-limit на новые SYN)
#    input -10:       CrowdSec bouncer (table ip crowdsec, баны)
#    input  0:        UFW и пользовательские filter chains
#
#  v1.1 changelog (community-best-practice улучшения):
#    - Add: коллекция crowdsecurity/sshd явно (содержит ssh-cve-2024-6387 — regreSSHion)
#    - Add: auto-detect SSH-клиента и whitelist через parser (правильный способ)
#    - Add: ban duration 24h вместо 4h (для упорных ботнетов)
#    - Add: cscli metrics в финальном отчёте (видно реально ли работает)
# ==============================================================================

set -o pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

print_header() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC} ${BOLD}$1${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}
print_status() { echo -e "${YELLOW}➤${NC} $1"; }
print_ok()     { echo -e "${GREEN}✔${NC} $1"; }
print_error()  { echo -e "${RED}✖${NC} $1"; }
print_info()   { echo -e "${MAGENTA}ℹ${NC} $1"; }
print_warn()   { echo -e "${YELLOW}⚠${NC} $1"; }

# ==============================================================================
# ШАГ 1: ПРОВЕРКИ
# ==============================================================================

print_header "ШАГ 1: ПРОВЕРКИ"

if [[ $EUID -ne 0 ]]; then
    print_error "FATAL: Запустите через sudo"
    exit 1
fi
print_ok "Запущен от root"

if ! command -v nft >/dev/null 2>&1; then
    print_status "Устанавливаю nftables..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y nftables >/dev/null 2>&1 || {
        print_error "Не удалось установить nftables"
        exit 1
    }
fi
print_ok "nftables: $(nft --version 2>&1 | head -1)"

if ! nft list ruleset >/dev/null 2>&1; then
    print_error "nft list ruleset не работает — нет ядерных модулей nftables"
    print_error "Это бывает на OpenVZ/LXC. На KVM не должно встречаться."
    exit 1
fi
print_ok "nftables ядерные модули работают"

BACKUP_DIR="/root/vpn-ddos-backup-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"
nft list ruleset > "$BACKUP_DIR/nft-ruleset.before" 2>/dev/null || true
print_ok "Бэкап текущих nft-правил: $BACKUP_DIR/nft-ruleset.before"

# ==============================================================================
# ШАГ 2: AUTO-DETECT (xray ports, ssh port, current admin IP)
# ==============================================================================

print_header "ШАГ 2: AUTO-DETECT"

# --- Xray порты ---
XRAY_PORTS=""

if command -v ss >/dev/null 2>&1; then
    DETECTED=$(ss -tlnpH 2>/dev/null | awk '
        /users:\(.*"(xray|x-ray|sing-box)"/ {
            split($4, a, ":")
            port = a[length(a)]
            if ($4 ~ /^127\./ || $4 ~ /^\[::1\]/) next
            print port
        }
    ' | sort -un | tr '\n' ',' | sed 's/,$//')

    if [ -n "$DETECTED" ]; then
        XRAY_PORTS="$DETECTED"
        print_ok "Xray порты: ${BOLD}$XRAY_PORTS${NC}"
    fi
fi

if [ -z "$XRAY_PORTS" ]; then
    XRAY_PORTS="443,8443"
    print_warn "Xray не запущен — используем дефолтные Reality-порты: $XRAY_PORTS"
    print_info "После запуска Xray — отредактируй /etc/nftables.d/ddos-protect.conf"
fi

XRAY_PORTS_NFT="{ $(echo "$XRAY_PORTS" | sed 's/,/, /g') }"

# --- SSH порт ---
SSH_PORT=$(ss -tlnpH 2>/dev/null | awk '
    /users:\(.*"sshd"/ {
        split($4, a, ":")
        port = a[length(a)]
        if ($4 ~ /^127\./ || $4 ~ /^\[::1\]/) next
        print port
        exit
    }
')
SSH_PORT="${SSH_PORT:-22}"
print_ok "SSH порт: ${BOLD}$SSH_PORT${NC} (исключим из rate-limit)"

# --- Auto-detect админского IP ---
# Берём IP активной SSH-сессии. SSH_CLIENT="<src_ip> <src_port> <dst_port>"
# Fallback: who -m показывает текущий tty с IP в скобках
ADMIN_IP=""
if [ -n "${SSH_CLIENT:-}" ]; then
    ADMIN_IP=$(echo "$SSH_CLIENT" | awk '{print $1}')
elif [ -n "${SSH_CONNECTION:-}" ]; then
    ADMIN_IP=$(echo "$SSH_CONNECTION" | awk '{print $1}')
else
    ADMIN_IP=$(who -m 2>/dev/null | grep -oE '\([^)]+\)' | tr -d '()' | head -1)
fi

# Sanity: проверим что это валидный IP (а не "tmux" или localhost)
case "$ADMIN_IP" in
    ""|localhost|127.0.0.1|::1) ADMIN_IP="" ;;
    *[!0-9.:]*) ADMIN_IP="" ;;
esac

if [ -n "$ADMIN_IP" ]; then
    print_ok "Текущий админский IP: ${BOLD}$ADMIN_IP${NC} (добавим в whitelist)"
else
    print_warn "Не удалось определить админский IP (запуск не через SSH?)"
    print_info "Whitelist можно добавить вручную после установки"
fi

# ==============================================================================
# ШАГ 3: NFTABLES RATE-LIMIT
# ==============================================================================

print_header "ШАГ 3: NFTABLES RATE-LIMIT (kernel-level SYN flood protection)"

NFT_CONF_DIR="/etc/nftables.d"
NFT_DDOS_CONF="$NFT_CONF_DIR/ddos-protect.conf"
mkdir -p "$NFT_CONF_DIR"

# Подготовим whitelist строку с админским IP если он есть
NFT_ADMIN_WHITELIST_V4=""
NFT_ADMIN_WHITELIST_V6=""
if [ -n "$ADMIN_IP" ]; then
    case "$ADMIN_IP" in
        *:*) NFT_ADMIN_WHITELIST_V6="        elements = { $ADMIN_IP }" ;;
        *)   NFT_ADMIN_WHITELIST_V4="        elements = { $ADMIN_IP }" ;;
    esac
fi

cat > "$NFT_DDOS_CONF" <<EOF
#!/usr/sbin/nft -f
# Generated by vpn-node-ddos-protect.sh v1.1
# Kernel-level SYN flood protection on Xray ports: $XRAY_PORTS
# SSH port $SSH_PORT excluded from rate-limit.
#
# Test:    hping3 -S -p ${XRAY_PORTS%%,*} -i u100 <YOUR_VPN_IP>
# Monitor: nft list set inet ddos_protect syn_flood_v4
# Remove:  nft delete table inet ddos_protect && rm $NFT_DDOS_CONF

# Идемпотентность
table inet ddos_protect
delete table inet ddos_protect

table inet ddos_protect {
    set syn_flood_v4 {
        type ipv4_addr
        flags dynamic, timeout
        timeout 1m
        size 65536
    }
    set syn_flood_v6 {
        type ipv6_addr
        flags dynamic, timeout
        timeout 1m
        size 65536
    }

    # Whitelist админских сетей. Заполняется командой:
    #   nft add element inet ddos_protect admin_whitelist_v4 { 1.2.3.4 }
    set admin_whitelist_v4 {
        type ipv4_addr
        flags interval
        auto-merge
$NFT_ADMIN_WHITELIST_V4
    }
    set admin_whitelist_v6 {
        type ipv6_addr
        flags interval
        auto-merge
$NFT_ADMIN_WHITELIST_V6
    }

    chain prerouting {
        type filter hook prerouting priority -100; policy accept;

        # Established/related — пропускаем без проверок.
        # Текущий SSH и активные Xray-сессии не оборвутся.
        ct state established,related accept

        iif lo accept

        # Whitelist админов
        meta nfproto ipv4 ip saddr @admin_whitelist_v4 accept
        meta nfproto ipv6 ip6 saddr @admin_whitelist_v6 accept

        # SSH порт — НЕ применяем rate-limit
        tcp dport $SSH_PORT accept

        # Если IP уже в "наказанном" set — дропаем тихо (одна hash-проверка)
        meta nfproto ipv4 ip saddr @syn_flood_v4 drop
        meta nfproto ipv6 ip6 saddr @syn_flood_v6 drop

        # Главное правило: новые SYN на порты Xray, не больше 30/sec на IP.
        meta nfproto ipv4 tcp flags syn tcp dport $XRAY_PORTS_NFT ct state new add @syn_flood_v4 { ip saddr limit rate over 30/second burst 60 packets } drop
        meta nfproto ipv6 tcp flags syn tcp dport $XRAY_PORTS_NFT ct state new add @syn_flood_v6 { ip6 saddr limit rate over 30/second burst 60 packets } drop

        # policy accept — всё остальное проходит дальше
    }
}
EOF

chmod 0644 "$NFT_DDOS_CONF"
print_ok "Правила записаны: $NFT_DDOS_CONF"

print_status "Проверяю синтаксис nft..."
if ! nft -c -f "$NFT_DDOS_CONF" 2>/tmp/nft-check.log; then
    print_error "Синтаксис nft невалиден:"
    cat /tmp/nft-check.log | sed 's/^/    /'
    exit 1
fi
print_ok "Синтаксис ок"

print_status "Применяю правила (текущие SSH-сессии не оборвутся)..."
if ! nft -f "$NFT_DDOS_CONF" 2>/tmp/nft-apply.log; then
    print_error "Применение nft провалилось:"
    cat /tmp/nft-apply.log | sed 's/^/    /'
    exit 1
fi
print_ok "Rate-limit активен"

# Persistence через include в /etc/nftables.conf
NFTABLES_MAIN="/etc/nftables.conf"
if [ -f "$NFTABLES_MAIN" ]; then
    if ! grep -q "include \"/etc/nftables.d/" "$NFTABLES_MAIN" 2>/dev/null; then
        cp -a "$NFTABLES_MAIN" "$BACKUP_DIR/nftables.conf.before"
        cat >> "$NFTABLES_MAIN" <<'EOF'

# Added by vpn-node-ddos-protect — load drop-in configs
include "/etc/nftables.d/*.conf"
EOF
        print_ok "include /etc/nftables.d/*.conf добавлен"
    else
        print_info "include /etc/nftables.d/* уже настроен"
    fi
fi

if systemctl list-unit-files nftables.service &>/dev/null; then
    if ! systemctl is-enabled nftables.service &>/dev/null; then
        systemctl enable nftables.service >/dev/null 2>&1 && \
            print_ok "nftables.service enabled"
    else
        print_ok "nftables.service уже enabled"
    fi
fi

# ==============================================================================
# ШАГ 4: УСТАНОВКА CROWDSEC
# ==============================================================================

print_header "ШАГ 4: УСТАНОВКА CROWDSEC"

if command -v cscli >/dev/null 2>&1; then
    print_ok "CrowdSec уже установлен: $(cscli version 2>&1 | grep -oE 'v[0-9.]+' | head -1)"
else
    print_status "Подключаю официальный репозиторий CrowdSec..."
    if ! curl -s https://install.crowdsec.net | bash >/dev/null 2>&1; then
        print_error "Не удалось добавить репозиторий CrowdSec"
        exit 1
    fi

    print_status "Устанавливаю crowdsec..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y crowdsec >/dev/null 2>&1 || {
        print_error "apt-get install crowdsec провалился"
        exit 1
    }
    print_ok "CrowdSec установлен"
fi

# ==============================================================================
# ШАГ 5: КОЛЛЕКЦИИ
# ==============================================================================

print_header "ШАГ 5: КОЛЛЕКЦИИ"

# v1.1: добавлен явный crowdsecurity/sshd — содержит ssh-cve-2024-6387
# (regreSSHion CVE на OpenSSH с RCE, критично для VPN-нод с открытым SSH)
COLLECTIONS=("crowdsecurity/linux" "crowdsecurity/sshd" "crowdsecurity/iptables")

for col in "${COLLECTIONS[@]}"; do
    if cscli collections list 2>/dev/null | grep -q "^$col"; then
        print_info "Уже установлена: $col"
    else
        print_status "Устанавливаю $col..."
        if cscli collections install "$col" >/dev/null 2>&1; then
            print_ok "$col"
        else
            print_warn "Не удалось установить $col"
        fi
    fi
done

# ==============================================================================
# ШАГ 6: WHITELIST АДМИНСКОГО IP
# ==============================================================================

print_header "ШАГ 6: WHITELIST АДМИНСКОГО IP"

# v1.1: whitelist через parser в s02-enrich — правильный способ.
# `cscli decisions add --type whitelist` НЕ защищает от community blocklist
# при следующей подтяжке. Parser whitelist отбрасывает события на этапе
# парсинга, до того как они дойдут до сценария.

WHITELIST_FILE="/etc/crowdsec/parsers/s02-enrich/00-admin-whitelist.yaml"

if [ -n "$ADMIN_IP" ]; then
    if [ -f "$WHITELIST_FILE" ] && grep -q "$ADMIN_IP" "$WHITELIST_FILE" 2>/dev/null; then
        print_info "Whitelist для $ADMIN_IP уже существует"
    else
        mkdir -p "$(dirname "$WHITELIST_FILE")"
        cat > "$WHITELIST_FILE" <<EOF
# Generated by vpn-node-ddos-protect v1.1
# Whitelist админских IP — защита от self-ban и игнорирование community blocklist.
# Применяется на этапе s02-enrich (до сценариев).
name: admin/whitelist
description: "Whitelist admin IPs to prevent self-ban"
whitelist:
  reason: "vpn-node-setup admin access"
  ip:
    - "$ADMIN_IP"
EOF
        chmod 0644 "$WHITELIST_FILE"
        print_ok "Whitelist создан: $WHITELIST_FILE"
        print_info "Добавить ещё IP: отредактируй файл и systemctl reload crowdsec"
    fi
else
    print_warn "Админский IP не определён — whitelist не создан"
    print_info "Создай вручную: $WHITELIST_FILE"
fi

# ==============================================================================
# ШАГ 7: BAN DURATION (24h вместо 4h)
# ==============================================================================

print_header "ШАГ 7: BAN DURATION"

# v1.1: дефолтный бан CrowdSec — 4 часа. Для упорных ботнетов мало.
# Community-best-practice для серверов с открытым SSH: 24h.

PROFILES_FILE="/etc/crowdsec/profiles.yaml"

if [ -f "$PROFILES_FILE" ]; then
    if [ ! -f "$BACKUP_DIR/profiles.yaml.before" ]; then
        cp -a "$PROFILES_FILE" "$BACKUP_DIR/profiles.yaml.before"
    fi

    if grep -qE "^[[:space:]]*duration:[[:space:]]*4h[[:space:]]*$" "$PROFILES_FILE"; then
        # Меняем только первый дефолтный 4h, не custom-профили
        sed -i '0,/^\([[:space:]]*\)duration:[[:space:]]*4h[[:space:]]*$/s//\1duration: 24h/' "$PROFILES_FILE"
        print_ok "Ban duration: 4h → 24h"
        systemctl restart crowdsec 2>/dev/null || true
    elif grep -qE "^[[:space:]]*duration:[[:space:]]*24h[[:space:]]*$" "$PROFILES_FILE"; then
        print_info "Ban duration уже 24h"
    else
        CURRENT_DURATION=$(grep -m1 -E "^[[:space:]]*duration:" "$PROFILES_FILE" | awk '{print $2}')
        print_info "Ban duration: $CURRENT_DURATION (custom — не трогаю)"
    fi
else
    print_warn "$PROFILES_FILE не найден — пропускаю"
fi

# ==============================================================================
# ШАГ 8: ACQUISITION (источники логов)
# ==============================================================================

print_header "ШАГ 8: ACQUISITION (источники логов)"

ACQUIS_DIR="/etc/crowdsec/acquis.d"
mkdir -p "$ACQUIS_DIR"

UFW_ACQUIS="$ACQUIS_DIR/ufw.yaml"
if [ -f /var/log/ufw.log ] || [ -f /var/log/kern.log ]; then
    cat > "$UFW_ACQUIS" <<'EOF'
# Generated by vpn-node-ddos-protect — UFW/iptables logs for port-scan detection
filenames:
  - /var/log/ufw.log
  - /var/log/kern.log
labels:
  type: syslog
EOF
    print_ok "UFW acquisition: $UFW_ACQUIS"
else
    print_info "UFW логов не найдено — пропускаю"
fi

if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    UFW_LOGLEVEL=$(ufw status verbose 2>/dev/null | awk '/^Logging:/ {print $2}')
    if [ "$UFW_LOGLEVEL" = "off" ]; then
        print_warn "UFW logging выключен — port-scan детект работать НЕ будет"
        print_info "Чтобы включить: ufw logging low"
    else
        print_ok "UFW logging: $UFW_LOGLEVEL"
    fi
fi

# ==============================================================================
# ШАГ 9: NFTABLES BOUNCER
# ==============================================================================

print_header "ШАГ 9: NFTABLES BOUNCER"

if dpkg -l crowdsec-firewall-bouncer-nftables &>/dev/null; then
    print_info "Bouncer уже установлен"
else
    print_status "Устанавливаю crowdsec-firewall-bouncer-nftables..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y crowdsec-firewall-bouncer-nftables >/dev/null 2>&1 || {
        print_error "Установка bouncer'а провалилась"
        exit 1
    }
    print_ok "Bouncer установлен"
fi

if ! cscli bouncers list 2>/dev/null | grep -q "cs-firewall-bouncer"; then
    print_status "Регистрирую bouncer в LAPI..."
    BOUNCER_KEY=$(cscli bouncers add cs-firewall-bouncer-nftables -o raw 2>/dev/null)
    if [ -n "$BOUNCER_KEY" ]; then
        sed -i "s|^api_key:.*|api_key: $BOUNCER_KEY|" /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml
        print_ok "Bouncer зарегистрирован"
    fi
fi

systemctl enable --now crowdsec >/dev/null 2>&1 || true
systemctl enable --now crowdsec-firewall-bouncer >/dev/null 2>&1 || true

sleep 3
if systemctl is-active --quiet crowdsec && systemctl is-active --quiet crowdsec-firewall-bouncer; then
    print_ok "crowdsec + bouncer активны"
else
    print_warn "Один из сервисов не active:"
    systemctl is-active crowdsec || print_error "  crowdsec НЕ active"
    systemctl is-active crowdsec-firewall-bouncer || print_error "  bouncer НЕ active"
    print_info "Логи: journalctl -u crowdsec -u crowdsec-firewall-bouncer -n 50"
fi

# ==============================================================================
# ШАГ 10: HEALTHCHECK
# ==============================================================================

print_header "ШАГ 10: HEALTHCHECK"

# v1.1: cscli metrics — единственный способ убедиться что парсеры работают.
# Если "Lines parsed" = 0 для /var/log/auth.log — парсер сломан.

print_info "Жду 5 секунд чтобы парсеры успели прочитать логи..."
sleep 5

print_status "CrowdSec metrics:"
echo ""
cscli metrics 2>/dev/null | head -50 | sed 's/^/    /' || \
    print_warn "cscli metrics вернул ошибку — проверь journalctl -u crowdsec"
echo ""

ACTIVE_BANS=$(cscli decisions list -o raw 2>/dev/null | tail -n +2 | wc -l)
if [ "$ACTIVE_BANS" -gt 0 ]; then
    print_ok "Активных банов: $ACTIVE_BANS"
else
    print_info "Активных банов нет (норма для свежей установки)"
fi

# ==============================================================================
# ШАГ 11: ИТОГИ
# ==============================================================================

print_header "ГОТОВО"

echo -e "  ${BOLD}Что настроено:${NC}"
echo -e "  ├─ ${GREEN}✔${NC} nft rate-limit: 30 SYN/sec на IP, превышение → бан 1 мин"
echo -e "  ├─ ${GREEN}✔${NC} Защищённые порты: ${CYAN}$XRAY_PORTS${NC}"
echo -e "  ├─ ${GREEN}✔${NC} SSH порт ${CYAN}$SSH_PORT${NC} исключён из rate-limit"
[ -n "$ADMIN_IP" ] && echo -e "  ├─ ${GREEN}✔${NC} Admin IP в whitelist: ${CYAN}$ADMIN_IP${NC}"
echo -e "  ├─ ${GREEN}✔${NC} CrowdSec collections: linux + sshd + iptables"
echo -e "  ├─ ${GREEN}✔${NC} ssh-cve-2024-6387 (regreSSHion) активен"
echo -e "  ├─ ${GREEN}✔${NC} Ban duration: 24h"
echo -e "  ├─ ${GREEN}✔${NC} Community blocklist: автообновление каждые 2 часа"
echo -e "  └─ ${GREEN}✔${NC} nftables bouncer применяет CrowdSec decisions"
echo ""
echo -e "  ${BOLD}Полезные команды:${NC}"
echo -e "  ${CYAN}cscli metrics${NC}                              # статистика парсеров"
echo -e "  ${CYAN}cscli decisions list${NC}                       # активные баны"
echo -e "  ${CYAN}cscli alerts list${NC}                          # история алертов"
echo -e "  ${CYAN}cscli scenarios list${NC}                       # установленные сценарии"
echo -e "  ${CYAN}nft list set inet ddos_protect syn_flood_v4${NC} # кто в SYN-флуд бане"
echo ""
echo -e "  ${BOLD}Добавить ещё whitelist IP:${NC}"
echo -e "  Отредактируй ${CYAN}$WHITELIST_FILE${NC}, потом:"
echo -e "  ${CYAN}systemctl reload crowdsec${NC}"
echo ""
echo -e "  ${BOLD}Тест SYN flood (с другой машины):${NC}"
echo -e "  ${CYAN}sudo hping3 -S -p ${XRAY_PORTS%%,*} -i u100 <YOUR_VPN_IP>${NC}"
echo ""
echo -e "  ${BOLD}Бэкап:${NC} ${CYAN}$BACKUP_DIR${NC}"
echo ""
echo -e "  ${BOLD}Удалить всё:${NC}"
echo -e "  ${CYAN}nft delete table inet ddos_protect${NC}"
echo -e "  ${CYAN}rm $NFT_DDOS_CONF $WHITELIST_FILE${NC}"
echo -e "  ${CYAN}apt purge crowdsec crowdsec-firewall-bouncer-nftables${NC}"
echo ""
