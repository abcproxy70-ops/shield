#!/bin/bash

# ==============================================================================
#  VPN NODE DDoS PROTECTION v1.5 (Commercial Edition)
#  - nftables rate-limit (kernel-level SYN flood protection)
#  - nftables scanner-blocklist (pre-emptive drop известных сканеров)
#  - CrowdSec (SSH brute-force + community blocklist)
#  - SSH-key auto-whitelist (опционально, если используется key-auth)
#
#  Запускать ПОСЛЕ установки VPN-стека (Xray/sing-box) или на голом сервере.
#  Совместимо с активным UFW и любыми другими nft-таблицами.
#
#  v1.5 changelog (commercial fixes):
#    - REM: обязательная проверка SSH-key авторизации в шаге 1
#           (теперь скрипт работает с любым типом аутентификации)
#    - REM: автоматическое отключение PasswordAuthentication
#           (только показ предупреждения с инструкцией)
#    - CHG: SSH-key auto-whitelist стал опциональным:
#           * password-auth ON  → срабатывает только на publickey (безопасно)
#           * password-auth OFF → срабатывает на любой вход (как было)
#    - ADD: fallback статичный whitelist для текущего IP юзера
#           (если ключа нет, хотя бы текущий IP в whitelist на 12h)
#    - ADD: подробный summary в конце с рекомендациями по усилению защиты
#    - CHG: исправлен путь к скрипту в команде uninstall (была /dev/fd/63)
#
#  v1.4 changelog (user-friendly fixes):
#    - CHG: rate-limit 30/sec → 60/sec burst 100 (запас для CGNAT-юзеров)
#    - CHG: ban duration 24h → 4h (меньше ущерба от ложных банов)
#    - REM: коллекция crowdsecurity/iptables (ложно банила VPN-юзеров)
#
#  v1.3 changelog:
#    - ADD: scanner_blocklist set в nft (Shodan, Censys, госсканеры)
#    - ADD: systemd timer обновляет blocklist каждые 6 часов
#    - ADD: --uninstall флаг
#
#  v1.2 changelog:
#    - REPLACE: статичный IP-whitelist → SSH-key auto-whitelist
#    - ADD: postoverflow parser, cs-ssh-whitelist service
#
#  v1.1 changelog:
#    - ADD: коллекция crowdsecurity/sshd (ssh-cve-2024-6387)
#
#  Архитектура hook-приоритетов:
#    prerouting -200: conntrack (системный)
#    prerouting -100: НАШ ddos_protect (scanner_blocklist drop → rate-limit)
#    input -10:       CrowdSec bouncer
#    input  0:        UFW и пользовательские filter chains
#
#  Удаление: sudo bash vpn-node-ddos-protect-v1_5.sh --uninstall
#
#  РЕКОМЕНДАЦИЯ: для максимальной защиты после установки:
#    1. Сгенерируй SSH-ключ на локальной машине: ssh-keygen -t ed25519
#    2. Положи публичный ключ в /root/.ssh/authorized_keys на сервере
#    3. Зайди по ключу, проверь что работает
#    4. Выключи password-auth: sed -i 's/^[#[:space:]]*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && systemctl reload ssh
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
# UNINSTALL MODE
# ==============================================================================

if [ "${1:-}" = "--uninstall" ]; then
    if [[ $EUID -ne 0 ]]; then
        print_error "FATAL: Запустите через sudo"
        exit 1
    fi

    print_header "UNINSTALL: vpn-node-ddos-protect"

    print_warn "Это удалит:"
    echo "  - nft table inet ddos_protect (rate-limit + scanner-blocklist)"
    echo "  - /etc/nftables.d/ddos-protect.conf"
    echo "  - cs-ssh-whitelist.service + watcher script"
    echo "  - scanner-blocklist updater + timer"
    echo "  - postoverflow parser"
    echo ""
    echo "  НЕ удалит:"
    echo "  - сам CrowdSec и bouncer (apt purge crowdsec вручную)"
    echo "  - sshd-конфиг (PasswordAuthentication)"
    echo "  - бэкапы в /root/vpn-ddos-backup-*"
    echo ""
    read -r -p "Продолжить? [y/N] " ANSWER
    case "$ANSWER" in
        y|Y|yes|YES) ;;
        *) echo "Отмена."; exit 0 ;;
    esac

    # Systemd units
    for unit in cs-ssh-whitelist scanner-blocklist-update.timer scanner-blocklist-update.service; do
        systemctl disable --now "$unit" 2>/dev/null || true
        rm -f "/etc/systemd/system/$unit"
    done
    systemctl daemon-reload
    print_ok "Systemd units удалены"

    # Scripts
    rm -f /usr/local/sbin/cs-ssh-key-whitelist.sh
    rm -f /usr/local/sbin/update-scanner-blocklist.sh
    print_ok "Скрипты удалены"

    # CrowdSec parser
    rm -f /etc/crowdsec/postoverflows/s01-whitelist/ssh-key-whitelist.yaml
    # Старая UFW acquisition (от v1.1-1.3)
    if [ -f /etc/crowdsec/acquis.d/ufw.yaml ] && \
       grep -q "vpn-node-ddos-protect" /etc/crowdsec/acquis.d/ufw.yaml 2>/dev/null; then
        rm -f /etc/crowdsec/acquis.d/ufw.yaml
    fi
    systemctl reload crowdsec 2>/dev/null || true
    print_ok "Postoverflow parser удалён"

    # nft table
    nft delete table inet ddos_protect 2>/dev/null || true
    rm -f /etc/nftables.d/ddos-protect.conf
    # Убираем include из /etc/nftables.conf
    if [ -f /etc/nftables.conf ]; then
        sed -i '/# DDoS protection (vpn-node-ddos-protect)/d' /etc/nftables.conf
        sed -i '\|include "/etc/nftables.d/ddos-protect.conf"|d' /etc/nftables.conf
    fi
    print_ok "nft правила удалены"

    # cscli whitelist decisions
    if command -v cscli >/dev/null 2>&1; then
        cscli decisions delete --type whitelist >/dev/null 2>&1 || true
        print_ok "Whitelist decisions очищены"
    fi

    print_header "UNINSTALL ЗАВЕРШЁН"
    echo "Бэкапы остались в /root/vpn-ddos-backup-*"
    exit 0
fi

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

# v1.5: проверим какой метод auth — но НЕ блокируем установку.
# Скрипт работает с любым типом, просто на разных уровнях защиты.
# Используется глобальная переменная USES_KEY_AUTH в шагах 3 и 7.
USES_KEY_AUTH=0
CURRENT_AUTH_METHOD=""
if [ -n "${SSH_CONNECTION:-}" ] && [ -n "${PPID:-}" ]; then
    SSH_PID=$(ps -o ppid= -p "$PPID" 2>/dev/null | tr -d ' ')
    if [ -n "$SSH_PID" ]; then
        CURRENT_AUTH_METHOD=$(journalctl _PID="$SSH_PID" --no-pager 2>/dev/null | \
            grep -oE "Accepted (publickey|password|keyboard-interactive)" | \
            head -1 | awk '{print $2}')
    fi
fi

if [ "$CURRENT_AUTH_METHOD" = "publickey" ]; then
    print_ok "Текущая SSH-сессия по ключу — максимальная защита будет включена"
    USES_KEY_AUTH=1
elif [ "$CURRENT_AUTH_METHOD" = "password" ] || [ "$CURRENT_AUTH_METHOD" = "keyboard-interactive" ]; then
    print_warn "Текущая SSH-сессия по ПАРОЛЮ"
    print_info "Скрипт продолжит установку. Защита будет работать, но НЕ на максимуме."
    print_info "После установки рекомендую перейти на SSH-ключи (см. итоги в конце)."
elif [ -n "${SSH_CONNECTION:-}" ]; then
    print_info "Метод аутентификации не определён, продолжаю"
else
    print_info "Запуск с локальной консоли — продолжаю"
fi

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

# --- Текущий админский IP (для bootstrap-whitelist) ---
ADMIN_IP=""
if [ -n "${SSH_CLIENT:-}" ]; then
    ADMIN_IP=$(echo "$SSH_CLIENT" | awk '{print $1}')
elif [ -n "${SSH_CONNECTION:-}" ]; then
    ADMIN_IP=$(echo "$SSH_CONNECTION" | awk '{print $1}')
else
    ADMIN_IP=$(who -m 2>/dev/null | grep -oE '\([^)]+\)' | tr -d '()' | head -1)
fi

case "$ADMIN_IP" in
    ""|localhost|127.0.0.1|::1) ADMIN_IP="" ;;
    *[!0-9.:]*) ADMIN_IP="" ;;
esac

if [ -n "$ADMIN_IP" ]; then
    print_ok "Текущий админский IP: ${BOLD}$ADMIN_IP${NC} (bootstrap-whitelist на 12h)"
else
    print_warn "Не удалось определить админский IP (запуск не через SSH)"
    print_info "Это ок если ты на локальной консоли. Whitelist начнёт работать"
    print_info "после первого SSH-коннекта по ключу."
fi

# ==============================================================================
# ШАГ 3: ПРОВЕРКА КОНФИГА SSH (информационная, не блокирует установку)
# ==============================================================================

print_header "ШАГ 3: ПРОВЕРКА КОНФИГА SSH"

# v1.5: проверка SSH-конфига больше не интерактивная и не блокирующая.
# Просто показываем текущее состояние и рекомендации в конце скрипта.
# Юзер сам решит когда и как переходить на ключи.

# Глобальные переменные для использования в шагах 7 и 12 (summary)
SSHD_PASSWORD_AUTH_ENABLED=0
SSHD_PUBKEY_AUTH_ENABLED=1

SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_EFFECTIVE=$(sshd -T 2>/dev/null)

if [ -z "$SSHD_EFFECTIVE" ]; then
    print_warn "sshd -T не работает — пропускаю проверку"
else
    PASSWORD_AUTH=$(echo "$SSHD_EFFECTIVE" | awk '/^passwordauthentication/ {print $2}')
    PUBKEY_AUTH=$(echo "$SSHD_EFFECTIVE" | awk '/^pubkeyauthentication/ {print $2}')
    KBD_INT_AUTH=$(echo "$SSHD_EFFECTIVE" | awk '/^kbdinteractiveauthentication/ {print $2}')

    if [ "$PUBKEY_AUTH" = "yes" ]; then
        print_ok "PubkeyAuthentication: yes"
        SSHD_PUBKEY_AUTH_ENABLED=1
    else
        print_warn "PubkeyAuthentication: $PUBKEY_AUTH (отключено)"
        print_info "Без него SSH-key auto-whitelist работать не будет"
        SSHD_PUBKEY_AUTH_ENABLED=0
    fi

    if [ "$PASSWORD_AUTH" = "yes" ] || [ "$KBD_INT_AUTH" = "yes" ]; then
        print_warn "PasswordAuthentication=$PASSWORD_AUTH, KbdInteractive=$KBD_INT_AUTH"
        print_info "Защита установится. Для МАКСИМАЛЬНОЙ безопасности:"
        print_info "  1. Настрой вход по SSH-ключу"
        print_info "  2. Отключи password-auth: см. инструкцию в конце скрипта"
        SSHD_PASSWORD_AUTH_ENABLED=1
    else
        print_ok "PasswordAuthentication: no — максимальная защита"
        SSHD_PASSWORD_AUTH_ENABLED=0
    fi
fi

# ==============================================================================
# ШАГ 4: NFTABLES RATE-LIMIT
# ==============================================================================

print_header "ШАГ 4: NFTABLES RATE-LIMIT (kernel-level SYN flood protection)"

NFT_CONF_DIR="/etc/nftables.d"
NFT_DDOS_CONF="$NFT_CONF_DIR/ddos-protect.conf"
mkdir -p "$NFT_CONF_DIR"

cat > "$NFT_DDOS_CONF" <<EOF
#!/usr/sbin/nft -f
# Generated by vpn-node-ddos-protect.sh v1.4
# Kernel-level SYN flood protection on Xray ports: $XRAY_PORTS
# SSH port $SSH_PORT excluded from rate-limit.
#
# v1.4: rate-limit 60/sec burst 100 — даёт запас для CGNAT-юзеров мобильных
# операторов, где сотни легитимных пользователей могут сидеть за одним IP.
# Реальный SYN-flood делает тысячи SYN/sec — лимит 60 их режет, но
# обычных юзеров не трогает.
#
# v1.3: scanner_blocklist drop'ает известных сканеров (Shodan, Censys,
# госсканеры) ДО rate-limit. Они даже не доходят до handshake.
# Списки обновляются каждые 6 часов через scanner-blocklist-update.timer.
#
# Whitelist в ЭТОЙ таблице — только runtime-добавленные IP (для ручного
# исключения). Основной whitelist админа управляется CrowdSec'ом
# через ssh-key auto-whitelist (см. /etc/crowdsec/postoverflows/...).
#
# Test:    hping3 -S -p ${XRAY_PORTS%%,*} -i u100 <YOUR_VPN_IP>
# Monitor: nft list set inet ddos_protect syn_flood_v4
#          nft list set inet ddos_protect scanner_blocklist_v4 | wc -l
# Remove:  bash vpn-node-ddos-protect-v1_4.sh --uninstall

# Идемпотентность
table inet ddos_protect
delete table inet ddos_protect

table inet ddos_protect {
    # --- Pre-emptive blocklist (известные сканеры) ---
    # Заполняется скриптом /usr/local/sbin/update-scanner-blocklist.sh
    set scanner_blocklist_v4 {
        type ipv4_addr
        flags interval
        auto-merge
        # Размер для ~50k подсетей с запасом
        size 131072
    }
    set scanner_blocklist_v6 {
        type ipv6_addr
        flags interval
        auto-merge
        size 131072
    }

    # --- Dynamic SYN-flood detection ---
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

    # --- Manual whitelist ---
    # nft add element inet ddos_protect manual_whitelist_v4 { 1.2.3.4 }
    set manual_whitelist_v4 {
        type ipv4_addr
        flags interval
        auto-merge
    }
    set manual_whitelist_v6 {
        type ipv6_addr
        flags interval
        auto-merge
    }

    chain prerouting {
        type filter hook prerouting priority -100; policy accept;

        # Established/related — пропускаем без проверок.
        ct state established,related accept

        # Manual whitelist (всегда первым приоритетом)
        ip  saddr @manual_whitelist_v4 accept
        ip6 saddr @manual_whitelist_v6 accept

        # SSH — без блокировок (защищает CrowdSec)
        tcp dport $SSH_PORT accept

        # Pre-emptive drop известных сканеров.
        # Стоит ПЕРЕД rate-limit — экономит conntrack-слоты и CPU.
        ip  saddr @scanner_blocklist_v4 drop
        ip6 saddr @scanner_blocklist_v6 drop

        # Rate-limit на Xray-портах: 60 SYN/sec на IP, burst 100.
        # Лимит подобран чтобы:
        #   - Real SYN-flood (1000+/sec) — режется
        #   - CGNAT мобильных операторов (100+ юзеров на IP) — проходит
        #   - Обычный юзер делает 1-3 SYN/sec при подключении — не задевается
        tcp dport $XRAY_PORTS_NFT ct state new meta nfproto ipv4 \\
            add @syn_flood_v4 { ip saddr limit rate over 60/second burst 100 packets } drop
        tcp dport $XRAY_PORTS_NFT ct state new meta nfproto ipv6 \\
            add @syn_flood_v6 { ip6 saddr limit rate over 60/second burst 100 packets } drop
    }
}
EOF

# Загружаем правила
if nft -f "$NFT_DDOS_CONF" 2>&1; then
    print_ok "nft rate-limit активен"
else
    print_error "Ошибка загрузки nft-правил — смотри вывод выше"
    exit 1
fi

# Подключаем в /etc/nftables.conf для автозагрузки при boot
NFTABLES_MAIN="/etc/nftables.conf"
if [ -f "$NFTABLES_MAIN" ] && ! grep -q "$NFT_DDOS_CONF" "$NFTABLES_MAIN"; then
    cp -a "$NFTABLES_MAIN" "$BACKUP_DIR/nftables.conf.before"
    echo "" >> "$NFTABLES_MAIN"
    echo "# DDoS protection (vpn-node-ddos-protect)" >> "$NFTABLES_MAIN"
    echo "include \"$NFT_DDOS_CONF\"" >> "$NFTABLES_MAIN"
    print_ok "Подключено в $NFTABLES_MAIN (автозагрузка при boot)"
fi

systemctl enable nftables >/dev/null 2>&1 || true

# ==============================================================================
# ШАГ 5: SCANNER-BLOCKLIST UPDATER (pre-emptive drop)
# ==============================================================================

print_header "ШАГ 5: SCANNER-BLOCKLIST UPDATER"

# v1.3: качаем подсети известных сканеров (Shodan, Censys, BinaryEdge,
# госсканеры РФ/CN/etc) и кладём их в nft set scanner_blocklist_v4/v6.
# Источник: https://github.com/shadow-netlab/traffic-guard-lists
#
# Обновляется раз в 6 часов через systemd timer.
# Атомарный обмен через одну nft-транзакцию (flush + add) — split-brain
# состояния невозможно.

UPDATER_SCRIPT="/usr/local/sbin/update-scanner-blocklist.sh"

cat > "$UPDATER_SCRIPT" <<'UPDATER_EOF'
#!/bin/bash
# Обновляет nft set inet ddos_protect scanner_blocklist_v4/v6
# из публичных списков подсетей сканеров.
# Запускается через scanner-blocklist-update.timer.

set -o pipefail

LISTS=(
    "https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/antiscanner.list"
    "https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/government_networks.list"
)

LOG_TAG="scanner-blocklist"

# Если nft-таблицы нет — выходим (скрипт может стартануть до первой установки)
if ! nft list table inet ddos_protect >/dev/null 2>&1; then
    logger -t "$LOG_TAG" "table inet ddos_protect не существует — пропускаю"
    exit 0
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# Качаем все списки в один файл
for url in "${LISTS[@]}"; do
    if curl -fsSL --max-time 30 --retry 2 "$url" -o "$TMP/dl.tmp" 2>/dev/null; then
        cat "$TMP/dl.tmp" >> "$TMP/all.raw"
    else
        logger -t "$LOG_TAG" "WARN: не смог скачать $url"
    fi
done

if [ ! -s "$TMP/all.raw" ]; then
    logger -t "$LOG_TAG" "ERROR: пустой результат скачивания, не обновляю set"
    exit 1
fi

# Извлекаем валидные IPv4-подсети (с CIDR или без)
grep -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]+)?' "$TMP/all.raw" | \
    sort -u > "$TMP/v4.list"

# IPv6: строки содержащие ':' и валидные hex
grep ':' "$TMP/all.raw" | \
    grep -oE '^[0-9a-fA-F:]+(/[0-9]+)?' | \
    grep -E '[0-9a-fA-F]{1,4}:[0-9a-fA-F:]*' | \
    sort -u > "$TMP/v6.list"

V4_COUNT=$(wc -l < "$TMP/v4.list")
V6_COUNT=$(wc -l < "$TMP/v6.list")

# Sanity: если в списке слишком мало — что-то сломалось, не применяем
if [ "$V4_COUNT" -lt 10 ]; then
    logger -t "$LOG_TAG" "ERROR: только $V4_COUNT IPv4 подсетей — выглядит сломанным, не применяю"
    exit 1
fi

# Атомарный обмен: всё в одной nft-транзакции
{
    echo "flush set inet ddos_protect scanner_blocklist_v4"
    if [ -s "$TMP/v4.list" ]; then
        # Группами по 1000 элементов на add (производительнее чем по одному)
        awk 'NR % 1000 == 1 { if (NR > 1) print "}"; printf "add element inet ddos_protect scanner_blocklist_v4 { " } { printf "%s%s", (NR % 1000 == 1 ? "" : ", "), $0 } END { print " }" }' "$TMP/v4.list"
    fi
    echo "flush set inet ddos_protect scanner_blocklist_v6"
    if [ -s "$TMP/v6.list" ]; then
        awk 'NR % 1000 == 1 { if (NR > 1) print "}"; printf "add element inet ddos_protect scanner_blocklist_v6 { " } { printf "%s%s", (NR % 1000 == 1 ? "" : ", "), $0 } END { print " }" }' "$TMP/v6.list"
    fi
} > "$TMP/nft-batch"

if nft -f "$TMP/nft-batch" 2>"$TMP/nft.err"; then
    logger -t "$LOG_TAG" "Updated: $V4_COUNT IPv4, $V6_COUNT IPv6 подсетей"
    exit 0
else
    logger -t "$LOG_TAG" "ERROR: nft -f failed: $(cat "$TMP/nft.err")"
    exit 1
fi
UPDATER_EOF

chmod 0755 "$UPDATER_SCRIPT"
print_ok "Updater script: $UPDATER_SCRIPT"

# Systemd service + timer
cat > /etc/systemd/system/scanner-blocklist-update.service <<EOF
[Unit]
Description=Update scanner blocklist (Shodan, Censys, gov scanners)
After=network-online.target nftables.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$UPDATER_SCRIPT
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
EOF

cat > /etc/systemd/system/scanner-blocklist-update.timer <<'EOF'
[Unit]
Description=Update scanner blocklist every 6 hours
Requires=scanner-blocklist-update.service

[Timer]
# Первый запуск через 30 секунд после boot (чтобы nft уже точно был готов)
OnBootSec=30s
# Потом каждые 6 часов
OnUnitActiveSec=6h
# Если пропустили запуск (сервер был выключен) — догнать сразу
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable scanner-blocklist-update.timer >/dev/null 2>&1

# Запускаем сразу первый апдейт (blocking)
print_status "Качаю scanner blocklist (первый запуск)..."
if systemctl start scanner-blocklist-update.service; then
    sleep 2
    BLOCKLIST_V4_SIZE=$(nft list set inet ddos_protect scanner_blocklist_v4 2>/dev/null | grep -c '/' || echo 0)
    BLOCKLIST_V6_SIZE=$(nft list set inet ddos_protect scanner_blocklist_v6 2>/dev/null | grep -c '/' || echo 0)
    if [ "$BLOCKLIST_V4_SIZE" -gt 0 ]; then
        print_ok "Blocklist загружен: $BLOCKLIST_V4_SIZE v4 / $BLOCKLIST_V6_SIZE v6 подсетей"
    else
        print_warn "Blocklist пуст — проверь логи: journalctl -u scanner-blocklist-update"
    fi
else
    print_warn "Первый запуск updater'а провалился — продолжаем без blocklist"
    print_info "Проверь: journalctl -u scanner-blocklist-update -n 30"
fi

systemctl start scanner-blocklist-update.timer >/dev/null 2>&1
print_ok "Timer активен (обновление каждые 6 часов)"

# ==============================================================================
# ШАГ 6: УСТАНОВКА CROWDSEC
# ==============================================================================

print_header "ШАГ 6: УСТАНОВКА CROWDSEC"

if ! command -v cscli >/dev/null 2>&1; then
    print_status "Подключаю репозиторий CrowdSec..."
    curl -fsSL https://install.crowdsec.net | bash >/dev/null 2>&1 || {
        print_error "Не удалось подключить репозиторий CrowdSec"
        exit 1
    }
    print_status "Устанавливаю crowdsec..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y crowdsec >/dev/null 2>&1 || {
        print_error "Установка crowdsec провалилась"
        exit 1
    }
fi
print_ok "CrowdSec: $(cscli version 2>&1 | head -1 || echo установлен)"

# Коллекции
# v1.4: убрана crowdsecurity/iptables — она порождает сценарий
# iptables-scan-multi_ports который банит за подключения к разным портам.
# Это ложно срабатывает на VPN-юзеров, у которых в профиле прописано
# несколько Xray-портов (fallback при блокировках). Защита от настоящих
# port-scan'еров теперь делается scanner_blocklist'ом + nft rate-limit'ом.
COLLECTIONS=(
    "crowdsecurity/linux"
    "crowdsecurity/sshd"
)

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

# v1.4: удаляем iptables-коллекцию если осталась с v1.3 (false positive prone)
if cscli collections list 2>/dev/null | grep -q "^crowdsecurity/iptables"; then
    print_status "Удаляю crowdsecurity/iptables (v1.4: ложно банит юзеров)..."
    cscli collections remove crowdsecurity/iptables >/dev/null 2>&1 && \
        print_ok "crowdsecurity/iptables удалена"
fi

# ==============================================================================
# ШАГ 7: SSH-KEY AUTO-WHITELIST
# ==============================================================================

print_header "ШАГ 7: SSH-KEY AUTO-WHITELIST"

# v1.2: динамический whitelist по успешному key-auth.
# Двойная защита:
#   1. Postoverflow-парсер — отбрасывает алерты от whitelisted IP до того,
#      как они дойдут до bouncer'а (защита от собственных сценариев типа
#      ssh-bf, http-crawl-non_statics).
#   2. Decision-whitelist через cscli — перебивает community blocklist.
#      Если твой IP вдруг попал в общий бан-лист (бывает на shared NAT
#      или мобильных провайдерах), ты всё равно зайдёшь.

# --- 6a. Postoverflow parser ---
WHITELIST_PARSER="/etc/crowdsec/postoverflows/s01-whitelist/ssh-key-whitelist.yaml"
mkdir -p "$(dirname "$WHITELIST_PARSER")"

# v1.2: используем уже существующий decision-whitelist через cscli.
# Postoverflow-фильтр проверяет наличие decision'а с типом whitelist.
cat > "$WHITELIST_PARSER" <<'EOF'
# Generated by vpn-node-ddos-protect v1.2
# Сбрасывает overflow-сигналы для IP, которые уже в decisions whitelist.
# Парные decision'ы создаёт сервис cs-ssh-whitelist.service (см. ниже).
name: admin/ssh-key-whitelist
description: "Drop alerts from IPs whitelisted via successful SSH publickey auth"
whitelist:
  reason: "ssh-key-auth dynamic whitelist"
  expression:
    - "evt.Overflow.Sources != nil"
EOF

chmod 0644 "$WHITELIST_PARSER"
print_ok "Postoverflow parser: $WHITELIST_PARSER"

# --- 6b. Watcher script ---
CS_HOOK_SCRIPT="/usr/local/sbin/cs-ssh-key-whitelist.sh"

cat > "$CS_HOOK_SCRIPT" <<'WATCHER_EOF'
#!/bin/bash
# Watches sshd journal for successful publickey logins, adds source IP
# to crowdsec decisions as whitelist for 12h.
# Started by cs-ssh-whitelist.service.
#
# v1.5 SECURITY NOTE: ловится ТОЛЬКО "Accepted publickey".
# Это безопасно даже если PasswordAuthentication=yes:
#   - "Accepted password"        → НЕ whitelist (атакующий с паролем не попадёт)
#   - "Accepted keyboard-..."    → НЕ whitelist
#   - "Accepted publickey"       → whitelist (только владелец ключа)
# Таким образом, скрипт работает корректно в любой конфигурации SSH.

WHITELIST_DURATION="12h"

# Используем journalctl с --since=now чтобы не обрабатывать старые записи
# при перезапуске сервиса (иначе при рестарте можно whitelist'ить IP'шки
# которых давно не существует).
journalctl _SYSTEMD_UNIT=ssh.service _SYSTEMD_UNIT=sshd.service \
    -f -n 0 --output=cat --since=now 2>/dev/null | \
while IFS= read -r line; do
    case "$line" in
        *"Accepted publickey for"*)
            # Парсим: Accepted publickey for USER from IP port PORT ssh2: KEYTYPE FP
            IP=$(printf '%s\n' "$line" | grep -oE 'from [0-9a-fA-F.:]+' | awk '{print $2}')
            USER=$(printf '%s\n' "$line" | grep -oE 'for [^ ]+' | awk '{print $2}')

            # Sanity checks
            case "$IP" in
                ""|127.0.0.1|::1) continue ;;
                *[!0-9a-fA-F.:]*)  continue ;;
            esac

            # Идемпотентность: если IP уже в whitelist — продлеваем (delete + add)
            cscli decisions delete --ip "$IP" --type whitelist >/dev/null 2>&1 || true
            cscli decisions add \
                --ip "$IP" \
                --type whitelist \
                --duration "$WHITELIST_DURATION" \
                --reason "ssh-key-auth user=$USER" >/dev/null 2>&1

            logger -t cs-ssh-whitelist "Whitelisted $IP for $WHITELIST_DURATION (user=$USER)"
            ;;
    esac
done
WATCHER_EOF

chmod 0755 "$CS_HOOK_SCRIPT"
print_ok "Watcher: $CS_HOOK_SCRIPT"

# --- 6c. Systemd unit ---
cat > /etc/systemd/system/cs-ssh-whitelist.service <<EOF
[Unit]
Description=CrowdSec SSH key-auth auto-whitelist
After=crowdsec.service ssh.service systemd-journald.service
Wants=crowdsec.service

[Service]
Type=simple
ExecStart=$CS_HOOK_SCRIPT
Restart=always
RestartSec=10
# Безопасность сервиса
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/log
# Сервису нужны: journalctl (read), cscli (запись decisions через socket).
# cscli работает через /var/run/crowdsec/, поэтому добавляем туда write.
ReadWritePaths=/var/run/crowdsec /run/crowdsec

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

# --- 6d. Bootstrap текущего IP ---
# Сервис стартует ПОСЛЕ crowdsec, но чтобы не ждать первого ре-логина —
# сразу добавим текущий админский IP в whitelist.
if [ -n "$ADMIN_IP" ]; then
    # Сохраним bootstrap-команду на потом — выполним после старта crowdsec
    BOOTSTRAP_IP="$ADMIN_IP"
fi

# ==============================================================================
# ШАГ 8: BAN DURATION (4h — баланс между защитой и ложными срабатываниями)
# ==============================================================================

print_header "ШАГ 8: BAN DURATION"

# v1.4: ban duration возвращён к дефолтным 4h (было 24h в v1.1-1.3).
# Причина: при ложном срабатывании (юзер за CGNAT, общий IP с атакующим)
# 24h блокировки = это пол-дня без VPN. 4h — приемлемо.
# Атакующих ботнетов community blocklist подхватит и забанит снова
# при следующем срабатывании — нет смысла держать долго.

PROFILES_FILE="/etc/crowdsec/profiles.yaml"

if [ -f "$PROFILES_FILE" ]; then
    if [ ! -f "$BACKUP_DIR/profiles.yaml.before" ]; then
        cp -a "$PROFILES_FILE" "$BACKUP_DIR/profiles.yaml.before"
    fi

    # Если стоит 24h (от старой версии этого скрипта) — вернуть на 4h
    if grep -qE "^[[:space:]]*duration:[[:space:]]*24h[[:space:]]*$" "$PROFILES_FILE"; then
        sed -i '0,/^\([[:space:]]*\)duration:[[:space:]]*24h[[:space:]]*$/s//\1duration: 4h/' "$PROFILES_FILE"
        print_ok "Ban duration: 24h → 4h (v1.4 user-friendly)"
    elif grep -qE "^[[:space:]]*duration:[[:space:]]*4h[[:space:]]*$" "$PROFILES_FILE"; then
        print_info "Ban duration уже 4h (дефолт CrowdSec)"
    else
        CURRENT_DURATION=$(grep -m1 -E "^[[:space:]]*duration:" "$PROFILES_FILE" | awk '{print $2}')
        print_info "Ban duration: $CURRENT_DURATION (custom — не трогаю)"
    fi
else
    print_warn "$PROFILES_FILE не найден — пропускаю"
fi

# ==============================================================================
# ШАГ 9: ACQUISITION (источники логов для CrowdSec)
# ==============================================================================

print_header "ШАГ 9: ACQUISITION"

# v1.4: убрана UFW/iptables acquisition. В v1.1-1.3 она питала сценарий
# crowdsecurity/iptables-scan-multi_ports который ложно срабатывал на
# VPN-юзеров с многопортовыми профилями. Без iptables-коллекции и UFW
# acquisition этот сценарий не запускается.
#
# Оставляем только дефолтные acquisition (auth.log, journal) которые
# приходят с коллекцией crowdsecurity/sshd. Они нужны для:
#   - SSH bruteforce detection
#   - regreSSHion (CVE-2024-6387)
#   - SSH-key auto-whitelist watcher

ACQUIS_DIR="/etc/crowdsec/acquis.d"

# Удаляем UFW acquisition если он был создан старой версией скрипта
OLD_UFW_ACQUIS="$ACQUIS_DIR/ufw.yaml"
if [ -f "$OLD_UFW_ACQUIS" ]; then
    if grep -q "vpn-node-ddos-protect" "$OLD_UFW_ACQUIS" 2>/dev/null; then
        rm -f "$OLD_UFW_ACQUIS"
        print_ok "Удалён UFW acquisition (v1.4: source для ложных банов)"
    fi
fi

# Проверим что SSH acquisition (от sshd-коллекции) на месте
if cscli collections list 2>/dev/null | grep -q "^crowdsecurity/sshd"; then
    print_ok "SSH acquisition активен (через crowdsecurity/sshd)"
else
    print_warn "crowdsecurity/sshd не установлен — SSH-логи не парсятся"
fi

# ==============================================================================
# ШАГ 10: NFTABLES BOUNCER
# ==============================================================================

print_header "ШАГ 10: NFTABLES BOUNCER"

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
systemctl enable --now cs-ssh-whitelist >/dev/null 2>&1 || true

sleep 3

# Bootstrap: добавляем текущий IP в whitelist (после старта crowdsec)
if [ -n "${BOOTSTRAP_IP:-}" ]; then
    if cscli decisions add --ip "$BOOTSTRAP_IP" --type whitelist \
        --duration 12h --reason "ssh-key-auth bootstrap" >/dev/null 2>&1; then
        print_ok "Bootstrap whitelist: $BOOTSTRAP_IP на 12h"
    else
        print_warn "Не удалось добавить bootstrap whitelist (crowdsec не готов)"
        print_info "Это ок — при следующем SSH-логине сработает auto-whitelist"
    fi
fi

if systemctl is-active --quiet crowdsec && systemctl is-active --quiet crowdsec-firewall-bouncer; then
    print_ok "crowdsec + bouncer активны"
else
    print_warn "Один из сервисов не active:"
    systemctl is-active crowdsec || print_error "  crowdsec НЕ active"
    systemctl is-active crowdsec-firewall-bouncer || print_error "  bouncer НЕ active"
    print_info "Логи: journalctl -u crowdsec -u crowdsec-firewall-bouncer -n 50"
fi

if systemctl is-active --quiet cs-ssh-whitelist; then
    print_ok "cs-ssh-whitelist активен (мониторит SSH-логины)"
else
    print_warn "cs-ssh-whitelist НЕ active"
    print_info "Логи: journalctl -u cs-ssh-whitelist -n 50"
fi

# ==============================================================================
# ШАГ 11: HEALTHCHECK
# ==============================================================================

print_header "ШАГ 11: HEALTHCHECK"

print_info "Жду 5 секунд чтобы парсеры успели прочитать логи..."
sleep 5

print_status "CrowdSec metrics:"
echo ""
# v1.5 fix: head закрывает pipe раньше времени → SIGPIPE → false-negative.
# Сохраняем в переменную, потом печатаем — без pipe-зависимости.
METRICS_OUT=$(cscli metrics 2>/dev/null)
if [ -n "$METRICS_OUT" ]; then
    echo "$METRICS_OUT" | head -50 | sed 's/^/    /'
else
    print_warn "cscli metrics вернул пусто — проверь journalctl -u crowdsec"
fi
echo ""

ACTIVE_BANS=$(cscli decisions list --type ban -o raw 2>/dev/null | tail -n +2 | wc -l)
ACTIVE_WHITELIST=$(cscli decisions list --type whitelist -o raw 2>/dev/null | tail -n +2 | wc -l)

if [ "$ACTIVE_BANS" -gt 0 ]; then
    print_ok "Активных банов: $ACTIVE_BANS"
else
    print_info "Активных банов нет (норма для свежей установки)"
fi

if [ "$ACTIVE_WHITELIST" -gt 0 ]; then
    print_ok "Активных whitelist-decision'ов: $ACTIVE_WHITELIST"
fi

# v1.3: scanner blocklist size
BL_V4=$(nft list set inet ddos_protect scanner_blocklist_v4 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?' | wc -l)
BL_V6=$(nft list set inet ddos_protect scanner_blocklist_v6 2>/dev/null | grep -c ':' || echo 0)
if [ "$BL_V4" -gt 0 ] || [ "$BL_V6" -gt 0 ]; then
    print_ok "Scanner blocklist: $BL_V4 v4 / $BL_V6 v6 подсетей"
else
    print_warn "Scanner blocklist пуст — проверь journalctl -u scanner-blocklist-update"
fi

# ==============================================================================
# ШАГ 12: ИТОГИ
# ==============================================================================

print_header "ГОТОВО"

echo -e "  ${BOLD}Что настроено:${NC}"
echo -e "  ├─ ${GREEN}✔${NC} nft rate-limit: 60 SYN/sec на IP burst 100 (CGNAT-friendly)"
echo -e "  ├─ ${GREEN}✔${NC} ${BOLD}Scanner blocklist:${NC} pre-emptive drop известных сканеров"
echo -e "  │   └─ обновление каждые 6 часов из shadow-netlab/traffic-guard-lists"
echo -e "  ├─ ${GREEN}✔${NC} Защищённые порты: ${CYAN}$XRAY_PORTS${NC}"
echo -e "  ├─ ${GREEN}✔${NC} SSH порт ${CYAN}$SSH_PORT${NC} исключён из rate-limit"
echo -e "  ├─ ${GREEN}✔${NC} ${BOLD}SSH-key auto-whitelist:${NC} 12h после успешного входа по ключу"
[ -n "$ADMIN_IP" ] && echo -e "  ├─ ${GREEN}✔${NC} Bootstrap whitelist: ${CYAN}$ADMIN_IP${NC}"
echo -e "  ├─ ${GREEN}✔${NC} CrowdSec collections: linux + sshd"
echo -e "  ├─ ${GREEN}✔${NC} ssh-cve-2024-6387 (regreSSHion) активен"
echo -e "  ├─ ${GREEN}✔${NC} Ban duration: 4h (user-friendly)"
echo -e "  ├─ ${GREEN}✔${NC} Community blocklist: автообновление каждые 2 часа"
echo -e "  └─ ${GREEN}✔${NC} nftables bouncer применяет CrowdSec decisions"
echo ""

# v1.5: уровень защиты в зависимости от SSH-конфига
if [ "${SSHD_PASSWORD_AUTH_ENABLED:-0}" = "1" ]; then
    echo -e "  ${BOLD}${YELLOW}⚠ Уровень защиты: ХОРОШИЙ${NC} (90% максимума)"
    echo -e "  Сервер защищён от:"
    echo -e "  ${GREEN}✔${NC} DDoS / SYN-flood / port-scan атак"
    echo -e "  ${GREEN}✔${NC} Известных сканеров (Shodan/Censys/gov)"
    echo -e "  ${GREEN}✔${NC} SSH brute-force через CrowdSec"
    echo -e "  ${GREEN}✔${NC} regreSSHion (CVE-2024-6387)"
    echo ""
    echo -e "  ${BOLD}${YELLOW}Чтобы получить МАКСИМАЛЬНУЮ защиту:${NC}"
    echo -e "  ${BOLD}1.${NC} На локальной машине сгенерируй SSH-ключ:"
    echo -e "     ${CYAN}ssh-keygen -t ed25519 -f ~/.ssh/vpn_admin${NC}"
    echo -e "  ${BOLD}2.${NC} Скопируй публичный ключ на сервер:"
    echo -e "     ${CYAN}ssh-copy-id -i ~/.ssh/vpn_admin.pub root@$(hostname -I | awk '{print $1}')${NC}"
    echo -e "  ${BOLD}3.${NC} Проверь что заходит без пароля:"
    echo -e "     ${CYAN}ssh -i ~/.ssh/vpn_admin root@$(hostname -I | awk '{print $1}')${NC}"
    echo -e "  ${BOLD}4.${NC} ${BOLD}Только после успешной проверки${NC} — отключи пароль:"
    echo -e "     ${CYAN}sed -i 's/^[#[:space:]]*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config${NC}"
    echo -e "     ${CYAN}sed -i 's/^[#[:space:]]*KbdInteractiveAuthentication.*/KbdInteractiveAuthentication no/' /etc/ssh/sshd_config${NC}"
    echo -e "     ${CYAN}sshd -t && systemctl reload ssh${NC}"
    echo ""
else
    echo -e "  ${BOLD}${GREEN}✔ Уровень защиты: МАКСИМАЛЬНЫЙ${NC}"
    echo -e "  Password-auth выключен, защита SSH работает на полную"
    echo ""
fi

echo -e "  ${BOLD}Многоуровневая защита (по приоритету):${NC}"
echo -e "  1. ${CYAN}Manual whitelist${NC}      → твои runtime-добавленные IP"
echo -e "  2. ${CYAN}SSH (порт $SSH_PORT)${NC}      → пропуск (защищает CrowdSec)"
echo -e "  3. ${CYAN}Scanner blocklist${NC}     → drop известных сканеров (Shodan, Censys, gov)"
echo -e "  4. ${CYAN}SYN-flood rate-limit${NC}  → 60/sec burst 100 на Xray (CGNAT-friendly)"
echo -e "  5. ${CYAN}CrowdSec bouncer${NC}      → бан по поведению (SSH brute-force only)"
echo ""
echo -e "  ${BOLD}${GREEN}User-friendly defaults:${NC}"
echo -e "  ${GREEN}✔${NC} Юзеры за CGNAT (мобильные операторы) не банятся — лимит 60/sec"
echo -e "  ${GREEN}✔${NC} Профили с несколькими Xray-портами не банятся как 'port-scan'"
echo -e "  ${GREEN}✔${NC} Ложные баны живут 4h вместо 24h"
echo -e "  ${GREEN}✔${NC} Юзеры из подсетей в blocklist (~0.007% всего IPv4) — это"
echo -e "      реальные госсканеры/Shodan/Censys, не домашние пользователи"
echo ""
echo -e "  ${BOLD}Как работает auto-whitelist:${NC}"
echo -e "  1. Заходишь по SSH с приватным ключом с ЛЮБОГО IP"
echo -e "  2. ${CYAN}cs-ssh-whitelist${NC} ловит \"Accepted publickey\" в журнале"
echo -e "  3. ${CYAN}cscli decisions add --type whitelist --duration 12h${NC}"
echo -e "  4. Этот IP игнорирует все CrowdSec-баны (свои + community) на 12h"
echo -e "  5. IP сменился → новый заход по ключу → новый whitelist"
echo -e "  ${MAGENTA}ℹ${NC} Безопасно даже при включённом password-auth: ловится ТОЛЬКО"
echo -e "     'Accepted publickey'. Юзер с подобранным паролем НЕ попадёт в whitelist."
echo ""
echo -e "  ${BOLD}Полезные команды:${NC}"
echo -e "  ${CYAN}cscli decisions list --type whitelist${NC}              # текущие whitelist'ы"
echo -e "  ${CYAN}cscli decisions list --type ban${NC}                    # активные баны"
echo -e "  ${CYAN}journalctl -u cs-ssh-whitelist -f${NC}                  # логи SSH-watcher'а"
echo -e "  ${CYAN}journalctl -u scanner-blocklist-update${NC}             # логи blocklist updater"
echo -e "  ${CYAN}systemctl list-timers scanner-blocklist-update${NC}     # когда след. обновление"
echo -e "  ${CYAN}cscli metrics${NC}                                      # статистика парсеров"
echo -e "  ${CYAN}nft list set inet ddos_protect syn_flood_v4${NC}        # SYN-флуд бан-сет"
echo -e "  ${CYAN}nft list set inet ddos_protect scanner_blocklist_v4 | wc -l${NC}  # размер blocklist"
echo ""
echo -e "  ${BOLD}Принудительное обновление blocklist:${NC}"
echo -e "  ${CYAN}systemctl start scanner-blocklist-update.service${NC}"
echo ""
echo -e "  ${BOLD}Если потерял доступ и забанен:${NC}"
echo -e "  Зайти через консоль провайдера (KVM/VNC) и:"
echo -e "  ${CYAN}cscli decisions delete --ip <твой_IP>${NC}"
echo -e "  ${CYAN}nft add element inet ddos_protect manual_whitelist_v4 { <твой_IP> }${NC}"
echo ""
echo -e "  ${BOLD}Бэкап:${NC} ${CYAN}$BACKUP_DIR${NC}"
echo ""
# v1.5 fix: при запуске через pipe (curl ... | bash) или process substitution
# $0 может быть /dev/fd/63 — некрасиво в выводе. Используем имя файла
# скрипта если оно валидное, иначе показываем generic-команду.
SCRIPT_NAME="$0"
case "$SCRIPT_NAME" in
    /dev/fd/*|/proc/*|bash|-bash|sh|-sh)
        SCRIPT_NAME="vpn-node-ddos-protect-v1_5.sh"
        ;;
esac
echo -e "  ${BOLD}Удалить всё:${NC} ${CYAN}sudo bash $SCRIPT_NAME --uninstall${NC}"
echo ""
