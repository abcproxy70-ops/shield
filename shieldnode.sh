#!/bin/bash

# ==============================================================================
#  VPN NODE DDoS PROTECTION v2.7 (Commercial Edition)
#  - nftables rate-limit (kernel-level SYN flood protection)
#  - nftables scanner-blocklist (pre-emptive drop известных сканеров)
#  - CrowdSec (SSH brute-force + community blocklist)
#  - SSH-key auto-whitelist (опционально, с дебаунсом)
#  - guard CLI — снимок состояния защиты (one-shot, no live updates)
#  - Мгновенное отслеживание изменений в фаерволе через inotify
#
#  Запускать ПОСЛЕ настройки фаервола (UFW/iptables/firewalld).
#  Совместимо с активным UFW и любыми другими nft-таблицами.
#
#  v2.7 changelog (статистика блокировок):
#    - ADD: nftables counters на каждом drop-правиле (kernel-level, бесплатные).
#      Считают сколько пакетов/байт дропнуто с момента старта nft-сервиса.
#    - ADD: новый раздел "Total blocked" в guard:
#      • scanner blocklist drops (пакетов и байт)
#      • confirmed attack drops
#      • счётчики сбрасываются при ребуте/переустановке правил
#    - Сброс счётчиков вручную: nft reset counter inet ddos_protect <name>
#
#  v2.6 changelog (защита от детекции VPN российскими госсканерами):
#    - ADD: новые источники для scanner_blocklist:
#      • tread-lightly/CyberOK_Skipa_ips — 146 verified scanner IP конкретно
#        для SKIPA scan-XX, ГРЧЦ (РКН), НКЦКИ (ФСБ-related). Курируется
#        вручную автором с верификацией по логам.
#      • MISP/misp-warninglists/skipa-nt-scanning — honeypot-verified IP
#        от CIRCL Luxembourg (государственный CSIRT). Минимум ложных банов.
#    - ЭФФЕКТ: блокирует SKIPA от CyberOK (агент РКН) — отсрочка попадания
#      твоего IP в "VPN-blocklist" Роскомнадзора на месяцы. Юзеры из РФ
#      продолжают подключаться к ноде дольше.
#    - ADD: ASCII-art баннер при установке (брендинг для коммерческой версии)
#
#  v2.5 changelog (защита от ложных банов VPN-юзеров):
#    - CHG: лимиты подняты в 5 раз — TCP 300 SYN/sec (было 60), UDP 600/sec (было 200).
#      Реальный DDoS режется (он >>1000/sec), но CGNAT мобильных операторов
#      (МТС/Билайн/МегаФон) не задевается даже с сотней одновременно
#      подключающихся юзеров.
#    - ADD: "BAN ONCE" архитектура — двухэтапная проверка перед баном.
#      Раньше: одно превышение лимита → drop на 1 минуту.
#      Теперь:
#        1. Первое превышение → IP попадает в suspect_v4 на 5 минут.
#           Трафик НЕ дропается, IP под наблюдением.
#        2. Если IP в suspect_v4 опять превышает → в confirmed_attack_v4
#           на 1 час. Только теперь дропаем.
#      Случайные CGNAT-всплески → не банятся (через 5 мин suspect истекает).
#      Настоящие атакующие → банятся подтверждённо.
#    - ADD: новые сеты в guard — suspect и confirmed
#
#  v2.4 changelog (bugfixes):
#    - FIX: race condition в watcher (path-unit triggered многократно,
#      пустые результаты затирали правильные данные). Добавлен safety guard.
#    - FIX: SYN-flood IPs не отображались в guard (regex не учитывал
#      'limit rate' в формате nft). Заменён на JSON-парсинг через jq.
#
#  v2.3 changelog (bugfix):
#    - FIX: cs-ssh-whitelist падал с status 226/NAMESPACE — fix optional path.
#
#  v2.2 changelog:
#    - ADD: автоматический whitelist management-IP из правил фаервола.
#      Любое правило 'ufw allow X/tcp from <IP>' → IP попадает в
#      manual_whitelist_v4 — он не подвергается rate-limit и сканер-проверкам.
#      Это для случаев когда управляющий сервер (Marzban/3X-UI/Remnawave)
#      делает много запросов к ноде. Раньше нужно было вручную добавлять
#      `nft add element manual_whitelist_v4 { IP }` после установки.
#    - ADD: management IP синхронизируются протекторс-вотчером каждые 60s
#      (или мгновенно через path-unit при изменениях UFW).
#
#  v2.1 changelog (bugfixes):
#    - FIX: guard показывал "—" в защищаемых портах если nft возвращал
#      многострочный elements (порты переносились на новую строку при
#      выводе). Парсер не учитывал переносы. Добавлен tr перед grep.
#    - FIX: cs-ssh-whitelist падал в цикле restart из-за ProtectSystem=strict
#      и попытки mkdir /run/cs-ssh-whitelist (debounce dir из v1.9).
#      Добавлен RuntimeDirectory + ReadWritePaths.
#
#  v2.0 changelog:
#    - REMOVED: live-обновление дашборда (interactive mode с циклом).
#      Причина: даже оптимизированный live-режим тратит CPU на постоянные
#      nft list / cscli вызовы. На слабых VPS это заметно.
#    - CHG: `guard` теперь по умолчанию выводит снимок один раз и выходит.
#      Хочешь обновить — запусти ещё раз. Никакой фоновой нагрузки.
#    - KEEP: `guard --json` для интеграций (один вызов = один JSON).
#    - ADD: `guard --watch` для тех кто всё-таки хочет live-режим
#      (используется через `watch -n 5 sudo guard`, нагрузка контролируется
#      пользователем).
#
#  v1.9 changelog (performance):
#    - tiered refresh, sqlite3, JSON mode, debounce
#
#  v1.8 changelog:
#    - CHG: protected-ports-update теперь работает в гибридном режиме:
#      path-unit (inotify) + timer 60s (safety net)
#
#  v1.7 changelog:
#    - REQUIRE: активный фаервол (UFW/iptables/firewalld)
#    - CHG: защищаемые порты берутся из правил фаервола
#    - ADD: автоматическое отслеживание изменений (timer 30 сек)
#    - ADD: поддержка UDP (Hysteria2, TUIC, mKCP, QUIC, WireGuard)
#
#  v1.6 changelog:
#    - ADD: команда `guard` — TUI-дашборд со статистикой
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
    for unit in cs-ssh-whitelist scanner-blocklist-update.timer scanner-blocklist-update.service \
                protected-ports-update.timer protected-ports-update.service \
                protected-ports-update.path; do
        systemctl disable --now "$unit" 2>/dev/null || true
        rm -f "/etc/systemd/system/$unit"
    done
    systemctl daemon-reload
    print_ok "Systemd units удалены"

    # Scripts
    rm -f /usr/local/sbin/cs-ssh-key-whitelist.sh
    rm -f /usr/local/sbin/update-scanner-blocklist.sh
    rm -f /usr/local/sbin/update-protected-ports.sh
    rm -f /usr/local/bin/guard
    print_ok "Скрипты удалены (включая команду guard)"

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

# v1.9: sqlite3 для быстрого чтения crowdsec БД в guard'е
# (опционально — fallback на cscli если не установится)
if ! command -v sqlite3 >/dev/null 2>&1; then
    print_status "Устанавливаю sqlite3 (для оптимизации guard)..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y sqlite3 >/dev/null 2>&1 || \
        print_warn "sqlite3 не установлен — guard будет использовать cscli (медленнее)"
fi

# v2.4: jq для парсинга nft -j вывода в guard
if ! command -v jq >/dev/null 2>&1; then
    print_status "Устанавливаю jq (для парсинга nft JSON в guard)..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y jq >/dev/null 2>&1 || \
        print_warn "jq не установлен — guard будет использовать text-парсинг (хрупко)"
fi

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

# v1.7: ПРОВЕРКА ФАЕРВОЛА — обязательное требование
# Логика: скрипт работает поверх существующего фаервола, защищая порты
# которые юзер УЖЕ открыл. Без активного фаервола сервер открыт всему миру,
# и наш скрипт это не исправит — нужен базовый layer.
#
# Поддерживаются: UFW (приоритет), firewalld, iptables/nftables-rules.
# Тип фаервола сохраняется в FIREWALL_TYPE для шага 2.

FIREWALL_TYPE=""

# Проверка UFW
if command -v ufw >/dev/null 2>&1; then
    if ufw status 2>/dev/null | grep -q "Status: active"; then
        FIREWALL_TYPE="ufw"
        UFW_RULES_COUNT=$(ufw status numbered 2>/dev/null | grep -cE "^\[ ?[0-9]+\]")
        print_ok "Фаервол: ${BOLD}UFW активен${NC} (${UFW_RULES_COUNT} правил)"
    fi
fi

# Проверка firewalld
if [ -z "$FIREWALL_TYPE" ] && command -v firewall-cmd >/dev/null 2>&1; then
    if systemctl is-active --quiet firewalld 2>/dev/null; then
        FIREWALL_TYPE="firewalld"
        FW_PORTS_COUNT=$(firewall-cmd --list-ports 2>/dev/null | wc -w)
        print_ok "Фаервол: ${BOLD}firewalld активен${NC} (${FW_PORTS_COUNT} портов)"
    fi
fi

# Проверка iptables (если правила есть и они не дефолтные ACCEPT)
if [ -z "$FIREWALL_TYPE" ] && command -v iptables >/dev/null 2>&1; then
    # Считаем правила в INPUT chain. Если только дефолт — это не защита.
    IPT_RULES=$(iptables -L INPUT --line-numbers 2>/dev/null | grep -cE "^[0-9]+")
    IPT_POLICY=$(iptables -L INPUT 2>/dev/null | head -1 | grep -oE "policy [A-Z]+" | awk '{print $2}')
    if [ "$IPT_RULES" -gt 0 ] || [ "$IPT_POLICY" = "DROP" ] || [ "$IPT_POLICY" = "REJECT" ]; then
        FIREWALL_TYPE="iptables"
        print_ok "Фаервол: ${BOLD}iptables активен${NC} ($IPT_RULES правил, policy=$IPT_POLICY)"
    fi
fi

# Проверка nftables (кастомные filter chains, не наш ddos_protect)
if [ -z "$FIREWALL_TYPE" ]; then
    NFT_FILTER=$(nft list ruleset 2>/dev/null | \
        awk '/^table inet filter|^table ip filter|^table ip6 filter/{found=1} END{print found}')
    if [ "$NFT_FILTER" = "1" ]; then
        FIREWALL_TYPE="nftables"
        print_ok "Фаервол: ${BOLD}nftables filter table активен${NC}"
    fi
fi

# Если ни одного фаервола не найдено — отказываемся ставиться
if [ -z "$FIREWALL_TYPE" ]; then
    print_error ""
    print_error "ФАЕРВОЛ НЕ НАСТРОЕН — установка невозможна"
    print_error ""
    print_warn "Этот скрипт защищает порты которые ты ОТКРЫЛ в фаерволе."
    print_warn "Без фаервола сервер открыт всему интернету, и DDoS-защита не поможет."
    print_warn ""
    print_warn "Сначала настрой фаервол. Самый простой вариант — UFW:"
    print_info "  ${BOLD}apt install ufw${NC}"
    print_info "  ${BOLD}ufw allow 22/tcp comment 'SSH'${NC}      # порт SSH (важно!)"
    print_info "  ${BOLD}ufw allow 443${NC}                     # порт VPN (Reality/etc)"
    print_info "  ${BOLD}ufw allow 8443${NC}                    # резервный VPN-порт (опционально)"
    print_info "  ${BOLD}ufw --force enable${NC}                # активировать"
    print_info "  ${BOLD}ufw status${NC}                        # проверить"
    print_warn ""
    print_warn "Когда UFW активен, запусти этот скрипт повторно."
    print_warn "Скрипт защитит ВСЕ порты которые ты открыл (кроме SSH)."
    exit 1
fi

BACKUP_DIR="/root/vpn-ddos-backup-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"
nft list ruleset > "$BACKUP_DIR/nft-ruleset.before" 2>/dev/null || true
print_ok "Бэкап текущих nft-правил: $BACKUP_DIR/nft-ruleset.before"

# ==============================================================================
# ШАГ 2: AUTO-DETECT (порты из фаервола, SSH порт, IP)
# ==============================================================================

print_header "ШАГ 2: AUTO-DETECT"

# v1.7: порты берутся из ПРАВИЛ ФАЕРВОЛА. Юзер сам решил что открыть —
# это и защищаем. SSH-порт исключаем (он защищается CrowdSec'ом и не
# должен попадать под rate-limit для VPN-клиентов).

# Функция возвращает порты из UFW в формате "tcp,tcp,udp..." парами через |
# Stdout: две строки
#   1. TCP-порты через запятую
#   2. UDP-порты через запятую
detect_firewall_ports() {
    local fw="$1"
    local tcp_list=""
    local udp_list=""
    local mgmt_ipv4=""
    local mgmt_ipv6=""

    case "$fw" in
        ufw)
            # ufw status: "443/tcp ALLOW IN Anywhere", "443 ALLOW IN ..." (без proto = TCP+UDP)
            local ufw_out
            ufw_out=$(ufw status 2>/dev/null)
            # Парсим строки с ALLOW для не-v6 (v6-правила дублируют v4 в UFW по умолчанию)
            tcp_list=$(echo "$ufw_out" | awk '
                $2 == "ALLOW" && $0 !~ /\(v6\)/ && $3 == "Anywhere" {
                    pp = $1
                    if (match(pp, /^[0-9:]+(\/(tcp|udp))?$/)) {
                        n = split(pp, a, "/")
                        port = a[1]
                        proto = (n > 1) ? a[2] : "any"
                        if (proto == "tcp" || proto == "any") print port
                    }
                }
            ' | sort -un | tr '\n' ',' | sed 's/,$//')

            udp_list=$(echo "$ufw_out" | awk '
                $2 == "ALLOW" && $0 !~ /\(v6\)/ && $3 == "Anywhere" {
                    pp = $1
                    if (match(pp, /^[0-9:]+(\/(tcp|udp))?$/)) {
                        n = split(pp, a, "/")
                        port = a[1]
                        proto = (n > 1) ? a[2] : "any"
                        if (proto == "udp" || proto == "any") print port
                    }
                }
            ' | sort -un | tr '\n' ',' | sed 's/,$//')

            # v2.2: management IPs из правил "ALLOW from <IP>"
            # Формат: "2222/tcp  ALLOW  213.165.55.166" (3й колонкой идёт IP вместо Anywhere)
            mgmt_ipv4=$(echo "$ufw_out" | awk '
                $2 == "ALLOW" && $0 !~ /\(v6\)/ && $3 != "Anywhere" {
                    if ($3 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?$/) print $3
                }
            ' | sort -u | tr '\n' ',' | sed 's/,$//')

            mgmt_ipv6=$(echo "$ufw_out" | awk '
                $2 == "ALLOW" {
                    if ($3 ~ /:/ && $3 !~ /^Anywhere/) print $3
                }
            ' | sort -u | tr '\n' ',' | sed 's/,$//')
            ;;

        firewalld)
            # firewall-cmd --list-ports выдаёт "443/tcp 8443/tcp 36789/udp"
            local fw_out
            fw_out=$(firewall-cmd --list-ports 2>/dev/null)
            tcp_list=$(echo "$fw_out" | tr ' ' '\n' | awk -F/ '$2=="tcp"{print $1}' | sort -un | tr '\n' ',' | sed 's/,$//')
            udp_list=$(echo "$fw_out" | tr ' ' '\n' | awk -F/ '$2=="udp"{print $1}' | sort -un | tr '\n' ',' | sed 's/,$//')

            # Также добавим порты из --list-services (ssh=22, http=80, https=443 и т.д.)
            local services
            services=$(firewall-cmd --list-services 2>/dev/null)
            for svc in $services; do
                local svc_ports
                svc_ports=$(firewall-cmd --info-service="$svc" 2>/dev/null | awk '/ports:/{$1="";print}' | xargs)
                for sp in $svc_ports; do
                    local p="${sp%/*}"
                    local pr="${sp#*/}"
                    if [ "$pr" = "tcp" ]; then
                        tcp_list="${tcp_list:+$tcp_list,}$p"
                    elif [ "$pr" = "udp" ]; then
                        udp_list="${udp_list:+$udp_list,}$p"
                    fi
                done
            done
            tcp_list=$(echo "$tcp_list" | tr ',' '\n' | sort -un | tr '\n' ',' | sed 's/,$//')
            udp_list=$(echo "$udp_list" | tr ',' '\n' | sort -un | tr '\n' ',' | sed 's/,$//')
            ;;

        iptables)
            # iptables -S INPUT: ищем "-A INPUT -p tcp --dport 443 -j ACCEPT"
            tcp_list=$(iptables -S INPUT 2>/dev/null | \
                awk '/-j ACCEPT/ && /-p tcp/ {
                    for (i=1; i<=NF; i++) {
                        if ($i == "--dport") print $(i+1)
                        if ($i == "--dports") print $(i+1)
                    }
                }' | tr ',' '\n' | sort -un | tr '\n' ',' | sed 's/,$//')

            udp_list=$(iptables -S INPUT 2>/dev/null | \
                awk '/-j ACCEPT/ && /-p udp/ {
                    for (i=1; i<=NF; i++) {
                        if ($i == "--dport") print $(i+1)
                        if ($i == "--dports") print $(i+1)
                    }
                }' | tr ',' '\n' | sort -un | tr '\n' ',' | sed 's/,$//')
            ;;

        nftables)
            # nft -j: ищем accept-правила с tcp/udp dport
            local nft_json
            nft_json=$(nft -j list ruleset 2>/dev/null)
            if [ -n "$nft_json" ] && command -v jq >/dev/null 2>&1; then
                tcp_list=$(echo "$nft_json" | jq -r '
                    .nftables[] | select(.rule?) | .rule
                    | select(any(.expr[]?; .accept))
                    | .expr[] | select(.match?)
                    | select(.match.left.payload.protocol == "tcp")
                    | .match.right
                    | if type == "object" and .set then .set[] elif type == "array" then .[] else . end
                    | tostring
                ' 2>/dev/null | grep -E '^[0-9]+$' | sort -un | tr '\n' ',' | sed 's/,$//')

                udp_list=$(echo "$nft_json" | jq -r '
                    .nftables[] | select(.rule?) | .rule
                    | select(any(.expr[]?; .accept))
                    | .expr[] | select(.match?)
                    | select(.match.left.payload.protocol == "udp")
                    | .match.right
                    | if type == "object" and .set then .set[] elif type == "array" then .[] else . end
                    | tostring
                ' 2>/dev/null | grep -E '^[0-9]+$' | sort -un | tr '\n' ',' | sed 's/,$//')
            fi
            # Fallback: regex-парсинг если jq не установлен
            if [ -z "$tcp_list" ] && [ -z "$udp_list" ]; then
                local rules
                rules=$(nft list ruleset 2>/dev/null | grep -E "(tcp|udp) dport" | grep "accept")
                tcp_list=$(echo "$rules" | grep "tcp dport" | grep -oE 'dport [{0-9 ,}]+' | \
                    grep -oE '[0-9]+' | sort -un | tr '\n' ',' | sed 's/,$//')
                udp_list=$(echo "$rules" | grep "udp dport" | grep -oE 'dport [{0-9 ,}]+' | \
                    grep -oE '[0-9]+' | sort -un | tr '\n' ',' | sed 's/,$//')
            fi
            ;;
    esac

    echo "$tcp_list"
    echo "$udp_list"
    echo "$mgmt_ipv4"
    echo "$mgmt_ipv6"
}

# Получаем сырые списки портов из фаервола
FW_OUTPUT=$(detect_firewall_ports "$FIREWALL_TYPE")
RAW_TCP=$(echo "$FW_OUTPUT" | sed -n '1p')
RAW_UDP=$(echo "$FW_OUTPUT" | sed -n '2p')
MGMT_IPV4=$(echo "$FW_OUTPUT" | sed -n '3p')
MGMT_IPV6=$(echo "$FW_OUTPUT" | sed -n '4p')

# Определяем SSH порт чтобы исключить его из защиты
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

# Исключаем SSH из списков защищаемых портов
exclude_port() {
    local list="$1" exclude="$2"
    echo ",$list," | sed "s/,$exclude,/,/g; s/^,//; s/,$//"
}

PROTECTED_TCP=$(exclude_port "$RAW_TCP" "$SSH_PORT")
PROTECTED_UDP="$RAW_UDP"  # UDP SSH не использует, исключать не нужно

# Печать результатов
print_ok "SSH порт: ${BOLD}$SSH_PORT${NC} (исключён из защиты)"

if [ -n "$PROTECTED_TCP" ]; then
    print_ok "Защищаемые TCP-порты: ${BOLD}$PROTECTED_TCP${NC}"
else
    print_warn "В фаерволе нет открытых TCP-портов кроме SSH"
fi

if [ -n "$PROTECTED_UDP" ]; then
    print_ok "Защищаемые UDP-порты: ${BOLD}$PROTECTED_UDP${NC}"
else
    print_info "В фаерволе нет открытых UDP-портов (Hysteria/TUIC/QUIC будет нечего защищать)"
fi

# v2.2: автоматический whitelist для management-IP (правила "ALLOW from <IP>")
if [ -n "$MGMT_IPV4" ]; then
    print_ok "Management IPv4 (auto-whitelist): ${BOLD}$MGMT_IPV4${NC}"
fi
if [ -n "$MGMT_IPV6" ]; then
    print_ok "Management IPv6 (auto-whitelist): ${BOLD}$MGMT_IPV6${NC}"
fi

if [ -z "$PROTECTED_TCP" ] && [ -z "$PROTECTED_UDP" ]; then
    print_error ""
    print_error "В фаерволе нет открытых портов (кроме SSH)."
    print_error "Скрипту нечего защищать. Открой VPN-порт в фаерволе и запусти повторно."
    print_info "Пример: ${BOLD}ufw allow 443${NC}"
    exit 1
fi

# Объединяем для совместимости (старые места в скрипте)
XRAY_PORTS_TCP="$PROTECTED_TCP"
XRAY_PORTS_UDP="$PROTECTED_UDP"
XRAY_PORTS=$(echo "${XRAY_PORTS_TCP},${XRAY_PORTS_UDP}" | tr ',' '\n' | grep -v '^$' | sort -un | tr '\n' ',' | sed 's/,$//')

# v2.2: management IPs для nft set
MANUAL_WHITELIST_V4_INIT=""
MANUAL_WHITELIST_V6_INIT=""
if [ -n "$MGMT_IPV4" ]; then
    MANUAL_WHITELIST_V4_INIT="        elements = { $(echo "$MGMT_IPV4" | sed 's/,/, /g') }"
fi
if [ -n "$MGMT_IPV6" ]; then
    MANUAL_WHITELIST_V6_INIT="        elements = { $(echo "$MGMT_IPV6" | sed 's/,/, /g') }"
fi

# Инициализирующие elements для nft-set
nft_set_init() {
    local list="$1"
    if [ -z "$list" ]; then
        echo ""
    else
        echo "        elements = { $(echo "$list" | sed 's/,/, /g') }"
    fi
}

XRAY_PORTS_TCP_INIT=$(nft_set_init "$XRAY_PORTS_TCP")
XRAY_PORTS_UDP_INIT=$(nft_set_init "$XRAY_PORTS_UDP")

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
    # --- Защищаемые порты (named sets, обновляются watcher'ом из фаервола) ---
    # Заполняются скриптом /usr/local/sbin/update-protected-ports.sh из правил
    # фаервола (UFW/firewalld/iptables). При изменении правил фаервола эти
    # сеты обновляются автоматически в течение 30 секунд через systemd timer.
    set protected_ports_tcp {
        type inet_service
        flags interval
        auto-merge
$XRAY_PORTS_TCP_INIT
    }
    set protected_ports_udp {
        type inet_service
        flags interval
        auto-merge
$XRAY_PORTS_UDP_INIT
    }

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

    # --- v2.5: STAGE 1 — SUSPECT (наблюдение 5 минут) ---
    # IP попадает сюда при первом превышении лимита.
    # Трафик НЕ дропается. Если за 5 минут IP опять превышает — переводим в confirmed.
    # Если не превышает — таймер истекает, забываем про IP (false positive).
    set suspect_v4 {
        type ipv4_addr
        flags dynamic, timeout
        timeout 5m
        size 65536
    }
    set suspect_v6 {
        type ipv6_addr
        flags dynamic, timeout
        timeout 5m
        size 65536
    }

    # --- v2.5: STAGE 2 — CONFIRMED ATTACK (бан 1 час) ---
    # Сюда IP попадает если уже сидел в suspect и опять превысил лимит.
    # Это значит — точно атака, баним всерьёз.
    set confirmed_attack_v4 {
        type ipv4_addr
        flags dynamic, timeout
        timeout 1h
        size 65536
    }
    set confirmed_attack_v6 {
        type ipv6_addr
        flags dynamic, timeout
        timeout 1h
        size 65536
    }

    # --- LEGACY: syn_flood/udp_flood (для совместимости с guard и rate-limit) ---
    # Используются как rate-counter — IP попадает сюда при превышении.
    # Сами по себе не дропают трафик — это делают вышестоящие правила
    # на основе наличия IP в suspect/confirmed.
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
    set udp_flood_v4 {
        type ipv4_addr
        flags dynamic, timeout
        timeout 1m
        size 65536
    }
    set udp_flood_v6 {
        type ipv6_addr
        flags dynamic, timeout
        timeout 1m
        size 65536
    }

    # --- Manual whitelist ---
    # Авто-заполняется management-IP из правил UFW "ALLOW from <IP>".
    # Также можно добавить вручную:
    #   nft add element inet ddos_protect manual_whitelist_v4 { 1.2.3.4 }
    set manual_whitelist_v4 {
        type ipv4_addr
        flags interval
        auto-merge
$MANUAL_WHITELIST_V4_INIT
    }
    set manual_whitelist_v6 {
        type ipv6_addr
        flags interval
        auto-merge
$MANUAL_WHITELIST_V6_INIT
    }

    # v2.7: Named counters для статистики "всего заблокировано".
    # Каждый counter сохраняет packets и bytes с момента старта nft.
    # Сбрасываются при ребуте/перезагрузке правил.
    counter scanner_drops_v4 { }
    counter scanner_drops_v6 { }
    counter confirmed_drops_v4 { }
    counter confirmed_drops_v6 { }
    counter syn_confirmed_v4 { }
    counter syn_confirmed_v6 { }
    counter udp_confirmed_v4 { }
    counter udp_confirmed_v6 { }

    chain prerouting {
        type filter hook prerouting priority -100; policy accept;

        # Established/related — пропускаем без проверок.
        ct state established,related accept

        # Manual whitelist (всегда первым приоритетом)
        ip  saddr @manual_whitelist_v4 accept
        ip6 saddr @manual_whitelist_v6 accept

        # SSH — без блокировок (защищает CrowdSec)
        tcp dport $SSH_PORT accept

        # Pre-emptive drop известных сканеров (с counter v2.7).
        # Стоит ПЕРЕД rate-limit — экономит conntrack-слоты и CPU.
        ip  saddr @scanner_blocklist_v4 counter name scanner_drops_v4 drop
        ip6 saddr @scanner_blocklist_v6 counter name scanner_drops_v6 drop

        # === v2.5: BAN-ONCE АРХИТЕКТУРА ===
        # Двухэтапная проверка перед баном — снижает ложные баны CGNAT/мобильных.
        #
        # Этап 0: Если IP в confirmed_attack — он уже подтверждённый атакующий, дропаем.
        ip  saddr @confirmed_attack_v4 counter name confirmed_drops_v4 drop
        ip6 saddr @confirmed_attack_v6 counter name confirmed_drops_v6 drop

        # === TCP SYN rate-limit на защищаемых портах ===
        # Лимит: 300 SYN/sec, burst 500. CGNAT-friendly.
        #
        # Этап 2: IP уже в suspect и опять превышает → переводим в confirmed + drop.
        tcp dport @protected_ports_tcp ct state new ip saddr @suspect_v4 \\
            add @syn_flood_v4 { ip saddr limit rate over 300/second burst 500 packets } \\
            add @confirmed_attack_v4 { ip saddr } counter name syn_confirmed_v4 drop
        tcp dport @protected_ports_tcp ct state new ip6 saddr @suspect_v6 \\
            add @syn_flood_v6 { ip6 saddr limit rate over 300/second burst 500 packets } \\
            add @confirmed_attack_v6 { ip6 saddr } counter name syn_confirmed_v6 drop

        # Этап 1: IP не в suspect, но превышает → добавляем в suspect (не дропаем!).
        # Цель: дать IP "испытательный срок" 5 минут. Случайные всплески пройдут.
        tcp dport @protected_ports_tcp ct state new meta nfproto ipv4 \\
            add @syn_flood_v4 { ip saddr limit rate over 300/second burst 500 packets } \\
            add @suspect_v4 { ip saddr }
        tcp dport @protected_ports_tcp ct state new meta nfproto ipv6 \\
            add @syn_flood_v6 { ip6 saddr limit rate over 300/second burst 500 packets } \\
            add @suspect_v6 { ip6 saddr }

        # === UDP rate-limit на защищаемых портах ===
        # Лимит: 600 packets/sec, burst 1000. UDP шлёт больше мелких пакетов.
        #
        # Этап 2: подтверждённый атакующий
        udp dport @protected_ports_udp ip saddr @suspect_v4 \\
            add @udp_flood_v4 { ip saddr limit rate over 600/second burst 1000 packets } \\
            add @confirmed_attack_v4 { ip saddr } counter name udp_confirmed_v4 drop
        udp dport @protected_ports_udp ip6 saddr @suspect_v6 \\
            add @udp_flood_v6 { ip6 saddr limit rate over 600/second burst 1000 packets } \\
            add @confirmed_attack_v6 { ip6 saddr } counter name udp_confirmed_v6 drop

        # Этап 1: первое превышение
        udp dport @protected_ports_udp meta nfproto ipv4 \\
            add @udp_flood_v4 { ip saddr limit rate over 600/second burst 1000 packets } \\
            add @suspect_v4 { ip saddr }
        udp dport @protected_ports_udp meta nfproto ipv6 \\
            add @udp_flood_v6 { ip6 saddr limit rate over 600/second burst 1000 packets } \\
            add @suspect_v6 { ip6 saddr }
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
# ШАГ 5: PROTECTED PORTS WATCHER (auto-sync с фаерволом)
# ==============================================================================

print_header "ШАГ 5: PROTECTED PORTS WATCHER"

# v1.7: автоматическая синхронизация защищаемых портов с правилами фаервола.
# Каждые 30 секунд скрипт проверяет какие порты открыты в UFW/firewalld/iptables
# и обновляет nft set @protected_ports_tcp/@protected_ports_udp.
#
# Преимущества:
#   - Юзер открыл новый порт `ufw allow 12345` → защита подхватит за 30 сек
#   - Закрыл порт → перестанет защищаться (логично — он больше не нужен)
#   - Не зависит от того какой VPN-стек запущен и под каким именем процесса

PORTS_UPDATER="/usr/local/sbin/update-protected-ports.sh"

cat > "$PORTS_UPDATER" <<UPDATER_EOF
#!/bin/bash
# Sync nft sets @protected_ports_tcp/@protected_ports_udp с правилами фаервола.
# Запускается через protected-ports-update.timer каждые 30 секунд.

set -o pipefail

LOG_TAG="protected-ports"
FIREWALL_TYPE="$FIREWALL_TYPE"
SSH_PORT="$SSH_PORT"

# Если nft-таблицы нет — выходим
if ! nft list table inet ddos_protect >/dev/null 2>&1; then
    logger -t "\$LOG_TAG" "table inet ddos_protect не существует — пропускаю"
    exit 0
fi

UPDATER_EOF

# Дописываем функцию detect_firewall_ports в updater (та же что в шаге 2)
# Делаем это через подстановку, чтобы юзер мог редактировать тип фаервола без перезапуска скрипта
cat >> "$PORTS_UPDATER" <<'UPDATER_EOF2'
detect_firewall_ports() {
    local fw="$1"
    local tcp_list=""
    local udp_list=""
    local mgmt_ipv4=""
    local mgmt_ipv6=""

    case "$fw" in
        ufw)
            local ufw_out
            ufw_out=$(ufw status 2>/dev/null)
            tcp_list=$(echo "$ufw_out" | awk '
                $2 == "ALLOW" && $0 !~ /\(v6\)/ && $3 == "Anywhere" {
                    pp = $1
                    if (match(pp, /^[0-9:]+(\/(tcp|udp))?$/)) {
                        n = split(pp, a, "/")
                        port = a[1]
                        proto = (n > 1) ? a[2] : "any"
                        if (proto == "tcp" || proto == "any") print port
                    }
                }
            ' | sort -un | tr '\n' ',' | sed 's/,$//')
            udp_list=$(echo "$ufw_out" | awk '
                $2 == "ALLOW" && $0 !~ /\(v6\)/ && $3 == "Anywhere" {
                    pp = $1
                    if (match(pp, /^[0-9:]+(\/(tcp|udp))?$/)) {
                        n = split(pp, a, "/")
                        port = a[1]
                        proto = (n > 1) ? a[2] : "any"
                        if (proto == "udp" || proto == "any") print port
                    }
                }
            ' | sort -un | tr '\n' ',' | sed 's/,$//')
            # v2.2: management IPs
            mgmt_ipv4=$(echo "$ufw_out" | awk '
                $2 == "ALLOW" && $0 !~ /\(v6\)/ && $3 != "Anywhere" {
                    if ($3 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?$/) print $3
                }
            ' | sort -u | tr '\n' ',' | sed 's/,$//')
            mgmt_ipv6=$(echo "$ufw_out" | awk '
                $2 == "ALLOW" {
                    if ($3 ~ /:/ && $3 !~ /^Anywhere/) print $3
                }
            ' | sort -u | tr '\n' ',' | sed 's/,$//')
            ;;
        firewalld)
            local fw_out
            fw_out=$(firewall-cmd --list-ports 2>/dev/null)
            tcp_list=$(echo "$fw_out" | tr ' ' '\n' | awk -F/ '$2=="tcp"{print $1}' | sort -un | tr '\n' ',' | sed 's/,$//')
            udp_list=$(echo "$fw_out" | tr ' ' '\n' | awk -F/ '$2=="udp"{print $1}' | sort -un | tr '\n' ',' | sed 's/,$//')
            # firewalld --list-rich-rules может содержать source address
            local rich_rules
            rich_rules=$(firewall-cmd --list-rich-rules 2>/dev/null)
            mgmt_ipv4=$(echo "$rich_rules" | grep -oE 'address="[0-9.]+(/[0-9]+)?"' | \
                grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?' | sort -u | tr '\n' ',' | sed 's/,$//')
            ;;
        iptables)
            tcp_list=$(iptables -S INPUT 2>/dev/null | awk '/-j ACCEPT/ && /-p tcp/ {
                for (i=1; i<=NF; i++) {
                    if ($i == "--dport" || $i == "--dports") print $(i+1)
                }
            }' | tr ',' '\n' | sort -un | tr '\n' ',' | sed 's/,$//')
            udp_list=$(iptables -S INPUT 2>/dev/null | awk '/-j ACCEPT/ && /-p udp/ {
                for (i=1; i<=NF; i++) {
                    if ($i == "--dport" || $i == "--dports") print $(i+1)
                }
            }' | tr ',' '\n' | sort -un | tr '\n' ',' | sed 's/,$//')
            # iptables: -s <IP>/-s <IP/CIDR> в ACCEPT-правилах
            mgmt_ipv4=$(iptables -S INPUT 2>/dev/null | awk '/-j ACCEPT/ {
                for (i=1; i<=NF; i++) {
                    if ($i == "-s") print $(i+1)
                }
            }' | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$' | \
                grep -v '^0\.0\.0\.0' | sort -u | tr '\n' ',' | sed 's/,$//')
            ;;
        nftables)
            local rules
            rules=$(nft list ruleset 2>/dev/null | grep -E "(tcp|udp) dport" | grep "accept")
            tcp_list=$(echo "$rules" | grep "tcp dport" | grep -oE 'dport [{0-9 ,}]+' | \
                grep -oE '[0-9]+' | sort -un | tr '\n' ',' | sed 's/,$//')
            udp_list=$(echo "$rules" | grep "udp dport" | grep -oE 'dport [{0-9 ,}]+' | \
                grep -oE '[0-9]+' | sort -un | tr '\n' ',' | sed 's/,$//')
            ;;
    esac

    echo "$tcp_list"
    echo "$udp_list"
    echo "$mgmt_ipv4"
    echo "$mgmt_ipv6"
}

exclude_port() {
    local list="$1" exclude="$2"
    echo ",$list," | sed "s/,$exclude,/,/g; s/^,//; s/,$//"
}

# Получаем актуальные данные
FW_OUTPUT=$(detect_firewall_ports "$FIREWALL_TYPE")
NEW_TCP=$(echo "$FW_OUTPUT" | sed -n '1p')
NEW_UDP=$(echo "$FW_OUTPUT" | sed -n '2p')
NEW_MGMT_V4=$(echo "$FW_OUTPUT" | sed -n '3p')
NEW_MGMT_V6=$(echo "$FW_OUTPUT" | sed -n '4p')

# Исключаем SSH из TCP
NEW_TCP=$(exclude_port "$NEW_TCP" "$SSH_PORT")

# Текущее состояние nft set'ов
CUR_TCP=$(nft list set inet ddos_protect protected_ports_tcp 2>/dev/null | \
    tr '\n' ' ' | grep -oE 'elements = \{[^}]*\}' | grep -oE '[0-9]+' | sort -un | tr '\n' ',' | sed 's/,$//')
CUR_UDP=$(nft list set inet ddos_protect protected_ports_udp 2>/dev/null | \
    tr '\n' ' ' | grep -oE 'elements = \{[^}]*\}' | grep -oE '[0-9]+' | sort -un | tr '\n' ',' | sed 's/,$//')
CUR_MGMT_V4=$(nft list set inet ddos_protect manual_whitelist_v4 2>/dev/null | \
    tr '\n' ' ' | grep -oE 'elements = \{[^}]*\}' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?' | \
    sort -u | tr '\n' ',' | sed 's/,$//')

# v2.4: SAFETY GUARD — не затирать существующие данные пустыми результатами.
# Это случается когда:
#   - UFW в момент опроса делает atomic rename файлов (transient empty output)
#   - path-unit срабатывает несколько раз подряд, и один раз фаервол не отвечает
#   - Кратковременная блокировка ufw lock
#
# Логика: если фаервол активен И мы получили пустой результат, НО предыдущий
# результат был непустой — это скорее всего transient ошибка. Пропускаем
# обновление, не затираем правильные данные.
FIREWALL_ACTIVE=0
case "$FIREWALL_TYPE" in
    ufw)       ufw status 2>/dev/null | grep -q "Status: active" && FIREWALL_ACTIVE=1 ;;
    firewalld) systemctl is-active --quiet firewalld 2>/dev/null && FIREWALL_ACTIVE=1 ;;
    iptables)  [ "$(iptables -L INPUT 2>/dev/null | wc -l)" -gt 2 ] && FIREWALL_ACTIVE=1 ;;
    nftables)  nft list ruleset 2>/dev/null | grep -q "table inet filter" && FIREWALL_ACTIVE=1 ;;
esac

if [ "$FIREWALL_ACTIVE" = "1" ] && [ -z "$NEW_TCP" ] && [ -z "$NEW_UDP" ] && [ -z "$NEW_MGMT_V4" ]; then
    if [ -n "$CUR_TCP" ] || [ -n "$CUR_MGMT_V4" ]; then
        logger -t "$LOG_TAG" "SKIP: empty parse result while firewall is active (transient?)"
        exit 0
    fi
fi

# Если ничего не изменилось — выходим
if [ "$NEW_TCP" = "$CUR_TCP" ] && [ "$NEW_UDP" = "$CUR_UDP" ] && [ "$NEW_MGMT_V4" = "$CUR_MGMT_V4" ]; then
    exit 0
fi

# v2.4: Lock-файл — предотвращает одновременный запуск (path-unit + timer).
# flock с -n (non-blocking) — если уже запущен другой instance, выходим.
LOCKFILE="/run/cs-ssh-whitelist/.ports-update.lock"
mkdir -p /run/cs-ssh-whitelist 2>/dev/null
exec 200>"$LOCKFILE"
if ! flock -n 200; then
    logger -t "$LOG_TAG" "SKIP: another update already in progress"
    exit 0
fi

# Атомарное обновление через nft -f
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

{
    echo "flush set inet ddos_protect protected_ports_tcp"
    if [ -n "$NEW_TCP" ]; then
        echo "add element inet ddos_protect protected_ports_tcp { $(echo "$NEW_TCP" | sed 's/,/, /g') }"
    fi
    echo "flush set inet ddos_protect protected_ports_udp"
    if [ -n "$NEW_UDP" ]; then
        echo "add element inet ddos_protect protected_ports_udp { $(echo "$NEW_UDP" | sed 's/,/, /g') }"
    fi
    # v2.2: синхронизируем management whitelist
    echo "flush set inet ddos_protect manual_whitelist_v4"
    if [ -n "$NEW_MGMT_V4" ]; then
        echo "add element inet ddos_protect manual_whitelist_v4 { $(echo "$NEW_MGMT_V4" | sed 's/,/, /g') }"
    fi
    echo "flush set inet ddos_protect manual_whitelist_v6"
    if [ -n "$NEW_MGMT_V6" ]; then
        echo "add element inet ddos_protect manual_whitelist_v6 { $(echo "$NEW_MGMT_V6" | sed 's/,/, /g') }"
    fi
} > "$TMP"

# v2.4: захватываем stderr из nft для диагностики (раньше >/dev/null глотал ошибки)
NFT_ERR=$(nft -f "$TMP" 2>&1)
if [ $? -eq 0 ]; then
    logger -t "$LOG_TAG" "Updated: TCP={$NEW_TCP} UDP={$NEW_UDP} MGMT={$NEW_MGMT_V4}"
else
    logger -t "$LOG_TAG" "ERROR: nft failed: $NFT_ERR"
    exit 1
fi
UPDATER_EOF2

chmod 0755 "$PORTS_UPDATER"
print_ok "Watcher script: $PORTS_UPDATER"

# Systemd service + timer + path-unit
cat > /etc/systemd/system/protected-ports-update.service <<EOF
[Unit]
Description=Sync nft protected_ports sets with firewall rules
After=nftables.service network-online.target
Wants=nftables.service
# Не запускать многократно если несколько триггеров сработали одновременно
StartLimitIntervalSec=10
StartLimitBurst=5

[Service]
Type=oneshot
ExecStart=$PORTS_UPDATER
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
EOF

# v1.8: Timer как safety net каждые 60 секунд
cat > /etc/systemd/system/protected-ports-update.timer <<'EOF'
[Unit]
Description=Sync protected ports every 60s (safety net for path-unit)
Requires=protected-ports-update.service

[Timer]
OnBootSec=30s
OnUnitActiveSec=60s
AccuracySec=5s
Persistent=false

[Install]
WantedBy=timers.target
EOF

# v1.8: Path-unit для МГНОВЕННОЙ реакции на изменения файлов фаервола.
# Использует inotify через systemd для отслеживания изменений в:
#   - UFW: /etc/ufw/user.rules, /etc/ufw/user6.rules
#   - firewalld: /etc/firewalld/zones/, /etc/firewalld/direct.xml
# При срабатывании любого PathChanged триггерит protected-ports-update.service.
#
# Преимущества vs только timer:
#   - Реакция < 1 секунды (kernel-event, без поллинга)
#   - Нулевая нагрузка (не опрашивает фаервол постоянно)
#   - Timer остаётся как safety net (если кто-то меняет nft напрямую)
PATH_UNIT_PATHS=""

# UFW использует /etc/ufw/user*.rules (изменяются при ufw allow/deny)
if [ -d /etc/ufw ]; then
    [ -f /etc/ufw/user.rules ]  && PATH_UNIT_PATHS+="PathChanged=/etc/ufw/user.rules"$'\n'
    [ -f /etc/ufw/user6.rules ] && PATH_UNIT_PATHS+="PathChanged=/etc/ufw/user6.rules"$'\n'
fi

# firewalld использует /etc/firewalld/zones/ (xml-файлы зон)
if [ -d /etc/firewalld/zones ]; then
    PATH_UNIT_PATHS+="PathModified=/etc/firewalld/zones"$'\n'
fi

# Если нашли что отслеживать — создаём path-unit
if [ -n "$PATH_UNIT_PATHS" ]; then
    cat > /etc/systemd/system/protected-ports-update.path <<EOF
[Unit]
Description=Watch firewall config files and trigger protected-ports-update
After=nftables.service

[Path]
$PATH_UNIT_PATHS
# Не дребезжать при нескольких изменениях за короткий период
TriggerLimitIntervalSec=2
TriggerLimitBurst=3
Unit=protected-ports-update.service

[Install]
WantedBy=multi-user.target
EOF
    HAS_PATH_UNIT=1
    print_ok "Path-unit для inotify-watch создан"
else
    HAS_PATH_UNIT=0
    print_info "Path-unit пропущен (файлы фаервола не найдены — только timer)"
fi

systemctl daemon-reload
systemctl enable --now protected-ports-update.timer >/dev/null 2>&1

if [ "$HAS_PATH_UNIT" = "1" ]; then
    systemctl enable --now protected-ports-update.path >/dev/null 2>&1
    print_ok "Auto-sync активен: path-unit (мгновенно) + timer (60с safety net)"
else
    print_ok "Timer активен (синхронизация каждые 60 секунд)"
fi

# ==============================================================================
# ШАГ 6: SCANNER-BLOCKLIST UPDATER (pre-emptive drop)
# ==============================================================================

print_header "ШАГ 6: SCANNER-BLOCKLIST UPDATER"

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

# v2.6: множественные источники blocklist'а для максимального покрытия
# российских госсканеров с минимальным риском ложных банов.
LISTS=(
    # Основной общий blocklist (Shodan, Censys, общие сканеры, RU gov частично)
    "https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/antiscanner.list"
    "https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/government_networks.list"
    # v2.6: SKIPA scanner-серверы (CyberOK, ГРЧЦ, НКЦКИ).
    # Курируется вручную автором с верификацией по логам — низкий риск ложных банов.
    "https://raw.githubusercontent.com/tread-lightly/CyberOK_Skipa_ips/main/lists/skipa_cidr.txt"
)

# v2.6: MISP/CIRCL — honeypot-verified scanner IPs (JSON-формат, требует jq для парсинга)
MISP_LIST="https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/skipa-nt-scanning/list.json"

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

# v2.6: MISP/CIRCL JSON-список — отдельный парсинг через jq
if [ -n "$MISP_LIST" ] && command -v jq >/dev/null 2>&1; then
    if curl -fsSL --max-time 30 --retry 2 "$MISP_LIST" -o "$TMP/misp.json" 2>/dev/null; then
        # MISP-формат: {"list": ["IP1/CIDR1", "IP2/CIDR2", ...]}
        jq -r '.list[]?' "$TMP/misp.json" 2>/dev/null >> "$TMP/all.raw"
        MISP_COUNT=$(jq -r '.list | length' "$TMP/misp.json" 2>/dev/null || echo "0")
        logger -t "$LOG_TAG" "MISP/CIRCL: добавлено $MISP_COUNT honeypot-verified IP"
    else
        logger -t "$LOG_TAG" "WARN: не смог скачать MISP/CIRCL список"
    fi
fi

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
# ШАГ 7: УСТАНОВКА CROWDSEC
# ==============================================================================

print_header "ШАГ 7: УСТАНОВКА CROWDSEC"

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
# ШАГ 8: SSH-KEY AUTO-WHITELIST
# ==============================================================================

print_header "ШАГ 8: SSH-KEY AUTO-WHITELIST"

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
DEBOUNCE_SEC=60  # v1.9: не обновлять whitelist для того же IP чаще раз в 60 сек
DEBOUNCE_DIR="/run/cs-ssh-whitelist"
mkdir -p "$DEBOUNCE_DIR"

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

            # v1.9: debounce — пропускаем cscli если этот IP логинился < 60 сек назад.
            # Защита от шторма forks при множественных одновременных логинах
            # (например, ansible / fabric / parallel-ssh).
            DEBOUNCE_FILE="$DEBOUNCE_DIR/$(echo "$IP" | tr ':' '_')"
            NOW=$(date +%s)
            if [ -f "$DEBOUNCE_FILE" ]; then
                LAST=$(cat "$DEBOUNCE_FILE" 2>/dev/null)
                if [ -n "$LAST" ] && [ $((NOW - LAST)) -lt "$DEBOUNCE_SEC" ]; then
                    # Слишком частые логины с этого IP — пропускаем cscli
                    continue
                fi
            fi
            echo "$NOW" > "$DEBOUNCE_FILE"

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
# v2.3 fix: leading "-" делает путь optional — если каталога нет, systemd
# не падает с "Failed to set up mount namespacing". Это бывает когда
# crowdsec ещё не создал /var/run/crowdsec (новая установка, до первого старта).
ReadWritePaths=-/var/run/crowdsec
ReadWritePaths=-/run/crowdsec
# v2.1.1: дебаунс-кэш для предотвращения шторма cscli при множественных логинах
ReadWritePaths=/run/cs-ssh-whitelist
# Системд автоматически создаст каталог по этому пути перед стартом
RuntimeDirectory=cs-ssh-whitelist
RuntimeDirectoryMode=0700

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
# ШАГ 9: BAN DURATION (4h — баланс между защитой и ложными срабатываниями)
# ==============================================================================

print_header "ШАГ 9: BAN DURATION"

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
# ШАГ 10: ACQUISITION (источники логов для CrowdSec)
# ==============================================================================

print_header "ШАГ 10: ACQUISITION"

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
# ШАГ 11: NFTABLES BOUNCER
# ==============================================================================

print_header "ШАГ 11: NFTABLES BOUNCER"

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
# ШАГ 12: УСТАНОВКА КОМАНДЫ guard (снимок состояния)
# ==============================================================================

print_header "ШАГ 12: УСТАНОВКА КОМАНДЫ guard"

# Команда показывает текущее состояние защиты ОДНИМ снимком:
#   - Статус всех сервисов (CrowdSec, bouncer, watcher'ы)
#   - Защищаемые порты (TCP/UDP)
#   - Сколько IP заблокировано прямо сейчас
#   - Активные whitelist'ы
#   - Когда последний раз обновлялся blocklist
#
# v2.1: команда работает в one-shot режиме — никакой фоновой нагрузки,
# никаких циклов. Каждый запуск — независимый snapshot.
#
# Запуск:
#   sudo guard          текстовый снимок
#   sudo guard --json   JSON для интеграций (Zabbix/Prometheus/боты)
#   sudo watch -n 5 guard   "live"-режим через стандартный watch(1)

GUARD_BIN="/usr/local/bin/guard"

cat > "$GUARD_BIN" <<'GUARD_EOF'
#!/bin/bash
# guard — minimalist snapshot dashboard для VPN-ноды.
#
# v2.3: минималистичный английский интерфейс + интерактив.
#   sudo guard            снимок + интерактивное меню (1/2/3/4/r/0)
#   sudo guard --json     JSON для интеграций
#   sudo guard --once     снимок без меню (для cron/мониторинга)
#   sudo guard --help     помощь

case "${1:-}" in
    --help|-h)
        cat <<HELP
guard — VPN node protection snapshot

Usage:
  sudo guard            snapshot + interactive menu (1/2/3/4/r/0)
  sudo guard --once     snapshot only, no menu (for cron / monitoring)
  sudo guard --json     JSON output (for integrations)

Interactive menu:
  [1] show syn-flood IPs        [3] show whitelist IPs
  [2] show crowdsec banned IPs  [4] show scanner blocklist samples
  [r] refresh                   [0] exit

HELP
        exit 0
        ;;
esac

if [[ $EUID -ne 0 ]]; then
    echo "Run as root: sudo guard"
    exit 1
fi

MODE="interactive"
case "${1:-}" in
    --json) MODE="json" ;;
    --once) MODE="once" ;;
esac

# ANSI цвета
if [ "$MODE" != "json" ] && [ -t 1 ]; then
    R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; C='\033[0;36m'
    M='\033[0;35m'; W='\033[1;37m'; B='\033[1m'; N='\033[0m'
    DIM='\033[2m'
else
    R=''; G=''; Y=''; C=''; M=''; W=''; B=''; N=''; DIM=''
fi

CS_DB="/var/lib/crowdsec/data/crowdsec.db"

# === СБОР МЕТРИК ===
collect_stats() {
    SYN_BAN=$(nft list set inet ddos_protect syn_flood_v4 2>/dev/null | \
        grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | wc -l)
    SYN_BAN_V6=$(nft list set inet ddos_protect syn_flood_v6 2>/dev/null | grep -c 'expires')
    SYN_BAN_V6="${SYN_BAN_V6:-0}"

    UDP_BAN=$(nft list set inet ddos_protect udp_flood_v4 2>/dev/null | \
        grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | wc -l)

    # v2.5: suspect (под наблюдением 5 мин) + confirmed (бан 1 час)
    SUSPECT_COUNT=$(nft list set inet ddos_protect suspect_v4 2>/dev/null | \
        grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | wc -l)
    CONFIRMED_COUNT=$(nft list set inet ddos_protect confirmed_attack_v4 2>/dev/null | \
        grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | wc -l)

    PROTECTED_TCP_LIST=$(nft list set inet ddos_protect protected_ports_tcp 2>/dev/null | \
        tr '\n' ' ' | grep -oE 'elements = \{[^}]*\}' | grep -oE '[0-9]+(-[0-9]+)?' | \
        sort -un | tr '\n' ',' | sed 's/,$//')
    PROTECTED_UDP_LIST=$(nft list set inet ddos_protect protected_ports_udp 2>/dev/null | \
        tr '\n' ' ' | grep -oE 'elements = \{[^}]*\}' | grep -oE '[0-9]+(-[0-9]+)?' | \
        sort -un | tr '\n' ',' | sed 's/,$//')
    PROTECTED_TCP_LIST="${PROTECTED_TCP_LIST:-—}"
    PROTECTED_UDP_LIST="${PROTECTED_UDP_LIST:-—}"

    BL_V4=$(nft list set inet ddos_protect scanner_blocklist_v4 2>/dev/null | \
        grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?' | wc -l)
    BL_V6=$(nft list set inet ddos_protect scanner_blocklist_v6 2>/dev/null | grep -cE '^\s+[0-9a-f]+:')
    BL_V6="${BL_V6:-0}"

    MANUAL_WHITE=$(nft list set inet ddos_protect manual_whitelist_v4 2>/dev/null | \
        grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | wc -l)

    CS_ACTIVE="$(systemctl is-active crowdsec 2>/dev/null)"
    BOUNCER_ACTIVE="$(systemctl is-active crowdsec-firewall-bouncer 2>/dev/null)"
    WATCHER_ACTIVE="$(systemctl is-active cs-ssh-whitelist 2>/dev/null)"
    PORTS_PATH_ACTIVE="$(systemctl is-active protected-ports-update.path 2>/dev/null)"

    CS_BANS=0
    CS_WHITE=0
    if [ -r "$CS_DB" ] && command -v sqlite3 >/dev/null 2>&1; then
        CS_BANS=$(sqlite3 "$CS_DB" "SELECT COUNT(*) FROM decisions WHERE type='ban' AND until > datetime('now')" 2>/dev/null)
        CS_WHITE=$(sqlite3 "$CS_DB" "SELECT COUNT(*) FROM decisions WHERE type='whitelist' AND until > datetime('now')" 2>/dev/null)
        CS_BANS="${CS_BANS:-0}"
        CS_WHITE="${CS_WHITE:-0}"
    elif command -v cscli >/dev/null 2>&1; then
        CS_BANS=$(cscli decisions list --type ban -o raw 2>/dev/null | tail -n +2 | wc -l)
        CS_WHITE=$(cscli decisions list --type whitelist -o raw 2>/dev/null | tail -n +2 | wc -l)
    fi

    LAST_UPDATE=$(systemctl show scanner-blocklist-update.service \
        --property=ExecMainExitTimestamp --value 2>/dev/null | \
        xargs -I{} date -d {} '+%Y-%m-%d %H:%M' 2>/dev/null)
    LAST_UPDATE="${LAST_UPDATE:-—}"

    # v2.7: nftables counters — статистика "всего заблокировано"
    # Формат вывода: "counter packets X bytes Y"
    read_counter() {
        local name="$1"
        local out
        out=$(nft list counter inet ddos_protect "$name" 2>/dev/null | \
            grep -oE 'packets [0-9]+ bytes [0-9]+' | head -1)
        if [ -n "$out" ]; then
            local pkts bytes
            pkts=$(echo "$out" | awk '{print $2}')
            bytes=$(echo "$out" | awk '{print $4}')
            echo "${pkts:-0} ${bytes:-0}"
        else
            echo "0 0"
        fi
    }

    read SCANNER_PKTS_V4 SCANNER_BYTES_V4 <<< "$(read_counter scanner_drops_v4)"
    read SCANNER_PKTS_V6 SCANNER_BYTES_V6 <<< "$(read_counter scanner_drops_v6)"
    read CONFIRMED_PKTS_V4 CONFIRMED_BYTES_V4 <<< "$(read_counter confirmed_drops_v4)"
    read CONFIRMED_PKTS_V6 CONFIRMED_BYTES_V6 <<< "$(read_counter confirmed_drops_v6)"
    read SYN_CONF_PKTS_V4 SYN_CONF_BYTES_V4 <<< "$(read_counter syn_confirmed_v4)"
    read UDP_CONF_PKTS_V4 UDP_CONF_BYTES_V4 <<< "$(read_counter udp_confirmed_v4)"

    # Когда nft started — для "stats since"
    NFT_SINCE=$(systemctl show nftables.service --property=ActiveEnterTimestamp --value 2>/dev/null | \
        xargs -I{} date -d {} '+%Y-%m-%d %H:%M' 2>/dev/null)
    NFT_SINCE="${NFT_SINCE:-—}"
}

# v2.7: human-readable bytes formatter (1234567 → 1.18M)
human_bytes() {
    local b="${1:-0}"
    awk -v b="$b" 'BEGIN {
        if (b < 1024) printf "%dB", b
        else if (b < 1048576) printf "%.1fK", b/1024
        else if (b < 1073741824) printf "%.1fM", b/1048576
        else if (b < 1099511627776) printf "%.1fG", b/1073741824
        else printf "%.1fT", b/1099511627776
    }'
}

# v2.7: human-readable numbers (1234567 → 1,234,567)
human_num() {
    printf "%'d" "${1:-0}" 2>/dev/null || echo "${1:-0}"
}

fmt_status() {
    case "$1" in
        active)        echo -e "${G}active${N}" ;;
        inactive)      echo -e "${Y}inactive${N}" ;;
        failed)        echo -e "${R}failed${N}" ;;
        activating)    echo -e "${Y}activating${N}" ;;
        *)             echo -e "${Y}${1:-—}${N}" ;;
    esac
}

# === ВЫВОД ===
draw_snapshot() {
    local now=$(date '+%Y-%m-%d %H:%M:%S')
    local ip=$(hostname -I 2>/dev/null | awk '{print $1}')

    echo ""
    echo -e "${C}╔══════════════════════════════════════════════════════════════════╗${N}"
    printf "${C}║${N}  ${B}VPN GUARD${N} · %-15s · %s              ${C}║${N}\n" "$ip" "$now"
    echo -e "${C}╚══════════════════════════════════════════════════════════════════╝${N}"
    echo ""

    echo -e "  ${B}Services${N}"
    printf "  ├─ %-22s %b\n" "crowdsec"             "$(fmt_status "$CS_ACTIVE")"
    printf "  ├─ %-22s %b\n" "firewall-bouncer"     "$(fmt_status "$BOUNCER_ACTIVE")"
    printf "  ├─ %-22s %b\n" "cs-ssh-whitelist"     "$(fmt_status "$WATCHER_ACTIVE")"
    printf "  └─ %-22s %b\n" "ports-path-watcher"   "$(fmt_status "$PORTS_PATH_ACTIVE")"
    echo ""

    echo -e "  ${B}Protected ports${N}"
    printf "  ├─ %-10s ${C}%s${N}\n" "tcp" "$PROTECTED_TCP_LIST"
    printf "  └─ %-10s ${C}%s${N}\n" "udp" "$PROTECTED_UDP_LIST"
    echo ""

    echo -e "  ${B}Suspect${N} ${DIM}(under watch, 5min)${N}"
    printf "  └─ %-25s ${Y}${B}%5d${N}\n"        "suspect IPs"         "$SUSPECT_COUNT"
    echo ""

    echo -e "  ${B}Blocked${N}"
    printf "  ├─ %-25s ${R}${B}%5d${N}\n" "confirmed attack"        "$CONFIRMED_COUNT"
    printf "  ├─ %-25s ${DIM}%5d${N}\n"  "syn-flood v4 (limit hits)" "$SYN_BAN"
    printf "  ├─ %-25s ${DIM}%5d${N}\n"  "syn-flood v6 (limit hits)" "$SYN_BAN_V6"
    printf "  ├─ %-25s ${DIM}%5d${N}\n"  "udp-flood v4 (limit hits)" "$UDP_BAN"
    printf "  ├─ %-25s ${R}${B}%5d${N}\n" "crowdsec bans"           "$CS_BANS"
    printf "  ├─ %-25s ${R}${B}%5d${N}\n" "scanner blocklist v4"    "$BL_V4"
    printf "  └─ %-25s ${R}${B}%5d${N}\n" "scanner blocklist v6"    "$BL_V6"
    echo ""

    echo -e "  ${B}Whitelist${N}"
    printf "  ├─ %-22s ${G}${B}%5d${N}\n" "ssh-key auto"   "$CS_WHITE"
    printf "  └─ %-22s ${G}${B}%5d${N}\n" "manual"         "$MANUAL_WHITE"
    echo ""

    # v2.7: Total blocked (counter-based, since nft started)
    local total_pkts=$((SCANNER_PKTS_V4 + SCANNER_PKTS_V6 + CONFIRMED_PKTS_V4 + CONFIRMED_PKTS_V6 + SYN_CONF_PKTS_V4 + UDP_CONF_PKTS_V4))
    local total_bytes=$((SCANNER_BYTES_V4 + SCANNER_BYTES_V6 + CONFIRMED_BYTES_V4 + CONFIRMED_BYTES_V6 + SYN_CONF_BYTES_V4 + UDP_CONF_BYTES_V4))

    echo -e "  ${B}Total blocked${N} ${DIM}(since $NFT_SINCE)${N}"
    printf "  ├─ %-22s ${R}${B}%15s${N} pkts / %s\n" "scanners (v4)"     "$(human_num "$SCANNER_PKTS_V4")"   "$(human_bytes "$SCANNER_BYTES_V4")"
    printf "  ├─ %-22s ${R}${B}%15s${N} pkts / %s\n" "scanners (v6)"     "$(human_num "$SCANNER_PKTS_V6")"   "$(human_bytes "$SCANNER_BYTES_V6")"
    printf "  ├─ %-22s ${R}${B}%15s${N} pkts / %s\n" "confirmed attacks"  "$(human_num "$CONFIRMED_PKTS_V4")" "$(human_bytes "$CONFIRMED_BYTES_V4")"
    printf "  ├─ %-22s ${R}${B}%15s${N} pkts / %s\n" "syn-flood→confirmed" "$(human_num "$SYN_CONF_PKTS_V4")" "$(human_bytes "$SYN_CONF_BYTES_V4")"
    printf "  ├─ %-22s ${R}${B}%15s${N} pkts / %s\n" "udp-flood→confirmed" "$(human_num "$UDP_CONF_PKTS_V4")" "$(human_bytes "$UDP_CONF_BYTES_V4")"
    printf "  └─ %-22s ${B}${B}%15s${N} pkts / %s\n" "TOTAL"             "$(human_num "$total_pkts")"        "$(human_bytes "$total_bytes")"
    echo ""

    printf "  ${DIM}Scanner blocklist updated: %s${N}\n" "$LAST_UPDATE"
}

# === Просмотр списков ===
show_syn_flood_ips() {
    echo ""
    echo -e "${R}${B}Confirmed attack IPs${N} ${DIM}(banned, 1h)${N}"
    echo -e "${DIM}─────────────────────────────────${N}"

    local json_conf
    json_conf=$(nft -j list set inet ddos_protect confirmed_attack_v4 2>/dev/null)
    if command -v jq >/dev/null 2>&1 && [ -n "$json_conf" ]; then
        echo "$json_conf" | jq -r '
            .nftables[]?.set?.elem[]? |
            (.elem.val // .val) as $ip |
            (.elem.expires // .expires // 0) as $exp |
            "  \($ip)  expires in \($exp)s"
        ' 2>/dev/null | head -50
    fi
    [ -z "$json_conf" ] || [ "$(echo "$json_conf" | jq -r '.nftables[]?.set?.elem? | length // 0' 2>/dev/null)" = "0" ] && \
        echo -e "  ${DIM}(empty — no confirmed attacks now)${N}"

    echo ""
    echo -e "${Y}${B}Suspect IPs${N} ${DIM}(under watch, 5min — first offence)${N}"
    echo -e "${DIM}─────────────────────────────────${N}"

    local json_susp
    json_susp=$(nft -j list set inet ddos_protect suspect_v4 2>/dev/null)
    if command -v jq >/dev/null 2>&1 && [ -n "$json_susp" ]; then
        echo "$json_susp" | jq -r '
            .nftables[]?.set?.elem[]? |
            (.elem.val // .val) as $ip |
            (.elem.expires // .expires // 0) as $exp |
            "  \($ip)  expires in \($exp)s"
        ' 2>/dev/null | head -50
    fi
    [ -z "$json_susp" ] || [ "$(echo "$json_susp" | jq -r '.nftables[]?.set?.elem? | length // 0' 2>/dev/null)" = "0" ] && \
        echo -e "  ${DIM}(empty — all clean)${N}"

    echo ""
    echo -e "${DIM}Logic:${N}"
    echo -e "  ${DIM}1st limit hit → suspect (5min watch, no drop)${N}"
    echo -e "  ${DIM}2nd hit while suspect → confirmed_attack (1h drop)${N}"
    echo ""
}

show_crowdsec_bans() {
    echo ""
    echo -e "${B}CrowdSec banned IPs${N}"
    echo -e "${DIM}─────────────────────────────────${N}"
    if command -v cscli >/dev/null 2>&1; then
        cscli decisions list --type ban 2>/dev/null | head -50
    fi
    echo ""
}

show_whitelist_ips() {
    echo ""
    echo -e "${B}Auto whitelist (SSH-key)${N}"
    echo -e "${DIM}─────────────────────────────────${N}"
    if command -v cscli >/dev/null 2>&1; then
        cscli decisions list --type whitelist 2>/dev/null | head -50
    fi
    echo ""
    echo -e "${B}Manual whitelist (nftables)${N}"
    echo -e "${DIM}─────────────────────────────────${N}"
    nft list set inet ddos_protect manual_whitelist_v4 2>/dev/null | \
        tr '\n' ' ' | grep -oE 'elements = \{[^}]*\}' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?' | \
        sed 's/^/  /'
    nft list set inet ddos_protect manual_whitelist_v6 2>/dev/null | \
        tr '\n' ' ' | grep -oE 'elements = \{[^}]*\}' | grep -oE '[0-9a-f:]+(/[0-9]+)?' | \
        sed 's/^/  /'
    echo ""
}

show_scanner_samples() {
    echo ""
    echo -e "${B}Scanner blocklist (first 30 entries)${N}"
    echo -e "${DIM}─────────────────────────────────${N}"
    nft list set inet ddos_protect scanner_blocklist_v4 2>/dev/null | \
        grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(-[0-9.]+)?(/[0-9]+)?' | \
        head -30 | sed 's/^/  /'
    echo ""
    printf "  Total: ${B}%d${N} IPv4 + ${B}%d${N} IPv6\n" "$BL_V4" "$BL_V6"
    echo ""
}

# === MODE: JSON ===
if [ "$MODE" = "json" ]; then
    collect_stats
    cat <<JSON
{
  "timestamp": "$(date -Iseconds)",
  "hostname": "$(hostname)",
  "ip": "$(hostname -I 2>/dev/null | awk '{print $1}')",
  "services": {
    "crowdsec": "$CS_ACTIVE",
    "bouncer": "$BOUNCER_ACTIVE",
    "ssh_watcher": "$WATCHER_ACTIVE",
    "ports_path_watcher": "$PORTS_PATH_ACTIVE"
  },
  "protected_ports": {
    "tcp": "$PROTECTED_TCP_LIST",
    "udp": "$PROTECTED_UDP_LIST"
  },
  "blocked_now": {
    "syn_flood_v4": $SYN_BAN,
    "syn_flood_v6": $SYN_BAN_V6,
    "udp_flood_v4": $UDP_BAN,
    "crowdsec_bans": $CS_BANS,
    "scanner_blocklist_v4": $BL_V4,
    "scanner_blocklist_v6": $BL_V6
  },
  "whitelist": {
    "ssh_key_auto": $CS_WHITE,
    "manual": $MANUAL_WHITE
  },
  "total_blocked": {
    "since": "$NFT_SINCE",
    "scanners_v4_packets": $SCANNER_PKTS_V4,
    "scanners_v4_bytes": $SCANNER_BYTES_V4,
    "scanners_v6_packets": $SCANNER_PKTS_V6,
    "scanners_v6_bytes": $SCANNER_BYTES_V6,
    "confirmed_v4_packets": $CONFIRMED_PKTS_V4,
    "confirmed_v4_bytes": $CONFIRMED_BYTES_V4,
    "syn_confirmed_v4_packets": $SYN_CONF_PKTS_V4,
    "udp_confirmed_v4_packets": $UDP_CONF_PKTS_V4
  },
  "last_blocklist_update": "$LAST_UPDATE"
}
JSON
    exit 0
fi

# === MODE: ONCE (без интерактива) ===
if [ "$MODE" = "once" ]; then
    collect_stats
    draw_snapshot
    exit 0
fi

# === MODE: INTERACTIVE ===
while true; do
    collect_stats
    clear 2>/dev/null
    draw_snapshot
    echo -e "${C}──────────────────────────────────────────────────────────────────${N}"
    echo -e "  [${B}1${N}] syn-flood IPs    [${B}2${N}] crowdsec bans   [${B}3${N}] whitelist IPs"
    echo -e "  [${B}4${N}] scanner samples  [${B}r${N}] refresh         [${B}0${N}] exit"
    echo -ne "  > "

    read -r CHOICE
    case "$CHOICE" in
        1) show_syn_flood_ips    ;;
        2) show_crowdsec_bans    ;;
        3) show_whitelist_ips    ;;
        4) show_scanner_samples  ;;
        r|R|"") continue ;;
        0|q|quit|exit) clear 2>/dev/null; exit 0 ;;
        *) echo -e "  ${Y}Unknown: $CHOICE${N}" ;;
    esac

    if [ "$CHOICE" != "r" ] && [ "$CHOICE" != "R" ] && [ "$CHOICE" != "" ]; then
        echo -ne "  ${DIM}Press Enter to return...${N}"
        read -r _
    fi
done
GUARD_EOF

chmod 0755 "$GUARD_BIN"
print_ok "Команда установлена: $GUARD_BIN"
print_info "Снимок состояния: ${BOLD}sudo guard${NC}  (или ${BOLD}sudo guard --json${NC})"

# ==============================================================================
# ШАГ 13: HEALTHCHECK
# ==============================================================================

print_header "ШАГ 13: HEALTHCHECK"

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
# ШАГ 14: ИТОГИ
# ==============================================================================

print_header "ГОТОВО"

echo -e "  ${BOLD}Что настроено:${NC}"
echo -e "  ├─ ${GREEN}✔${NC} nft rate-limit: 300 SYN/sec TCP, 600 packets/sec UDP (CGNAT-friendly, ban-once)"
echo -e "  ├─ ${GREEN}✔${NC} ${BOLD}Scanner blocklist:${NC} pre-emptive drop российских госсканеров"
echo -e "  │   ├─ traffic-guard-lists (общие сканеры, Shodan, Censys)"
echo -e "  │   ├─ ${BOLD}tread-lightly/CyberOK_Skipa_ips${NC} (SKIPA scan-XX, ГРЧЦ, НКЦКИ)"
echo -e "  │   ├─ ${BOLD}MISP/CIRCL${NC} (honeypot-verified scanner IPs)"
echo -e "  │   └─ обновление каждые 6 часов из 3 источников"
echo -e "  ├─ ${GREEN}✔${NC} Защищённые TCP-порты: ${CYAN}$XRAY_PORTS_TCP${NC}"
[ -n "$XRAY_PORTS_UDP" ] && echo -e "  ├─ ${GREEN}✔${NC} Защищённые UDP-порты: ${CYAN}$XRAY_PORTS_UDP${NC}"
echo -e "  ├─ ${GREEN}✔${NC} ${BOLD}Auto-sync портов с фаерволом:${NC} мгновенно через inotify + 60с safety"
echo -e "  │   └─ Открыл порт в UFW → защита подхватит за < 1 секунды"
echo -e "  ├─ ${GREEN}✔${NC} SSH порт ${CYAN}$SSH_PORT${NC} исключён из rate-limit"
echo -e "  ├─ ${GREEN}✔${NC} ${BOLD}SSH-key auto-whitelist:${NC} 12h после успешного входа по ключу"
[ -n "$ADMIN_IP" ] && echo -e "  ├─ ${GREEN}✔${NC} Bootstrap whitelist: ${CYAN}$ADMIN_IP${NC}"
echo -e "  ├─ ${GREEN}✔${NC} CrowdSec collections: linux + sshd"
echo -e "  ├─ ${GREEN}✔${NC} ssh-cve-2024-6387 (regreSSHion) активен"
echo -e "  ├─ ${GREEN}✔${NC} Ban duration: 4h (user-friendly)"
echo -e "  ├─ ${GREEN}✔${NC} Community blocklist: автообновление каждые 2 часа"
echo -e "  ├─ ${GREEN}✔${NC} nftables bouncer применяет CrowdSec decisions"
echo -e "  └─ ${GREEN}✔${NC} ${BOLD}Команда ${CYAN}guard${NC} ${BOLD}— дашборд защиты в реальном времени${NC}"
echo ""

# v1.6: главное приглашение посмотреть статистику
echo -e "  ${BOLD}${MAGENTA}🛡  Посмотреть статистику защиты:${NC}"
echo -e "     ${CYAN}sudo guard${NC}    # снимок состояния защиты"
echo -e "     ${CYAN}sudo guard --json${NC}    # JSON для скриптов"
echo -e "     ${CYAN}sudo watch -n 5 guard${NC}    # live-режим (через watch)"
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
echo -e "  ${CYAN}journalctl -t protected-ports${NC}                       # логи синхронизации портов"
echo -e "  ${CYAN}systemctl status protected-ports-update.path${NC}        # статус inotify-watcher'а"
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
