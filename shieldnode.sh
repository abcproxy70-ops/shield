#!/bin/bash

# ==============================================================================
#  VPN NODE DDoS PROTECTION v3.8 (Commercial Edition)
#  - nftables rate-limit (kernel-level SYN flood protection, IPv4-only)
#  - nftables scanner-blocklist (pre-emptive drop известных сканеров)
#  - nftables connection-flood + slowloris защита (ct count + new-conn rate)
#  - nftables TCP flag sanity (drop invalid combinations)
#  - nftables anti-spoofing (fib saddr — стронгер чем rp_filter loose)
#  - nftables TCP MSS clamping (улучшает скорость VPN, устраняет фрагментацию)
#  - CrowdSec (SSH brute-force + community blocklist)
#  - guard CLI — снимок состояния защиты (one-shot, no live updates)
#  - Человекочитаемые логи в /var/log/shieldnode/events.log
#  - Мгновенное отслеживание изменений в фаерволе через inotify
#
#  Запускать ПОСЛЕ настройки фаервола (UFW/iptables/firewalld).
#  Совместимо с активным UFW и любыми другими nft-таблицами.
#  Совместимо с vpn-node-setup.sh v4.0 (XanMod + IPv6 disabled).
#
#  v3.8 changelog (perf + защита-улучшения, без подлагиваний для клиентов):
#    - ADD: TCP MSS clamping в nft chain forward.
#      Что: для new TCP-соединений устанавливает MSS option = "path MTU - 40".
#      Зачем: устраняет фрагментацию пакетов в VPN-туннеле (клиент жалуется
#      "сайт не открывается / медленно грузит") — стандартная VPN-болезнь
#      когда MTU 1500 на eth0 + tun0/wg0 ломает large-packet path.
#      Эффект: УСКОРЯЕТ VPN, не замедляет. Применяется только к forwarded
#      трафику (через ноду), не к локальному (SSH/control plane не задевает).
#    - ADD: fib saddr type missing drop (anti-spoofing уровень 2).
#      Что: дропает пакеты у которых FIB не знает обратного маршрута к src IP.
#      Стронгер чем rp_filter loose — ловит spoofed src из соседних сетей.
#      Включается ТОЛЬКО если у сервера один upstream-интерфейс (детектится
#      автоматически). На multi-homed VPS — пропускается с warning'ом
#      (asymmetric routing там нормален). tun*/wg*/docker*/lo исключены.
#
#  v3.7 changelog (standalone-ready: shieldnode работает БЕЗ vpn-node-setup.sh):
#    - ADD: shieldnode теперь сам ставит критичные security sysctl, скопированные
#      из vpn-node-setup.sh (один-в-один значения). Скрипт перестал зависеть от
#      порядка установки — защита работает даже если setup запускался раньше,
#      позже или вообще не ставился. Скопированы 9 ключей:
#        • tcp_syncookies=1, tcp_rfc1337=1
#        • rp_filter=2 (loose, all+default — обязательно для VPN-форвардинга)
#        • accept_redirects=0 (all+default)
#        • send_redirects=0 (all+default)
#        • icmp_echo_ignore_broadcasts=1
#      Все значения проверены на безопасность для VPN-нагрузки (Reality/sing-box
#      /Hysteria/TUIC) — не ломают форвардинг, mux, мобильных клиентов, CGNAT.
#    - CHANGE: /etc/sysctl.d/99-shieldnode.conf → /etc/sysctl.d/90-shieldnode.conf.
#      Префикс 90 < 99 — теперь vpn-node-setup.sh (99-xray-tuning) грузится
#      ПОСЛЕ нас. При любых будущих коллизиях по ключам setup всегда выигрывает.
#      Если на сервере был старый 99-shieldnode.conf — uninstall чистит оба имени.
#
#  v3.6 changelog (compatibility с vpn-node-setup.sh + IPv6 dropped):
#    - REMOVED: ВСЯ IPv6-логика. Причина: vpn-node-setup.sh отключает IPv6
#      через /etc/sysctl.d/99-disable-ipv6.conf, и оставленные ip6 sets +
#      rules были мёртвым кодом, расходовавшим память и засорявшим guard.
#      Удалено: scanner_blocklist_v6, suspect_v6, confirmed_attack_v6,
#      syn_flood_v6, udp_flood_v6, newconn_rate_v6, manual_whitelist_v6,
#      все *_v6 counters, ip6 saddr правила, meta nfproto ipv4/ipv6 фильтры,
#      MGMT_IPV6 detection в UFW/iptables/firewalld/nftables, BL_V6/SYN_BAN_V6
#      в guard, *_v6_packets/_bytes в JSON output.
#    - REMOVED: net.ipv4.tcp_max_syn_backlog из 99-shieldnode.conf.
#      Причина: vpn-node-setup.sh ставит =65535 в /etc/sysctl.d/99-xray-tuning.conf;
#      shieldnode перетирал на 4096 (по алфавиту 99-shieldnode > 99-xray).
#      Не наша зона ответственности — backlog настраивается под профиль RAM.
#    - REMOVED: net.ipv6.conf.all.accept_source_route, accept_redirects из
#      99-shieldnode.conf (IPv6 отключён глобально).
#    - FIX: stale changelog (v3.3) говорил rp_filter=1; фактически с v3.4
#      ставится =2 (loose). Привёл комментарий в соответствие.
#
#  v3.5 changelog (HTTP-flood защита + читаемые логи + cleanup):
#    - REMOVED: SSH-key auto-whitelist полностью удалён.
#      Причина: cs-ssh-whitelist на одном из серверов перестал пускать
#      админа (race condition между journald и cscli decisions). CrowdSec
#      sshd-bf и ssh-cve коллекции защищают SSH самостоятельно. Manual
#      whitelist (через UFW ALLOW from <IP>) остаётся.
#      Удалено: cs-ssh-key-whitelist.sh, cs-ssh-whitelist.service,
#      postoverflow ssh-key-whitelist.yaml, ШАГ 8, $CS_WHITE/ssh_key_auto.
#    - ADD: Connection-flood / slowloris / HTTP-flood защита (ШАГ 4):
#      • ct count limit на src IP для TCP DPT 443: max 50 concurrent → suspect
#      • new connections rate-limit: 50 new conn/min на src
#      • TCP flag sanity: drop invalid combinations (FIN+SYN, RST+SYN, all flags)
#      • manual_whitelist обходит все три проверки
#    - ADD: Человекочитаемый /var/log/shieldnode/events.log:
#      • формат: [TS] EVENT_TYPE ip=X port=Y type=Z hits=N
#      • агрегатор пишет туда параллельно с sqlite
#      • в guard новый раздел "Recent events" + кнопка [9] view full log
#    - ADD: /var/log/shieldnode/install.log — все шаги установки через tee
#    - ADD: /etc/logrotate.d/shieldnode (compress, rotate 30, daily, maxsize 50M)
#    - CLEANUP: удалены legacy fallback'и парсинга nft через grep/awk (jq есть всегда)
#    - CLEANUP: удалены закомментированные блоки и дубли apt install jq
#
#  v3.4 changelog (VPN forwarding fix):
#    - FIX: rp_filter=1 (strict) → rp_filter=2 (loose). Strict mode мог
#      ломать VPN-форвардинг — пакет приходит на eth0, ответ через tun0,
#      strict rp_filter дропает asymmetric routing. Loose mode (RFC 3704)
#      разрешает legitimate routing и при этом защищает от IP-spoofing.
#      Это значение совпадает с vpn-node-setup.sh (XanMod tuning).
#
#  v3.3 changelog (security hardening 2026):
#    - ADD: apt upgrade openssh-server при установке.
#      Закрывает критические CVE 2025-2026:
#      • CVE-2025-26466 — pre-auth DoS через SSH2_MSG_PING (введён в 9.5p1)
#      • CVE-2025-26465 — MitM при VerifyHostKeyDNS=yes
#      • CVE-2026-35414 — AuthorizedKeysCommand bypass (нужен OpenSSH ≥10.3)
#    - ADD: sysctl kernel hardening (через /etc/sysctl.d/99-shieldnode.conf):
#      • net.ipv4.tcp_syncookies=1 — защита от SYN-flood даже при переполнении backlog
#      • net.ipv4.tcp_max_syn_backlog=4096 — больше места для SYN-RECV соединений
#      • net.ipv4.tcp_synack_retries=2 — быстрее освобождать слоты при атаке
#      • net.ipv4.conf.all.rp_filter=2 — защита от IP-spoofing (loose, см. v3.4 fix)
#      • net.ipv4.conf.all.accept_source_route=0 — отключить source routing
#      • net.ipv4.icmp_echo_ignore_broadcasts=1 — защита от smurf-атак
#      • net.ipv4.tcp_rfc1337=1 — защита от TIME_WAIT assassination
#    - ВНИМАНИЕ: после установки рекомендуется ребут чтобы apt upgrade
#      применил новый sshd binary.
#
#  v3.2 changelog (UI polish + актуализация документации):
#    - FIX: рамки меню в guard съезжали из-за 2-cell ширины эмодзи в терминалах.
#      Решение: убраны эмодзи из меню, оставлены только в заголовках разделов.
#      Теперь рамки выровнены везде (xterm/screen/tmux/ssh-клиенты).
#    - FIX: footer установки содержал устаревшую информацию:
#      • "60/sec burst 100" → теперь правильно "300/sec burst 500" (v2.5+)
#      • "Удалить: bash vpn-node-ddos-protect-v1_5.sh" → актуальная версия
#      • Добавлено упоминание ban-once архитектуры
#      • Добавлено упоминание SKIPA blocklist + MISP/CIRCL
#      • Добавлены команды для управления историей блокировок
#
#  v3.1 changelog (КРИТИЧЕСКИЙ FIX UFW conflict):
#    - FIX: после установки скрипта UFW переставал работать после ребута.
#      Причина: /etc/nftables.conf содержит `flush ruleset` который при
#      загрузке nftables.service удаляет ВСЕ правила, включая UFW.
#      Мы добавляли свой include в этот же файл — после ребута nftables
#      load чистил UFW и не загружал его обратно.
#    - SOLUTION: использовать отдельный systemd-сервис shieldnode-nftables
#      который загружает только нашу таблицу /etc/nftables.d/ddos-protect.conf
#      БЕЗ flush ruleset. UFW и наш сервис не конфликтуют.
#    - При апгрейде с v3.0 — миграция автоматическая, удалит include из
#      /etc/nftables.conf и установит свой сервис.
#
#  v3.0 changelog (UI redesign):
#    - REWRITE: полностью переработан guard — современный UI с двойными
#      рамками, секциями-карточками, статус-индикаторами, иконками.
#    - Главный экран: hero-карточка со сводкой (заблокировано всего, активные
#      атаки, статус сервисов одной строкой).
#    - Двухколоночное меню — компактнее, читаемее.
#    - Добавлены ASCII-bar для визуализации scanner blocklist coverage.
#    - Все labels на английском, дашборд готов для мультиязычной версии.
#
#  v2.9 changelog (полная история блокировок):
#    - ADD: persistent история блокировок в /var/lib/shieldnode/events.db (sqlite).
#      Таблица events(ts, type, ip, port, count) — агрегирует в реальном
#      времени. Размер БД остаётся маленьким (тысячи строк за год).
#    - ADD: nftables logging для scanner и confirmed_attack drops.
#      Через rate-limit (1 пакет/сек на IP) — не забиваем journald.
#    - ADD: shieldnode-aggregator.service — собирает события из journald
#      каждые 60 секунд, дедуплицирует и пишет в БД.
#    - ADD: новый раздел "All-time stats" в guard:
#      • scanners blocked: 12,847 IP за всё время
#      • ddos blocked: 234 IP за всё время
#      • ssh brute-force blocked: 89 IP (из crowdsec.db)
#      • top 10 атакующих стран
#    - ADD: команды [6] history, [7] top attackers в guard
#
#  v2.8 changelog (UX-фиксы):
#    - ADD: ожидание apt lock в начале скрипта (до 5 минут).
#      На свежих VPS unattended-upgrades держит dpkg lock 2-5 минут после
#      первой загрузки. Раньше: установка падала с "Установка crowdsec
#      провалилась". Теперь: ждём с прогресс-индикатором и продолжаем.
#    - CHG: ошибки apt теперь показываются (раньше глотались через
#      `>/dev/null 2>&1`). Если что-то падает — в выводе видно что именно.
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
    echo "  - scanner-blocklist updater + timer"
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
    for unit in scanner-blocklist-update.timer scanner-blocklist-update.service \
                protected-ports-update.timer protected-ports-update.service \
                protected-ports-update.path \
                shieldnode-aggregator.timer shieldnode-aggregator.service \
                shieldnode-nftables.service; do
        systemctl disable --now "$unit" 2>/dev/null || true
        rm -f "/etc/systemd/system/$unit"
    done
    # v3.5: legacy unit от ≤v3.4 — удаляем если осталось от старой установки
    systemctl disable --now cs-ssh-whitelist 2>/dev/null || true
    rm -f /etc/systemd/system/cs-ssh-whitelist.service
    systemctl daemon-reload
    print_ok "Systemd units удалены"

    # Scripts
    rm -f /usr/local/sbin/cs-ssh-key-whitelist.sh
    rm -f /usr/local/sbin/update-scanner-blocklist.sh
    rm -f /usr/local/sbin/update-protected-ports.sh
    rm -f /usr/local/sbin/shieldnode-aggregator.sh
    rm -f /usr/local/bin/guard
    print_ok "Скрипты удалены (включая команду guard)"

    # БД истории событий (v2.9)
    rm -rf /var/lib/shieldnode

    # v3.5: human-readable логи + logrotate
    rm -rf /var/log/shieldnode
    rm -f /etc/logrotate.d/shieldnode
    print_ok "Логи и logrotate-конфиг удалены"

    # Sysctl hardening (v3.3+, оба имени файла — старое 99 и новое 90 из v3.7)
    REMOVED_SYSCTL=0
    for f in /etc/sysctl.d/99-shieldnode.conf /etc/sysctl.d/90-shieldnode.conf; do
        if [ -f "$f" ]; then
            rm -f "$f"
            REMOVED_SYSCTL=1
        fi
    done
    if [ "$REMOVED_SYSCTL" = "1" ]; then
        sysctl --system >/dev/null 2>&1 || true
        print_ok "Sysctl hardening удалён (применятся defaults)"
    fi

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
# v3.5: install.log — все шаги установки в /var/log/shieldnode/install.log
# ==============================================================================
# Поднимаем тут (до ШАГ 1), чтобы покрыть проверки и весь output установки.
# Используем tee + process substitution: stdout и stderr идут И на терминал,
# И в файл. Если tee недоступен или /var/log не пишется — продолжаем без лога.
INSTALL_LOG_DIR="/var/log/shieldnode"
INSTALL_LOG="$INSTALL_LOG_DIR/install.log"
if mkdir -p "$INSTALL_LOG_DIR" 2>/dev/null && touch "$INSTALL_LOG" 2>/dev/null; then
    chmod 0750 "$INSTALL_LOG_DIR" 2>/dev/null || true
    chmod 0640 "$INSTALL_LOG" 2>/dev/null || true
    {
        echo ""
        echo "═══════════════════════════════════════════════════════════════"
        echo "shieldnode install run — $(date '+%Y-%m-%d %H:%M:%S %z')"
        echo "  host: $(hostname)"
        echo "  user: $(id -un) (uid=$EUID)"
        echo "  args: $*"
        echo "═══════════════════════════════════════════════════════════════"
    } >> "$INSTALL_LOG"
    # Перенаправляем stdout И stderr в tee (видим на экране + пишем в лог).
    # Это ставится ДО первого print_* — все шаги установки попадут в файл.
    exec > >(tee -a "$INSTALL_LOG") 2>&1
fi

# ==============================================================================
# v3.7: LEGACY CLEANUP (миграция со старых версий)
# ==============================================================================
# Точечно убираем артефакты старых версий, чтобы не висели orphan-файлы.
# Делаем тихо — если ничего нет, ничего не происходит.
# Полная зачистка остаётся в --uninstall блоке.

LEGACY_CLEANED=0

# v≤3.4: SSH-key auto-whitelist (удалён в v3.5)
if [ -f /etc/systemd/system/cs-ssh-whitelist.service ]; then
    systemctl disable --now cs-ssh-whitelist 2>/dev/null || true
    rm -f /etc/systemd/system/cs-ssh-whitelist.service
    rm -f /usr/local/sbin/cs-ssh-key-whitelist.sh
    rm -f /etc/crowdsec/postoverflows/s01-whitelist/ssh-key-whitelist.yaml
    rm -rf /run/cs-ssh-whitelist
    systemctl daemon-reload 2>/dev/null || true
    LEGACY_CLEANED=1
fi

if [ "$LEGACY_CLEANED" = "1" ]; then
    print_status "Legacy cleanup: удалены артефакты ≤v3.4 (cs-ssh-whitelist)"
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

# v2.8: ждём пока apt освободится (unattended-upgrades на свежих VPS)
wait_for_apt_lock() {
    local max_wait=300  # 5 минут максимум
    local elapsed=0
    local first_msg=1

    while pgrep -f "apt-get|apt |dpkg|unattended-upgr" >/dev/null 2>&1 || \
          fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || \
          fuser /var/lib/apt/lists/lock >/dev/null 2>&1 || \
          fuser /var/lib/dpkg/lock >/dev/null 2>&1; do

        if [ $first_msg -eq 1 ]; then
            print_status "Ждём пока освободится apt (unattended-upgrades в процессе)..."
            print_info "Это может занять 2-5 минут на свежем VPS"
            first_msg=0
        fi

        if [ $elapsed -ge $max_wait ]; then
            print_warn "apt всё ещё занят после 5 минут ожидания"
            print_info "Попробуй: sudo killall unattended-upgr; sleep 5; и запусти скрипт заново"
            return 1
        fi

        sleep 5
        elapsed=$((elapsed + 5))
        printf "\r  ${YELLOW}⏳${NC} Ждём apt lock... ${BOLD}${elapsed}s${NC}    "
    done

    if [ $first_msg -eq 0 ]; then
        printf "\r"
        print_ok "apt освободился (ждали ${elapsed}s)"
    fi
    return 0
}

# Проверяем apt lock перед любыми установками
wait_for_apt_lock || exit 1

if ! command -v nft >/dev/null 2>&1; then
    print_status "Устанавливаю nftables..."
    if ! DEBIAN_FRONTEND=noninteractive apt-get install -y nftables; then
        print_error "Не удалось установить nftables"
        exit 1
    fi
fi
print_ok "nftables: $(nft --version 2>&1 | head -1)"

# v1.9: sqlite3 для быстрого чтения crowdsec БД в guard'е
# (опционально — fallback на cscli если не установится)
if ! command -v sqlite3 >/dev/null 2>&1; then
    wait_for_apt_lock
    print_status "Устанавливаю sqlite3 (для оптимизации guard)..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y sqlite3 >/dev/null 2>&1 || \
        print_warn "sqlite3 не установлен — guard будет использовать cscli (медленнее)"
fi

# v2.4: jq для парсинга nft -j вывода в guard
if ! command -v jq >/dev/null 2>&1; then
    wait_for_apt_lock
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

# v3.3: SECURITY HARDENING
# Закрытие свежих CVE 2025-2026 + sysctl kernel hardening.

# 1) Апгрейд OpenSSH (закрывает CVE-2025-26465/26466, CVE-2026-35414)
SSH_VERSION=$(ssh -V 2>&1 | grep -oE 'OpenSSH_[0-9]+\.[0-9]+(p[0-9]+)?' | head -1)
if [ -n "$SSH_VERSION" ]; then
    print_info "OpenSSH: $SSH_VERSION"
    # Проверяем версию: < 9.9p2 уязвим к CVE-2025-26466
    SSH_MAJOR=$(echo "$SSH_VERSION" | grep -oE '[0-9]+\.[0-9]+' | head -1)
    if dpkg --compare-versions "$SSH_MAJOR" "lt" "10.3" 2>/dev/null; then
        print_warn "Версия OpenSSH потенциально уязвима к CVE-2025-26466 / CVE-2026-35414"
        print_status "Обновляю openssh-server (apt upgrade)..."
        wait_for_apt_lock
        if DEBIAN_FRONTEND=noninteractive apt-get install --only-upgrade -y openssh-server openssh-client >/dev/null 2>&1; then
            NEW_VERSION=$(ssh -V 2>&1 | grep -oE 'OpenSSH_[0-9]+\.[0-9]+(p[0-9]+)?' | head -1)
            if [ "$NEW_VERSION" != "$SSH_VERSION" ]; then
                print_ok "OpenSSH обновлён: $SSH_VERSION → $NEW_VERSION"
                print_info "Перезагрузи ssh: systemctl restart ssh (или ребут)"
            else
                print_info "OpenSSH уже последней версии в репо ($SSH_VERSION)"
                print_info "Если репо старый — обнови дистрибутив или через backports"
            fi
        else
            print_warn "Не удалось обновить openssh — продолжаю установку"
        fi
    else
        print_ok "OpenSSH версия не уязвима к известным CVE"
    fi
fi

# 2) Sysctl kernel hardening
print_status "Применяю sysctl kernel hardening..."

# v3.7: миграция со старого имени 99-shieldnode.conf → 90-shieldnode.conf.
# Префикс 90 < 99, теперь vpn-node-setup.sh (99-xray-tuning) грузится ПОСЛЕ нас
# и при коллизиях побеждает (но коллизий быть не должно — setup ставит те же
# значения что и мы, см. блок ниже).
if [ -f /etc/sysctl.d/99-shieldnode.conf ]; then
    rm -f /etc/sysctl.d/99-shieldnode.conf
    print_info "Удалён старый /etc/sysctl.d/99-shieldnode.conf (миграция v3.7)"
fi

SYSCTL_FILE="/etc/sysctl.d/90-shieldnode.conf"
cat > "$SYSCTL_FILE" <<'SYSCTL_EOF'
# Shieldnode kernel hardening v3.7
# Префикс 90 — это базовая security-полка. vpn-node-setup.sh (99-xray-tuning)
# может перетереть отдельные ключи, если у оператора другие приоритеты.
#
# v3.7: shieldnode стал standalone. Раньше критичные security-ключи
# (rp_filter, syncookies, redirects, ...) ставил только vpn-node-setup.sh,
# из-за чего без него shieldnode работал на дефолтах ядра (rp_filter=1
# strict — ломал VPN-форвардинг). Теперь shieldnode сам пишет минимум,
# нужный для своей работы. Значения скопированы из vpn-node-setup.sh
# один-в-один — конфликта не будет.
#
# Зону ответственности setup'а (BBRv3, qdisc=fq, conntrack tuning, buffer
# sizes, file-max, swappiness, ip_forward, ephemeral ports, keepalives,
# tcp_max_syn_backlog, tcp_tw_reuse) shieldnode НЕ трогает.

# === SYN-flood mitigation ===
# SYN cookies (kernel сам активирует когда backlog переполнен)
net.ipv4.tcp_syncookies = 1
# Сколько раз отправлять SYN+ACK перед сдачей (по умолчанию 5 — слишком долго под flood)
net.ipv4.tcp_synack_retries = 2
# Сколько раз ретраить SYN при исходящих (по умолчанию 6)
net.ipv4.tcp_syn_retries = 3

# === IP-spoofing mitigation ===
# Reverse path filter (RFC 3704), режим 2 = loose.
# КРИТИЧНО для VPN: режим 1 (strict) дропает asymmetric routing
# (пакет приходит на eth0, ответ через tun0 — нормально для VPN).
# Режим 2 защищает от spoofing и при этом не ломает форвардинг.
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
# Source routing — древняя угроза, отключаем
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
# ICMP redirects — могут использоваться для атак (man-in-the-middle)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
# VPN-нода — forwarding-роутер, ICMP redirects слать не должна
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# === ICMP hardening ===
# Игнорировать broadcast ping (smurf-атаки)
net.ipv4.icmp_echo_ignore_broadcasts = 1
# Игнорировать bogus ICMP responses
net.ipv4.icmp_ignore_bogus_error_responses = 1

# === TCP hardening ===
# Защита от TIME_WAIT assassination (RFC 1337)
net.ipv4.tcp_rfc1337 = 1

# === Logging ===
# Логировать martian packets (странные source IP — ранний сигнал атаки)
net.ipv4.conf.all.log_martians = 1
SYSCTL_EOF

# Применяем
if sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1; then
    print_ok "Sysctl hardening применён ($SYSCTL_FILE)"
else
    print_warn "Не все sysctl применились (некоторые модули могут отсутствовать)"
    print_info "Проверь: sysctl -p $SYSCTL_FILE"
fi

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

            # v2.2: management IPs из правил "ALLOW from <IP>" (только IPv4, v3.6)
            # Формат: "2222/tcp  ALLOW  213.165.55.166" (3й колонкой идёт IP вместо Anywhere)
            mgmt_ipv4=$(echo "$ufw_out" | awk '
                $2 == "ALLOW" && $0 !~ /\(v6\)/ && $3 != "Anywhere" {
                    if ($3 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?$/) print $3
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
            # nft -j: ищем accept-правила с tcp/udp dport (jq mandatory, см. ШАГ 1)
            local nft_json
            nft_json=$(nft -j list ruleset 2>/dev/null)
            if [ -n "$nft_json" ]; then
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
            ;;
    esac

    echo "$tcp_list"
    echo "$udp_list"
    echo "$mgmt_ipv4"
}

# Получаем сырые списки портов из фаервола
FW_OUTPUT=$(detect_firewall_ports "$FIREWALL_TYPE")
RAW_TCP=$(echo "$FW_OUTPUT" | sed -n '1p')
RAW_UDP=$(echo "$FW_OUTPUT" | sed -n '2p')
MGMT_IPV4=$(echo "$FW_OUTPUT" | sed -n '3p')

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

# v2.2: manual whitelist для management-IP (правила UFW "ALLOW from <IP>")
if [ -n "$MGMT_IPV4" ]; then
    print_ok "Management IPv4 (manual whitelist): ${BOLD}$MGMT_IPV4${NC}"
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

# v2.2: management IPs для nft set (только IPv4, v3.6)
MANUAL_WHITELIST_V4_INIT=""
if [ -n "$MGMT_IPV4" ]; then
    MANUAL_WHITELIST_V4_INIT="        elements = { $(echo "$MGMT_IPV4" | sed 's/,/, /g') }"
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
    print_ok "Текущий админский IP: ${BOLD}$ADMIN_IP${NC}"
    print_info "Если хочешь добавить в manual whitelist: sudo ufw allow from $ADMIN_IP"
else
    print_info "Админский IP не определён (запуск с локальной консоли — это ок)"
fi

# v3.8: детект upstream-интерфейсов для anti-spoofing (fib saddr).
# Считаем интерфейсы в основной таблице маршрутизации, исключая виртуальные.
# Если интерфейсов больше 1 — multi-homed VPS, fib может дать false-positive
# из-за asymmetric routing → отключаем правило.
UPSTREAM_IFACES=$(ip -o -4 route show default 2>/dev/null | awk '{print $5}' | sort -u)
UPSTREAM_COUNT=$(echo "$UPSTREAM_IFACES" | grep -cE '^[a-z]')
if [ "$UPSTREAM_COUNT" = "1" ] && [ -n "$UPSTREAM_IFACES" ]; then
    ENABLE_FIB_ANTISPOOF=1
    print_ok "Single-homed VPS (uplink: ${BOLD}$UPSTREAM_IFACES${NC}) — fib anti-spoofing будет включён"
else
    ENABLE_FIB_ANTISPOOF=0
    print_warn "Multi-homed VPS (${UPSTREAM_COUNT} default routes) — fib anti-spoofing ОТКЛЮЧЁН"
    print_info "На multi-homed asymmetric routing нормален; fib может дать false-positive."
    print_info "rp_filter=2 (loose) от vpn-node-setup.sh продолжает защищать от spoofing."
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

# v3.8: подготовка conditional-правил для nft template.
# fib anti-spoofing — только на single-homed VPS.
if [ "${ENABLE_FIB_ANTISPOOF:-0}" = "1" ]; then
    FIB_ANTISPOOF_RULE="        # === v3.8: ANTI-SPOOFING (fib reverse-path) ===
        # Стронгер чем rp_filter loose — ловит spoofed src из соседних сетей,
        # для которых kernel'у не известен обратный маршрут.
        # iif lo пропускаем (локальный трафик не должен попадать под fib check).
        # Включено потому что VPS single-homed (один upstream).
        iif \"lo\" accept
        fib saddr . iif oif missing counter name tcp_invalid drop"
else
    FIB_ANTISPOOF_RULE="        # fib anti-spoofing отключён (multi-homed VPS — может дать false-positive)"
fi

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
# исключения). Manual whitelist управляется через UFW (ALLOW from <IP>):
# скрипт update-protected-ports.sh синхронит management-IP из UFW в nft.
#
# Test:    hping3 -S -p ${XRAY_PORTS%%,*} -i u100 <YOUR_VPN_IP>
# Monitor: nft list set inet ddos_protect syn_flood_v4
#          nft list set inet ddos_protect scanner_blocklist_v4 | wc -l
# Remove:  bash vpn-node-ddos-protect-v3_5.sh --uninstall

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

    # --- v2.5: STAGE 2 — CONFIRMED ATTACK (бан 1 час) ---
    # Сюда IP попадает если уже сидел в suspect и опять превысил лимит.
    # Это значит — точно атака, баним всерьёз.
    set confirmed_attack_v4 {
        type ipv4_addr
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
    set udp_flood_v4 {
        type ipv4_addr
        flags dynamic, timeout
        timeout 1m
        size 65536
    }

    # v3.5: rate-limit новых TCP-соединений (отдельно от SYN-flood — SYN считает ВСЕ
    # SYN-пакеты включая retry, а это считает уникальные new-conn по conntrack).
    # Дополняет SYN-rate-limit для случаев когда атакующий шлёт мало SYN, но
    # быстро открывает/закрывает много соединений (HTTP-flood через TLS).
    set newconn_rate_v4 {
        type ipv4_addr
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

    # v2.7: Named counters для статистики "всего заблокировано".
    # Каждый counter сохраняет packets и bytes с момента старта nft.
    # Сбрасываются при ребуте/перезагрузке правил.
    counter scanner_drops_v4 { }
    counter confirmed_drops_v4 { }
    counter syn_confirmed_v4 { }
    counter udp_confirmed_v4 { }
    # v3.5: counters для HTTP/connection-flood защиты
    counter conn_flood_v4 { }     # ct count > 50 на src
    counter newconn_flood_v4 { }  # >50 new conn/min на src
    counter tcp_invalid { }       # invalid TCP flag combos

    chain prerouting {
        type filter hook prerouting priority -100; policy accept;

        # Established/related — пропускаем без проверок.
        ct state established,related accept

        # Manual whitelist (всегда первым приоритетом)
        ip saddr @manual_whitelist_v4 accept

        # SSH — без блокировок (защищает CrowdSec)
        tcp dport $SSH_PORT accept

$FIB_ANTISPOOF_RULE

        # === v3.5: TCP FLAG SANITY ===
        # Дропаем пакеты с невозможными комбинациями TCP-флагов.
        # Используются port-сканерами (nmap -sN/-sF/-sX), evasion-сценариями,
        # и stateless-атаками. Легитимный трафик их не использует.
        # tcp flags syn,fin    → SYN+FIN одновременно (XMAS-вариант)
        # tcp flags syn,rst    → SYN+RST одновременно (невозможно в TCP)
        # tcp flags fin,rst    → FIN+RST одновременно (нет смысла)
        # tcp flags == 0x0     → null scan (все флаги выключены)
        # tcp flags == fin,psh,urg → XMAS scan (nmap -sX)
        tcp flags & (fin|syn) == (fin|syn) counter name tcp_invalid drop
        tcp flags & (syn|rst) == (syn|rst) counter name tcp_invalid drop
        tcp flags & (fin|rst) == (fin|rst) counter name tcp_invalid drop
        tcp flags & (fin|syn|rst|psh|ack|urg) == 0x0 counter name tcp_invalid drop
        tcp flags & (fin|syn|rst|psh|ack|urg) == (fin|psh|urg) counter name tcp_invalid drop

        # Pre-emptive drop известных сканеров (с counter v2.7).
        # Стоит ПЕРЕД rate-limit — экономит conntrack-слоты и CPU.
        # v2.9: log с rate-limit 1/sec на IP — для history БД (агрегатор парсит journald)
        ip saddr @scanner_blocklist_v4 limit rate 1/second \\
            log prefix "[shield:scanner] " level info flags ip options \\
            counter name scanner_drops_v4 drop
        ip saddr @scanner_blocklist_v4 counter name scanner_drops_v4 drop

        # === v2.5: BAN-ONCE АРХИТЕКТУРА ===
        # Двухэтапная проверка перед баном — снижает ложные баны CGNAT/мобильных.
        #
        # Этап 0: Если IP в confirmed_attack — он уже подтверждённый атакующий, дропаем.
        # v2.9: log с rate-limit 1/sec на IP — для history БД
        ip saddr @confirmed_attack_v4 limit rate 1/second \\
            log prefix "[shield:ddos] " level info flags ip options \\
            counter name confirmed_drops_v4 drop
        ip saddr @confirmed_attack_v4 counter name confirmed_drops_v4 drop

        # === v3.5: CONNECTION-FLOOD / SLOWLORIS ЗАЩИТА ===
        # Защищает от: тысяч одновременных TCP-соединений с одного IP,
        # медленного TLS handshake (slowloris), HTTP-flood через established TCP.
        # Применяется только к защищаемым TCP-портам (Xray/Reality/sing-box).
        # manual_whitelist уже пропущен выше.
        #
        # Лимиты подобраны для VPN-трафика:
        #   ct count    > 50  — concurrent connections per src IP (mux=5-20 норма,
        #                       CGNAT с 50 юзерами = до 1000, но это редкость
        #                       одновременно — большинство idle)
        #   new conn    > 50/min — скорость открытия новых соединений
        #
        # Поведение: первое нарушение → suspect (5 мин watch, no drop),
        # второе → confirmed_attack (1h drop). Та же ban-once что у SYN-flood.

        # Этап 2: IP уже в suspect и снова превышает ct count → confirmed + drop.
        tcp dport @protected_ports_tcp ct state new ip saddr @suspect_v4 \\
            ct count over 50 \\
            add @confirmed_attack_v4 { ip saddr } counter name conn_flood_v4 drop

        # Этап 1: первое превышение ct count → suspect (no drop).
        tcp dport @protected_ports_tcp ct state new \\
            ct count over 50 \\
            add @suspect_v4 { ip saddr } counter name conn_flood_v4

        # === v3.5: NEW CONNECTION RATE-LIMIT ===
        # Отдельно от SYN — считает уникальные new-conn по conntrack
        # (SYN-rate ловит retry/duplicate, а это — реальную скорость подключений).
        # Лимит: 50 new-conn/минуту на src IP.

        # Этап 2: suspect + снова превышает → confirmed.
        tcp dport @protected_ports_tcp ct state new ip saddr @suspect_v4 \\
            add @newconn_rate_v4 { ip saddr limit rate over 50/minute burst 100 packets } \\
            add @confirmed_attack_v4 { ip saddr } counter name newconn_flood_v4 drop

        # Этап 1: первое превышение → suspect.
        tcp dport @protected_ports_tcp ct state new \\
            add @newconn_rate_v4 { ip saddr limit rate over 50/minute burst 100 packets } \\
            add @suspect_v4 { ip saddr } counter name newconn_flood_v4

        # === TCP SYN rate-limit на защищаемых портах ===
        # Лимит: 300 SYN/sec, burst 500. CGNAT-friendly.
        #
        # Этап 2: IP уже в suspect и опять превышает → переводим в confirmed + drop.
        tcp dport @protected_ports_tcp ct state new ip saddr @suspect_v4 \\
            add @syn_flood_v4 { ip saddr limit rate over 300/second burst 500 packets } \\
            add @confirmed_attack_v4 { ip saddr } counter name syn_confirmed_v4 drop

        # Этап 1: IP не в suspect, но превышает → добавляем в suspect (не дропаем!).
        # Цель: дать IP "испытательный срок" 5 минут. Случайные всплески пройдут.
        tcp dport @protected_ports_tcp ct state new \\
            add @syn_flood_v4 { ip saddr limit rate over 300/second burst 500 packets } \\
            add @suspect_v4 { ip saddr }

        # === UDP rate-limit на защищаемых портах ===
        # Лимит: 600 packets/sec, burst 1000. UDP шлёт больше мелких пакетов.
        #
        # Этап 2: подтверждённый атакующий
        udp dport @protected_ports_udp ip saddr @suspect_v4 \\
            add @udp_flood_v4 { ip saddr limit rate over 600/second burst 1000 packets } \\
            add @confirmed_attack_v4 { ip saddr } counter name udp_confirmed_v4 drop

        # Этап 1: первое превышение
        udp dport @protected_ports_udp \\
            add @udp_flood_v4 { ip saddr limit rate over 600/second burst 1000 packets } \\
            add @suspect_v4 { ip saddr }
    }

    # === v3.8: TCP MSS CLAMPING (forward hook) ===
    # Что: для new TCP connection clamp MSS option в SYN до "path MTU - 40".
    # Зачем: VPN-туннели (tun0/wg0) часто имеют MTU < 1500. Без clamping'а
    # клиент шлёт пакет 1460 byte payload (MSS=1460 для eth0 1500), который
    # потом приходится фрагментировать или дропать с ICMP "frag needed".
    # Симптом без clamping'а: "сайт грузится медленно" / "не открывается".
    # С clamping'ом: клиент сразу шлёт правильный MSS, нет ретрансмитов.
    #
    # priority: filter (после rate-limit'а в prerouting, перед NAT).
    # Применяется ТОЛЬКО к forwarded трафику (не локальному SSH/control plane).
    chain forward {
        type filter hook forward priority filter; policy accept;
        tcp flags syn tcp option maxseg size set rt mtu
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

# v3.1: НЕ встраиваемся в /etc/nftables.conf!
# Тот файл содержит `flush ruleset` который убивает UFW при ребуте.
# Вместо этого создаём свой systemd-сервис shieldnode-nftables.service
# который загружает только нашу таблицу БЕЗ flush.

# Если предыдущая версия добавила include — удаляем (миграция с v3.0)
NFTABLES_MAIN="/etc/nftables.conf"
if [ -f "$NFTABLES_MAIN" ] && grep -q "$NFT_DDOS_CONF" "$NFTABLES_MAIN"; then
    print_status "Удаляю старый include из $NFTABLES_MAIN (миграция v3.0→v3.1)"
    cp -a "$NFTABLES_MAIN" "$BACKUP_DIR/nftables.conf.before"
    sed -i '/# DDoS protection (vpn-node-ddos-protect)/d' "$NFTABLES_MAIN"
    sed -i "\|include \"$NFT_DDOS_CONF\"|d" "$NFTABLES_MAIN"
    print_ok "Старый include удалён"
fi

# Создаём свой systemd-сервис для загрузки нашей таблицы
cat > /etc/systemd/system/shieldnode-nftables.service <<EOF
[Unit]
Description=Shieldnode DDoS protection nftables ruleset
Documentation=https://github.com/abcproxy70-ops/shield
DefaultDependencies=no
Before=network-pre.target
Wants=network-pre.target
After=nftables.service
# Запускаемся ПОСЛЕ ufw чтобы наши правила не пересекались
After=ufw.service

[Service]
Type=oneshot
RemainAfterExit=yes
# Загружаем ТОЛЬКО нашу таблицу БЕЗ flush ruleset
# Это сохраняет UFW и любые другие nft-правила
ExecStart=/usr/sbin/nft -f $NFT_DDOS_CONF
# При остановке/restart удаляем только нашу таблицу
ExecStop=/usr/sbin/nft delete table inet ddos_protect
ExecReload=/usr/sbin/nft -f $NFT_DDOS_CONF

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable shieldnode-nftables.service >/dev/null 2>&1

# Перезапускаем чтобы наш ruleset точно загрузился
if systemctl restart shieldnode-nftables.service 2>/dev/null; then
    print_ok "Сервис shieldnode-nftables.service установлен и активен"
    print_info "Загружает только нашу таблицу — UFW не пересекается"
else
    print_warn "shieldnode-nftables не стартанул — проверь: journalctl -u shieldnode-nftables -n 30"
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
            # v2.2: management IPs (только IPv4, v3.6)
            mgmt_ipv4=$(echo "$ufw_out" | awk '
                $2 == "ALLOW" && $0 !~ /\(v6\)/ && $3 != "Anywhere" {
                    if ($3 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?$/) print $3
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
            # v3.5: jq-парсинг (jq mandatory, ставится в ШАГ 1).
            local nft_json
            nft_json=$(nft -j list ruleset 2>/dev/null)
            if [ -n "$nft_json" ]; then
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
            ;;
    esac

    echo "$tcp_list"
    echo "$udp_list"
    echo "$mgmt_ipv4"
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
# v3.5: переехали в /run/shieldnode (cs-ssh-whitelist удалён).
LOCKFILE="/run/shieldnode/.ports-update.lock"
mkdir -p /run/shieldnode 2>/dev/null
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
    # v2.2: синхронизируем management whitelist (только IPv4, v3.6)
    echo "flush set inet ddos_protect manual_whitelist_v4"
    if [ -n "$NEW_MGMT_V4" ]; then
        echo "add element inet ddos_protect manual_whitelist_v4 { $(echo "$NEW_MGMT_V4" | sed 's/,/, /g') }"
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
# v3.5: lock-файл /run/shieldnode/.ports-update.lock (раньше использовался
# /run/cs-ssh-whitelist, удалён вместе с auto-whitelist).
RuntimeDirectory=shieldnode
RuntimeDirectoryMode=0755
ReadWritePaths=/run/shieldnode
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
# госсканеры РФ/CN/etc) и кладём их в nft set scanner_blocklist_v4.
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

# Извлекаем валидные IPv4-подсети (с CIDR или без). v3.6: IPv6 убран — ядро отключает v6.
grep -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]+)?' "$TMP/all.raw" | \
    sort -u > "$TMP/v4.list"

V4_COUNT=$(wc -l < "$TMP/v4.list")

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
} > "$TMP/nft-batch"

if nft -f "$TMP/nft-batch" 2>"$TMP/nft.err"; then
    logger -t "$LOG_TAG" "Updated: $V4_COUNT IPv4 подсетей"
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
    if [ "$BLOCKLIST_V4_SIZE" -gt 0 ]; then
        print_ok "Blocklist загружен: $BLOCKLIST_V4_SIZE v4 подсетей"
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
    wait_for_apt_lock
    print_status "Подключаю репозиторий CrowdSec..."
    if ! curl -fsSL https://install.crowdsec.net | bash; then
        print_error "Не удалось подключить репозиторий CrowdSec"
        print_info "Проверь интернет: curl -v https://install.crowdsec.net"
        exit 1
    fi

    wait_for_apt_lock
    print_status "Устанавливаю crowdsec..."
    if ! DEBIAN_FRONTEND=noninteractive apt-get install -y crowdsec; then
        print_error "Установка crowdsec провалилась"
        print_info "Попробуй вручную: sudo apt-get install -y crowdsec"
        print_info "Или проверь: sudo apt-cache policy crowdsec"
        exit 1
    fi
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
    wait_for_apt_lock
    print_status "Устанавливаю crowdsec-firewall-bouncer-nftables..."
    if ! DEBIAN_FRONTEND=noninteractive apt-get install -y crowdsec-firewall-bouncer-nftables; then
        print_error "Установка bouncer'а провалилась"
        exit 1
    fi
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
# ШАГ 11: HISTORY AGGREGATOR (события из journald → sqlite)
# ==============================================================================

print_header "ШАГ 11: HISTORY AGGREGATOR"

# v2.9: парсим логи nftables [shield:scanner] / [shield:ddos] из journald
# и пишем в /var/lib/shieldnode/events.db с агрегацией.

DB_DIR="/var/lib/shieldnode"
DB_FILE="$DB_DIR/events.db"
mkdir -p "$DB_DIR"
chmod 0750 "$DB_DIR"

# v3.5: human-readable лог-каталог для events.log
LOG_DIR="/var/log/shieldnode"
EVENTS_LOG="$LOG_DIR/events.log"
mkdir -p "$LOG_DIR"
chmod 0750 "$LOG_DIR"
touch "$EVENTS_LOG"
chmod 0640 "$EVENTS_LOG"

# v3.5: logrotate для events.log + install.log
cat > /etc/logrotate.d/shieldnode <<'LOGROTATE_EOF'
/var/log/shieldnode/*.log {
    daily
    rotate 30
    maxsize 50M
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
    su root root
    create 0640 root root
}
LOGROTATE_EOF
print_ok "Logrotate: /etc/logrotate.d/shieldnode (daily, rotate 30, maxsize 50M)"

# Инициализируем БД
sqlite3 "$DB_FILE" <<'SQL_EOF'
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    type        TEXT NOT NULL,            -- 'scanner' | 'ddos'
    ip          TEXT NOT NULL,
    first_seen  INTEGER NOT NULL,         -- unix timestamp
    last_seen   INTEGER NOT NULL,
    count       INTEGER NOT NULL DEFAULT 1,
    UNIQUE(type, ip) ON CONFLICT REPLACE
);

CREATE INDEX IF NOT EXISTS idx_events_type ON events(type);
CREATE INDEX IF NOT EXISTS idx_events_last_seen ON events(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_events_count ON events(count DESC);

CREATE TABLE IF NOT EXISTS aggregator_state (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
SQL_EOF
chmod 0640 "$DB_FILE"
print_ok "БД создана: $DB_FILE"

# Скрипт-агрегатор
AGG_SCRIPT="/usr/local/sbin/shieldnode-aggregator.sh"
cat > "$AGG_SCRIPT" <<'AGG_EOF'
#!/bin/bash
# Парсит journald на предмет log-сообщений от nft и пишет в sqlite.
# v3.5: дополнительно пишет человекочитаемый лог в /var/log/shieldnode/events.log

DB="/var/lib/shieldnode/events.db"
EVENTS_LOG="/var/log/shieldnode/events.log"
LOG_TAG="shieldnode-agg"

# Если БД нет — выходим
[ -r "$DB" ] || { logger -t "$LOG_TAG" "DB not found: $DB"; exit 0; }

# v3.5: убедимся что events.log пишется (создан в установщике, но защита от удаления)
mkdir -p "$(dirname "$EVENTS_LOG")" 2>/dev/null
touch "$EVENTS_LOG" 2>/dev/null

# Получаем cursor (где остановились в прошлый раз)
CURSOR=$(sqlite3 "$DB" "SELECT value FROM aggregator_state WHERE key='cursor' LIMIT 1" 2>/dev/null)

# Читаем journald с того места где остановились
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

if [ -n "$CURSOR" ]; then
    journalctl --output=cat --output-fields=MESSAGE --no-pager \
        --after-cursor="$CURSOR" --show-cursor 2>/dev/null > "$TMP" || true
else
    # Первый запуск — берём за последний час
    journalctl --output=cat --output-fields=MESSAGE --no-pager \
        --since="1 hour ago" --show-cursor 2>/dev/null > "$TMP" || true
fi

# Извлекаем cursor из последней строки и удаляем его из вывода
NEW_CURSOR=$(grep -oE '^-- cursor: .+$' "$TMP" | tail -1 | sed 's/^-- cursor: //')

# Парсим сообщения [shield:scanner] и [shield:ddos]
# Формат kernel-лога: "[shield:scanner] IN=eth0 SRC=85.142.100.2 DST=... PROTO=TCP DPT=8443 ..."
declare -A scanner_ips ddos_ips
# v3.5: для events.log — собираем порт назначения и тип flood'а
declare -A ddos_ports ddos_proto

while IFS= read -r line; do
    case "$line" in
        *"[shield:scanner]"*)
            ip=$(echo "$line" | grep -oE 'SRC=[^ ]+' | head -1 | cut -d= -f2)
            [ -n "$ip" ] && scanner_ips[$ip]=$((${scanner_ips[$ip]:-0} + 1))
            ;;
        *"[shield:ddos]"*)
            ip=$(echo "$line" | grep -oE 'SRC=[^ ]+' | head -1 | cut -d= -f2)
            port=$(echo "$line" | grep -oE 'DPT=[0-9]+' | head -1 | cut -d= -f2)
            proto=$(echo "$line" | grep -oE 'PROTO=[A-Z]+' | head -1 | cut -d= -f2)
            if [ -n "$ip" ]; then
                ddos_ips[$ip]=$((${ddos_ips[$ip]:-0} + 1))
                # Запоминаем последний порт/proto виденный для этого IP
                [ -n "$port" ] && ddos_ports[$ip]="$port"
                [ -n "$proto" ] && ddos_proto[$ip]="$proto"
            fi
            ;;
    esac
done < "$TMP"

# v3.5: пишем человекочитаемые строки в events.log
TS=$(date '+%Y-%m-%d %H:%M:%S')
{
    for ip in "${!scanner_ips[@]}"; do
        cnt=${scanner_ips[$ip]}
        echo "[$TS] SCANNER ip=$ip hits=$cnt"
    done
    for ip in "${!ddos_ips[@]}"; do
        cnt=${ddos_ips[$ip]}
        port=${ddos_ports[$ip]:-?}
        proto=${ddos_proto[$ip]:-?}
        # Тип flood'а: TCP=SYN-flood, UDP=UDP-flood (грубо, более точно — counters в guard)
        case "$proto" in
            TCP) ftype="SYN-flood" ;;
            UDP) ftype="UDP-flood" ;;
            *)   ftype="$proto-flood" ;;
        esac
        echo "[$TS] DDOS BLOCK ip=$ip port=$port type=$ftype hits=$cnt"
    done
} >> "$EVENTS_LOG" 2>/dev/null

# v3.5: CrowdSec bans — читаем из decisions, дописываем НОВЫЕ в events.log
CS_DB="/var/lib/crowdsec/data/crowdsec.db"
LAST_CS_ID_FILE="/var/lib/shieldnode/.last_crowdsec_decision_id"
if [ -r "$CS_DB" ]; then
    LAST_ID=$(cat "$LAST_CS_ID_FILE" 2>/dev/null || echo 0)
    LAST_ID="${LAST_ID:-0}"
    NEW_DECISIONS=$(sqlite3 -separator '|' "$CS_DB" \
        "SELECT id, value, scenario, until FROM decisions WHERE type='ban' AND id > $LAST_ID ORDER BY id" 2>/dev/null)
    if [ -n "$NEW_DECISIONS" ]; then
        MAX_ID=$LAST_ID
        while IFS='|' read -r did val scen until; do
            [ -z "$did" ] && continue
            # value формата "Ip:1.2.3.4" или "Range:1.2.3.0/24"
            ip=${val#*:}
            # Краткий reason из scenario
            reason=${scen##*/}
            # duration: пытаемся прикинуть из until - now
            if [ -n "$until" ]; then
                until_ts=$(date -d "$until" +%s 2>/dev/null)
                now_ts=$(date +%s)
                if [ -n "$until_ts" ] && [ "$until_ts" -gt "$now_ts" ]; then
                    dur_sec=$((until_ts - now_ts))
                    if [ $dur_sec -lt 3600 ]; then dur="${dur_sec}s"
                    elif [ $dur_sec -lt 86400 ]; then dur="$((dur_sec/3600))h"
                    else dur="$((dur_sec/86400))d"
                    fi
                else
                    dur="?"
                fi
            else
                dur="?"
            fi
            echo "[$TS] CROWDSEC BAN ip=$ip reason=$reason duration=$dur" >> "$EVENTS_LOG"
            [ "$did" -gt "$MAX_ID" ] && MAX_ID=$did
        done <<< "$NEW_DECISIONS"
        echo "$MAX_ID" > "$LAST_CS_ID_FILE" 2>/dev/null
    fi
fi

# Bulk-update в БД через одну транзакцию (быстро)
NOW=$(date +%s)
{
    echo "BEGIN TRANSACTION;"
    for ip in "${!scanner_ips[@]}"; do
        cnt=${scanner_ips[$ip]}
        echo "INSERT INTO events(type, ip, first_seen, last_seen, count) VALUES('scanner', '$ip', $NOW, $NOW, $cnt) ON CONFLICT(type, ip) DO UPDATE SET last_seen=$NOW, count=count+$cnt;"
    done
    for ip in "${!ddos_ips[@]}"; do
        cnt=${ddos_ips[$ip]}
        echo "INSERT INTO events(type, ip, first_seen, last_seen, count) VALUES('ddos', '$ip', $NOW, $NOW, $cnt) ON CONFLICT(type, ip) DO UPDATE SET last_seen=$NOW, count=count+$cnt;"
    done
    if [ -n "$NEW_CURSOR" ]; then
        # Экранируем одинарные кавычки в cursor
        ESC_CURSOR=$(echo "$NEW_CURSOR" | sed "s/'/''/g")
        echo "INSERT OR REPLACE INTO aggregator_state(key, value) VALUES('cursor', '$ESC_CURSOR');"
    fi
    echo "COMMIT;"
} | sqlite3 "$DB" 2>/dev/null

# Лог
TOTAL_SCANNERS=${#scanner_ips[@]}
TOTAL_DDOS=${#ddos_ips[@]}
if [ $TOTAL_SCANNERS -gt 0 ] || [ $TOTAL_DDOS -gt 0 ]; then
    logger -t "$LOG_TAG" "Processed: scanners=$TOTAL_SCANNERS unique IPs, ddos=$TOTAL_DDOS unique IPs"
fi
AGG_EOF

chmod 0750 "$AGG_SCRIPT"
print_ok "Aggregator: $AGG_SCRIPT"

# Systemd service + timer (раз в минуту)
cat > /etc/systemd/system/shieldnode-aggregator.service <<EOF
[Unit]
Description=Shieldnode events aggregator (journald → sqlite)
After=systemd-journald.service

[Service]
Type=oneshot
ExecStart=$AGG_SCRIPT
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=$DB_DIR
ReadWritePaths=$LOG_DIR
EOF

cat > /etc/systemd/system/shieldnode-aggregator.timer <<'EOF'
[Unit]
Description=Run shieldnode aggregator every minute
Requires=shieldnode-aggregator.service

[Timer]
OnBootSec=2min
OnUnitActiveSec=1min
AccuracySec=10s
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now shieldnode-aggregator.timer >/dev/null 2>&1
print_ok "Aggregator timer активен (запуск раз в минуту)"

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
  sudo guard            snapshot + interactive menu
  sudo guard --once     snapshot only, no menu (for cron / monitoring)
  sudo guard --json     JSON output (for integrations)

Interactive menu:
  [1] active attacks            [4] scanner blocklist samples
  [2] crowdsec banned IPs       [6] recent history
  [3] whitelist IPs             [7] top attackers (all-time)
                                [9] view full /var/log/shieldnode/events.log
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

    MANUAL_WHITE=$(nft list set inet ddos_protect manual_whitelist_v4 2>/dev/null | \
        grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | wc -l)

    CS_ACTIVE="$(systemctl is-active crowdsec 2>/dev/null)"
    BOUNCER_ACTIVE="$(systemctl is-active crowdsec-firewall-bouncer 2>/dev/null)"
    PORTS_PATH_ACTIVE="$(systemctl is-active protected-ports-update.path 2>/dev/null)"

    CS_BANS=0
    if [ -r "$CS_DB" ] && command -v sqlite3 >/dev/null 2>&1; then
        CS_BANS=$(sqlite3 "$CS_DB" "SELECT COUNT(*) FROM decisions WHERE type='ban' AND until > datetime('now')" 2>/dev/null)
        CS_BANS="${CS_BANS:-0}"
    elif command -v cscli >/dev/null 2>&1; then
        CS_BANS=$(cscli decisions list --type ban -o raw 2>/dev/null | tail -n +2 | wc -l)
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
    read CONFIRMED_PKTS_V4 CONFIRMED_BYTES_V4 <<< "$(read_counter confirmed_drops_v4)"
    read SYN_CONF_PKTS_V4 SYN_CONF_BYTES_V4 <<< "$(read_counter syn_confirmed_v4)"
    read UDP_CONF_PKTS_V4 UDP_CONF_BYTES_V4 <<< "$(read_counter udp_confirmed_v4)"
    # v3.5: HTTP/conn-flood counters
    read CONN_FLOOD_PKTS_V4 CONN_FLOOD_BYTES_V4 <<< "$(read_counter conn_flood_v4)"
    read NEWCONN_FLOOD_PKTS_V4 NEWCONN_FLOOD_BYTES_V4 <<< "$(read_counter newconn_flood_v4)"
    read TCP_INVALID_PKTS TCP_INVALID_BYTES <<< "$(read_counter tcp_invalid)"

    # Когда nft started — для "stats since"
    NFT_SINCE=$(systemctl show nftables.service --property=ActiveEnterTimestamp --value 2>/dev/null | \
        xargs -I{} date -d {} '+%Y-%m-%d %H:%M' 2>/dev/null)
    NFT_SINCE="${NFT_SINCE:-—}"

    # v2.9: All-time stats из /var/lib/shieldnode/events.db
    SHIELD_DB="/var/lib/shieldnode/events.db"
    ALLTIME_SCANNERS=0
    ALLTIME_DDOS=0
    ALLTIME_SCANNER_PKTS=0
    ALLTIME_DDOS_PKTS=0
    DB_SINCE="—"

    if [ -r "$SHIELD_DB" ] && command -v sqlite3 >/dev/null 2>&1; then
        ALLTIME_SCANNERS=$(sqlite3 "$SHIELD_DB" "SELECT COUNT(*) FROM events WHERE type='scanner'" 2>/dev/null)
        ALLTIME_DDOS=$(sqlite3 "$SHIELD_DB" "SELECT COUNT(*) FROM events WHERE type='ddos'" 2>/dev/null)
        ALLTIME_SCANNER_PKTS=$(sqlite3 "$SHIELD_DB" "SELECT COALESCE(SUM(count), 0) FROM events WHERE type='scanner'" 2>/dev/null)
        ALLTIME_DDOS_PKTS=$(sqlite3 "$SHIELD_DB" "SELECT COALESCE(SUM(count), 0) FROM events WHERE type='ddos'" 2>/dev/null)
        ALLTIME_SCANNERS="${ALLTIME_SCANNERS:-0}"
        ALLTIME_DDOS="${ALLTIME_DDOS:-0}"
        ALLTIME_SCANNER_PKTS="${ALLTIME_SCANNER_PKTS:-0}"
        ALLTIME_DDOS_PKTS="${ALLTIME_DDOS_PKTS:-0}"

        # Самое раннее событие — "since"
        FIRST_TS=$(sqlite3 "$SHIELD_DB" "SELECT MIN(first_seen) FROM events" 2>/dev/null)
        if [ -n "$FIRST_TS" ] && [ "$FIRST_TS" != "" ]; then
            DB_SINCE=$(date -d "@$FIRST_TS" '+%Y-%m-%d %H:%M' 2>/dev/null)
        fi
    fi

    # CrowdSec all-time bans (за всю историю в crowdsec.db)
    CS_ALLTIME_BANS=0
    if [ -r "$CS_DB" ] && command -v sqlite3 >/dev/null 2>&1; then
        # Считаем уникальные IP которые когда-либо были забанены
        CS_ALLTIME_BANS=$(sqlite3 "$CS_DB" "SELECT COUNT(DISTINCT value) FROM decisions WHERE type='ban'" 2>/dev/null)
        CS_ALLTIME_BANS="${CS_ALLTIME_BANS:-0}"
    fi
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
    local hn=$(hostname -s 2>/dev/null)

    # ===== HERO HEADER =====
    # v3.2: убран эмодзи 🛡 — занимает 2 cells, ломает выравнивание правой ║
    echo ""
    echo -e "${C}╔══════════════════════════════════════════════════════════════════╗${N}"
    printf "${C}║${N}  ${B}SHIELDNODE${N} ${DIM}·${N} ${C}%-15s${N} ${DIM}·${N} %s ${DIM}·${N} %s    ${C}║${N}\n" "$ip" "$hn" "$now"
    echo -e "${C}╚══════════════════════════════════════════════════════════════════╝${N}"

    # ===== HERO STATS (3 колонки) =====
    local total_alltime=$((ALLTIME_SCANNERS + ALLTIME_DDOS + CS_ALLTIME_BANS))
    local active_threats=$((CS_BANS + CONFIRMED_COUNT))
    local active_color="${G}"
    [ "$active_threats" -gt 0 ] && active_color="${R}"

    echo ""
    echo -e "  ${DIM}┌──────────────────────┬──────────────────────┬────────────────────┐${N}"
    printf  "  ${DIM}│${N} ${DIM}Blocklist coverage${N}   ${DIM}│${N} ${DIM}All-time blocked${N}     ${DIM}│${N} ${DIM}Active threats${N}     ${DIM}│${N}\n"
    printf  "  ${DIM}│${N} ${C}${B}%-20s${N} ${DIM}│${N} ${M}${B}%-20s${N} ${DIM}│${N} ${active_color}${B}%-18s${N} ${DIM}│${N}\n" \
        "$(human_num "$BL_V4") IPs" "$(human_num "$total_alltime") IPs" "$active_threats now"
    echo -e "  ${DIM}└──────────────────────┴──────────────────────┴────────────────────┘${N}"
    echo ""

    # ===== SERVICES (compact one-line) =====
    local svc_line=""
    svc_line+=$(svc_dot "$CS_ACTIVE" "crowdsec")"  "
    svc_line+=$(svc_dot "$BOUNCER_ACTIVE" "bouncer")"  "
    svc_line+=$(svc_dot "$PORTS_PATH_ACTIVE" "ports")
    echo -e "  ${B}⚙  Services${N}"
    echo -e "  $svc_line"
    echo ""

    # ===== PROTECTED PORTS =====
    echo -e "  ${B}🔒 Protected${N}"
    printf  "  ├─ ${DIM}TCP:${N}  ${C}%s${N}\n" "$PROTECTED_TCP_LIST"
    printf  "  └─ ${DIM}UDP:${N}  ${C}%s${N}\n" "$PROTECTED_UDP_LIST"
    echo ""

    # ===== ACTIVE NOW =====
    echo -e "  ${B}🔥 Active blocks${N} ${DIM}(right now, dynamic timeouts)${N}"
    printf  "  ├─ ${R}confirmed attacks${N}     ${R}${B}%5d${N} IPs ${DIM}(banned 1h)${N}\n"             "$CONFIRMED_COUNT"
    printf  "  ├─ ${Y}suspect (watched)${N}     ${Y}${B}%5d${N} IPs ${DIM}(observed 5min)${N}\n"        "$SUSPECT_COUNT"
    printf  "  ├─ ${R}crowdsec bans${N}         ${R}${B}%5d${N} IPs ${DIM}(behavioural detection)${N}\n" "$CS_BANS"
    printf  "  ├─ ${R}scanner blocklist${N}     ${R}${B}%5d${N} IPs ${DIM}(IPv4)${N}\n"                  "$BL_V4"
    printf  "  └─ ${G}whitelist${N}             ${G}${B}%5d${N} IPs ${DIM}(manual)${N}\n" "$MANUAL_WHITE"
    echo ""

    # ===== TOTAL BLOCKED (since boot) =====
    local total_pkts=$((SCANNER_PKTS_V4 + CONFIRMED_PKTS_V4 + SYN_CONF_PKTS_V4 + UDP_CONF_PKTS_V4 + CONN_FLOOD_PKTS_V4 + NEWCONN_FLOOD_PKTS_V4 + TCP_INVALID_PKTS))
    local total_bytes=$((SCANNER_BYTES_V4 + CONFIRMED_BYTES_V4 + SYN_CONF_BYTES_V4 + UDP_CONF_BYTES_V4 + CONN_FLOOD_BYTES_V4 + NEWCONN_FLOOD_BYTES_V4 + TCP_INVALID_BYTES))

    echo -e "  ${B}📊 Since reboot${N} ${DIM}($NFT_SINCE)${N}"
    printf  "  ├─ ${DIM}scanner drops:${N}        %12s pkts  ${DIM}/${N} %s\n"   "$(human_num "$SCANNER_PKTS_V4")" "$(human_bytes "$SCANNER_BYTES_V4")"
    printf  "  ├─ ${DIM}attack drops:${N}         %12s pkts  ${DIM}/${N} %s\n"   "$(human_num "$CONFIRMED_PKTS_V4")" "$(human_bytes "$CONFIRMED_BYTES_V4")"
    printf  "  ├─ ${DIM}rate-limit (syn):${N}     %12s pkts  ${DIM}/${N} %s\n"   "$(human_num "$SYN_CONF_PKTS_V4")" "$(human_bytes "$SYN_CONF_BYTES_V4")"
    printf  "  ├─ ${DIM}rate-limit (udp):${N}     %12s pkts  ${DIM}/${N} %s\n"   "$(human_num "$UDP_CONF_PKTS_V4")" "$(human_bytes "$UDP_CONF_BYTES_V4")"
    printf  "  ├─ ${DIM}conn-flood (ct>50):${N}   %12s pkts  ${DIM}/${N} %s\n"   "$(human_num "$CONN_FLOOD_PKTS_V4")" "$(human_bytes "$CONN_FLOOD_BYTES_V4")"
    printf  "  ├─ ${DIM}new-conn flood:${N}       %12s pkts  ${DIM}/${N} %s\n"   "$(human_num "$NEWCONN_FLOOD_PKTS_V4")" "$(human_bytes "$NEWCONN_FLOOD_BYTES_V4")"
    printf  "  ├─ ${DIM}TCP flag invalid:${N}     %12s pkts  ${DIM}/${N} %s\n"   "$(human_num "$TCP_INVALID_PKTS")" "$(human_bytes "$TCP_INVALID_BYTES")"
    printf  "  └─ ${B}total:${N}                ${B}%12s${N} pkts  ${DIM}/${N} ${B}%s${N}\n" "$(human_num "$total_pkts")" "$(human_bytes "$total_bytes")"
    echo ""

    # ===== ALL-TIME (persistent) =====
    echo -e "  ${B}📈 All-time history${N} ${DIM}(since $DB_SINCE, persistent in sqlite)${N}"
    printf  "  ├─ ${M}🤖 scanners blocked:${N}    %12s unique IPs ${DIM}(%s hits)${N}\n" "$(human_num "$ALLTIME_SCANNERS")"   "$(human_num "$ALLTIME_SCANNER_PKTS")"
    printf  "  ├─ ${M}💥 ddos blocked:${N}        %12s unique IPs ${DIM}(%s hits)${N}\n" "$(human_num "$ALLTIME_DDOS")"       "$(human_num "$ALLTIME_DDOS_PKTS")"
    printf  "  └─ ${M}🔑 ssh brute attempts:${N}  %12s unique IPs ${DIM}(crowdsec)${N}\n" "$(human_num "$CS_ALLTIME_BANS")"
    echo ""

    # ===== RECENT EVENTS (v3.5) =====
    local events_log="/var/log/shieldnode/events.log"
    if [ -r "$events_log" ]; then
        echo -e "  ${B}🕒 Recent events${N} ${DIM}(last 5 from $events_log — [9] for full log)${N}"
        local last_lines
        last_lines=$(tail -5 "$events_log" 2>/dev/null)
        if [ -z "$last_lines" ]; then
            echo -e "  ${DIM}└─ (empty — no events yet)${N}"
        else
            echo "$last_lines" | sed 's/^/  /'
        fi
        echo ""
    fi

    printf "  ${DIM}🔄 Scanner blocklist updated: %s${N}\n" "$LAST_UPDATE"
}

# Helper: status dot для compact services line
svc_dot() {
    local status="$1"
    local label="$2"
    case "$status" in
        active)        echo -e "${G}●${N} ${DIM}${label}${N}" ;;
        inactive)      echo -e "${Y}●${N} ${DIM}${label}${N}" ;;
        failed)        echo -e "${R}●${N} ${DIM}${label}${N}" ;;
        activating)    echo -e "${Y}◐${N} ${DIM}${label}${N}" ;;
        *)             echo -e "${Y}?${N} ${DIM}${label}${N}" ;;
    esac
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
    printf "  Total: ${B}%d${N} IPv4 subnets\n" "$BL_V4"
    echo ""
}

# v2.9: история блокировок из sqlite
show_history() {
    echo ""
    local db="/var/lib/shieldnode/events.db"

    if [ ! -r "$db" ] || ! command -v sqlite3 >/dev/null 2>&1; then
        echo -e "${Y}History DB not available${N}"
        echo -e "${DIM}Aggregator должен запуститься: sudo systemctl start shieldnode-aggregator.service${N}"
        echo ""
        return
    fi

    echo -e "${B}Recent blocked events${N} ${DIM}(last 30, from /var/lib/shieldnode/events.db)${N}"
    echo -e "${DIM}─────────────────────────────────${N}"
    printf "  ${DIM}%-10s %-18s %-9s %s${N}\n" "TYPE" "IP" "HITS" "LAST SEEN"

    sqlite3 "$db" "
        SELECT type, ip, count, datetime(last_seen, 'unixepoch', 'localtime')
        FROM events
        ORDER BY last_seen DESC
        LIMIT 30
    " 2>/dev/null | while IFS='|' read -r type ip cnt ts; do
        case "$type" in
            scanner) color="${Y}" ;;
            ddos)    color="${R}" ;;
            *)       color="${N}" ;;
        esac
        printf "  ${color}%-10s${N} %-18s ${B}%-9s${N} ${DIM}%s${N}\n" "$type" "$ip" "$cnt" "$ts"
    done
    echo ""

    local total_scan total_ddos
    total_scan=$(sqlite3 "$db" "SELECT COUNT(*) FROM events WHERE type='scanner'" 2>/dev/null)
    total_ddos=$(sqlite3 "$db" "SELECT COUNT(*) FROM events WHERE type='ddos'" 2>/dev/null)
    printf "  Total in DB: ${Y}${B}%d${N} scanners, ${R}${B}%d${N} ddos\n" "${total_scan:-0}" "${total_ddos:-0}"
    echo ""
}

# v2.9: топ-атакующих из sqlite
show_top_attackers() {
    echo ""
    local db="/var/lib/shieldnode/events.db"

    if [ ! -r "$db" ] || ! command -v sqlite3 >/dev/null 2>&1; then
        echo -e "${Y}History DB not available${N}"
        echo ""
        return
    fi

    echo -e "${B}Top-20 attackers (by hit count, all-time)${N}"
    echo -e "${DIM}─────────────────────────────────${N}"
    printf "  ${DIM}%-10s %-18s %-9s %s${N}\n" "TYPE" "IP" "HITS" "FIRST SEEN"

    sqlite3 "$db" "
        SELECT type, ip, count, datetime(first_seen, 'unixepoch', 'localtime')
        FROM events
        ORDER BY count DESC
        LIMIT 20
    " 2>/dev/null | while IFS='|' read -r type ip cnt ts; do
        case "$type" in
            scanner) color="${Y}" ;;
            ddos)    color="${R}" ;;
            *)       color="${N}" ;;
        esac
        printf "  ${color}%-10s${N} %-18s ${B}%-9s${N} ${DIM}%s${N}\n" "$type" "$ip" "$cnt" "$ts"
    done
    echo ""
    echo -e "  ${DIM}Tip: высокий hit-count → персистентный сканер/атакующий${N}"
    echo ""
}

# v3.5: показать /var/log/shieldnode/events.log через less
show_full_log() {
    echo ""
    local log="/var/log/shieldnode/events.log"
    if [ ! -r "$log" ]; then
        echo -e "${Y}events.log not available${N} ${DIM}($log)${N}"
        echo -e "${DIM}Aggregator пишет туда раз в минуту. Запусти вручную:${N}"
        echo -e "${DIM}  sudo systemctl start shieldnode-aggregator.service${N}"
        echo ""
        return
    fi
    local lines
    lines=$(wc -l < "$log" 2>/dev/null)
    lines="${lines:-0}"
    echo -e "${B}Full events log${N} ${DIM}($log, $lines lines)${N}"
    echo -e "${DIM}─────────────────────────────────${N}"
    if command -v less >/dev/null 2>&1; then
        # v3.8.1: подсказка + надёжные флаги less.
        # -F = exit если влезает на экран
        # -X = не очищать экран при выходе (чтобы юзер видел что вернулся в guard)
        # -R = raw control chars (для ANSI-цветов в логе)
        # -K = exit по Ctrl-C
        # -E = quit при достижении конца файла
        echo -e "${DIM}Навигация: ↑↓ стрелки, PgUp/PgDn, ${B}q${N}${DIM} — выход${N}"
        echo -e "${DIM}Если застрял в команде less (видишь \":\") — нажми ${B}ESC${N}${DIM} затем ${B}q${N}"
        sleep 1
        LESS="" less -FRXKE "$log"
    else
        echo -e "${DIM}less не установлен, показываю последние 200 строк${N}"
        echo ""
        tail -200 "$log"
    fi
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
    "ports_path_watcher": "$PORTS_PATH_ACTIVE"
  },
  "protected_ports": {
    "tcp": "$PROTECTED_TCP_LIST",
    "udp": "$PROTECTED_UDP_LIST"
  },
  "blocked_now": {
    "syn_flood_v4": $SYN_BAN,
    "udp_flood_v4": $UDP_BAN,
    "crowdsec_bans": $CS_BANS,
    "scanner_blocklist_v4": $BL_V4
  },
  "whitelist": {
    "manual": $MANUAL_WHITE
  },
  "total_blocked": {
    "since": "$NFT_SINCE",
    "scanners_v4_packets": $SCANNER_PKTS_V4,
    "scanners_v4_bytes": $SCANNER_BYTES_V4,
    "confirmed_v4_packets": $CONFIRMED_PKTS_V4,
    "confirmed_v4_bytes": $CONFIRMED_BYTES_V4,
    "syn_confirmed_v4_packets": $SYN_CONF_PKTS_V4,
    "udp_confirmed_v4_packets": $UDP_CONF_PKTS_V4,
    "conn_flood_v4_packets": $CONN_FLOOD_PKTS_V4,
    "newconn_flood_v4_packets": $NEWCONN_FLOOD_PKTS_V4,
    "tcp_invalid_packets": $TCP_INVALID_PKTS
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

    # ===== MENU =====
    # v3.2: убраны эмодзи из меню — они занимают 2-cell в терминале и ломают рамки
    echo -e "${C}┌─────────────────────────────────────────────────────────────────┐${N}"
    echo -e "${C}│${N}  ${B}Actions${N}                                                        ${C}│${N}"
    echo -e "${C}├─────────────────────────────────────────────────────────────────┤${N}"
    echo -e "${C}│${N}  [${B}1${N}] Active attacks         [${B}2${N}] CrowdSec bans                   ${C}│${N}"
    echo -e "${C}│${N}  [${B}3${N}] Whitelist IPs          [${B}4${N}] Scanner blocklist               ${C}│${N}"
    echo -e "${C}│${N}  [${B}6${N}] Recent history         [${B}7${N}] Top attackers                   ${C}│${N}"
    echo -e "${C}│${N}  [${B}9${N}] View full events.log                                       ${C}│${N}"
    echo -e "${C}├─────────────────────────────────────────────────────────────────┤${N}"
    echo -e "${C}│${N}  [${B}r${N}] Refresh                [${B}0${N}] Exit                            ${C}│${N}"
    echo -e "${C}└─────────────────────────────────────────────────────────────────┘${N}"
    echo -ne "  ${B}>${N} "

    read -r CHOICE
    case "$CHOICE" in
        1) show_syn_flood_ips    ;;
        2) show_crowdsec_bans    ;;
        3) show_whitelist_ips    ;;
        4) show_scanner_samples  ;;
        6) show_history          ;;
        7) show_top_attackers    ;;
        9) show_full_log         ;;
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

if [ "$ACTIVE_BANS" -gt 0 ]; then
    print_ok "Активных банов: $ACTIVE_BANS"
else
    print_info "Активных банов нет (норма для свежей установки)"
fi

# v1.3: scanner blocklist size
BL_V4=$(nft list set inet ddos_protect scanner_blocklist_v4 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?' | wc -l)
if [ "$BL_V4" -gt 0 ]; then
    print_ok "Scanner blocklist: $BL_V4 IPv4 подсетей"
else
    print_warn "Scanner blocklist пуст — проверь journalctl -u scanner-blocklist-update"
fi

# ==============================================================================
# ШАГ 14: ИТОГИ
# ==============================================================================

print_header "ГОТОВО"

echo -e "  ${BOLD}Что настроено:${NC}"
echo -e "  ├─ ${GREEN}✔${NC} nft rate-limit: 300 SYN/sec TCP, 600 packets/sec UDP (CGNAT-friendly, ban-once)"
echo -e "  ├─ ${GREEN}✔${NC} ${BOLD}HTTP/conn-flood защита (v3.5):${NC} ct count 50 + new-conn 50/min + TCP flag sanity"
if [ "${ENABLE_FIB_ANTISPOOF:-0}" = "1" ]; then
    echo -e "  ├─ ${GREEN}✔${NC} ${BOLD}Anti-spoofing (v3.8):${NC} fib reverse-path check (single-homed VPS)"
fi
echo -e "  ├─ ${GREEN}✔${NC} ${BOLD}TCP MSS clamping (v3.8):${NC} устраняет фрагментацию в VPN-туннеле (faster, не slower)"
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
echo -e "  1. ${CYAN}Manual whitelist${NC}      → доверенные IP (management из UFW + manual)"
echo -e "  2. ${CYAN}SSH (порт $SSH_PORT)${NC}      → пропуск (защищает CrowdSec)"
if [ "${ENABLE_FIB_ANTISPOOF:-0}" = "1" ]; then
    echo -e "  3. ${CYAN}Anti-spoofing${NC}         → drop пакетов с нерутабельным src (fib check)"
fi
echo -e "  4. ${CYAN}Scanner blocklist${NC}     → drop ${BOLD}~3000${NC} известных сканеров"
echo -e "      ├─ shadow-netlab/traffic-guard-lists (общие: Shodan, Censys, gov)"
echo -e "      ├─ tread-lightly/CyberOK_Skipa_ips (SKIPA, ГРЧЦ, НКЦКИ)"
echo -e "      └─ MISP/CIRCL warninglists (honeypot-verified)"
echo -e "  5. ${CYAN}Confirmed attack${NC}      → drop IP подтверждённых атакующих (1 час)"
echo -e "  6. ${CYAN}Rate-limit ban-once${NC}   → 1й удар = suspect (5 мин), 2й = бан"
echo -e "      ├─ TCP SYN: ${BOLD}300/sec burst 500${NC} (CGNAT-friendly)"
echo -e "      ├─ UDP:     ${BOLD}600/sec burst 1000${NC}"
echo -e "      ├─ ct count: ${BOLD}50 concurrent${NC} на src IP (slowloris/conn-flood)"
echo -e "      ├─ new-conn: ${BOLD}50/min burst 100${NC} (HTTP-flood через TLS)"
echo -e "      └─ TCP flags: drop XMAS/NULL/SYN+FIN/SYN+RST/FIN+RST"
echo -e "  7. ${CYAN}CrowdSec bouncer${NC}      → бан по поведению (SSH brute, regreSSHion)"
echo -e "  8. ${CYAN}MSS clamping (forward)${NC} → ускорение VPN-трафика, устранение фрагментации"
echo ""
echo -e "  ${BOLD}${GREEN}User-friendly defaults:${NC}"
echo -e "  ${GREEN}✔${NC} CGNAT юзеры (МТС/Билайн/МегаФон) не банятся — лимит 300/sec на IP"
echo -e "  ${GREEN}✔${NC} Ban-once архитектура: случайный всплеск ≠ бан, два подряд = бан"
echo -e "  ${GREEN}✔${NC} Профили с несколькими Xray-портами не банятся как 'port-scan'"
echo -e "  ${GREEN}✔${NC} Ложные баны от CrowdSec живут 4h вместо 24h"
echo -e "  ${GREEN}✔${NC} Юзеры из подсетей в blocklist — реально госсканеры, не домашние"
echo ""
echo -e "  ${BOLD}Как работает manual whitelist (v3.5):${NC}"
echo -e "  1. Открой свой management-IP в UFW: ${CYAN}sudo ufw allow from <IP>${NC}"
echo -e "  2. Path-watcher (${CYAN}protected-ports-update.path${NC}) подхватит изменение"
echo -e "  3. IP попадёт в ${CYAN}nft set manual_whitelist_v4${NC} (обходит scanner+rate-limit+ct count)"
echo -e "  4. CrowdSec-баны для этого IP переписать вручную: ${CYAN}cscli decisions delete --ip <IP>${NC}"
echo -e "  ${MAGENTA}ℹ${NC} v3.5: SSH-key auto-whitelist удалён (вызывал баны админов на shared IP)."
echo -e "     SSH защищён через CrowdSec sshd-bf + ssh-cve коллекции."
echo ""
echo -e "  ${BOLD}История блокировок (v2.9+):${NC}"
echo -e "  ├─ ${CYAN}/var/lib/shieldnode/events.db${NC} — sqlite БД с историей всех IP"
echo -e "  ├─ ${CYAN}/var/log/shieldnode/events.log${NC} — человекочитаемый лог (v3.5)"
echo -e "  ├─ Агрегатор парсит journald раз в минуту, бесплатно по CPU"
echo -e "  ├─ В guard: [6] history, [7] top attackers, [9] view full log (v3.5)"
echo -e "  └─ Smetka: \`sqlite3 /var/lib/shieldnode/events.db 'SELECT * FROM events'\`"
echo ""
echo -e "  ${BOLD}Полезные команды:${NC}"
echo -e "  ${CYAN}sudo guard${NC}                                          # дашборд"
echo -e "  ${CYAN}tail -f /var/log/shieldnode/events.log${NC}              # human-readable события"
echo -e "  ${CYAN}less /var/log/shieldnode/install.log${NC}                # лог установки (v3.5)"
echo -e "  ${CYAN}cscli decisions list --type ban${NC}                     # активные CrowdSec-баны"
echo -e "  ${CYAN}journalctl -u scanner-blocklist-update${NC}              # логи blocklist updater"
echo -e "  ${CYAN}journalctl -t shieldnode-agg${NC}                        # логи агрегатора"
echo -e "  ${CYAN}systemctl list-timers${NC}                               # когда след. обновления"
echo -e "  ${CYAN}cscli metrics${NC}                                       # статистика парсеров"
echo -e "  ${CYAN}nft list set inet ddos_protect confirmed_attack_v4${NC}  # подтверждённые баны"
echo -e "  ${CYAN}nft list set inet ddos_protect scanner_blocklist_v4 | wc -l${NC}  # размер blocklist"
echo ""
echo -e "  ${BOLD}Принудительное обновление:${NC}"
echo -e "  ${CYAN}systemctl start scanner-blocklist-update.service${NC}    # обновить blocklist сейчас"
echo -e "  ${CYAN}systemctl start shieldnode-aggregator.service${NC}       # обновить историю сейчас"
echo ""
echo -e "  ${BOLD}Если потерял доступ и забанен:${NC}"
echo -e "  Зайти через консоль провайдера (KVM/VNC) и:"
echo -e "  ${CYAN}cscli decisions delete --ip <твой_IP>${NC}"
echo -e "  ${CYAN}nft delete element inet ddos_protect confirmed_attack_v4 { <IP> }${NC}"
echo -e "  ${CYAN}nft add element inet ddos_protect manual_whitelist_v4 { <IP> }${NC}"
echo ""
echo -e "  ${BOLD}Бэкап:${NC} ${CYAN}$BACKUP_DIR${NC}"
echo ""
# v1.5 fix: при запуске через pipe (curl ... | bash) или process substitution
# $0 может быть /dev/fd/63 — некрасиво в выводе. Используем generic-команду.
SCRIPT_NAME="$0"
case "$SCRIPT_NAME" in
    /dev/fd/*|/proc/*|bash|-bash|sh|-sh)
        SCRIPT_NAME="shieldnode.sh"
        ;;
esac
echo -e "  ${BOLD}Удалить всё:${NC} ${CYAN}sudo bash $SCRIPT_NAME --uninstall${NC}"
echo -e "  ${DIM}или: bash <(curl -sL https://raw.githubusercontent.com/abcproxy70-ops/shield/main/shieldnode.sh) --uninstall${NC}"
echo ""
