#!/bin/bash

# ==============================================================================
#  VPN NODE DDoS PROTECTION v3.13.1 (Commercial Edition) — HOTFIX
#  - nftables rate-limit (kernel-level SYN flood protection, IPv4-only)
#  - nftables scanner-blocklist (pre-emptive drop известных сканеров)
#  - nftables threat-blocklist (Spamhaus DROP + FireHOL Level 1, v3.12.0)
#  - nftables custom-blocklist (operator personal IPs, v3.12.0)
#  - nftables mobile-RU AS whitelist (CGNAT-friendly, v3.13.0+)
#  - nftables connection-flood + slowloris защита (PROPER per-IP ct count)
#  - nftables TCP flag sanity (drop invalid combinations)
#  - nftables anti-spoofing (fib saddr — стронгер чем rp_filter loose)
#  - nftables TCP MSS clamping (улучшает скорость VPN, устраняет фрагментацию)
#  - Tor exit blocklist (опционально через BLOCK_TOR=1)
#  - CrowdSec (SSH brute-force + community blocklist)
#  - guard CLI — дашборд защиты с ASN/owner column для top attackers (v3.12.0)
#  - Человекочитаемые логи в /var/log/shieldnode/events.log
#  - Мгновенное отслеживание изменений в фаерволе через inotify
#  - Опциональный конфиг /etc/shieldnode/shieldnode.conf (v3.12.0)
#  - File-based blocklists в /etc/shieldnode/lists/*.txt (v3.12.0)
#
#  v3.13.1 hotfix changelog:
#
#    [BUG-MOBILE-RU-ORDER] В v3.13.0 mobile_ru_whitelist стоял ПОСЛЕ
#      threat/scanner/custom/tor blocklist drop'ов в prerouting. Это значит:
#      если mobile-RU CIDR попал в один из blocklist'ов (например retail
#      pool 90.150.64.0/20 в gov_networks scanner-list), весь /20 дропался
#      ДО проверки whitelist'а. Семантика "whitelist выигрывает" не работала.
#
#      FIX: правила mobile_ru_whitelist'а перенесены ВЫШЕ всех blocklist
#      drop'ов в prerouting — сразу после manual_whitelist. Теперь mobile-RU
#      IP проходит relaxed-проверки и accept'ится, минуя scanner/threat/custom
#      blocklist'ы. Реальные атаки всё ещё ловятся через ct=1000 / 2000-newconn.
#
#    [BUG-DEAD-COUNTER] Counter mobile_ru_newconn_flood_v4 был определён в
#      template, но никогда не инкрементировался — newconn-overflow проходил
#      через общий newconn_overflow chain со стандартными counters.
#      Guard CLI всегда показывал 0 для этого counter'а.
#
#      FIX: counter удалён из template и из guard CLI. Newconn drops для
#      mobile-RU теперь идут через стандартный newconn_flood_v4 (правильно —
#      это не отличается от обычной overflow-логики).
#
#    [OBSERVABILITY] Добавлен log prefix '[shield:mobile_ru_drop]' для
#      mobile_ru_conn_flood_v4 (когда CGNAT превысил даже relaxed-лимит
#      ct>1000). Aggregator парсит этот prefix → events.db с type='mobile_ru'.
#      Per-IP analytics для mobile-RU drops теперь работает.
#
#  v3.13.0 changelog:
#
#    [MOBILE-RU-WHITELIST] Российские мобильные операторы (МТС, T2/Tele2,
#      МегаФон, Билайн) выдают CGNAT-IP с 50-200 абонентами за один IP.
#      Даже после CGNAT-fix v3.12.0 (ct=400) бывают ложные срабатывания —
#      когда несколько активных юзеров одновременно дают пик 400+ conn.
#
#      РЕШЕНИЕ: отдельный nft set mobile_ru_whitelist_v4 (interval, auto-merge,
#      ~5000-10000 CIDR'ов) с ОТДЕЛЬНЫМИ relaxed limits:
#         - ct count: 400 → 1000  (массивный CGNAT)
#         - newconn:  500/min → 2000/min, burst 1000 → 4000
#         - SYN/UDP rate-limit остаются (защита от реальных flood-атак)
#
#      Whitelist'нутые AS (12 шт., проверены через RIPEstat):
#         AS8359 MTS, AS28884 MTS Siberia
#         AS12958 T2, AS15378 T2 (Yota), AS41330 T2 NSK, AS42437 T2 RND, AS48190 T2 EKB
#         AS31133 MegaFon, AS31163 MegaFon Kavkaz, AS12714 MegaFon
#         AS3216 Vimpelcom, AS8402 Corbina, AS16345 Beeline
#
#      ИСТОЧНИК: MaxMind GeoLite2-ASN-CSV (бесплатный, license key).
#      Обновляется раз в неделю (MaxMind релизит втор/пят).
#
#      БЕЗ KEY: установка продолжается с WARN, set остаётся пустым,
#      поведение идентично v3.12.0. Включается заданием в /etc/shieldnode/shieldnode.conf:
#         MAXMIND_LICENSE_KEY="abcd1234..."
#
#      OBSERVABILITY: updater логирует overlap c scanner_blocklist'ом
#      (если ваш AS попал в чей-то scanner-list).
#
#  v3.12.0 changelog:
#
#    [CGNAT FIX] Российские мобильные операторы (T2/Tele2 AS12958/AS15378/
#      AS48190, МТС AS8359, МегаФон AS25513) выдают CGNAT-IP с 200-350
#      concurrent connections от одного IP к одному dst-port. Старые лимиты
#      (ct count 150, new-conn 200/min, suspect→confirmed бан 1h) банили
#      легитимных мобильных юзеров.
#
#      FIX:
#        - ct count: 150 → 400 (CGNAT-friendly, ловит slowloris >400)
#        - new-conn rate: 200/min burst 500 → 500/min burst 1000
#        - confirmed_attack timeout: 1h → 15min (быстрая разблокировка
#          false-positive CGNAT, реальная атака возобновится → re-ban)
#
#      Регресс: ct count 400 ловит реальные slowloris (200-500 conn). UDP
#      rate-limit (600/sec) и SYN rate-limit (300/sec) не трогали.
#
#    [BLOCKLISTS-V2] Новая архитектура blocklists. Раньше: 2 жёстко зашитых
#      updater'а (scanner, tor) с дублирующимся кодом. Теперь: единый
#      универсальный updater /usr/local/sbin/shieldnode-update-blocklist.sh
#      обслуживает 4 blocklist'а (scanner, threat, tor, custom).
#
#      Возможности:
#        - File-based lists: оператор кладёт IPs в /etc/shieldnode/lists/*.txt
#        - URL-based: дефолтные источники + переопределение через конфиг
#        - Union: file + URL объединяются для одного set'а
#        - Опциональный /etc/shieldnode/shieldnode.conf (override defaults)
#        - Templated systemd units: shieldnode-update@<name>.{service,timer}
#        - Path-watcher для custom.txt (inotify trigger на изменение файла)
#
#      Парсер поддерживает Spamhaus (";SBL"), FireHOL (комментарии),
#      MISP/CIRCL JSON, plain IP/CIDR.
#
#    [GUARD-CLI-v2] Главный экран guard переделан:
#        - Active threats (верхний блок) — текущее состояние банов
#        - Top attackers с ASN/owner column через ipinfo.io (кэш 7d в events.db)
#        - Today drops/bytes по типам (scanner, threat, custom, tor, attack)
#        - Меньше кнопок (1/2/3/4/u/r/q вместо 1-8)
#
#    [INSTALL-UI] Сжатый final summary (~10 строк вместо 100). Шаги установки
#      объединены: меньше зелёных галочек, больше сигнала.
#
#    [PIPE-MODE] При установке через `bash <(curl ...)` скрипт сам скачивает
#      дефолтные /etc/shieldnode/lists/*.txt с github. При git-clone установке
#      использует ./lists/ из репо.
#
#    [v3.12.0 OPEN] Российские мобильные whitelist (AS-based) — отложено в v3.13.
#
#  v3.11.3 hotfix changelog:
#
#    [BUG-MULTILINE-SMOKE] Smoke-test ложно репортил "protected_ports_tcp пуст"
#      хотя set был заполнен корректно.
#
#      Симптом на проде: каждая установка показывала FAIL даже когда
#      `nft list set` показывал нормальные данные. Прошлые попытки
#      "исправить" updater (v3.11.2 PER-SET-PROTECTION + RETRY-ON-EMPTY)
#      решали несуществующую проблему — реально баг был в smoke-check
#      парсере.
#
#      Корень: nft форматирует длинные `elements = { ... }` на несколько
#      строк (после ~7 элементов):
#        elements = { 80, 443-444, 6443, 7441, 7443,
#                     8443, 9999 }
#      Старый smoke-check: `grep -oE 'elements = \{[^}]*\}'` работает
#      только в пределах одной строки. На multi-line блоке regex не
#      матчит → SMOKE_TCP=0 → ложный FAIL.
#
#      FIX: добавлен `tr '\n' ' '` для flattening multi-line input
#      (тот же подход что в updater'e CUR_TCP — но в smoke check был
#      пропущен). Применено к smoke check #2 (TCP) и #3 (UDP).
#
#      Регресс-тест: nft set с 7+ элементами → smoke-check показывает
#      правильное количество вместо 0.
#
#  v3.11.2 hotfix changelog:
#
#    [BUG-PORTS-WIPE] protected_ports_tcp периодически обнулялся таймером.
#
#      Симптом на проде: smoke-test FAIL, set пуст. journalctl -t protected-ports
#      показывал чередование:
#        19:42:03  Updated: TCP={443,444,...}   ← правильно
#        19:42:31  Updated: TCP={}              ← ЧЕРЕЗ 28с timer обнулил!
#        19:50:18  Updated: TCP={443,444,...}   ← правильно (ручной запуск)
#
#      Корень: detect_firewall_ports() иногда возвращает empty при transient
#      UFW state (atomic rename файла). Safety-guard срабатывал только если
#      одновременно: FIREWALL_ACTIVE=1, ВСЕ NEW пустые, ANY CUR непустой.
#      Если FIREWALL_ACTIVE detection тоже попал в transient — guard не
#      срабатывал → flush применялся → set обнулялся.
#
#      После обнуления, следующий transient run видел CUR=empty → guard вообще
#      не активировался → состояние "залипало" empty до timer'а с реальными
#      данными.
#
#      FIX (двойная защита):
#      1. RETRY-ON-EMPTY: если detect возвращает все пустые → sleep 0.3s →
#         retry один раз. Покрывает atomic-rename window UFW.
#      2. PER-SET PROTECTION: для КАЖДОГО set'а отдельно: flush only if
#         (NEW непустой) ИЛИ (CUR пустой). Это значит: если NEW для конкретного
#         set'а пуст, но CUR непуст — НЕ ТРОГАЕМ этот set. Защищает от
#         частичных parse fail'ов где, например, TCP попал в transient но
#         MGMT прочитался корректно (или наоборот).
#
#    [BUG-SSH-BACKPORT] OpenSSH 9.6p1 на Ubuntu 24.04 ошибочно ругался как
#      уязвимый к CVE-2025-26466, хотя Canonical backport'ит фикс в
#      1:9.6p1-3ubuntu13.8+. Старая проверка смотрела только upstream
#      version (9.6 < 9.9 → vulnerable).
#
#      FIX: смотрим dpkg-version openssh-server и сверяем с known-patched
#      для конкретного дистрибутива (ubuntu:24.04 → 1:9.6p1-3ubuntu13.8+,
#      ubuntu:22.04 → 1:8.9p1-3ubuntu0.11+, debian:12 → 1:9.2p1-2+deb12u4+,
#      etc). Учитывает что 8.x не affected by CVE-2025-26466 в принципе.
#
#  v3.11.1 hotfix changelog (3 production-discovered bugs):
#
#    [BUG-CRITICAL] Backticks в комментарии nft template heredoc =
#      command substitution → "add: command not found" + protected_ports пустые.
#
#      Симптом на проде:
#        ШАГ 4: NFTABLES RATE-LIMIT
#        /dev/fd/63: line 1448: add: command not found
#        ✔ nft rate-limit активен               ← false positive
#        ...
#        ШАГ 13: HEALTHCHECK
#        ✖ FAIL: protected_ports_tcp пуст       ← реальная регрессия
#
#      Корень: heredoc `cat > $NFT_DDOS_CONF <<EOF ... EOF` (БЕЗ кавычек
#      вокруг EOF) интерпретирует backticks как command substitution.
#      В шаблоне был комментарий:
#        # Раньше (v3.5..v3.10.1): два правила делали `add @newconn_rate_v4` на
#                                                    ↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑
#      bash пытается выполнить `add @newconn_rate_v4` как команду →
#      "add: command not found" + heredoc PARTIALLY rendered. Output
#      файл создаётся (rate-limit правила работают), но parametrization
#      $XRAY_PORTS_TCP_INIT может попасть в недо-render'еную секцию →
#      protected_ports_tcp set остаётся пустым → smoke-test FAIL.
#
#      Воспроизведено локально: bash heredoc с backticks → точно такая же ошибка.
#
#      FIX: backticks в комментариях заменены на одинарные кавычки.
#      Также проверены ВСЕ остальные heredocs на наличие backticks в
#      комментариях — найдено и исправлено.
#
#    [BUG-CSCLI-FMT] CrowdSec 1.7.x вывод `cscli collections list` теперь
#      table-format ("│ name │ status │ ...") вместо plain "name v0.7 enabled".
#      Старый regex `grep -q "^crowdsecurity/sshd"` не матчит — линия
#      начинается с "│ ".
#
#      Симптом на проде:
#        ШАГ 7: УСТАНОВКА CROWDSEC
#        ➤ Устанавливаю crowdsecurity/sshd...
#        ✔ crowdsecurity/sshd                    ← реально установлен
#        ...
#        ШАГ 9: ACQUISITION
#        ⚠ crowdsecurity/sshd не установлен      ← false negative
#
#      FIX: используем `cscli collections list -o raw` для stable CSV
#      вывода (один collection per line, no formatting), затем
#      `awk -F, 'NR>1 && $1 == "crowdsecurity/sshd"'`.
#
#    [BUG-SMOKE-MULTILINE] `$(grep -c ... || echo 0)` produces "0\n0"
#      когда input пустой → integer comparison "[: 0\n0: integer expression
#      expected" в smoke-test.
#
#      Симптом на проде:
#        ✔ Smoke: 18080 CAPI decisions (community blocklist работает)
#        /dev/fd/63: line 3897: [: 0
#        0: integer expression expected
#        ✖ Smoke-test НЕ ПРОЙДЕН            ← false negative из-за multiline
#
#      Корень: `grep -c PATTERN` на пустом stdin → exit 1, печатает "0".
#      Дальше `|| echo 0` срабатывает (потому что grep вернул не-zero),
#      печатает второй "0" на новой строке. Результат: VAR="0\n0".
#      `[ "$VAR" -gt 0 ]` падает с ошибкой integer expression.
#
#      FIX: убран `|| echo 0`, добавлено `${VAR:-0}` для дефолта при пустом
#      выводе, и trim multiline через `head -1` где нужно.
#
#  v3.11 changelog (Tor exit blocklist):
#
#    [FEATURE] Опциональная блокировка Tor exit nodes на уровне nft.
#      Активация: переменная окружения BLOCK_TOR=1 при запуске скрипта,
#      либо файл /etc/shieldnode/block_tor (touch для включения).
#      По умолчанию ОТКЛЮЧЕНО — операторы которые обслуживают параноиков
#      (Tor → VPN bridge users) могут оставить выключенным.
#
#      Источники списка (в порядке fallback):
#        1. https://check.torproject.org/torbulkexitlist (~1352 IPv4)
#        2. https://www.dan.me.uk/torlist/?exit (с фильтром v4-only,
#           rate-limit раз в 30 минут)
#
#      Архитектура:
#        - Новый nft set `tor_exit_blocklist_v4` (interval, auto-merge)
#        - Правило в prerouting: `ip saddr @tor_exit_blocklist_v4 drop`
#          (после whitelist'ов, до scanner_blocklist — Tor IPs не должны
#          даже считаться как сканеры в нашей статистике)
#        - Логгирование первых 100 drops/час с тегом [shield:tor]
#        - Отдельный counter tor_drops для guard CLI
#        - Hourly cron (`/etc/cron.hourly/shieldnode-tor-update`) —
#          torproject обновляется каждые 30 мин, hourly = разумный compromise
#        - Sanity-валидация (тот же фильтр что для scanner_blocklist в
#          v3.10.2 BUG-6: prefix>=8, отсев bogons)
#        - Если оба источника недоступны — set остаётся последний known-good
#          состояние, не очищается (важно: иначе короткий network glitch
#          снимает защиту)
#
#      Метрики наблюдения в guard CLI:
#        Tor exit drops:   {N} pkts (last 1h)
#        Tor exit blocks:  {M} active IPs in set
#
#      Поведение в SAFE-режиме:
#        - Если установка не может скачать список Tor с обоих источников —
#          BLOCK_TOR=1 не активируется, выводится WARN.
#        - Если cron-обновление fail'нется 3 раза подряд — set очищается
#          (иначе устаревший список будет блочить уже-неTor IPs).
#
#  v3.10.4 changelog (CrowdSec deep audit, part 2):
#
#    [BUG-14] Acquisition не настраивается явно для SSHD на Minimal Ubuntu 24.04.
#      Корень: при установке crowdsec wizard сканирует /var/log/ и создаёт
#      acquis.yaml только для FOUND log files. На Minimal Ubuntu 24.04 (или
#      cloud images типа Oracle Cloud free tier) /var/log/auth.log не
#      существует — система пишет только в journald. Wizard не создаёт
#      acquisition для SSH, и crowdsecurity/sshd сценарии никогда не
#      получают данные. `cscli metrics` показывает пустые counters.
#      Симптом: установка прошла "успешно", но cscli decisions list пустой
#      даже после реальных SSH-атак.
#      FIX: после установки crowdsec проверяем наличие SSH-acquisition
#      (либо file:/var/log/auth.log, либо journalctl). Если нет — создаём
#      /etc/crowdsec/acquis.d/sshd.yaml с journalctl-filter sshd.service.
#
#    [BUG-15] CAPI registration не проверяется → нет community blocklist.
#      Корень: при apt install crowdsec на машинах за NAT/прокси/корпоративным
#      фаерволом CAPI registration может silently fail. Это не помечается
#      как ошибка установки. На выходе у юзера локальная CrowdSec без
#      community blocklist (это самая ценная фича, ради которой ставится
#      CrowdSec). `cscli capi status` returns auth error, но никто не
#      смотрит. Скрипт молча проходит.
#      FIX: после установки делаем `cscli capi status`. Если non-zero exit —
#      пытаемся `cscli capi register` ещё раз. Если опять fail — выводим
#      WARNING с инструкциями.
#
#    [BUG-16] Дубль bouncer registration на повторных запусках.
#      Корень: на повторном запуске скрипта (например, после изменения портов
#      в UFW) проверка `cscli bouncers list | grep -q "cs-firewall-bouncer"`
#      — подстрочный match, поэтому НЕ создаётся дубль.
#      Но при rerun на чистой системе после ручного `cscli bouncers delete`
#      (если оператор экспериментирует) — apt postinst уже зарегистрировал
#      bouncer как `cs-firewall-bouncer`, мы попытаемся зарегистрировать
#      `cs-firewall-bouncer-nftables` потому что наша проверка сработала
#      на устаревший cache. Получим два bouncer'а в БД, один сломанный.
#      FIX: явно проверяем что bouncer-имя реально работает через
#      `cscli bouncers list -o json` + jq, и только если registration
#      нерабочая — пытаемся пересоздать.
#
#    [BUG-17] Mgmt IPs whitelist через decision не блокирует scenario trigger.
#      Корень: `cscli decisions add --type whitelist` создаёт decision с
#      типом "whitelist" в БД. Bouncer не дропает такие IP. ОДНАКО, scenario
#      всё равно срабатывает (генерируется alert, увеличиваются counters,
#      и signal отправляется в CAPI как сигнал атаки). На CAPI side это
#      может ухудшить наш community contribution score → меньше блок-листов
#      по подписке.
#      FIX: добавляем postoverflow whitelist в /etc/crowdsec/postoverflows/
#      s01-whitelist/shieldnode-mgmt.yaml. Postoverflow срабатывает ПОСЛЕ
#      scenario trigger, но ДО decision/alert — alerts тоже не идут.
#
#    [BUG-18] Acquisition с syslog-type читается ДВАЖДЫ если есть и
#      auth.log, и journalctl (rsyslog активен на Ubuntu 24.04 default).
#      Корень: Ubuntu 24.04 default имеет rsyslog → /var/log/auth.log
#      ВТОРАЯ копия данных в journald. Если wizard создаст acquis для
#      auth.log А мы добавим acquis для journalctl-sshd → каждый log line
#      обработается дважды → двойные счётчики leaky bucket → preliminary
#      ban при половине реального threshold.
#      Симптом: ssh-bf срабатывает на 2-3 неправильных попытках вместо 5.
#      FIX: при создании sshd.yaml acquisition (BUG-14) сначала
#      проверяем что нет уже работающего file-based acquisition с
#      auth.log. Если есть — пропускаем создание journalctl-acquisition.
#
#    [BUG-19] cscli simulation status не проверяется.
#      Корень: некоторые scenarios (e.g. `crowdsecurity/http-bf-wordpress_bf`)
#      приходят в simulation mode по дефолту. В simulation mode они
#      производят alerts, но не decisions. Пользователь установил коллекцию
#      с этим сценарием, видит alerts — но IP не банится. Не очевидно
#      без проверки. Для нашего скрипта (только linux + sshd) это не
#      проблема, но если оператор добавит свои коллекции, сюрприз.
#      FIX: smoke-test print'ает количество scenarios в simulation mode.
#
#  v3.10.3 changelog (CrowdSec audit fixes):
#
#    [BUG-9] Bouncer работает в input hook ПОСЛЕ нашего prerouting → пакеты
#      от CrowdSec-banned IP всё равно проходят через наш rate-limit.
#      Корень: bouncer по дефолту создаёт `table ip crowdsec` с цепочкой
#      `crowdsec-chain` в hook input priority -10. Наша же таблица
#      `inet ddos_protect` сидит в prerouting priority -100. Prerouting
#      выполняется НАМНОГО раньше input, поэтому banned-IP попадает в
#      наш newconn_rate_v4 → suspect_v4 → confirmed_attack_v4 ПРЕЖДЕ ЧЕМ
#      bouncer его дропнет. Проверено эмпирически в network-namespace:
#      30 fast pings от заблокированного IP → 19 hits на нашем
#      newconn_overflow ДО того как bouncer drop сработал.
#      Последствия: лишний CPU-расход на каждом пакете от banned IP,
#      ложные алерты в /var/log/shieldnode/events.log, IP попадает
#      одновременно в crowdsec ban (4h) И в наш confirmed_attack_v4 (1h).
#      FIX: меняем приоритет bouncer'а на raw (-300) и hook на prerouting,
#      чтобы CrowdSec drops срабатывали ДО нашей логики rate-limit.
#      После этого banned-IP вообще не доходит до нашей цепочки.
#
#    [BUG-10] Bouncer пытается работать с IPv6 на нодах с отключённым IPv6.
#      Корень: vpn-node-setup.sh v4.0 отключает IPv6 (sysctl + grub),
#      но bouncer config defaults: `ipv6.enabled: true`. На таких нодах
#      bouncer каждые 10 секунд пишет в /var/log/crowdsec-firewall-bouncer.log
#      ошибки про netlink ENOENT и невозможность создать table ip6 crowdsec6.
#      Последствия: лог-спам, забивает диск (10 событий/мин × 1440 мин = 14400
#      строк/день).
#      FIX: после установки bouncer'а патчим config — disable IPv6 если в
#      sysctl IPv6 отключён (net.ipv6.conf.all.disable_ipv6=1).
#
#    [BUG-11 SECURITY] Mgmt IPs в UFW whitelist НЕ передаются в CrowdSec.
#      Корень: скрипт парсит `ufw status` и кладёт mgmt IPs в наш nft set
#      `manual_whitelist_v4`. Но CrowdSec про эти IPs ничего не знает.
#      Если админ 5 раз неправильно введёт SSH-пароль (или fail2ban-style
#      сценарий поменяется в hub upgrade), CrowdSec забанит его IP.
#      Bouncer дропает на хук-уровне, наш `manual_whitelist_v4` в другой
#      таблице/цепочке не помогает. Админ заблокирован на 4 часа.
#      Симптом: "не могу подключиться по SSH со своего IP" — а нода живая.
#      FIX: при установке создаём CrowdSec whitelist через
#      `cscli decisions add --type whitelist` для всех IPs из MGMT_IPV4.
#      Также делаем postoverflow whitelist по тем же IPs.
#
#    [BUG-12] sed для ban duration патчит только ПЕРВУЮ запись `duration: 24h`.
#      Корень: дефолтный CrowdSec profiles.yaml содержит ТРИ профиля
#      (captcha_remediation, default_ip_remediation, default_range_remediation),
#      каждый со своим `duration: 4h`. Старая версия скрипта (v1.1-1.3)
#      устанавливала 24h во все три. Команда
#      `sed -i '0,/^...duration: 24h.../s//.../'` использует range-
#      замену "первая встреченная строка" — обновляет только профиль Ip,
#      оставляя Range и captcha на 24h. Юзер за CGNAT (Range-scope) сидит
#      в бане 24h вместо 4h.
#      FIX: убран `0,` из sed → теперь патчатся все вхождения 24h → 4h.
#
#    [BUG-13] Hub update никогда не запускается → стареющие правила.
#      Корень: cscli коллекции/сценарии регулярно обновляются (новые
#      sshd-bf варианты, исправления regex'ов в парсерах). На свежей
#      установке скрипт ставит коллекции через `cscli collections install`,
#      но никогда не делает `cscli hub update && cscli hub upgrade`.
#      Через полгода правила устаревают, новые scenarios не подхватываются.
#      На CrowdSec >= 1.7.2 идёт встроенный systemd-таймер hub-update,
#      на старых версиях нет.
#      FIX: после установки делаем единоразовый `cscli hub update && cscli
#      hub upgrade`. Плюс если crowdsec версия < 1.7.2, добавляем cron-job
#      ежедневного hub-update.
#
#    [DOCS] Уточнения в комментариях про взаимодействие CrowdSec с нашей
#      защитой. Исправлены упоминания "защищает CrowdSec" в местах, где
#      имеется в виду конкретно SSH-bouncer.
#
#  v3.10.2 changelog (audit fixes — major reliability + CGNAT false-positives):
#
#    [BUG-1 CRITICAL] UFW port-range "N:M" ломал updater целиком.
#      Корень: ufw allow 4000:5000/tcp выводится в `ufw status` как
#      "4000:5000/tcp ALLOW Anywhere". Старый regex `^[0-9:]+(\/...)?$` пропускал
#      эту строку через парсер, и "4000:5000" попадал в `add element { 4000:5000 }`,
#      что nftables отвергает (требуется "4000-5000" через дефис). Вся транзакция
#      `nft -f` падала с "Servname not supported", set оставался пустым.
#      Симптом: оператор открыл диапазон → защита TCP не работает вообще.
#      FIX: regex переписан под `^[0-9]+(:[0-9]+)?(,...)*(\/(tcp|udp))?$`,
#      добавлен gsub(/:/, "-") для нормализации в nft-синтаксис.
#
#    [BUG-3] Multi-port `80,443/tcp` молча игнорировался.
#      Корень: тот же regex `^[0-9:]+...$` не пропускал запятую → строка
#      `80,443/tcp ALLOW Anywhere` молча отбрасывалась. Защита для этих портов
#      не активировалась, без single ошибки в логах.
#      FIX: новый regex принимает comma-list, awk раскручивает 80,443 в две
#      отдельные строки.
#
#    [BUG-8 HIGH] UFW локализация ломала детект FIREWALL_ACTIVE.
#      Корень: строка "Status: active" в /usr/share/ufw/messages/*.mo
#      переводится для ru/uk/it/fr/es/pt/zh/etc. На сервере с LANG=ru_RU
#      `ufw status` выводит "Состояние: активен", и `grep -q "Status: active"`
#      не находит ничего → FIREWALL_ACTIVE=0 → safety-guard updater'а никогда
#      не срабатывает → любой transient empty parse затирает sets. Также при
#      установке детект типа фаервола падает на Russian-locale → FIREWALL_TYPE
#      идёт в iptables-fallback и не находит порты UFW (они в ufw-user-input
#      chain, не в INPUT) → install говорит "В фаерволе нет открытых портов".
#      Этот баг был назван в v3.10.1 changelog как hypothesis (b) — теперь
#      он подтверждён прямой проверкой /usr/share/ufw/messages/ru.mo.
#      FIX: все вызовы `ufw status` обёрнуты в `LANG=C LC_ALL=C ufw status`,
#      детект надёжен независимо от системной локали.
#
#    [BUG-2] Safety-guard updater'а не покрывал UDP-only setup'ы.
#      Корень: проверка "не затирай ничего пустым" сравнивала только
#      $CUR_TCP || $CUR_MGMT_V4. Для Hysteria/TUIC/WireGuard-only нод (где
#      открыт только UDP-порт без admin-IP whitelist) обе переменные пусты,
#      и transient empty parse валился через все защиты → UDP set
#      обнулялся.
#      FIX: добавлена проверка $CUR_UDP в условие safety-guard.
#
#    [BUG-7] Multi-SSH detect видел только первый sshd-listener.
#      Корень: awk-парсер `ss -tlnpH` имел `exit` после первого совпадения.
#      Второй SSH-порт (типичный сценарий миграции "старый порт + новый
#      порт") не исключался из защиты → попадал под SYN-rate limits.
#      FIX: убран exit, все sshd-listener-порты собираются и исключаются.
#
#    [BUG-6 SECURITY] Scanner blocklist принимал любые префиксы и bogons.
#      Корень: парсер `grep -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]+)?'`
#      не валидирует /N. Если кто-то отравит upstream-источник
#      (PR-poison shadow-netlab/traffic-guard-lists или взлом репо),
#      запушив `0.0.0.0/0` или `8.8.8.8/8` — всё применится без вопросов.
#      Set @scanner_blocklist_v4 c rule `ip saddr @set ... drop` в prerouting
#      = полный network blackhole или дроп Google DNS.
#      Sanity-guard "если <10 — abort" не помогает, у атакующего тысячи
#      реальных IP плюс одна злая запись.
#      FIX: добавлена sanity-валидация: prefix >= /8, отсев bogons (0/8,
#      10/8, 127/8, 169.254/16, 172.16/12, 192.168/16, multicast 224-239).
#
#    [BUG-4] Stale labels в guard CLI ("ct>50", "5min watch").
#      Корень: при апгрейде до v3.9 (lct count 50→100, suspect timeout
#      5min→30min) лейблы в guard heredoc'е не обновили.
#      FIX: лейблы синхронизированы с реальным шаблоном.
#
#    [SUSPECT-4 HIGH] Двойной touch named-meter в Stage 2 + Stage 1
#      эффективно делил per-IP rate-limit на 2 для CGNAT.
#      Корень: `add @rate_v4 { ip saddr limit rate over X }` вызывался из
#      двух правил подряд для одного пакета. Эмпирически в network-namespace
#      доказано (single-rule: burst=10 → 10 free; double-rule: burst=10 → 5
#      free, drain 2× быстрее). Для CGNAT IP, держащих 100 conn/min при
#      номинальном лимите 150/min, эффективная стоимость 200 токенов/min при
#      refill 150/min → bucket пустеет через 6 минут → confirmed_attack.
#      Это отдельный механизм false-positive'ов CGNAT, не закрытый v3.9.
#      FIX: новые цепочки newconn_overflow и syn_overflow выделены отдельно.
#      Главная цепочка делает meter-update ровно ОДИН раз на пакет, потом
#      jump в подцепочку решает: confirmed (если уже suspect) или suspect.
#      Лимиты подняты с учётом теперь корректной семантики:
#        ct count: 100 → 150 (CGNAT 50 юзеров с TCP+UDP реально дают 80-120)
#        new-conn: 150/min → 200/min, burst 300 → 500
#        SYN: 300/sec оставлен (уже cgnat-friendly после фикса)
#        UDP: 600/sec оставлен
#
#    [PERF Risk-4] Aggregator перепарсивал каждую log-line через
#      `echo $line | grep | head | cut` — 4 fork+exec на строку.
#      Бенчмарк на 10k log-lines: 94 секунды. Под штормом 50k events/min
#      aggregator не успевал, события терялись.
#      FIX: переписано через single-pass awk. Бенчмарк: 0.026s на 10k =
#      ~3700× ускорение. Теперь даже storm 100k+/min обрабатывается в <1s.
#
#    [SQLITE] events.db переведён в WAL mode при инициализации.
#      Concurrent guard reads + aggregator writes больше не блокируются.
#
#    [DOCS] FIB anti-spoof rule в комментариях упоминает исключения
#      tun*/wg*/docker*. Реально в коде только `iif "lo" accept`. Тестами
#      доказано что для tun*/wg* трафика fib lookup возвращает корректный
#      oif (через те же интерфейсы), и rule не дропает legitimate traffic.
#      Поведение правильное, исправлен только comment в changelog v3.8.
#
#    [HARDEN] Smoke-test после установки: проверка что таблица создалась
#      и protected_ports_tcp/udp непустые (если в UFW есть правила).
#      Раньше "ставится молча" → оператор не знал что v3.5 ct count баг
#      проработал 4 версии без обнаружения. Smoke-test ловит подобные
#      регрессии сразу.
#
#  v3.10.1 changelog (REVERT v3.10 incorrect parser fix):
#    - REVERT: v3.10 поменял awk-фильтр UFW парсера с $3 == "Anywhere" на
#      $4 == "Anywhere". Это было НЕПРАВИЛЬНО.
#      Корень моей ошибки: я анализировал вывод "ufw status verbose" (с
#      колонкой IN), где Anywhere — это $4. Но скрипт вызывает обычный
#      "ufw status" (без verbose), где Anywhere — это $3.
#      После v3.10 парсер на ВСЕХ серверах перестал находить порты:
#      "В фаерволе нет открытых TCP-портов кроме SSH" / TCP={}.
#      v3.10.1 откатывает парсер обратно к $3 (как было в v3.9 и раньше).
#    - NOTE: оригинальная проблема "Updated: TCP={}" наблюдавшаяся ДО v3.10
#      имеет другой корень. Возможные причины:
#        a) race condition: updater запускался во время изменения UFW-правил
#        b) locale: LANG=ru_RU мог сломать парсинг "ALLOW"/"Anywhere"
#        c) первые запуски сразу после установки UFW
#      В v3.10.1 ошибочный фикс убран; парсер вернулся в рабочее состояние.
#
#  v3.9 changelog (CRITICAL FIX: ложные баны клиентов на CGNAT):
#    - CRITICAL FIX: правило "ct count over 50" банило ВСЕХ клиентов VPN-ноды.
#      Корень проблемы: синтаксис "ct count over N" БЕЗ "ip saddr" — это
#      ГЛОБАЛЬНЫЙ счётчик conntrack по всей системе, а не per-IP.
#      Когда у ноды >50 conntrack-записей (норма для VPN), КАЖДЫЙ новый TCP
#      на VPN-порту матчил это правило → попадал в suspect → второй матч →
#      confirmed_attack (бан 1ч). Проявление на проде: 42 ложных бана
#      российских CGNAT-клиентов за 6 секунд.
#      Подтверждение: counter conn_flood_v4=189 packets, syn_confirmed_v4=0,
#      newconn_flood_v4=0 → бан шёл ИСКЛЮЧИТЕЛЬНО через сломанный ct count.
#      Правильный синтаксис per-IP (Red Hat RHEL 8 docs):
#        add @set { ip saddr ct count over N }
#      Где N — concurrent connections от конкретного src IP, set хранит
#      элементы автоматически с per-element счётчиком.
#    - CHANGE: лимиты подняты под реальные CGNAT-нагрузки в РФ:
#      • ct count: 50 → 100 (CGNAT с 50 юзерами легко даёт 80-150 concurrent)
#      • new-conn rate: 50/min → 150/min, burst 100 → 300
#      • SYN rate: 300/sec → оставлен (для CGNAT уже OK)
#      • UDP rate: 600/sec → оставлен
#    - CHANGE: suspect_v4 timeout 5min → 30min.
#      Зачем: 5min слишком коротко — клиент с retry (Reality, mux) может
#      залезть в suspect, через 6 минут попробовать снова, и счётчик
#      сбросится — ban-once архитектура не работает. 30min даёт окно
#      определить настоящего атакующего.
#    - ADD: [8] Unban all в guard interactive menu.
#      Что: одной кнопкой очистить confirmed_attack_v4 + suspect_v4.
#      Зачем: при ложных срабатываниях (как этот баг) или ручной коррекции
#      нужна простая команда вместо `nft flush set ...` руками.
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

# v3.11.1 BUG-CSCLI-FMT FIX: устойчивая проверка установлена ли коллекция
# в CrowdSec независимо от формата вывода cscli (table в 1.7+, plain в 1.6).
# Используем `-o raw` который даёт CSV-like формат, стабильный между версиями.
# Header: первая строка "name", далее "name,status,version,description"
cscli_collection_installed() {
    local name="$1"
    [ -z "$name" ] && return 1
    command -v cscli >/dev/null 2>&1 || return 1
    cscli collections list -o raw 2>/dev/null | \
        awk -F, -v target="$name" 'NR > 1 && $1 == target { found=1; exit } END { exit !found }'
}

# ==============================================================================
# v3.12.0 GLOBAL CONFIG (paths, repo URL, defaults)
# ==============================================================================

# Github repo для скачивания дефолтных lists/*.txt при pipe-mode установке.
# Можно переопределить через env (для тестинга на форке).
SHIELD_REPO_URL="${SHIELD_REPO_URL:-https://raw.githubusercontent.com/abcproxy70-ops/shield/main}"

# Каталоги
SHIELD_ETC_DIR="/etc/shieldnode"
SHIELD_LISTS_DIR="$SHIELD_ETC_DIR/lists"
SHIELD_CONF_FILE="$SHIELD_ETC_DIR/shieldnode.conf"
SHIELD_DEFAULTS_FILE="/usr/local/sbin/shieldnode-defaults.sh"
SHIELD_UPDATER_SCRIPT="/usr/local/sbin/shieldnode-update-blocklist.sh"
SHIELD_STATE_DIR="/var/lib/shieldnode"

# v3.12.0: detect pipe-mode (curl | bash) vs git-clone-mode (./shieldnode.sh)
# Pipe-mode → BASH_SOURCE[0] = /dev/fd/* или похожее → нет ./lists рядом со скриптом
# Git-mode → BASH_SOURCE[0] — реальный файл, рядом может лежать ./lists/
SHIELD_SCRIPT_PATH="${BASH_SOURCE[0]:-$0}"
SHIELD_PIPE_MODE=0
case "$SHIELD_SCRIPT_PATH" in
    /dev/fd/*|/proc/*|bash|-bash|sh|-sh|"")
        SHIELD_PIPE_MODE=1
        SHIELD_SCRIPT_DIR=""
        ;;
    *)
        if [ -f "$SHIELD_SCRIPT_PATH" ]; then
            SHIELD_SCRIPT_DIR="$(cd "$(dirname "$SHIELD_SCRIPT_PATH")" && pwd)"
        else
            SHIELD_PIPE_MODE=1
            SHIELD_SCRIPT_DIR=""
        fi
        ;;
esac

# v3.12.0: дефолтные blocklist sources. Если /etc/shieldnode/shieldnode.conf
# существует — он переопределит эти массивы (через source).
DEFAULT_LOCAL_BLOCKLISTS=(
    "scanner=$SHIELD_LISTS_DIR/scanner.txt"
    "threat=$SHIELD_LISTS_DIR/threat.txt"
    "tor=$SHIELD_LISTS_DIR/tor.txt"
    "custom=$SHIELD_LISTS_DIR/custom.txt"
)

# Объединение URL'ов через запятую → один set
DEFAULT_REMOTE_BLOCKLISTS=(
    "scanner=https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/antiscanner.list,https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/government_networks.list,https://raw.githubusercontent.com/tread-lightly/CyberOK_Skipa_ips/main/lists/skipa_cidr.txt"
    "threat=https://www.spamhaus.org/drop/drop.txt,https://iplists.firehol.org/files/firehol_level1.netset"
    "tor=https://check.torproject.org/torbulkexitlist"
    # custom: только локальный файл, без URL
    "custom="
)

DEFAULT_SCANNER_UPDATE_INTERVAL="6h"
DEFAULT_THREAT_UPDATE_INTERVAL="1d"
DEFAULT_TOR_UPDATE_INTERVAL="1h"
DEFAULT_CUSTOM_UPDATE_INTERVAL="6h"   # для custom: timer редкий, основной trigger — path-watcher

DEFAULT_MIN_ENTRIES_SCANNER=100
DEFAULT_MIN_ENTRIES_THREAT=500
DEFAULT_MIN_ENTRIES_TOR=100
DEFAULT_MIN_ENTRIES_CUSTOM=0

DEFAULT_FAIL_THRESHOLD=3

# nft set names — для совместимости с v3.11.x state на проде сохраняем
# имя tor_exit_blocklist_v4 (старое). Маппинг: имя в updater'е → реальный nft set.
shield_nft_set_name() {
    case "$1" in
        scanner)    echo "scanner_blocklist_v4" ;;
        threat)     echo "threat_blocklist_v4"  ;;
        tor)        echo "tor_exit_blocklist_v4" ;;   # legacy compat
        custom)     echo "custom_blocklist_v4"  ;;
        mobile_ru)  echo "mobile_ru_whitelist_v4" ;;  # v3.13.0
        *) return 1 ;;
    esac
}

# v3.13.0: mobile-RU whitelist defaults
ENABLE_RU_MOBILE_WHITELIST="${ENABLE_RU_MOBILE_WHITELIST:-1}"
MAXMIND_LICENSE_KEY="${MAXMIND_LICENSE_KEY:-}"

# Список AS — российские мобильные операторы (CGNAT pool'ы).
# Проверены через RIPEstat: stat.ripe.net/data/as-overview/data.json?resource=ASxxxx
# Включены: явные mobile/Vimpelcom AS. Исключены: МГТС fixed-line (AS25513),
# Mod MVNO (AS39855), gov-only AS.
DEFAULT_MOBILE_RU_AS_LIST=(
    8359   # МТС PJSC
    28884  # МТС Siberia
    12958  # T2 Mobile (Tele2)
    15378  # T2 Mobile (бывший Yota)
    41330  # T2 Mobile Novosibirsk
    42437  # T2 Mobile Rostov
    48190  # T2 Mobile Ekaterinburg
    31133  # MegaFon
    31163  # MegaFon Kavkaz
    12714  # MegaFon-AS (бэкбон)
    3216   # Vimpelcom (Beeline)
    8402   # Corbina (Vimpelcom)
    16345  # Beeline-AS
)

DEFAULT_MOBILE_RU_UPDATE_INTERVAL="1w"   # MaxMind обновляется 2 раза в неделю
DEFAULT_MIN_ENTRIES_MOBILE_RU=100        # ниже — что-то сломалось

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
                tor-blocklist-update.timer tor-blocklist-update.service \
                protected-ports-update.timer protected-ports-update.service \
                protected-ports-update.path \
                shieldnode-aggregator.timer shieldnode-aggregator.service \
                shieldnode-nftables.service \
                shieldnode-update@scanner.timer shieldnode-update@scanner.service \
                shieldnode-update@threat.timer  shieldnode-update@threat.service \
                shieldnode-update@tor.timer     shieldnode-update@tor.service \
                shieldnode-update@custom.timer  shieldnode-update@custom.service \
                shieldnode-update@custom.path \
                shieldnode-update@mobile_ru.timer shieldnode-update@mobile_ru.service; do
        systemctl disable --now "$unit" 2>/dev/null || true
        rm -f "/etc/systemd/system/$unit"
    done
    # v3.12.0: убираем templated unit-файлы (если timer'ы создавались из шаблона)
    rm -f /etc/systemd/system/shieldnode-update@.service
    rm -f /etc/systemd/system/shieldnode-update@.timer
    # v3.5: legacy unit от ≤v3.4 — удаляем если осталось от старой установки
    systemctl disable --now cs-ssh-whitelist 2>/dev/null || true
    rm -f /etc/systemd/system/cs-ssh-whitelist.service
    systemctl daemon-reload
    print_ok "Systemd units удалены"

    # Scripts
    rm -f /usr/local/sbin/cs-ssh-key-whitelist.sh
    rm -f /usr/local/sbin/update-scanner-blocklist.sh
    rm -f /usr/local/sbin/update-tor-blocklist.sh
    rm -f /usr/local/sbin/update-protected-ports.sh
    rm -f /usr/local/sbin/shieldnode-aggregator.sh
    rm -f /usr/local/sbin/shieldnode-update-blocklist.sh
    rm -f /usr/local/sbin/shieldnode-update-mobile-ru.sh
    rm -f /usr/local/sbin/shieldnode-defaults.sh
    rm -f /usr/local/bin/guard
    print_ok "Скрипты удалены (включая команду guard)"

    # v3.11: BLOCK_TOR marker
    rm -f /etc/shieldnode/block_tor
    # v3.12.0: lists и опциональный config
    rm -rf /etc/shieldnode/lists
    rm -f /etc/shieldnode/shieldnode.conf
    rmdir /etc/shieldnode 2>/dev/null || true

    # БД истории событий (v2.9), включая ASN cache (v3.12.0) и fail counters
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

    # cscli whitelist decisions (включая v3.10.3 mgmt whitelist)
    if command -v cscli >/dev/null 2>&1; then
        cscli decisions delete --type whitelist >/dev/null 2>&1 || true
        print_ok "Whitelist decisions очищены"
    fi

    # v3.10.3: убираем cron-job hub upgrade
    rm -f /etc/cron.daily/cscli-hub-upgrade

    # v3.10.4: убираем postoverflow whitelist
    rm -f /etc/crowdsec/postoverflows/s01-whitelist/shieldnode-mgmt.yaml

    # v3.10.4: убираем journalctl SSH acquisition если он от нас
    if [ -f /etc/crowdsec/acquis.d/sshd.yaml ] && \
       grep -q "v3.10.4" /etc/crowdsec/acquis.d/sshd.yaml 2>/dev/null; then
        rm -f /etc/crowdsec/acquis.d/sshd.yaml
        print_ok "Удалён shieldnode SSH acquisition"
    fi
    systemctl reload crowdsec >/dev/null 2>&1 || true

    # v3.10.3: восстанавливаем оригинальный bouncer config если есть бэкап
    if [ -f "$BACKUP_DIR/crowdsec-firewall-bouncer.yaml.before" ]; then
        cp -a "$BACKUP_DIR/crowdsec-firewall-bouncer.yaml.before" \
              /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml
        systemctl restart crowdsec-firewall-bouncer 2>/dev/null || true
        print_ok "Bouncer config восстановлен из бэкапа"
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

    # v3.11.1: Ubuntu/Debian backport-aware check.
    # Проблема: upstream OpenSSH 9.6p1 уязвим к CVE-2025-26466, но Ubuntu 24.04
    # имеет backport (1:9.6p1-3ubuntu13.8+) который УЖЕ ИСПРАВЛЕН. Старая
    # проверка `[ ssh_version < 9.9p2 ]` ругалась на patched 9.6p1 ложно.
    #
    # FIX: смотрим dpkg-version openssh-server и сверяем с известными
    # patched-версиями для конкретного дистрибутива.
    SSH_VULNERABLE=0
    OS_ID=$(. /etc/os-release 2>/dev/null && echo "$ID")
    OS_VER=$(. /etc/os-release 2>/dev/null && echo "$VERSION_ID")
    DPKG_SSH_VER=$(dpkg-query -W -f='${Version}' openssh-server 2>/dev/null)

    if [ -n "$DPKG_SSH_VER" ]; then
        # Известные patched-версии (USN-7270-1, Feb 2025):
        case "$OS_ID:$OS_VER" in
            ubuntu:24.04|ubuntu:24.10)
                # Ubuntu 24.04: patched в 1:9.6p1-3ubuntu13.8 и выше
                if dpkg --compare-versions "$DPKG_SSH_VER" "lt" "1:9.6p1-3ubuntu13.8" 2>/dev/null; then
                    SSH_VULNERABLE=1
                fi
                ;;
            ubuntu:22.04)
                # Ubuntu 22.04: 8.9p1, не affected by CVE-2025-26466 (introduced in 9.5p1)
                # Но проверим CVE-2025-26465 — patched в 1:8.9p1-3ubuntu0.11
                if dpkg --compare-versions "$DPKG_SSH_VER" "lt" "1:8.9p1-3ubuntu0.11" 2>/dev/null; then
                    SSH_VULNERABLE=1
                fi
                ;;
            ubuntu:20.04)
                # 8.2p1 — не affected by CVE-2025-26466
                # CVE-2025-26465 patched в 1:8.2p1-4ubuntu0.12
                if dpkg --compare-versions "$DPKG_SSH_VER" "lt" "1:8.2p1-4ubuntu0.12" 2>/dev/null; then
                    SSH_VULNERABLE=1
                fi
                ;;
            debian:12)
                # Bookworm: 9.2p1 — не affected by CVE-2025-26466 (introduced 9.5p1)
                # CVE-2025-26465 patched в 1:9.2p1-2+deb12u4
                if dpkg --compare-versions "$DPKG_SSH_VER" "lt" "1:9.2p1-2+deb12u4" 2>/dev/null; then
                    SSH_VULNERABLE=1
                fi
                ;;
            debian:11)
                # Bullseye: 8.4p1 — не affected by CVE-2025-26466
                if dpkg --compare-versions "$DPKG_SSH_VER" "lt" "1:8.4p1-5+deb11u4" 2>/dev/null; then
                    SSH_VULNERABLE=1
                fi
                ;;
            *)
                # Неизвестный дистрибутив — fallback на upstream-версию
                SSH_MAJOR=$(echo "$SSH_VERSION" | grep -oE '[0-9]+\.[0-9]+' | head -1)
                if dpkg --compare-versions "$SSH_MAJOR" "lt" "9.9" 2>/dev/null; then
                    SSH_VULNERABLE=1
                    print_info "Неизвестный дистрибутив ($OS_ID:$OS_VER) — fallback на upstream-проверку"
                fi
                ;;
        esac
    fi

    if [ "$SSH_VULNERABLE" = "1" ]; then
        print_warn "Версия OpenSSH потенциально уязвима ($DPKG_SSH_VER)"
        print_status "Обновляю openssh-server (apt upgrade)..."
        wait_for_apt_lock
        if DEBIAN_FRONTEND=noninteractive apt-get install --only-upgrade -y openssh-server openssh-client >/dev/null 2>&1; then
            NEW_DPKG_VER=$(dpkg-query -W -f='${Version}' openssh-server 2>/dev/null)
            if [ "$NEW_DPKG_VER" != "$DPKG_SSH_VER" ]; then
                print_ok "OpenSSH обновлён: $DPKG_SSH_VER → $NEW_DPKG_VER"
                print_info "Перезагрузи ssh: systemctl restart ssh (или ребут)"
            else
                print_info "OpenSSH уже последней версии в репо ($DPKG_SSH_VER)"
                print_info "Если репо старый — обнови дистрибутив или через backports"
            fi
        else
            print_warn "Не удалось обновить openssh — продолжаю установку"
        fi
    else
        # Известная patched-версия для этого дистрибутива
        if [ -n "$DPKG_SSH_VER" ]; then
            print_ok "OpenSSH защищён (patched в $OS_ID:$OS_VER backport: $DPKG_SSH_VER)"
        else
            print_ok "OpenSSH версия не уязвима к известным CVE"
        fi
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
    # v3.10.2 BUG-8 FIX: LANG=C — иначе локализованный "Состояние: активен"
    # на ru_RU/uk_UA/etc сломает grep "Status: active".
    if LANG=C LC_ALL=C ufw status 2>/dev/null | grep -q "Status: active"; then
        FIREWALL_TYPE="ufw"
        UFW_RULES_COUNT=$(LANG=C LC_ALL=C ufw status numbered 2>/dev/null | grep -cE "^\[ ?[0-9]+\]")
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
            # ufw status: "443/tcp ALLOW IN Anywhere", "443 ALLOW IN ..." (без proto = TCP+UDP),
            # multi-port: "80,443/tcp ALLOW Anywhere", range: "4000:5000/tcp ALLOW Anywhere"
            local ufw_out
            # v3.10.2 BUG-8 FIX: LANG=C — иначе ru/uk/it/etc локали ломают парсер.
            ufw_out=$(LANG=C LC_ALL=C ufw status 2>/dev/null)
            # v3.10.2 BUG-1+3 FIX: regex теперь принимает port-range (N:M)
            # и multi-port (N,M,...) форматы UFW. Двоеточие нормализуется в дефис
            # (UFW: 4000:5000, nft: 4000-5000). Comma-list разворачивается в
            # отдельные порты.
            tcp_list=$(echo "$ufw_out" | awk '
                $2 == "ALLOW" && $0 !~ /\(v6\)/ && $3 == "Anywhere" {
                    pp = $1
                    if (match(pp, /^[0-9]+(:[0-9]+)?(,[0-9]+(:[0-9]+)?)*(\/(tcp|udp))?$/)) {
                        n = split(pp, a, "/")
                        ports = a[1]
                        proto = (n > 1) ? a[2] : "any"
                        if (proto == "tcp" || proto == "any") {
                            m = split(ports, plist, ",")
                            for (i = 1; i <= m; i++) {
                                p = plist[i]
                                gsub(/:/, "-", p)
                                print p
                            }
                        }
                    }
                }
            ' | sort -u | tr '\n' ',' | sed 's/,$//')

            udp_list=$(echo "$ufw_out" | awk '
                $2 == "ALLOW" && $0 !~ /\(v6\)/ && $3 == "Anywhere" {
                    pp = $1
                    if (match(pp, /^[0-9]+(:[0-9]+)?(,[0-9]+(:[0-9]+)?)*(\/(tcp|udp))?$/)) {
                        n = split(pp, a, "/")
                        ports = a[1]
                        proto = (n > 1) ? a[2] : "any"
                        if (proto == "udp" || proto == "any") {
                            m = split(ports, plist, ",")
                            for (i = 1; i <= m; i++) {
                                p = plist[i]
                                gsub(/:/, "-", p)
                                print p
                            }
                        }
                    }
                }
            ' | sort -u | tr '\n' ',' | sed 's/,$//')

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

# v3.10.2 BUG-7 FIX: убран `exit` после первого совпадения — все sshd-listener
# порты собираются. SSH_PORT (для display) — первый, остальные тоже исключаются
# из списков защищаемых портов.
SSH_PORTS=$(ss -tlnpH 2>/dev/null | awk '
    /users:\(.*"sshd"/ {
        split($4, a, ":")
        port = a[length(a)]
        if ($4 ~ /^127\./ || $4 ~ /^\[::1\]/) next
        print port
    }
' | sort -un | tr '\n' ',' | sed 's/,$//')
SSH_PORTS="${SSH_PORTS:-22}"
SSH_PORT=$(echo "$SSH_PORTS" | cut -d, -f1)

# Исключаем SSH (все ssh-порты) из списков защищаемых портов
exclude_port() {
    local list="$1" exclude="$2"
    echo ",$list," | sed "s/,$exclude,/,/g; s/^,//; s/,$//"
}

# v3.10.2: исключаем все SSH-порты, не только первый
exclude_ports_list() {
    local list="$1" excludes="$2"
    local IFS=','
    for e in $excludes; do
        list=$(exclude_port "$list" "$e")
    done
    echo "$list"
}

PROTECTED_TCP=$(exclude_ports_list "$RAW_TCP" "$SSH_PORTS")
PROTECTED_UDP="$RAW_UDP"  # UDP SSH не использует, исключать не нужно

# v3.10.2: формируем nft-set синтаксис для SSH-портов: "22, 2222"
SSH_PORTS_NFT=$(echo "$SSH_PORTS" | sed 's/,/, /g')

# Печать результатов
if [ "$SSH_PORTS" = "$SSH_PORT" ]; then
    print_ok "SSH порт: ${BOLD}$SSH_PORT${NC} (исключён из защиты)"
else
    print_ok "SSH порты: ${BOLD}$SSH_PORTS${NC} (все исключены из защиты)"
fi

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

# v3.11: Tor exit blocklist (опционально). Активируется через:
#   - переменную окружения BLOCK_TOR=1 при запуске
#   - либо файл-маркер /etc/shieldnode/block_tor (для повторных запусков)
# По умолчанию ОТКЛЮЧЕНО — операторы которые хостят Tor → VPN bridge для
# параноиков должны оставлять выключенным.
BLOCK_TOR="${BLOCK_TOR:-0}"
if [ -f /etc/shieldnode/block_tor ]; then
    BLOCK_TOR=1
fi
if [ "$BLOCK_TOR" = "1" ]; then
    print_ok "Tor exit blocklist: ${BOLD}ВКЛЮЧЁН${NC} (BLOCK_TOR=1)"
    print_info "Для отключения: rm /etc/shieldnode/block_tor && перезапустить скрипт"
else
    print_info "Tor exit blocklist: отключён (включить: BLOCK_TOR=1 sudo ./shieldnode.sh)"
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
    # Заполняется скриптом /usr/local/sbin/shieldnode-update-blocklist.sh scanner
    set scanner_blocklist_v4 {
        type ipv4_addr
        flags interval
        auto-merge
        # Размер для ~50k подсетей с запасом
        size 131072
    }

    # --- v3.12.0: Threat blocklist (Spamhaus DROP, FireHOL Level 1) ---
    # Заполняется /usr/local/sbin/shieldnode-update-blocklist.sh threat
    # Spamhaus DROP — известные criminally-controlled сети (low false-positive).
    # FireHOL Level 1 — агрегатор RBL'ов (high-confidence атакующие).
    set threat_blocklist_v4 {
        type ipv4_addr
        flags interval
        auto-merge
        size 65536
    }

    # --- v3.12.0: Custom blocklist (operator personal IPs) ---
    # Заполняется /usr/local/sbin/shieldnode-update-blocklist.sh custom
    # Источник: /etc/shieldnode/lists/custom.txt + опциональные URL'ы из конфига.
    # Path-watcher inotify-триггерит обновление сразу при изменении файла.
    set custom_blocklist_v4 {
        type ipv4_addr
        flags interval
        auto-merge
        size 32768
    }

    # --- v3.13.0: Mobile-RU AS whitelist ---
    # Подсети российских мобильных операторов (AS8359 МТС, AS12958 T2, etc).
    # Заполняется /usr/local/sbin/shieldnode-update-blocklist.sh mobile_ru
    # Источник: MaxMind GeoLite2-ASN-CSV (требует MAXMIND_LICENSE_KEY).
    # Если key нет — set пустой, никакого whitelist'инга (поведение v3.12.0).
    # ВАЖНО: эти IP получают РЕЛАКСИРОВАННЫЕ лимиты (ct=1000, newconn=2000/min)
    # вместо стандартных (ct=400, newconn=500/min) — для CGNAT с 50-200 абонентами.
    # Scanner/threat/custom blocklist'ы НЕ обходятся — реальные атаки всё равно ловятся.
    set mobile_ru_whitelist_v4 {
        type ipv4_addr
        flags interval
        auto-merge
        size 65536
    }

    # --- v3.11: Tor exit blocklist ---
    # Заполняется /usr/local/sbin/shieldnode-update-blocklist.sh tor (v3.12.0)
    # из check.torproject.org/torbulkexitlist (~1500 IPs, individual /32).
    # Активен только если оператор включил BLOCK_TOR=1 при установке.
    # Если выключен — set пустой, правило 'ip saddr @... drop' no-op.
    set tor_exit_blocklist_v4 {
        type ipv4_addr
        flags interval
        auto-merge
        size 8192
    }
    # --- v2.5: STAGE 1 — SUSPECT (наблюдение 5 минут) ---
    # IP попадает сюда при первом превышении лимита.
    # Трафик НЕ дропается. Если за 5 минут IP опять превышает — переводим в confirmed.
    # Если не превышает — таймер истекает, забываем про IP (false positive).
    # v3.9: timeout поднят с 5m до 30m. Причина: 5m слишком коротко для
    # реальной защиты — клиент с retry (Reality mux, mobile reconnect) мог
    # залезть в suspect, через 6 мин попробовать снова, и таймер сбрасывался.
    # Ban-once не работал по сути. 30m даёт окно определить atакующего vs CGNAT.
    set suspect_v4 {
        type ipv4_addr
        flags dynamic, timeout
        timeout 30m
        size 65536
    }

    # v3.9: connlimit_v4 — отслеживает concurrent connections per source IP
    # для ct count. ВАЖНО: НЕ должен иметь timeout (по docs nftables wiki:
    # "ct count statement can only be used with add set statement, if you
    # define timeout, you will hit Operation is not supported error").
    # Conntrack table timers сами cleanup элементы при истечении соединений.
    set connlimit_v4 {
        type ipv4_addr
        flags dynamic
        size 65536
    }

    # --- v2.5: STAGE 2 — CONFIRMED ATTACK (бан 1 час) ---
    # Сюда IP попадает если уже сидел в suspect и опять превысил лимит.
    # Это значит — точно атака, баним всерьёз.
    # v3.12.0 CGNAT FIX: timeout 1h → 15min. Если CGNAT IP попал false-positive,
    # быстро разблочится. Реальная атака возобновится — снова попадёт в бан.
    set confirmed_attack_v4 {
        type ipv4_addr
        flags dynamic, timeout
        timeout 15m
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
    counter tor_drops_v4 { }      # v3.11: Tor exit nodes dropped
    counter threat_drops_v4 { }   # v3.12.0: Spamhaus/FireHOL drops
    counter custom_drops_v4 { }   # v3.12.0: operator personal blocklist drops
    counter mobile_ru_passes_v4 { }   # v3.13.0: mobile-RU IPs прошли relaxed-path
    counter mobile_ru_conn_flood_v4 { }   # v3.13.0: drops в relaxed-path (ct>1000)
    # v3.5: counters для HTTP/connection-flood защиты
    counter conn_flood_v4 { }     # ct count > 400 на src (v3.12.0: CGNAT-friendly)
    counter newconn_flood_v4 { }  # >50 new conn/min на src
    counter tcp_invalid { }       # invalid TCP flag combos

    chain prerouting {
        type filter hook prerouting priority -100; policy accept;

        # Established/related — пропускаем без проверок.
        ct state established,related accept

        # Manual whitelist (всегда первым приоритетом)
        ip saddr @manual_whitelist_v4 accept

        # SSH — без блокировок (защищает CrowdSec)
        # v3.10.2: поддержка нескольких SSH-портов (e.g. миграция 22 → 2222)
        tcp dport { $SSH_PORTS_NFT } accept

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

        # === v3.13.1: MOBILE-RU AS WHITELIST (relaxed limits, true whitelist) ===
        # Российские мобильные операторы (МТС, T2, МегаФон, Билайн) дают CGNAT
        # с 50-200 абонентами на 1 IP. Стандартный лимит ct=400 их банит при
        # пиковой активности (одновременная работа множества юзеров).
        #
        # ПОРЯДОК: правила здесь стоят ВЫШЕ blocklist drop'ов (threat/scanner/
        # custom/tor) — true whitelist semantics. Если mobile-RU CIDR попал
        # в один из blocklist'ов (например retail-pool в gov_networks), он
        # всё равно проходит через relaxed-проверки тут.
        #
        # ЛИМИТЫ:
        #   - ct=1000 (vs 400 default): покрывает CGNAT 100-200 юзеров.
        #   - newconn=2000/min burst 4000 (vs 500/min burst 1000): запас x4.
        #   - SYN/UDP rate-limit пропускаются (early accept).
        #
        # ATTACK PROTECTION остаётся:
        #   - реальный flood даже на mobile-RU поймается (>1000 conn = drop).
        #   - FIB anti-spoofing (если включён) отсеет spoofed mobile src.
        #
        # OBSERVABILITY: log prefix '[shield:mobile_ru_drop]' для overflow'ов
        # (когда mobile-RU IP превысил даже relaxed-лимит ct=1000). Aggregator
        # парсит → events.db с type='mobile_ru'.
        ip saddr @mobile_ru_whitelist_v4 tcp dport @protected_ports_tcp ct state new \\
            add @connlimit_v4 { ip saddr ct count over 1000 } \\
            log prefix "[shield:mobile_ru_drop] " level info flags ip options \\
            counter name mobile_ru_conn_flood_v4 drop
        ip saddr @mobile_ru_whitelist_v4 tcp dport @protected_ports_tcp ct state new \\
            add @newconn_rate_v4 { ip saddr limit rate over 2000/minute burst 4000 packets } \\
            jump newconn_overflow
        # Если mobile-RU IP прошёл relaxed-проверки — accept.
        # Это означает: blocklist drop'ы (threat/scanner/custom/tor) ниже
        # пропускаются для mobile-RU IP. Это корректное поведение для CGNAT —
        # 200 юзеров за одним IP не должны страдать из-за одного scanner'а среди них.
        ip saddr @mobile_ru_whitelist_v4 tcp dport @protected_ports_tcp ct state new \\
            counter name mobile_ru_passes_v4 accept

        # === v3.12.0: THREAT BLOCKLIST (Spamhaus DROP, FireHOL Level 1) ===
        # High-confidence криминальные сети. Идёт ПЕРВЫМ — самый дорогой
        # источник нежелательного трафика, отсекаем сразу.
        # Лог с rate-limit 1/sec для агрегатора и guard статистики.
        ip saddr @threat_blocklist_v4 limit rate 1/second \\
            log prefix "[shield:threat] " level info flags ip options \\
            counter name threat_drops_v4 drop
        ip saddr @threat_blocklist_v4 counter name threat_drops_v4 drop

        # === v3.12.0: CUSTOM BLOCKLIST (operator personal IPs) ===
        # Источник: /etc/shieldnode/lists/custom.txt (+ опциональные URL'ы).
        # Идёт после threat но до scanner — оператор может явно перехватить
        # любой IP даже если других списков его пока нет.
        ip saddr @custom_blocklist_v4 limit rate 1/second \\
            log prefix "[shield:custom] " level info flags ip options \\
            counter name custom_drops_v4 drop
        ip saddr @custom_blocklist_v4 counter name custom_drops_v4 drop

        # Pre-emptive drop известных сканеров (с counter v2.7).
        # Стоит ПЕРЕД rate-limit — экономит conntrack-слоты и CPU.
        # v2.9: log с rate-limit 1/sec на IP — для history БД (агрегатор парсит journald)
        ip saddr @scanner_blocklist_v4 limit rate 1/second \\
            log prefix "[shield:scanner] " level info flags ip options \\
            counter name scanner_drops_v4 drop
        ip saddr @scanner_blocklist_v4 counter name scanner_drops_v4 drop

        # === v3.11: Tor exit blocklist drop ===
        # Set заполняется только если оператор активировал BLOCK_TOR=1.
        # Иначе set пустой, эти 2 правила — no-op (overhead близок к нулю,
        # nft проверка пустого set'а — O(1)).
        # Лог с rate-limit 1/sec для guard CLI и aggregator статистики.
        ip saddr @tor_exit_blocklist_v4 limit rate 1/second \\
            log prefix "[shield:tor] " level info flags ip options \\
            counter name tor_drops_v4 drop
        ip saddr @tor_exit_blocklist_v4 counter name tor_drops_v4 drop

        # === v2.5: BAN-ONCE АРХИТЕКТУРА ===
        # Двухэтапная проверка перед баном — снижает ложные баны CGNAT/мобильных.
        #
        # Этап 0: Если IP в confirmed_attack — он уже подтверждённый атакующий, дропаем.
        # v2.9: log с rate-limit 1/sec на IP — для history БД
        ip saddr @confirmed_attack_v4 limit rate 1/second \\
            log prefix "[shield:ddos] " level info flags ip options \\
            counter name confirmed_drops_v4 drop
        ip saddr @confirmed_attack_v4 counter name confirmed_drops_v4 drop

        # === v3.5+v3.9: CONNECTION-FLOOD / SLOWLORIS ЗАЩИТА ===
        # Защищает от: тысяч одновременных TCP-соединений с одного IP,
        # медленного TLS handshake (slowloris), HTTP-flood через established TCP.
        # Применяется только к защищаемым TCP-портам (Xray/Reality/sing-box).
        # manual_whitelist уже пропущен выше.
        #
        # v3.9 CRITICAL FIX: правильный синтаксис per-source-IP.
        # Старый синтаксис "ct count over N" БЕЗ "ip saddr" в add-statement
        # был ГЛОБАЛЬНЫМ счётчиком conntrack. На VPN-нодах с >100 conntrack
        # это банило ВСЕХ клиентов. Правильный синтаксис (Red Hat docs +
        # nftables wiki Meters):
        #   add @set { ip saddr ct count over N }
        # Set ОБЯЗАТЕЛЬНО без timeout (иначе "Operation is not supported").
        # Conntrack timers сами cleanup элементы.
        #
        # v3.13.1: правила mobile_ru_whitelist перенесены ВЫШЕ blocklist drop'ов
        # (см. секцию 'MOBILE-RU AS WHITELIST' между TCP-flag-sanity и threat).
        # Здесь остаются только обычные conn-flood / newconn / SYN / UDP правила
        # которые применяются к НЕ-mobile трафику (mobile-RU уже accept выше).

        # === v3.5+v3.9+v3.10.2: CONNECTION-FLOOD / SLOWLORIS ЗАЩИТА ===
        # Защищает от: тысяч одновременных TCP-соединений с одного IP,
        # медленного TLS handshake (slowloris), HTTP-flood через established TCP.
        # Применяется только к защищаемым TCP-портам (Xray/Reality/sing-box).
        # manual_whitelist уже пропущен выше.
        #
        # v3.12.0 CGNAT FIX: лимит 150 → 400.
        # Анализ production traffic показал что российские мобильные операторы
        # (T2/Tele2 AS12958, AS15378, AS48190; МТС AS8359; МегаФон AS25513)
        # дают CGNAT-IP с 200-350 concurrent connections от одного IP к одному
        # dst-port. Лимит 150 банил легитимных мобильных юзеров.
        # 400 ловит slowloris (200-500 коннектов с одного IP), но не банит CGNAT.
        # Slowloris атаки которые держат 400+ коннектов всё равно дропаются.
        # v3.13.0: для mobile-RU AS используется relaxed-path выше; сюда попадает
        # только non-mobile трафик.
        tcp dport @protected_ports_tcp ct state new \\
            add @connlimit_v4 { ip saddr ct count over 400 } \\
            counter name conn_flood_v4 drop

        # === NEW CONNECTION RATE-LIMIT ===
        # v3.12.0 CGNAT FIX: 200/min → 500/min, burst 500 → 1000.
        # Один CGNAT IP с 50 юзерами легко даёт 200 new-conn/min при норме
        # (Telegram + браузер + Spotify + WhatsApp + бэкграунд = 4-5 conn/min/юзер).
        # 500/min даёт запас x2.5 для CGNAT, всё ещё ловит реальный HTTP-flood
        # (1000+ new-conn/min с одного IP).
        tcp dport @protected_ports_tcp ct state new \\
            add @newconn_rate_v4 { ip saddr limit rate over 500/minute burst 1000 packets } \\
            jump newconn_overflow

        # === TCP SYN rate-limit ===
        # v3.12.0: лимит остаётся 300/sec, CGNAT 50 юзеров обычно даёт 50-80 SYN/sec
        # реальная атака — 1000+ SYN/sec. 300 — хороший middle-ground.
        tcp dport @protected_ports_tcp ct state new \\
            add @syn_flood_v4 { ip saddr limit rate over 300/second burst 500 packets } \\
            jump syn_overflow

        # === UDP rate-limit ===
        # v3.12.0: 600/sec остаётся (UDP менее проблематичен с CGNAT)
        udp dport @protected_ports_udp \\
            add @udp_flood_v4 { ip saddr limit rate over 600/second burst 1000 packets } \\
            jump udp_overflow
    }

    # === v3.10.2: подцепочки overflow-обработки ===
    # Эти цепочки вызываются ИЗ prerouting через jump, ТОЛЬКО когда meter
    # уже обнаружил overflow (rate over limit). Решают: confirm-vs-suspect.
    # Не трогают meter-set'ы → не могут вызвать double-charge.
    chain newconn_overflow {
        # Уже под наблюдением → escalate в confirmed (бан 1ч)
        ip saddr @suspect_v4 add @confirmed_attack_v4 { ip saddr } counter name newconn_flood_v4 drop
        # Первое нарушение → suspect (наблюдение 30мин, без drop)
        add @suspect_v4 { ip saddr } counter name newconn_flood_v4
    }

    chain syn_overflow {
        ip saddr @suspect_v4 add @confirmed_attack_v4 { ip saddr } counter name syn_confirmed_v4 drop
        add @suspect_v4 { ip saddr }
    }

    chain udp_overflow {
        ip saddr @suspect_v4 add @confirmed_attack_v4 { ip saddr } counter name udp_confirmed_v4 drop
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

# v3.10.2 BUG-8 FIX: принудительная C-локаль — ru/uk/it/etc локали ломают
# парсинг "Status: active" (и могут сломать другие строки UFW в будущем).
export LANG=C LC_ALL=C

LOG_TAG="protected-ports"
FIREWALL_TYPE="$FIREWALL_TYPE"
# v3.10.2 BUG-7: SSH_PORTS — все sshd-listener порты (для multi-SSH setup'ов)
SSH_PORTS="$SSH_PORTS"

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
            # v3.10.2 BUG-8 FIX: LANG=C уже выставлен глобально, но дублируем
            # на случай если кто-то изменит export.
            ufw_out=$(LANG=C LC_ALL=C ufw status 2>/dev/null)
            # v3.10.2 BUG-1+3 FIX: regex принимает port-range (N:M) и multi-port (N,M).
            # Двоеточие → дефис (UFW: 4000:5000, nft: 4000-5000).
            tcp_list=$(echo "$ufw_out" | awk '
                $2 == "ALLOW" && $0 !~ /\(v6\)/ && $3 == "Anywhere" {
                    pp = $1
                    if (match(pp, /^[0-9]+(:[0-9]+)?(,[0-9]+(:[0-9]+)?)*(\/(tcp|udp))?$/)) {
                        n = split(pp, a, "/")
                        ports = a[1]
                        proto = (n > 1) ? a[2] : "any"
                        if (proto == "tcp" || proto == "any") {
                            m = split(ports, plist, ",")
                            for (i = 1; i <= m; i++) {
                                p = plist[i]
                                gsub(/:/, "-", p)
                                print p
                            }
                        }
                    }
                }
            ' | sort -u | tr '\n' ',' | sed 's/,$//')
            udp_list=$(echo "$ufw_out" | awk '
                $2 == "ALLOW" && $0 !~ /\(v6\)/ && $3 == "Anywhere" {
                    pp = $1
                    if (match(pp, /^[0-9]+(:[0-9]+)?(,[0-9]+(:[0-9]+)?)*(\/(tcp|udp))?$/)) {
                        n = split(pp, a, "/")
                        ports = a[1]
                        proto = (n > 1) ? a[2] : "any"
                        if (proto == "udp" || proto == "any") {
                            m = split(ports, plist, ",")
                            for (i = 1; i <= m; i++) {
                                p = plist[i]
                                gsub(/:/, "-", p)
                                print p
                            }
                        }
                    }
                }
            ' | sort -u | tr '\n' ',' | sed 's/,$//')
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

# v3.11.2 RETRY-ON-EMPTY: если ВСЕ результаты пустые — это либо real empty
# фаервол (rare), либо transient parse fail (common). Retry один раз через
# 0.3 сек чтобы дать UFW дописать atomic-rename и stabilize. Если retry
# тоже пустой — оставляем пусто и доверяем safety-guard.
if [ -z "$NEW_TCP" ] && [ -z "$NEW_UDP" ] && [ -z "$NEW_MGMT_V4" ]; then
    sleep 0.3
    FW_OUTPUT=$(detect_firewall_ports "$FIREWALL_TYPE")
    NEW_TCP=$(echo "$FW_OUTPUT" | sed -n '1p')
    NEW_UDP=$(echo "$FW_OUTPUT" | sed -n '2p')
    NEW_MGMT_V4=$(echo "$FW_OUTPUT" | sed -n '3p')
fi

# v3.10.2 BUG-7: исключаем все SSH-порты, не только первый.
exclude_port() {
    local list="$1" exclude="$2"
    echo ",$list," | sed "s/,$exclude,/,/g; s/^,//; s/,$//"
}
exclude_ports_list() {
    local list="$1" excludes="$2"
    local IFS=','
    for e in $excludes; do
        list=$(exclude_port "$list" "$e")
    done
    echo "$list"
}
NEW_TCP=$(exclude_ports_list "$NEW_TCP" "$SSH_PORTS")

# Текущее состояние nft set'ов
# v3.10.2: regex обновлён чтобы захватывать port-range (N-M) после auto-merge
CUR_TCP=$(nft list set inet ddos_protect protected_ports_tcp 2>/dev/null | \
    tr '\n' ' ' | grep -oE 'elements = \{[^}]*\}' | grep -oE '[0-9]+(-[0-9]+)?' | sort -u | tr '\n' ',' | sed 's/,$//')
CUR_UDP=$(nft list set inet ddos_protect protected_ports_udp 2>/dev/null | \
    tr '\n' ' ' | grep -oE 'elements = \{[^}]*\}' | grep -oE '[0-9]+(-[0-9]+)?' | sort -u | tr '\n' ',' | sed 's/,$//')
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
#
# v3.10.2 BUG-8 FIX: LANG=C для ufw status — иначе "Status: active" не находится
# в локализованных системах (ru_RU, uk_UA, etc.) → FIREWALL_ACTIVE=0 → safety
# guard никогда не срабатывает.
FIREWALL_ACTIVE=0
case "$FIREWALL_TYPE" in
    ufw)       LANG=C LC_ALL=C ufw status 2>/dev/null | grep -q "Status: active" && FIREWALL_ACTIVE=1 ;;
    firewalld) systemctl is-active --quiet firewalld 2>/dev/null && FIREWALL_ACTIVE=1 ;;
    iptables)  [ "$(iptables -L INPUT 2>/dev/null | wc -l)" -gt 2 ] && FIREWALL_ACTIVE=1 ;;
    nftables)  nft list ruleset 2>/dev/null | grep -q "table inet filter" && FIREWALL_ACTIVE=1 ;;
esac

# v3.10.2 BUG-2 FIX: добавлено CUR_UDP в проверку — иначе UDP-only setup'ы
# (Hysteria/TUIC/WireGuard без admin-IP whitelist) не защищались от transient
# wipe: при пустом NEW_* и непустом только CUR_UDP, safety-guard не срабатывал
# и UDP set обнулялся.
if [ "$FIREWALL_ACTIVE" = "1" ] && [ -z "$NEW_TCP" ] && [ -z "$NEW_UDP" ] && [ -z "$NEW_MGMT_V4" ]; then
    if [ -n "$CUR_TCP" ] || [ -n "$CUR_UDP" ] || [ -n "$CUR_MGMT_V4" ]; then
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

# v3.11.2 PER-SET PROTECTION: don't flush a set if NEW is empty but CUR was
# populated. This protects against transient parser fails that get past the
# global safety-guard (e.g. when UFW returns partial output and FIREWALL_ACTIVE
# detection ALSO returns 0 due to same transient).
#
# Логика: для каждого set'а отдельно решаем — flush+add или keep CUR.
#   NEW=empty, CUR=full   → SKIP (не трогаем set, оставляем CUR)
#   NEW=empty, CUR=empty  → flush (no-op, оба пустые)
#   NEW=full,  CUR=*      → flush + add (apply changes)
{
    if [ -n "$NEW_TCP" ] || [ -z "$CUR_TCP" ]; then
        echo "flush set inet ddos_protect protected_ports_tcp"
        if [ -n "$NEW_TCP" ]; then
            echo "add element inet ddos_protect protected_ports_tcp { $(echo "$NEW_TCP" | sed 's/,/, /g') }"
        fi
    fi
    if [ -n "$NEW_UDP" ] || [ -z "$CUR_UDP" ]; then
        echo "flush set inet ddos_protect protected_ports_udp"
        if [ -n "$NEW_UDP" ]; then
            echo "add element inet ddos_protect protected_ports_udp { $(echo "$NEW_UDP" | sed 's/,/, /g') }"
        fi
    fi
    # v2.2: синхронизируем management whitelist (только IPv4, v3.6)
    if [ -n "$NEW_MGMT_V4" ] || [ -z "$CUR_MGMT_V4" ]; then
        echo "flush set inet ddos_protect manual_whitelist_v4"
        if [ -n "$NEW_MGMT_V4" ]; then
            echo "add element inet ddos_protect manual_whitelist_v4 { $(echo "$NEW_MGMT_V4" | sed 's/,/, /g') }"
        fi
    fi
} > "$TMP"

# v3.11.2: если TMP пустой (всё защищено per-set guard'ом) — ничего не делаем
if [ ! -s "$TMP" ]; then
    logger -t "$LOG_TAG" "SKIP: per-set protection — все NEW пустые, CUR имеют данные"
    exit 0
fi

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
# ШАГ 6: BLOCKLIST UPDATER (universal, v3.12.0)
# ==============================================================================

print_header "ШАГ 6: BLOCKLIST UPDATER"

# v3.12.0: единый универсальный updater для всех blocklist'ов:
#   scanner — Shodan/Censys/government scanners (sources в DEFAULT_REMOTE_BLOCKLISTS)
#   threat  — Spamhaus DROP + FireHOL Level 1 (high-confidence атакующие)
#   tor     — официальный Tor exit list (если BLOCK_TOR=1)
#   custom  — operator personal /etc/shieldnode/lists/custom.txt
#
# Каждый name → один nft set:
#   scanner → scanner_blocklist_v4
#   threat  → threat_blocklist_v4
#   tor     → tor_exit_blocklist_v4   (legacy compat name)
#   custom  → custom_blocklist_v4
#
# Источники для каждого set'а — union: file-based (./lists/*.txt) +
# URL-based (REMOTE_BLOCKLISTS). Минимум: либо файл, либо URL'ы; если ничего —
# set остаётся пустым, drop-rule no-op.
#
# Конфиг /etc/shieldnode/shieldnode.conf опционален. Если есть — переопределяет
# DEFAULT_LOCAL_BLOCKLISTS, DEFAULT_REMOTE_BLOCKLISTS, *_UPDATE_INTERVAL,
# MIN_ENTRIES_*, FAIL_THRESHOLD.

# 1) Дефолты в /usr/local/sbin/shieldnode-defaults.sh — отдельный файл, чтобы
#    updater и установщик использовали один источник истины.
cat > "$SHIELD_DEFAULTS_FILE" <<DEFAULTS_EOF
#!/bin/bash
# shieldnode v3.13.1 — дефолты blocklists (генерится установщиком)
# НЕ редактировать руками — будет перезаписан при следующей установке/обновлении.
# Для переопределения — создай /etc/shieldnode/shieldnode.conf.

DEFAULT_LOCAL_BLOCKLISTS=(
$(for entry in "${DEFAULT_LOCAL_BLOCKLISTS[@]}"; do printf "    %q\n" "$entry"; done)
)

DEFAULT_REMOTE_BLOCKLISTS=(
$(for entry in "${DEFAULT_REMOTE_BLOCKLISTS[@]}"; do printf "    %q\n" "$entry"; done)
)

DEFAULT_SCANNER_UPDATE_INTERVAL="$DEFAULT_SCANNER_UPDATE_INTERVAL"
DEFAULT_THREAT_UPDATE_INTERVAL="$DEFAULT_THREAT_UPDATE_INTERVAL"
DEFAULT_TOR_UPDATE_INTERVAL="$DEFAULT_TOR_UPDATE_INTERVAL"
DEFAULT_CUSTOM_UPDATE_INTERVAL="$DEFAULT_CUSTOM_UPDATE_INTERVAL"
DEFAULT_MOBILE_RU_UPDATE_INTERVAL="$DEFAULT_MOBILE_RU_UPDATE_INTERVAL"

DEFAULT_MIN_ENTRIES_SCANNER=$DEFAULT_MIN_ENTRIES_SCANNER
DEFAULT_MIN_ENTRIES_THREAT=$DEFAULT_MIN_ENTRIES_THREAT
DEFAULT_MIN_ENTRIES_TOR=$DEFAULT_MIN_ENTRIES_TOR
DEFAULT_MIN_ENTRIES_CUSTOM=$DEFAULT_MIN_ENTRIES_CUSTOM
DEFAULT_MIN_ENTRIES_MOBILE_RU=$DEFAULT_MIN_ENTRIES_MOBILE_RU

DEFAULT_FAIL_THRESHOLD=$DEFAULT_FAIL_THRESHOLD

# v3.13.0: список AS для mobile-RU whitelist
DEFAULT_MOBILE_RU_AS_LIST=(
$(for asn in "${DEFAULT_MOBILE_RU_AS_LIST[@]}"; do printf "    %s\n" "$asn"; done)
)
DEFAULTS_EOF
chmod 0644 "$SHIELD_DEFAULTS_FILE"
print_ok "Defaults: $SHIELD_DEFAULTS_FILE"

# 2) Универсальный updater
cat > "$SHIELD_UPDATER_SCRIPT" <<'UPDATER_EOF'
#!/bin/bash
# shieldnode v3.12.0 — универсальный blocklist updater.
# Usage: shieldnode-update-blocklist.sh <scanner|threat|tor|custom>

set -o pipefail
export LANG=C LC_ALL=C

NAME="${1:-}"
case "$NAME" in
    scanner|threat|tor|custom) ;;
    mobile_ru)
        # v3.13.0: mobile_ru использует отдельный updater (MaxMind CSV).
        exec /usr/local/sbin/shieldnode-update-mobile-ru.sh "$@"
        ;;
    *) echo "Usage: $0 <scanner|threat|tor|custom|mobile_ru>" >&2; exit 1 ;;
esac

LOG_TAG="shieldnode-update-$NAME"
STATE_DIR="/var/lib/shieldnode"
mkdir -p "$STATE_DIR"
FAIL_COUNTER="$STATE_DIR/${NAME}_fail_count"

# nft set name (legacy compat для tor → tor_exit_blocklist_v4)
case "$NAME" in
    scanner) NFT_SET="scanner_blocklist_v4" ;;
    threat)  NFT_SET="threat_blocklist_v4"  ;;
    tor)     NFT_SET="tor_exit_blocklist_v4" ;;
    custom)  NFT_SET="custom_blocklist_v4"  ;;
esac

# Загружаем дефолты + опциональный override
# shellcheck source=/dev/null
. /usr/local/sbin/shieldnode-defaults.sh
if [ -f /etc/shieldnode/shieldnode.conf ]; then
    # shellcheck source=/dev/null
    . /etc/shieldnode/shieldnode.conf
fi

# Резолвим финальные значения: оператор может задать LOCAL_BLOCKLISTS /
# REMOTE_BLOCKLISTS; иначе берём DEFAULT_*.
[ "${#LOCAL_BLOCKLISTS[@]}"  -gt 0 ] || LOCAL_BLOCKLISTS=("${DEFAULT_LOCAL_BLOCKLISTS[@]}")
[ "${#REMOTE_BLOCKLISTS[@]}" -gt 0 ] || REMOTE_BLOCKLISTS=("${DEFAULT_REMOTE_BLOCKLISTS[@]}")

# Извлекаем для нашего NAME
LOCAL_PATHS=""
for entry in "${LOCAL_BLOCKLISTS[@]}"; do
    case "$entry" in
        "$NAME="*) LOCAL_PATHS="${entry#$NAME=}" ;;
    esac
done
REMOTE_URLS=""
for entry in "${REMOTE_BLOCKLISTS[@]}"; do
    case "$entry" in
        "$NAME="*) REMOTE_URLS="${entry#$NAME=}" ;;
    esac
done

# MIN_ENTRIES + FAIL_THRESHOLD: per-name override → DEFAULT_*
case "$NAME" in
    scanner) MIN_ENTRIES="${MIN_ENTRIES_SCANNER:-$DEFAULT_MIN_ENTRIES_SCANNER}" ;;
    threat)  MIN_ENTRIES="${MIN_ENTRIES_THREAT:-$DEFAULT_MIN_ENTRIES_THREAT}"   ;;
    tor)     MIN_ENTRIES="${MIN_ENTRIES_TOR:-$DEFAULT_MIN_ENTRIES_TOR}"         ;;
    custom)  MIN_ENTRIES="${MIN_ENTRIES_CUSTOM:-$DEFAULT_MIN_ENTRIES_CUSTOM}"   ;;
esac
FAIL_THRESHOLD_VAL="${FAIL_THRESHOLD:-$DEFAULT_FAIL_THRESHOLD}"

# Если nft-таблицы нет — выходим (скрипт может запуститься до первой установки)
if ! nft list table inet ddos_protect >/dev/null 2>&1; then
    logger -t "$LOG_TAG" "table inet ddos_protect не существует — пропускаю"
    exit 0
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

REMOTE_DOWNLOADED=0
REMOTE_TRIED=0

# 1) Скачиваем все URL'ы (через запятую в REMOTE_URLS)
if [ -n "$REMOTE_URLS" ]; then
    IFS=',' read -ra URL_ARR <<< "$REMOTE_URLS"
    for url in "${URL_ARR[@]}"; do
        url="${url## }"; url="${url%% }"   # trim spaces
        [ -z "$url" ] && continue
        REMOTE_TRIED=$((REMOTE_TRIED + 1))
        # JSON-формат (MISP/CIRCL) — отдельная обработка через jq
        if echo "$url" | grep -qE '\.json($|\?)' && command -v jq >/dev/null 2>&1; then
            if curl -fsSL --max-time 30 --retry 2 "$url" -o "$TMP/dl-$REMOTE_TRIED.json" 2>/dev/null; then
                jq -r '..|strings? | select(test("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+(/[0-9]+)?$"))' \
                    "$TMP/dl-$REMOTE_TRIED.json" 2>/dev/null >> "$TMP/all.raw" && \
                    REMOTE_DOWNLOADED=$((REMOTE_DOWNLOADED + 1))
            else
                logger -t "$LOG_TAG" "WARN: не смог скачать (json) $url"
            fi
        else
            if curl -fsSL --max-time 30 --retry 2 "$url" -o "$TMP/dl-$REMOTE_TRIED.raw" 2>/dev/null; then
                cat "$TMP/dl-$REMOTE_TRIED.raw" >> "$TMP/all.raw"
                REMOTE_DOWNLOADED=$((REMOTE_DOWNLOADED + 1))
            else
                logger -t "$LOG_TAG" "WARN: не смог скачать $url"
            fi
        fi
    done
fi

# 2) Читаем локальные .txt (через запятую в LOCAL_PATHS — обычно один путь)
LOCAL_FOUND=0
if [ -n "$LOCAL_PATHS" ]; then
    IFS=',' read -ra PATH_ARR <<< "$LOCAL_PATHS"
    for p in "${PATH_ARR[@]}"; do
        p="${p## }"; p="${p%% }"
        [ -z "$p" ] && continue
        if [ -r "$p" ]; then
            cat "$p" >> "$TMP/all.raw"
            LOCAL_FOUND=$((LOCAL_FOUND + 1))
        fi
    done
fi

# 3) Если нет ничего — fail handling
if [ "$REMOTE_TRIED" -gt 0 ] && [ "$REMOTE_DOWNLOADED" -eq 0 ] && [ "$LOCAL_FOUND" -eq 0 ]; then
    # Все URL'ы failed AND нет локальных → инкрементируем fail counter
    CURRENT=$(cat "$FAIL_COUNTER" 2>/dev/null || echo 0)
    CURRENT="${CURRENT:-0}"
    CURRENT=$((CURRENT + 1))
    echo "$CURRENT" > "$FAIL_COUNTER"
    logger -t "$LOG_TAG" "ERROR: все URL'ы недоступны и нет local files (fail #$CURRENT/$FAIL_THRESHOLD_VAL)"
    if [ "$CURRENT" -ge "$FAIL_THRESHOLD_VAL" ]; then
        # 3+ подряд провалов → flush set'а (stale data protection)
        nft flush set inet ddos_protect "$NFT_SET" 2>/dev/null && \
            logger -t "$LOG_TAG" "flushed $NFT_SET после $CURRENT подряд провалов"
    fi
    exit 1
fi

# 4) Если ничего не скачано и нет local → set остаётся как есть (no-op)
if [ ! -s "$TMP/all.raw" ]; then
    logger -t "$LOG_TAG" "пустой результат, нет источников — пропускаю"
    exit 0
fi

# 5) Парсинг + sanity. Поддерживаем форматы:
#    - plain IP:           8.8.8.8
#    - CIDR:               1.2.3.0/24
#    - Spamhaus:           "1.2.3.0/24 ; SBL12345"
#    - FireHOL:            "# comment\n1.2.3.0/24"
#    - inline комментарий: "8.8.8.8 # google"
#
# Sanity (тот же что в v3.11.x scanner-update):
#    - prefix < 8 → отсев (слишком широко)
#    - bogons: 0/8, 10/8, 127/8, 169.254/16, 172.16-31/12, 192.168/16
#    - multicast/reserved: 224-255/8
grep -oE '^[[:space:]]*[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]+)?' "$TMP/all.raw" | \
    awk '{ sub(/^[[:space:]]+/, ""); print }' | \
    awk -F'[./]' '
    {
        prefix = (NF >= 5) ? $5 : 32
        if (prefix < 8 || prefix > 32) next
        o1 = $1 + 0
        if (o1 == 0)   next
        if (o1 == 10)  next
        if (o1 == 127) next
        if (o1 >= 224) next
        if (o1 == 169 && $2 + 0 == 254) next
        if (o1 == 172) {
            o2 = $2 + 0
            if (o2 >= 16 && o2 <= 31) next
        }
        if (o1 == 192 && $2 + 0 == 168) next
        print $0
    }' | sort -u > "$TMP/parsed.list"

V4_COUNT=$(wc -l < "$TMP/parsed.list")
V4_COUNT="${V4_COUNT:-0}"

# 6) Min check (для custom MIN_ENTRIES может быть 0 — допускается пустой)
if [ "$V4_COUNT" -lt "$MIN_ENTRIES" ]; then
    logger -t "$LOG_TAG" "ERROR: только $V4_COUNT IPv4 подсетей (ожидали >=$MIN_ENTRIES) — не применяю"
    # Инкрементируем fail counter
    CURRENT=$(cat "$FAIL_COUNTER" 2>/dev/null || echo 0)
    CURRENT="${CURRENT:-0}"
    CURRENT=$((CURRENT + 1))
    echo "$CURRENT" > "$FAIL_COUNTER"
    if [ "$CURRENT" -ge "$FAIL_THRESHOLD_VAL" ]; then
        nft flush set inet ddos_protect "$NFT_SET" 2>/dev/null && \
            logger -t "$LOG_TAG" "flushed $NFT_SET после $CURRENT провалов min-check"
    fi
    exit 1
fi

# 7) Атомарный flush + add (одна nft транзакция)
{
    echo "flush set inet ddos_protect $NFT_SET"
    if [ -s "$TMP/parsed.list" ]; then
        # Группами по 1000 элементов (производительнее чем по одному)
        awk -v setname="$NFT_SET" '
            NR % 1000 == 1 { if (NR > 1) print "}"; printf "add element inet ddos_protect %s { ", setname }
            { printf "%s%s", (NR % 1000 == 1 ? "" : ", "), $0 }
            END { print " }" }' "$TMP/parsed.list"
    fi
} > "$TMP/nft-batch"

if nft -f "$TMP/nft-batch" 2>"$TMP/nft.err"; then
    # Reset fail counter on success
    echo 0 > "$FAIL_COUNTER"
    logger -t "$LOG_TAG" "Updated $NFT_SET: $V4_COUNT IPv4 подсетей (remote=$REMOTE_DOWNLOADED/$REMOTE_TRIED, local=$LOCAL_FOUND)"
    exit 0
else
    logger -t "$LOG_TAG" "ERROR: nft -f failed: $(cat "$TMP/nft.err")"
    CURRENT=$(cat "$FAIL_COUNTER" 2>/dev/null || echo 0)
    CURRENT="${CURRENT:-0}"
    echo $((CURRENT + 1)) > "$FAIL_COUNTER"
    exit 1
fi
UPDATER_EOF
chmod 0755 "$SHIELD_UPDATER_SCRIPT"
print_ok "Updater: $SHIELD_UPDATER_SCRIPT"

# 2.5) v3.13.0: dedicated mobile-RU updater (использует MaxMind GeoLite2-ASN-CSV)
SHIELD_MOBILE_RU_UPDATER="/usr/local/sbin/shieldnode-update-mobile-ru.sh"
cat > "$SHIELD_MOBILE_RU_UPDATER" <<'MOBILE_RU_UPDATER_EOF'
#!/bin/bash
# shieldnode v3.13.1 — mobile-RU AS whitelist updater.
# Скачивает MaxMind GeoLite2-ASN-CSV, фильтрует по списку AS,
# заполняет nft set mobile_ru_whitelist_v4.
#
# Требует MAXMIND_LICENSE_KEY в /etc/shieldnode/shieldnode.conf или env.
# Без key — выходит с WARN, set остаётся пустым (поведение v3.12.0).

set -o pipefail
export LANG=C LC_ALL=C

LOG_TAG="shieldnode-update-mobile_ru"
STATE_DIR="/var/lib/shieldnode"
mkdir -p "$STATE_DIR"
FAIL_COUNTER="$STATE_DIR/mobile_ru_fail_count"
NFT_SET="mobile_ru_whitelist_v4"

# Загружаем дефолты + опциональный override
# shellcheck source=/dev/null
. /usr/local/sbin/shieldnode-defaults.sh
if [ -f /etc/shieldnode/shieldnode.conf ]; then
    # shellcheck source=/dev/null
    . /etc/shieldnode/shieldnode.conf
fi

# AS-список: из конфига MOBILE_RU_AS_LIST или DEFAULT_MOBILE_RU_AS_LIST
[ "${#MOBILE_RU_AS_LIST[@]}" -gt 0 ] || MOBILE_RU_AS_LIST=("${DEFAULT_MOBILE_RU_AS_LIST[@]}")

MIN_ENTRIES="${MIN_ENTRIES_MOBILE_RU:-$DEFAULT_MIN_ENTRIES_MOBILE_RU}"
FAIL_THRESHOLD_VAL="${FAIL_THRESHOLD:-$DEFAULT_FAIL_THRESHOLD}"
ENABLED="${ENABLE_RU_MOBILE_WHITELIST:-1}"

# Если фича выключена в конфиге — flush и exit
if [ "$ENABLED" != "1" ]; then
    nft flush set inet ddos_protect "$NFT_SET" 2>/dev/null
    logger -t "$LOG_TAG" "ENABLE_RU_MOBILE_WHITELIST=$ENABLED, set очищен"
    exit 0
fi

# Если license key нет — graceful WARN
if [ -z "$MAXMIND_LICENSE_KEY" ]; then
    logger -t "$LOG_TAG" "MAXMIND_LICENSE_KEY не задан, set остаётся пустым (поведение v3.12.0). Получи бесплатный ключ на https://www.maxmind.com/en/geolite2/signup и добавь в /etc/shieldnode/shieldnode.conf"
    exit 0
fi

# Если nft-таблицы нет — выходим
if ! nft list table inet ddos_protect >/dev/null 2>&1; then
    logger -t "$LOG_TAG" "table inet ddos_protect не существует — пропускаю"
    exit 0
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# 1) Скачиваем GeoLite2-ASN-CSV.zip (v3.13.0: ~5 MB архив)
URL="https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN-CSV&license_key=${MAXMIND_LICENSE_KEY}&suffix=zip"
if ! curl -fsSL --max-time 60 --retry 2 "$URL" -o "$TMP/asn.zip" 2>"$TMP/curl.err"; then
    logger -t "$LOG_TAG" "ERROR: не смог скачать MaxMind ($(cat "$TMP/curl.err"))"
    CURRENT=$(cat "$FAIL_COUNTER" 2>/dev/null || echo 0)
    CURRENT="${CURRENT:-0}"
    echo $((CURRENT + 1)) > "$FAIL_COUNTER"
    exit 1
fi

# 2) Извлекаем CSV (внутри архива GeoLite2-ASN-Blocks-IPv4.csv)
if ! command -v unzip >/dev/null 2>&1; then
    logger -t "$LOG_TAG" "ERROR: unzip не установлен (apt install unzip)"
    exit 1
fi

if ! unzip -j -o -q "$TMP/asn.zip" "*/GeoLite2-ASN-Blocks-IPv4.csv" -d "$TMP/" 2>/dev/null; then
    logger -t "$LOG_TAG" "ERROR: не смог распаковать MaxMind ZIP (формат изменился?)"
    exit 1
fi

CSV="$TMP/GeoLite2-ASN-Blocks-IPv4.csv"
if [ ! -s "$CSV" ]; then
    logger -t "$LOG_TAG" "ERROR: CSV пустой или не найден после unzip"
    exit 1
fi

# 3) Парсим CSV. Формат: network,autonomous_system_number,autonomous_system_organization
# Пример: 1.0.0.0/24,13335,"CLOUDFLARENET"
# Берём только наши AS, выводим CIDR.
AS_FILTER=$(IFS='|'; echo "${MOBILE_RU_AS_LIST[*]}")
awk -F, -v asns="$AS_FILTER" '
BEGIN {
    n = split(asns, arr, "|")
    for (i = 1; i <= n; i++) want[arr[i]] = 1
}
NR == 1 { next }   # skip header
{
    # CSV формат: "1.2.3.0/24",12345,"OrgName"
    cidr = $1
    asn = $2
    gsub(/"/, "", cidr)
    gsub(/"/, "", asn)
    if (asn in want) print cidr
}' "$CSV" > "$TMP/mobile_ru.list"

# Sanity-фильтр (тот же что в обычном updater'е): отсеиваем bogons и слишком широкие.
awk -F'[./]' '
{
    prefix = (NF >= 5) ? $5 : 32
    if (prefix < 8 || prefix > 32) next
    o1 = $1 + 0
    if (o1 == 0)   next
    if (o1 == 10)  next
    if (o1 == 127) next
    if (o1 >= 224) next
    if (o1 == 169 && $2 + 0 == 254) next
    if (o1 == 172) {
        o2 = $2 + 0
        if (o2 >= 16 && o2 <= 31) next
    }
    if (o1 == 192 && $2 + 0 == 168) next
    print $0
}' "$TMP/mobile_ru.list" | sort -u > "$TMP/mobile_ru.parsed"

V4_COUNT=$(wc -l < "$TMP/mobile_ru.parsed")
V4_COUNT="${V4_COUNT:-0}"

if [ "$V4_COUNT" -lt "$MIN_ENTRIES" ]; then
    logger -t "$LOG_TAG" "ERROR: только $V4_COUNT CIDR'ов (ожидали >=$MIN_ENTRIES) — не применяю. Возможно AS-список пустой или MaxMind вернул мало данных."
    CURRENT=$(cat "$FAIL_COUNTER" 2>/dev/null || echo 0)
    CURRENT="${CURRENT:-0}"
    echo $((CURRENT + 1)) > "$FAIL_COUNTER"
    if [ "$CURRENT" -ge "$FAIL_THRESHOLD_VAL" ]; then
        nft flush set inet ddos_protect "$NFT_SET" 2>/dev/null && \
            logger -t "$LOG_TAG" "flushed $NFT_SET после $CURRENT провалов"
    fi
    exit 1
fi

# 4) Атомарный flush + add
{
    echo "flush set inet ddos_protect $NFT_SET"
    if [ -s "$TMP/mobile_ru.parsed" ]; then
        awk -v setname="$NFT_SET" '
            NR % 1000 == 1 { if (NR > 1) print "}"; printf "add element inet ddos_protect %s { ", setname }
            { printf "%s%s", (NR % 1000 == 1 ? "" : ", "), $0 }
            END { print " }" }' "$TMP/mobile_ru.parsed"
    fi
} > "$TMP/nft-batch"

if nft -f "$TMP/nft-batch" 2>"$TMP/nft.err"; then
    echo 0 > "$FAIL_COUNTER"
    logger -t "$LOG_TAG" "Updated $NFT_SET: $V4_COUNT CIDR'ов из ${#MOBILE_RU_AS_LIST[@]} AS"

    # 5) Observability: проверяем overlap с scanner_blocklist (informational only)
    SCANNER_OVERLAP=0
    if SCANNER_DUMP=$(nft list set inet ddos_protect scanner_blocklist_v4 2>/dev/null); then
        # Извлекаем CIDR'ы из scanner_blocklist
        echo "$SCANNER_DUMP" | tr '\n' ' ' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?' | sort -u > "$TMP/scanner.cidrs"
        # Сравниваем (наивная string-проверка, не subnet-overlap, но даёт сигнал)
        SCANNER_OVERLAP=$(comm -12 "$TMP/mobile_ru.parsed" "$TMP/scanner.cidrs" | wc -l)
        SCANNER_OVERLAP="${SCANNER_OVERLAP:-0}"
        if [ "$SCANNER_OVERLAP" -gt 0 ]; then
            logger -t "$LOG_TAG" "INFO: overlap mobile-RU ↔ scanner_blocklist: $SCANNER_OVERLAP CIDR'ов. Whitelist выигрывает (правило стоит раньше в prerouting)."
        fi
    fi
    exit 0
else
    logger -t "$LOG_TAG" "ERROR: nft -f failed: $(cat "$TMP/nft.err")"
    CURRENT=$(cat "$FAIL_COUNTER" 2>/dev/null || echo 0)
    CURRENT="${CURRENT:-0}"
    echo $((CURRENT + 1)) > "$FAIL_COUNTER"
    exit 1
fi
MOBILE_RU_UPDATER_EOF
chmod 0755 "$SHIELD_MOBILE_RU_UPDATER"
print_ok "Mobile-RU updater: $SHIELD_MOBILE_RU_UPDATER"

# 3) Templated systemd unit (обслуживает все 4 blocklist'а)
cat > /etc/systemd/system/shieldnode-update@.service <<EOF
[Unit]
Description=Update shieldnode %i blocklist
After=network-online.target shieldnode-nftables.service
Wants=network-online.target
Requires=shieldnode-nftables.service

[Service]
Type=oneshot
ExecStart=$SHIELD_UPDATER_SCRIPT %i
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=$SHIELD_STATE_DIR
EOF

# 4) Per-list timers (с разными интервалами из defaults/config)
make_timer() {
    local n="$1" interval="$2"
    cat > "/etc/systemd/system/shieldnode-update@${n}.timer" <<EOF
[Unit]
Description=Update $n blocklist (every $interval)
Requires=shieldnode-update@${n}.service

[Timer]
OnBootSec=1min
OnUnitActiveSec=$interval
RandomizedDelaySec=10min
Persistent=true

[Install]
WantedBy=timers.target
EOF
}
make_timer scanner   "$DEFAULT_SCANNER_UPDATE_INTERVAL"
make_timer threat    "$DEFAULT_THREAT_UPDATE_INTERVAL"
make_timer tor       "$DEFAULT_TOR_UPDATE_INTERVAL"
make_timer custom    "$DEFAULT_CUSTOM_UPDATE_INTERVAL"
make_timer mobile_ru "$DEFAULT_MOBILE_RU_UPDATE_INTERVAL"

# 5) inotify path-watcher для custom (мгновенно реагирует на изменение файла)
cat > /etc/systemd/system/shieldnode-update@custom.path <<EOF
[Unit]
Description=Watch custom blocklist file

[Path]
PathChanged=$SHIELD_LISTS_DIR/custom.txt
PathExists=$SHIELD_LISTS_DIR/custom.txt
Unit=shieldnode-update@custom.service

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

# 6) Подготовка lists/ (pipe-mode скачивает с github, git-mode копирует ./lists/)
mkdir -p "$SHIELD_LISTS_DIR"
chmod 0755 "$SHIELD_LISTS_DIR"

prepare_seed_list() {
    local name="$1" target="$SHIELD_LISTS_DIR/${1}.txt"
    # Если уже есть (от прошлой установки) — оставляем как есть
    if [ -s "$target" ]; then
        return 0
    fi
    if [ "$SHIELD_PIPE_MODE" = "1" ]; then
        # Pipe-mode: качаем дефолтный seed с github
        if curl -fsSL --max-time 15 "$SHIELD_REPO_URL/lists/${name}.txt" -o "$target.tmp" 2>/dev/null; then
            mv "$target.tmp" "$target"
            return 0
        fi
        rm -f "$target.tmp"
    elif [ -n "$SHIELD_SCRIPT_DIR" ] && [ -f "$SHIELD_SCRIPT_DIR/lists/${name}.txt" ]; then
        cp "$SHIELD_SCRIPT_DIR/lists/${name}.txt" "$target"
        return 0
    fi
    # Fallback: пустой файл с заголовком
    cat > "$target" <<HDR_EOF
# shieldnode $name blocklist (one IP or CIDR per line, # = comment)
# Auto-merged with URL sources при наличии конфига.
HDR_EOF
}
for n in scanner threat tor custom; do
    prepare_seed_list "$n"
done

# Опциональный shieldnode.conf — если оператор положил рядом со скриптом, копируем
if [ -n "$SHIELD_SCRIPT_DIR" ] && [ -f "$SHIELD_SCRIPT_DIR/shieldnode.conf" ] && [ ! -f "$SHIELD_CONF_FILE" ]; then
    cp "$SHIELD_SCRIPT_DIR/shieldnode.conf" "$SHIELD_CONF_FILE"
    chmod 0644 "$SHIELD_CONF_FILE"
    print_ok "Config: $SHIELD_CONF_FILE (из git-clone)"
fi

print_ok "Lists: $SHIELD_LISTS_DIR/{scanner,threat,tor,custom}.txt"

# 7) Включаем и запускаем blocklists. Tor — только если BLOCK_TOR=1.
# v3.13.0: mobile_ru — только если ENABLE_RU_MOBILE_WHITELIST=1 (по умолчанию ON,
# но без MAXMIND_LICENSE_KEY первый запуск запишет WARN и оставит set пустым).
ENABLED_LISTS=(scanner threat custom)
if [ "$BLOCK_TOR" = "1" ]; then
    ENABLED_LISTS+=(tor)
    mkdir -p /etc/shieldnode
    touch /etc/shieldnode/block_tor
fi
if [ "${ENABLE_RU_MOBILE_WHITELIST:-1}" = "1" ]; then
    ENABLED_LISTS+=(mobile_ru)
fi

declare -A LIST_SIZES
for n in "${ENABLED_LISTS[@]}"; do
    systemctl enable "shieldnode-update@${n}.timer" >/dev/null 2>&1
    # Первый запуск (blocking) для немедленного заполнения set'а
    print_status "Загружаю $n blocklist..."
    if systemctl start "shieldnode-update@${n}.service" 2>/dev/null; then
        sleep 1
        SET_NAME=$(case "$n" in
            scanner)   echo "scanner_blocklist_v4" ;;
            threat)    echo "threat_blocklist_v4"  ;;
            tor)       echo "tor_exit_blocklist_v4" ;;
            custom)    echo "custom_blocklist_v4"  ;;
            mobile_ru) echo "mobile_ru_whitelist_v4" ;;
        esac)
        SIZE=$(nft list set inet ddos_protect "$SET_NAME" 2>/dev/null | tr '\n' ' ' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?' | wc -l)
        SIZE="${SIZE:-0}"
        LIST_SIZES[$n]="$SIZE"
    else
        LIST_SIZES[$n]=0
    fi
    systemctl start "shieldnode-update@${n}.timer" >/dev/null 2>&1
done

# Path-watcher для custom (всегда активен независимо от BLOCK_TOR)
systemctl enable --now shieldnode-update@custom.path >/dev/null 2>&1

print_ok "Blocklists активны: $(
    for n in "${ENABLED_LISTS[@]}"; do
        printf "%s=%s " "$n" "${LIST_SIZES[$n]:-0}"
    done
)"


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
    # v3.11.1: устойчивая проверка через cscli_collection_installed (BUG-CSCLI-FMT)
    if cscli_collection_installed "$col"; then
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
# v3.11.1: устойчивая проверка через cscli_collection_installed (BUG-CSCLI-FMT)
if cscli_collection_installed "crowdsecurity/iptables"; then
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
    # v3.10.3 BUG-12 FIX: убран `0,` префикс из sed — теперь патчатся ВСЕ
    # вхождения. Дефолтный profiles.yaml содержит 3 профиля (captcha,
    # default_ip_remediation, default_range_remediation), все с
    # `duration: 4h`. Старая версия (v1.1-1.3) ставила 24h во все три, но
    # downgrade патчил только первый (Ip-scope). Range-scope оставался 24h
    # → юзер за CGNAT сидел в бане 24h вместо 4h.
    if grep -qE "^[[:space:]]*duration:[[:space:]]*24h[[:space:]]*$" "$PROFILES_FILE"; then
        sed -i 's/^\([[:space:]]*\)duration:[[:space:]]*24h[[:space:]]*$/\1duration: 4h/' "$PROFILES_FILE"
        print_ok "Ban duration: 24h → 4h во всех профилях (v3.10.3 BUG-12)"
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

ACQUIS_DIR="/etc/crowdsec/acquis.d"
mkdir -p "$ACQUIS_DIR"

# Удаляем UFW acquisition если он был создан старой версией скрипта
OLD_UFW_ACQUIS="$ACQUIS_DIR/ufw.yaml"
if [ -f "$OLD_UFW_ACQUIS" ]; then
    if grep -q "vpn-node-ddos-protect" "$OLD_UFW_ACQUIS" 2>/dev/null; then
        rm -f "$OLD_UFW_ACQUIS"
        print_ok "Удалён UFW acquisition (v1.4: source для ложных банов)"
    fi
fi

# v3.10.4 BUG-14 + BUG-18 FIX: явно убеждаемся что SSHD acquisition есть.
# Wizard может НЕ создать acquisition если /var/log/auth.log отсутствует
# (Minimal Ubuntu 24.04, cloud images). Без acquisition коллекция sshd
# работает в холостую — никаких decisions не создаётся.
#
# Стратегия:
#   1. Проверяем существующие acquis-источники для SSH (file или journalctl)
#   2. Если нет ничего — создаём journalctl-based acquis для sshd.service
#   3. Если есть file-based для /var/log/auth.log — НЕ дублируем (BUG-18:
#      double-counting в leaky bucket → ssh-bf срабатывает на 2-3 попытках
#      вместо 5)
SSH_ACQUIS_FOUND=0
SSH_FILE_ACQUIS=0
SSH_JOURNALD_ACQUIS=0

# Сканируем acquis.yaml + acquis.d/*.yaml на SSH-источники
for acquis_file in /etc/crowdsec/acquis.yaml "$ACQUIS_DIR"/*.yaml; do
    [ -f "$acquis_file" ] || continue
    # File-based для auth.log
    if grep -qE "^\s*-\s+/var/log/auth\.log" "$acquis_file" 2>/dev/null; then
        SSH_FILE_ACQUIS=1
        SSH_ACQUIS_FOUND=1
    fi
    # Journalctl-based для sshd.service
    if grep -qE "_SYSTEMD_UNIT=sshd\.service" "$acquis_file" 2>/dev/null; then
        SSH_JOURNALD_ACQUIS=1
        SSH_ACQUIS_FOUND=1
    fi
done

if [ "$SSH_ACQUIS_FOUND" = "0" ] && cscli_collection_installed "crowdsecurity/sshd"; then
    # Нет SSH acquisition, но коллекция установлена — создаём journalctl
    print_status "SSH acquisition отсутствует — создаю journalctl-based (BUG-14)"
    cat > "$ACQUIS_DIR/sshd.yaml" <<'SSHD_ACQUIS_EOF'
# v3.10.4: SSH acquisition через journalctl (BUG-14 fix).
# Универсально работает на всех Ubuntu/Debian, не зависит от наличия
# /var/log/auth.log (на Minimal Ubuntu файла нет).
source: journalctl
journalctl_filter:
  - "_SYSTEMD_UNIT=sshd.service"
labels:
  type: syslog
SSHD_ACQUIS_EOF
    chmod 644 "$ACQUIS_DIR/sshd.yaml"
    systemctl reload crowdsec >/dev/null 2>&1 || systemctl restart crowdsec >/dev/null 2>&1
    print_ok "Создан /etc/crowdsec/acquis.d/sshd.yaml (journalctl)"
elif [ "$SSH_FILE_ACQUIS" = "1" ] && [ "$SSH_JOURNALD_ACQUIS" = "1" ]; then
    # BUG-18: двойной acquisition — auth.log + journalctl. Это double-counts
    # каждое событие. Удаляем дублирующийся journalctl-acquis если он наш.
    if [ -f "$ACQUIS_DIR/sshd.yaml" ] && grep -q "v3.10.4" "$ACQUIS_DIR/sshd.yaml"; then
        rm -f "$ACQUIS_DIR/sshd.yaml"
        systemctl reload crowdsec >/dev/null 2>&1
        print_ok "Удалён дубль journalctl SSH acquisition (BUG-18: file-based уже работает)"
    else
        print_warn "Двойной SSH acquisition (file + journald). leaky bucket будет срабатывать в 2× быстрее."
        print_info "Проверь /etc/crowdsec/acquis.yaml и acquis.d/*.yaml — оставь один источник."
    fi
elif [ "$SSH_FILE_ACQUIS" = "1" ]; then
    print_ok "SSH acquisition: file:/var/log/auth.log"
elif [ "$SSH_JOURNALD_ACQUIS" = "1" ]; then
    print_ok "SSH acquisition: journalctl (sshd.service)"
fi

# Проверим что SSH-коллекция установлена (BUG-CSCLI-FMT fix)
if cscli_collection_installed "crowdsecurity/sshd"; then
    print_ok "SSH parsing активен (через crowdsecurity/sshd)"
else
    print_warn "crowdsecurity/sshd не установлен — SSH-логи не парсятся"
fi

# v3.10.4 BUG-15 FIX: проверяем что CAPI registration реально прошла.
# На машинах за corporate proxy/firewall apt postinst может silently fail.
# Без CAPI нет community blocklist — теряется самая ценная фича.
print_status "Проверяю CAPI registration (BUG-15)..."
if cscli capi status >/dev/null 2>&1; then
    print_ok "CAPI: registered + работает"
else
    print_warn "CAPI status не OK — пытаюсь зарегистрироваться..."
    # Удаляем существующие credentials если они невалидные
    if cscli capi register >/dev/null 2>&1; then
        systemctl restart crowdsec >/dev/null 2>&1
        sleep 3
        if cscli capi status >/dev/null 2>&1; then
            print_ok "CAPI зарегистрирован успешно"
        else
            print_warn "CAPI всё ещё не работает — проверь сеть"
            print_info "Без CAPI не будет community blocklist (главная фича CrowdSec)"
            print_info "Проверь: curl -v https://api.crowdsec.net"
            print_info "За proxy/NAT? См. docs.crowdsec.net про HTTP_PROXY"
        fi
    else
        print_warn "cscli capi register failed"
    fi
fi

# v3.10.4 BUG-17 FIX: postoverflow whitelist для mgmt IPs.
# `cscli decisions add --type whitelist` не предотвращает scenario trigger
# (alerts всё равно идут в CAPI как сигналы атаки → ухудшение нашего
# community contribution score). Postoverflow whitelist — правильный способ
# глушить scenarios на доверенных IP до того как они попадут в alert.
if [ -n "$MGMT_IPV4" ]; then
    POSTOVERFLOW_WL="/etc/crowdsec/postoverflows/s01-whitelist/shieldnode-mgmt.yaml"
    mkdir -p "$(dirname "$POSTOVERFLOW_WL")"

    # Формируем YAML-список IP
    # Save and restore IFS (we're at top level, can't use `local`)
    OLD_IFS="$IFS"

    # Split MGMT_IPV4 into pure IPs vs CIDRs (different YAML fields per CrowdSec spec)
    TMP_IPS=""
    TMP_CIDRS=""
    IFS=','
    for entry in $MGMT_IPV4; do
        entry=$(echo "$entry" | tr -d ' ')
        [ -z "$entry" ] && continue
        case "$entry" in
            */32)
                # /32 — pure IP, strip /32
                TMP_IPS="$TMP_IPS ${entry%/32}"
                ;;
            */*)
                # CIDR (e.g. 192.168.1.0/24)
                TMP_CIDRS="$TMP_CIDRS $entry"
                ;;
            *)
                # No mask = single IP
                TMP_IPS="$TMP_IPS $entry"
                ;;
        esac
    done
    IFS="$OLD_IFS"

    {
        echo "# v3.10.4 BUG-17: postoverflow whitelist для mgmt IPs."
        echo "# Срабатывает ПОСЛЕ scenario trigger но ДО alert/decision —"
        echo "# scenario не оставляет следов на наших IP."
        echo "name: shieldnode/mgmt-whitelist"
        echo "description: \"Whitelist mgmt IPs from UFW (auto-generated)\""
        echo "whitelist:"
        echo "  reason: \"shieldnode mgmt IP\""
        if [ -n "$TMP_IPS" ]; then
            echo "  ip:"
            for ip in $TMP_IPS; do
                echo "    - \"$ip\""
            done
        fi
        if [ -n "$TMP_CIDRS" ]; then
            echo "  cidr:"
            for cidr in $TMP_CIDRS; do
                echo "    - \"$cidr\""
            done
        fi
    } > "$POSTOVERFLOW_WL"
    chmod 644 "$POSTOVERFLOW_WL"
    systemctl reload crowdsec >/dev/null 2>&1 || systemctl restart crowdsec >/dev/null 2>&1
    print_ok "Postoverflow whitelist mgmt IPs (BUG-17)"
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

# ============================================================================
# v3.10.3 BUG-9 + BUG-10 FIX: правим bouncer config
# ============================================================================
# BUG-9: bouncer по дефолту: ipv4.priority=-10, hook=input. Это срабатывает
# ПОСЛЕ нашей цепочки prerouting (priority -100). Banned-IP проходит наши
# rate-limits и попадает в suspect_v4 ДО того как bouncer его дропнет.
# Эмпирически проверено: 30 fast pings → 19 hits на newconn_overflow.
# FIX: ставим bouncer на hook prerouting с priority -200 (раньше нашего -100).
# Banned-IP дропнется до того как наша логика его увидит.
#
# BUG-10: ipv6.enabled=true по дефолту. На IPv6-disabled нодах bouncer пишет
# в лог 8640 ошибок/сутки. FIX: если в системе IPv6 отключён — disable в
# bouncer config.
BOUNCER_CFG="/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml"
if [ -f "$BOUNCER_CFG" ]; then
    BOUNCER_CHANGED=0

    # Backup before patching
    if [ ! -f "$BACKUP_DIR/crowdsec-firewall-bouncer.yaml.before" ]; then
        cp -a "$BOUNCER_CFG" "$BACKUP_DIR/crowdsec-firewall-bouncer.yaml.before"
    fi

    # BUG-9: ipv4 priority -10 → -200, hook input → prerouting
    if grep -qE '^\s*priority:\s*-10\s*$' "$BOUNCER_CFG"; then
        # Меняем оба priority (ipv4 + ipv6 секции, обе по дефолту -10)
        sed -i 's/^\([[:space:]]*\)priority:[[:space:]]*-10[[:space:]]*$/\1priority: -200/g' "$BOUNCER_CFG"
        BOUNCER_CHANGED=1
        print_ok "Bouncer priority: -10 → -200 (BUG-9: раньше нашего prerouting)"
    fi

    # nftables_hooks меняем с [input, forward] на [prerouting]
    if grep -qE '^[[:space:]]*-\s+input\s*$' "$BOUNCER_CFG" && \
       grep -qE '^[[:space:]]*-\s+forward\s*$' "$BOUNCER_CFG"; then
        # Заменяем блок nftables_hooks: [input, forward] → [prerouting]
        # (используем awk для надёжной обработки YAML-блока)
        awk '
        BEGIN { in_hooks = 0 }
        /^nftables_hooks:/ { in_hooks = 1; print; print "  - prerouting"; next }
        in_hooks && /^[[:space:]]*-/ { next }   # пропускаем старые элементы списка
        in_hooks && !/^[[:space:]]*-/ { in_hooks = 0 }
        { print }
        ' "$BOUNCER_CFG" > "$BOUNCER_CFG.new" && mv "$BOUNCER_CFG.new" "$BOUNCER_CFG"
        BOUNCER_CHANGED=1
        print_ok "Bouncer hooks: input,forward → prerouting (BUG-9)"
    fi

    # BUG-10: disable IPv6 если в sysctl отключён
    if [ "$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null)" = "1" ]; then
        # В bouncer.yaml ipv6.enabled может быть в двух местах: ipv6: enabled: true (под nftables)
        # и disable_ipv6: false (top-level). Меняем оба.
        if grep -qE '^\s*disable_ipv6:\s*false' "$BOUNCER_CFG"; then
            sed -i 's/^\([[:space:]]*\)disable_ipv6:[[:space:]]*false[[:space:]]*$/\1disable_ipv6: true/' "$BOUNCER_CFG"
            BOUNCER_CHANGED=1
        fi
        # Под секцией ipv6: меняем enabled: true → false
        # Используем awk чтобы найти блок ipv6: и поменять enabled внутри
        awk '
        BEGIN { in_ipv6_block = 0 }
        /^[[:space:]]*ipv6:/ { in_ipv6_block = 1; print; next }
        in_ipv6_block && /^[a-zA-Z]/ { in_ipv6_block = 0 }
        in_ipv6_block && /^[[:space:]]*enabled:[[:space:]]*true/ {
            sub(/enabled:[[:space:]]*true/, "enabled: false"); print; next
        }
        { print }
        ' "$BOUNCER_CFG" > "$BOUNCER_CFG.new" && mv "$BOUNCER_CFG.new" "$BOUNCER_CFG"
        print_ok "Bouncer IPv6 отключён (BUG-10: в системе IPv6 disabled)"
        BOUNCER_CHANGED=1
    fi

    if [ "$BOUNCER_CHANGED" = "1" ]; then
        # Удаляем существующие cs-bouncer таблицы — они с правилами на старом hook
        nft delete table ip crowdsec 2>/dev/null || true
        nft delete table ip6 crowdsec6 2>/dev/null || true
    fi
fi

systemctl enable --now crowdsec >/dev/null 2>&1 || true
systemctl restart crowdsec-firewall-bouncer >/dev/null 2>&1 || \
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

# ============================================================================
# v3.10.3 BUG-11 SECURITY FIX: добавляем mgmt IPs в CrowdSec whitelist
# ============================================================================
# Без этого: если админ ошибётся 5 раз с SSH-паролем (или CrowdSec обновит
# scenarios с более чувствительным sshd-bf), его IP попадёт в ban → bouncer
# дропнет его на новом priority -200 (после BUG-9 fix) → админ заблокирован.
# Наш `manual_whitelist_v4` set здесь не помогает — bouncer работает в
# отдельной таблице.
if [ -n "$MGMT_IPV4" ]; then
    print_status "Добавляю mgmt IPs в CrowdSec whitelist (BUG-11 SECURITY)..."
    IFS=',' read -ra MGMT_LIST <<< "$MGMT_IPV4"
    for mgmt_ip in "${MGMT_LIST[@]}"; do
        # Очищаем от пробелов
        mgmt_ip=$(echo "$mgmt_ip" | tr -d ' ')
        [ -z "$mgmt_ip" ] && continue
        # cscli decisions add создаёт whitelist на 100 лет (3650 дней)
        if cscli decisions add --ip "$mgmt_ip" --type whitelist --duration 87600h \
            --reason "shieldnode mgmt IP whitelist" >/dev/null 2>&1; then
            print_ok "Mgmt whitelist: $mgmt_ip"
        else
            # Возможно уже в whitelist — это OK
            print_info "Mgmt whitelist (возможно уже есть): $mgmt_ip"
        fi
    done
fi

# ============================================================================
# v3.10.3 BUG-13 FIX: hub update + upgrade
# ============================================================================
# Без этого: сценарии устаревают, новые sshd-bf варианты не подхватываются.
# CrowdSec >= 1.7.2 имеет встроенный systemd timer (hubupdate.timer), на
# старых версиях нужен cron.
print_status "Обновляю CrowdSec hub (BUG-13)..."
if cscli hub update >/dev/null 2>&1; then
    if cscli hub upgrade >/dev/null 2>&1; then
        print_ok "Hub: коллекции/сценарии обновлены"
    fi
fi

# Проверяем CrowdSec версию для cron-fallback
CS_VER=$(cscli version 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1 | tr -d v)
if [ -n "$CS_VER" ]; then
    # dpkg --compare-versions работает с числами
    if dpkg --compare-versions "$CS_VER" lt "1.7.2" 2>/dev/null; then
        # Старая версия — добавляем cron для hub upgrade
        if [ ! -f /etc/cron.daily/cscli-hub-upgrade ]; then
            cat > /etc/cron.daily/cscli-hub-upgrade <<'CRON_EOF'
#!/bin/sh
# v3.10.3 BUG-13: ежедневный hub upgrade для CrowdSec < 1.7.2
# В 1.7.2+ есть встроенный systemd timer hubupdate.timer
cscli hub update >/dev/null 2>&1 && cscli hub upgrade >/dev/null 2>&1 || true
CRON_EOF
            chmod +x /etc/cron.daily/cscli-hub-upgrade
            print_ok "Cron daily hub-upgrade добавлен (CrowdSec $CS_VER < 1.7.2)"
        fi
    else
        # Новая версия — встроенный timer
        if systemctl list-unit-files | grep -q "crowdsec-hubupdate.timer"; then
            systemctl enable --now crowdsec-hubupdate.timer >/dev/null 2>&1 || true
            print_info "CrowdSec $CS_VER >= 1.7.2 — встроенный hub-upgrade timer"
        fi
    fi
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
-- v3.10.2: WAL mode позволяет concurrent reads (guard) + write (aggregator)
-- без блокировок. synchronous=NORMAL — приемлемый trade-off (риск потерять
-- последний commit при power-loss, но не corrupt'ить БД).
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;

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

-- v3.12.0: ASN/owner кэш для guard CLI top-attackers column
-- TTL 7 дней (cached_at + 604800 < now → re-fetch from ipinfo.io/<IP>)
CREATE TABLE IF NOT EXISTS asn_cache (
    ip         TEXT PRIMARY KEY,
    asn        TEXT,
    owner      TEXT,
    country    TEXT,
    cached_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_asn_cache_cached_at ON asn_cache(cached_at);
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

# Парсим сообщения [shield:scanner], [shield:ddos], [shield:tor] (v3.11),
# [shield:threat] и [shield:custom] (v3.12.0), [shield:mobile_ru_drop] (v3.13.1)
# Формат kernel-лога: "[shield:scanner] IN=eth0 SRC=85.142.100.2 DST=... PROTO=TCP DPT=8443 ..."
declare -A scanner_ips ddos_ips tor_ips threat_ips custom_ips mobile_ru_ips
# v3.5: для events.log — собираем порт назначения и тип flood'а
declare -A ddos_ports ddos_proto

# v3.10.2 PERF FIX: заменили per-line `echo $line | grep | head | cut` на
# single-pass awk. Бенчмарк на 10k log-lines: 94 сек → 0.026 сек (3700×).
# Под штормом 100k events/min теперь обрабатывается за <1 сек.
while IFS='|' read -r kind ip port proto; do
    case "$kind" in
        scanner)
            [ -n "$ip" ] && scanner_ips[$ip]=$((${scanner_ips[$ip]:-0} + 1))
            ;;
        ddos)
            if [ -n "$ip" ]; then
                ddos_ips[$ip]=$((${ddos_ips[$ip]:-0} + 1))
                [ -n "$port" ]  && ddos_ports[$ip]="$port"
                [ -n "$proto" ] && ddos_proto[$ip]="$proto"
            fi
            ;;
        tor)
            [ -n "$ip" ] && tor_ips[$ip]=$((${tor_ips[$ip]:-0} + 1))
            ;;
        threat)
            [ -n "$ip" ] && threat_ips[$ip]=$((${threat_ips[$ip]:-0} + 1))
            ;;
        custom)
            [ -n "$ip" ] && custom_ips[$ip]=$((${custom_ips[$ip]:-0} + 1))
            ;;
        mobile_ru)
            [ -n "$ip" ] && mobile_ru_ips[$ip]=$((${mobile_ru_ips[$ip]:-0} + 1))
            ;;
    esac
done < <(awk '
    /\[shield:scanner\]/ {
        if (match($0, /SRC=[^ ]+/)) {
            ip = substr($0, RSTART+4, RLENGTH-4)
            if (ip != "") print "scanner|" ip "||"
        }
    }
    /\[shield:ddos\]/ {
        ip=""; port=""; proto=""
        if (match($0, /SRC=[^ ]+/))    ip    = substr($0, RSTART+4, RLENGTH-4)
        if (match($0, /DPT=[0-9]+/))   port  = substr($0, RSTART+4, RLENGTH-4)
        if (match($0, /PROTO=[A-Z]+/)) proto = substr($0, RSTART+6, RLENGTH-6)
        if (ip != "") print "ddos|" ip "|" port "|" proto
    }
    /\[shield:tor\]/ {
        if (match($0, /SRC=[^ ]+/)) {
            ip = substr($0, RSTART+4, RLENGTH-4)
            if (ip != "") print "tor|" ip "||"
        }
    }
    /\[shield:threat\]/ {
        if (match($0, /SRC=[^ ]+/)) {
            ip = substr($0, RSTART+4, RLENGTH-4)
            if (ip != "") print "threat|" ip "||"
        }
    }
    /\[shield:custom\]/ {
        if (match($0, /SRC=[^ ]+/)) {
            ip = substr($0, RSTART+4, RLENGTH-4)
            if (ip != "") print "custom|" ip "||"
        }
    }
    /\[shield:mobile_ru_drop\]/ {
        if (match($0, /SRC=[^ ]+/)) {
            ip = substr($0, RSTART+4, RLENGTH-4)
            if (ip != "") print "mobile_ru|" ip "||"
        }
    }
' "$TMP")

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
    # v3.11: Tor exit drops
    for ip in "${!tor_ips[@]}"; do
        cnt=${tor_ips[$ip]}
        echo "[$TS] TOR EXIT BLOCK ip=$ip hits=$cnt"
    done
    # v3.12.0: threat + custom blocklists
    for ip in "${!threat_ips[@]}"; do
        cnt=${threat_ips[$ip]}
        echo "[$TS] THREAT BLOCK ip=$ip hits=$cnt"
    done
    for ip in "${!custom_ips[@]}"; do
        cnt=${custom_ips[$ip]}
        echo "[$TS] CUSTOM BLOCK ip=$ip hits=$cnt"
    done
    # v3.13.1: mobile-RU drops (превысили даже relaxed-лимит ct=1000)
    for ip in "${!mobile_ru_ips[@]}"; do
        cnt=${mobile_ru_ips[$ip]}
        echo "[$TS] MOBILE_RU OVERFLOW ip=$ip hits=$cnt (CGNAT exceeded ct=1000)"
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
    # v3.11: Tor exits
    for ip in "${!tor_ips[@]}"; do
        cnt=${tor_ips[$ip]}
        echo "INSERT INTO events(type, ip, first_seen, last_seen, count) VALUES('tor', '$ip', $NOW, $NOW, $cnt) ON CONFLICT(type, ip) DO UPDATE SET last_seen=$NOW, count=count+$cnt;"
    done
    # v3.12.0: threat + custom blocklists
    for ip in "${!threat_ips[@]}"; do
        cnt=${threat_ips[$ip]}
        echo "INSERT INTO events(type, ip, first_seen, last_seen, count) VALUES('threat', '$ip', $NOW, $NOW, $cnt) ON CONFLICT(type, ip) DO UPDATE SET last_seen=$NOW, count=count+$cnt;"
    done
    for ip in "${!custom_ips[@]}"; do
        cnt=${custom_ips[$ip]}
        echo "INSERT INTO events(type, ip, first_seen, last_seen, count) VALUES('custom', '$ip', $NOW, $NOW, $cnt) ON CONFLICT(type, ip) DO UPDATE SET last_seen=$NOW, count=count+$cnt;"
    done
    # v3.13.1: mobile-RU overflow events
    for ip in "${!mobile_ru_ips[@]}"; do
        cnt=${mobile_ru_ips[$ip]}
        echo "INSERT INTO events(type, ip, first_seen, last_seen, count) VALUES('mobile_ru', '$ip', $NOW, $NOW, $cnt) ON CONFLICT(type, ip) DO UPDATE SET last_seen=$NOW, count=count+$cnt;"
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
TOTAL_TOR=${#tor_ips[@]}
TOTAL_THREAT=${#threat_ips[@]}
TOTAL_CUSTOM=${#custom_ips[@]}
TOTAL_MOBILE_RU=${#mobile_ru_ips[@]}
if [ $TOTAL_SCANNERS -gt 0 ] || [ $TOTAL_DDOS -gt 0 ] || [ $TOTAL_TOR -gt 0 ] || [ $TOTAL_THREAT -gt 0 ] || [ $TOTAL_CUSTOM -gt 0 ] || [ $TOTAL_MOBILE_RU -gt 0 ]; then
    logger -t "$LOG_TAG" "Processed: scanners=$TOTAL_SCANNERS, ddos=$TOTAL_DDOS, tor=$TOTAL_TOR, threat=$TOTAL_THREAT, custom=$TOTAL_CUSTOM, mobile_ru=$TOTAL_MOBILE_RU unique IPs"
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

    LAST_UPDATE=$(systemctl show shieldnode-update@scanner.service \
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
    read TOR_PKTS_V4 TOR_BYTES_V4 <<< "$(read_counter tor_drops_v4)"     # v3.11
    # v3.12.0: threat + custom counters
    read THREAT_PKTS_V4 THREAT_BYTES_V4 <<< "$(read_counter threat_drops_v4)"
    read CUSTOM_PKTS_V4 CUSTOM_BYTES_V4 <<< "$(read_counter custom_drops_v4)"
    # v3.5: HTTP/conn-flood counters
    read CONN_FLOOD_PKTS_V4 CONN_FLOOD_BYTES_V4 <<< "$(read_counter conn_flood_v4)"
    read NEWCONN_FLOOD_PKTS_V4 NEWCONN_FLOOD_BYTES_V4 <<< "$(read_counter newconn_flood_v4)"
    read TCP_INVALID_PKTS TCP_INVALID_BYTES <<< "$(read_counter tcp_invalid)"

    # v3.11: размер tor blocklist set'а
    TOR_SET_SIZE=$(nft list set inet ddos_protect tor_exit_blocklist_v4 2>/dev/null | \
        tr '\n' ' ' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | wc -l)
    TOR_SET_SIZE="${TOR_SET_SIZE:-0}"

    # v3.12.0: размеры threat + custom blocklist set'ов
    THREAT_SET_SIZE=$(nft list set inet ddos_protect threat_blocklist_v4 2>/dev/null | \
        tr '\n' ' ' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?' | wc -l)
    THREAT_SET_SIZE="${THREAT_SET_SIZE:-0}"
    CUSTOM_SET_SIZE=$(nft list set inet ddos_protect custom_blocklist_v4 2>/dev/null | \
        tr '\n' ' ' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?' | wc -l)
    CUSTOM_SET_SIZE="${CUSTOM_SET_SIZE:-0}"

    # v3.13.0: размер mobile-RU whitelist + counters
    MOBILE_RU_SET_SIZE=$(nft list set inet ddos_protect mobile_ru_whitelist_v4 2>/dev/null | \
        tr '\n' ' ' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?' | wc -l)
    MOBILE_RU_SET_SIZE="${MOBILE_RU_SET_SIZE:-0}"
    read MOBILE_RU_PASS_PKTS MOBILE_RU_PASS_BYTES <<< "$(read_counter mobile_ru_passes_v4)"
    read MOBILE_RU_CONN_PKTS MOBILE_RU_CONN_BYTES <<< "$(read_counter mobile_ru_conn_flood_v4)"

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

# v3.12.0: ASN/owner lookup для top attackers через ipinfo.io.
# Кэш в events.db (asn_cache table), TTL 7 дней.
# При no-internet или rate-limit возвращает "?" — guard продолжает работать.
asn_ttl=604800   # 7 дней

asn_cache_get() {
    # echoes "asn|owner|country" if cached and fresh; empty otherwise
    local ip="$1" db="/var/lib/shieldnode/events.db"
    [ -r "$db" ] || return 1
    command -v sqlite3 >/dev/null 2>&1 || return 1
    local now; now=$(date +%s)
    sqlite3 "$db" "SELECT asn || '|' || COALESCE(owner,'') || '|' || COALESCE(country,'') FROM asn_cache WHERE ip = '$ip' AND cached_at + $asn_ttl > $now LIMIT 1" 2>/dev/null
}

asn_cache_put() {
    local ip="$1" asn="$2" owner="$3" country="$4" db="/var/lib/shieldnode/events.db"
    [ -w "$db" ] || return 1
    command -v sqlite3 >/dev/null 2>&1 || return 1
    local now; now=$(date +%s)
    # SQL-escape одинарных кавычек
    local esc_asn esc_owner esc_country
    esc_asn=$(echo "$asn"     | sed "s/'/''/g")
    esc_owner=$(echo "$owner" | sed "s/'/''/g")
    esc_country=$(echo "$country" | sed "s/'/''/g")
    sqlite3 "$db" "INSERT INTO asn_cache(ip, asn, owner, country, cached_at) VALUES('$ip','$esc_asn','$esc_owner','$esc_country',$now) ON CONFLICT(ip) DO UPDATE SET asn='$esc_asn', owner='$esc_owner', country='$esc_country', cached_at=$now" 2>/dev/null
}

asn_lookup_remote() {
    # Запрашиваем ipinfo.io/<IP> (JSON, 1 запрос даёт всё). Таймаут 2 сек.
    # Free tier: 50k req/month — c кэшем 7d вполне хватает.
    # Возвращает "asn|owner|country" или пустую строку.
    local ip="$1"
    local resp
    resp=$(curl -fsSL --max-time 2 "https://ipinfo.io/${ip}" 2>/dev/null) || return 1
    [ -z "$resp" ] && return 1
    # Парсим без jq (минимизация зависимостей):
    #   "org": "AS12958 T2 Mobile LLC"
    #   "country": "RU"
    local org country asn owner
    org=$(echo "$resp"     | grep -oE '"org"[[:space:]]*:[[:space:]]*"[^"]*"' | sed -E 's/.*"([^"]*)"$/\1/')
    country=$(echo "$resp" | grep -oE '"country"[[:space:]]*:[[:space:]]*"[^"]*"' | sed -E 's/.*"([^"]*)"$/\1/')
    if [ -n "$org" ]; then
        asn=$(echo "$org"   | awk '{print $1}')
        owner=$(echo "$org" | cut -d' ' -f2-)
    fi
    echo "${asn:-?}|${owner:-?}|${country:-?}"
}

# Lookup IP → "owner (country)" string (для отображения).
# Использует кэш + если miss/expired → один запрос к ipinfo.io.
asn_owner_string() {
    local ip="$1"
    local cached; cached=$(asn_cache_get "$ip")
    if [ -n "$cached" ]; then
        local owner country
        IFS='|' read -r _asn owner country <<< "$cached"
        if [ -n "$owner" ] && [ "$owner" != "?" ]; then
            echo "${owner} (${country})"
        else
            echo "?"
        fi
        return 0
    fi
    # Cache miss
    local fresh; fresh=$(asn_lookup_remote "$ip" 2>/dev/null)
    if [ -n "$fresh" ]; then
        local asn owner country
        IFS='|' read -r asn owner country <<< "$fresh"
        asn_cache_put "$ip" "$asn" "$owner" "$country"
        if [ -n "$owner" ] && [ "$owner" != "?" ]; then
            echo "${owner} (${country})"
        else
            echo "?"
        fi
        return 0
    fi
    echo "?"
}

# Top-N attackers из events.db за последние 24 часа.
# Печатает строки "ip<TAB>hits" (наибольшие сверху).
top_attackers_24h() {
    local n="${1:-20}" db="/var/lib/shieldnode/events.db"
    [ -r "$db" ] || return 1
    command -v sqlite3 >/dev/null 2>&1 || return 1
    local since=$(( $(date +%s) - 86400 ))
    sqlite3 -separator $'\t' "$db" \
        "SELECT ip, SUM(count) as hits FROM events WHERE last_seen >= $since GROUP BY ip ORDER BY hits DESC LIMIT $n" 2>/dev/null
}

# === ВЫВОД ===
draw_snapshot() {
    local now=$(date '+%Y-%m-%d %H:%M:%S')
    local ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    local hn=$(hostname -s 2>/dev/null)
    local uptime_str
    uptime_str=$(uptime -p 2>/dev/null | sed 's/^up //')

    # ===== HEADER (v3.12.0) =====
    echo ""
    echo -e "${C}══════════════════════════════════════════════════════════════════${N}"
    printf  "  ${B}shieldnode v3.13.1${N}   %s   ${DIM}up %s${N}\n" "$hn ($ip)" "${uptime_str:-?}"
    echo -e "${C}══════════════════════════════════════════════════════════════════${N}"
    echo ""

    # ===== ACTIVE THREATS (right now) =====
    local active_color="${G}"
    [ "$((CS_BANS + CONFIRMED_COUNT))" -gt 0 ] && active_color="${R}"
    echo -e "  ${B}Active threats (right now)${N}"
    printf  "  ├─ ${active_color}confirmed attack${N}    %s IP banned 15min\n"          "$(human_num "$CONFIRMED_COUNT")"
    printf  "  ├─ ${active_color}suspect (watched)${N}   %s IP under 30min observation\n" "$(human_num "$SUSPECT_COUNT")"
    printf  "  ├─ ${active_color}crowdsec bans${N}       %s IPs\n"                       "$(human_num "$CS_BANS")"
    local bl_summary="scanner=$(human_num "$BL_V4")"
    [ "$THREAT_SET_SIZE" -gt 0 ] && bl_summary+=", threat=$(human_num "$THREAT_SET_SIZE")"
    [ "$TOR_SET_SIZE"    -gt 0 ] && bl_summary+=", tor=$(human_num "$TOR_SET_SIZE")"
    [ "$CUSTOM_SET_SIZE" -gt 0 ] && bl_summary+=", custom=$(human_num "$CUSTOM_SET_SIZE")"
    printf  "  ├─ ${DIM}blocklists${N}          %s\n" "$bl_summary"
    # v3.13.0: mobile-RU whitelist line (только если активен и не пустой)
    if [ "$MOBILE_RU_SET_SIZE" -gt 0 ]; then
        printf  "  └─ ${G}mobile-RU whitelist${N} %s CIDRs ${DIM}(relaxed: ct=1000, newconn=2000/min, %s passes)${N}\n" \
            "$(human_num "$MOBILE_RU_SET_SIZE")" "$(human_num "$MOBILE_RU_PASS_PKTS")"
    else
        printf  "  └─ ${DIM}mobile-RU whitelist${N} ${DIM}disabled or empty (set MAXMIND_LICENSE_KEY in shieldnode.conf to enable)${N}\n"
    fi
    echo ""

    # ===== SERVICES (compact one-line) =====
    local svc_line=""
    svc_line+=$(svc_dot "$CS_ACTIVE" "crowdsec")"  "
    svc_line+=$(svc_dot "$BOUNCER_ACTIVE" "bouncer")"  "
    svc_line+=$(svc_dot "$PORTS_PATH_ACTIVE" "ports")
    echo -e "  ${B}Services${N}    $svc_line"
    echo ""

    # ===== PROTECTED PORTS =====
    echo -e "  ${B}Protected${N}"
    printf  "  ├─ ${DIM}TCP:${N}  ${C}%s${N}\n" "$PROTECTED_TCP_LIST"
    printf  "  └─ ${DIM}UDP:${N}  ${C}%s${N}\n" "$PROTECTED_UDP_LIST"
    echo ""

    # ===== TOP ATTACKERS (v3.12.0, last 24h, with ASN/owner) =====
    local top_lines
    top_lines=$(top_attackers_24h 5)
    if [ -n "$top_lines" ]; then
        echo -e "  ${B}Top attackers${N} ${DIM}(last 24h)${N}"
        local fmtd=""
        local lcount=0
        while IFS=$'\t' read -r ip hits; do
            [ -z "$ip" ] && continue
            lcount=$((lcount+1))
            local owner; owner=$(asn_owner_string "$ip")
            local prefix="├─"
            fmtd+=$(printf "  %s ${R}%-15s${N} ${DIM}%5s hits${N}   %s\n" "$prefix" "$ip" "$(human_num "$hits")" "$owner")
            fmtd+=$'\n'
        done <<< "$top_lines"
        # Меняем последний ├─ на └─
        if [ -n "$fmtd" ]; then
            fmtd=$(echo -e "$fmtd" | sed -E '$ s/├─/└─/' )
            echo -e "$fmtd"
        fi
        echo ""
    fi

    # ===== TODAY (drops / bytes) =====
    local total_pkts=$((SCANNER_PKTS_V4 + TOR_PKTS_V4 + THREAT_PKTS_V4 + CUSTOM_PKTS_V4 + CONFIRMED_PKTS_V4 + SYN_CONF_PKTS_V4 + UDP_CONF_PKTS_V4 + CONN_FLOOD_PKTS_V4 + NEWCONN_FLOOD_PKTS_V4 + TCP_INVALID_PKTS))
    local total_bytes=$((SCANNER_BYTES_V4 + TOR_BYTES_V4 + THREAT_BYTES_V4 + CUSTOM_BYTES_V4 + CONFIRMED_BYTES_V4 + SYN_CONF_BYTES_V4 + UDP_CONF_BYTES_V4 + CONN_FLOOD_BYTES_V4 + NEWCONN_FLOOD_BYTES_V4 + TCP_INVALID_BYTES))

    echo -e "  ${B}Drops since reboot${N} ${DIM}($NFT_SINCE)${N}"
    printf  "  ├─ ${DIM}scanner${N}             %12s pkts  ${DIM}/${N} %s\n" "$(human_num "$SCANNER_PKTS_V4")" "$(human_bytes "$SCANNER_BYTES_V4")"
    if [ "$THREAT_SET_SIZE" -gt 0 ] || [ "$THREAT_PKTS_V4" -gt 0 ]; then
        printf  "  ├─ ${DIM}threat${N}              %12s pkts  ${DIM}/${N} %s\n" "$(human_num "$THREAT_PKTS_V4")" "$(human_bytes "$THREAT_BYTES_V4")"
    fi
    if [ "$CUSTOM_SET_SIZE" -gt 0 ] || [ "$CUSTOM_PKTS_V4" -gt 0 ]; then
        printf  "  ├─ ${DIM}custom${N}              %12s pkts  ${DIM}/${N} %s\n" "$(human_num "$CUSTOM_PKTS_V4")" "$(human_bytes "$CUSTOM_BYTES_V4")"
    fi
    if [ "$TOR_SET_SIZE" -gt 0 ] || [ "$TOR_PKTS_V4" -gt 0 ]; then
        printf  "  ├─ ${DIM}tor exit${N}            %12s pkts  ${DIM}/${N} %s\n" "$(human_num "$TOR_PKTS_V4")" "$(human_bytes "$TOR_BYTES_V4")"
    fi
    printf  "  ├─ ${DIM}confirmed-attack${N}    %12s pkts  ${DIM}/${N} %s\n"   "$(human_num "$CONFIRMED_PKTS_V4")" "$(human_bytes "$CONFIRMED_BYTES_V4")"
    printf  "  ├─ ${DIM}rate-limit (syn)${N}    %12s pkts  ${DIM}/${N} %s\n"   "$(human_num "$SYN_CONF_PKTS_V4")" "$(human_bytes "$SYN_CONF_BYTES_V4")"
    printf  "  ├─ ${DIM}rate-limit (udp)${N}    %12s pkts  ${DIM}/${N} %s\n"   "$(human_num "$UDP_CONF_PKTS_V4")" "$(human_bytes "$UDP_CONF_BYTES_V4")"
    printf  "  ├─ ${DIM}conn-flood (ct>400)${N} %12s pkts  ${DIM}/${N} %s\n"   "$(human_num "$CONN_FLOOD_PKTS_V4")" "$(human_bytes "$CONN_FLOOD_BYTES_V4")"
    printf  "  ├─ ${DIM}new-conn flood${N}      %12s pkts  ${DIM}/${N} %s\n"   "$(human_num "$NEWCONN_FLOOD_PKTS_V4")" "$(human_bytes "$NEWCONN_FLOOD_BYTES_V4")"
    printf  "  ├─ ${DIM}TCP flag invalid${N}    %12s pkts  ${DIM}/${N} %s\n"   "$(human_num "$TCP_INVALID_PKTS")" "$(human_bytes "$TCP_INVALID_BYTES")"
    printf  "  └─ ${B}total${N}               ${B}%12s${N} pkts  ${DIM}/${N} ${B}%s${N}\n" "$(human_num "$total_pkts")" "$(human_bytes "$total_bytes")"
    echo ""

    # ===== ALL-TIME (persistent) =====
    echo -e "  ${B}All-time history${N} ${DIM}(since $DB_SINCE)${N}"
    printf  "  ├─ ${M}scanners blocked:${N}    %12s unique IPs ${DIM}(%s hits)${N}\n" "$(human_num "$ALLTIME_SCANNERS")"   "$(human_num "$ALLTIME_SCANNER_PKTS")"
    printf  "  ├─ ${M}ddos blocked:${N}        %12s unique IPs ${DIM}(%s hits)${N}\n" "$(human_num "$ALLTIME_DDOS")"       "$(human_num "$ALLTIME_DDOS_PKTS")"
    printf  "  └─ ${M}ssh brute attempts:${N}  %12s unique IPs ${DIM}(crowdsec)${N}\n" "$(human_num "$CS_ALLTIME_BANS")"
    echo ""

    # ===== RECENT EVENTS (v3.5) =====
    local events_log="/var/log/shieldnode/events.log"
    if [ -r "$events_log" ]; then
        echo -e "  ${B}Recent events${N} ${DIM}(last 5 — [9] for full log)${N}"
        local last_lines
        last_lines=$(tail -5 "$events_log" 2>/dev/null)
        if [ -z "$last_lines" ]; then
            echo -e "  ${DIM}└─ (empty — no events yet)${N}"
        else
            echo "$last_lines" | sed 's/^/  /'
        fi
        echo ""
    fi

    printf "  ${DIM}Blocklist updated: %s${N}\n" "$LAST_UPDATE"
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
    echo -e "${Y}${B}Suspect IPs${N} ${DIM}(under watch, 30min — first offence)${N}"
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
    echo -e "  ${DIM}1st limit hit → suspect (30min watch, no drop)${N}"
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

# v3.9: разбан всех IP в suspect_v4 и confirmed_attack_v4 одной командой.
# Используется при ложных срабатываниях или при ручной коррекции.
unban_all() {
    echo ""
    local susp conf
    susp=$(nft list set inet ddos_protect suspect_v4 2>/dev/null | \
        grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | wc -l)
    conf=$(nft list set inet ddos_protect confirmed_attack_v4 2>/dev/null | \
        grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | wc -l)
    echo -e "${B}Unban all confirmed attack + suspect${N}"
    echo -e "${DIM}─────────────────────────────────${N}"
    echo -e "  Сейчас в suspect:          ${Y}${susp}${N} IP"
    echo -e "  Сейчас в confirmed_attack: ${R}${conf}${N} IP"
    echo ""
    echo -ne "  ${B}Очистить оба set'а? [y/N]:${N} "
    read -r confirm
    case "$confirm" in
        y|Y|yes|YES)
            nft flush set inet ddos_protect suspect_v4 2>/dev/null
            nft flush set inet ddos_protect confirmed_attack_v4 2>/dev/null
            echo -e "  ${G}✓${N} Очищено: $susp suspect + $conf confirmed = $((susp + conf)) IP разбанены"
            echo -e "  ${DIM}Учти: connlimit_v4 не очищается (там conntrack timers cleanup автоматом)${N}"
            ;;
        *)
            echo -e "  ${DIM}Отменено${N}"
            ;;
    esac
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
    echo -e "${C}│${N}  [${B}8${N}] Unban all (suspect+confirmed)  [${B}9${N}] View full events.log    ${C}│${N}"
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
        8) unban_all             ;;
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

# v3.10.2 SMOKE TEST: ловим регрессии типа v3.5 ct count bug или v3.10 parser bug
# на этапе установки, чтобы не выкатывать сломанную защиту в прод.
print_status "Smoke-test: проверяю что защита реально активна..."

SMOKE_FAIL=0

# 1. Таблица создана?
if ! nft list table inet ddos_protect >/dev/null 2>&1; then
    print_error "FAIL: таблица inet ddos_protect не создана"
    SMOKE_FAIL=1
fi

# 2. protected_ports_tcp непустой если в UFW есть TCP-правила
# v3.11.3 BUG-MULTILINE FIX: nft форматирует длинные `elements = { ... }`
# на несколько строк (после ~7 элементов). grep -oE на single-line не матчит
# multi-line блок → SMOKE_TCP=0 → ложный FAIL даже когда set заполнен.
# Fix: tr '\n' ' ' для flattening (тот же подход что в updater'e CUR_TCP).
if [ -n "$PROTECTED_TCP" ]; then
    SMOKE_TCP=$(nft list set inet ddos_protect protected_ports_tcp 2>/dev/null | \
        tr '\n' ' ' | grep -oE 'elements = \{[^}]*\}' | grep -oE '[0-9]+(-[0-9]+)?' | wc -l)
    if [ "$SMOKE_TCP" -eq 0 ]; then
        print_error "FAIL: protected_ports_tcp пуст, ожидается: $PROTECTED_TCP"
        print_info "Это симптом BUG-1 (port-range в UFW) или BUG-8 (локализация)"
        print_info "Проверь:  sudo /usr/local/sbin/update-protected-ports.sh"
        print_info "          sudo journalctl -t protected-ports -n 20"
        SMOKE_FAIL=1
    else
        print_ok "Smoke: protected_ports_tcp содержит $SMOKE_TCP портов/диапазонов"
    fi
fi

# 3. protected_ports_udp непустой если в UFW есть UDP-правила (same multi-line fix)
if [ -n "$PROTECTED_UDP" ]; then
    SMOKE_UDP=$(nft list set inet ddos_protect protected_ports_udp 2>/dev/null | \
        tr '\n' ' ' | grep -oE 'elements = \{[^}]*\}' | grep -oE '[0-9]+(-[0-9]+)?' | wc -l)
    if [ "$SMOKE_UDP" -eq 0 ]; then
        print_error "FAIL: protected_ports_udp пуст, ожидается: $PROTECTED_UDP"
        SMOKE_FAIL=1
    else
        print_ok "Smoke: protected_ports_udp содержит $SMOKE_UDP портов/диапазонов"
    fi
fi

# 4. Все обязательные cleanup-цепочки и подцепочки на месте (refactor v3.10.2)
for chain in prerouting forward newconn_overflow syn_overflow udp_overflow; do
    if ! nft list chain inet ddos_protect "$chain" >/dev/null 2>&1; then
        print_error "FAIL: цепочка inet ddos_protect $chain не создана"
        SMOKE_FAIL=1
    fi
done

# 5. shieldnode-nftables.service в active-состоянии
if ! systemctl is-active --quiet shieldnode-nftables.service; then
    print_error "FAIL: shieldnode-nftables.service не active"
    print_info "Логи: sudo journalctl -u shieldnode-nftables -n 30"
    SMOKE_FAIL=1
fi

# 6. updater запускается без ошибок и нашёл хоть что-то
print_status "Smoke: запускаю updater вручную для проверки парсера..."
if ! /usr/local/sbin/update-protected-ports.sh 2>&1 | head -10; then
    : # не fatal — updater может exit 0 с "no change"
fi
sleep 1

# 7. Проверка что FIREWALL_ACTIVE детектится (для locale-fix BUG-8)
case "$FIREWALL_TYPE" in
    ufw)
        if ! LANG=C LC_ALL=C ufw status 2>/dev/null | grep -q "Status: active"; then
            print_warn "WARN: FIREWALL_ACTIVE детект мог не сработать"
            print_info "Если у тебя локализованный 'ufw status' — обновись до v3.10.2 (BUG-8 fix)"
        fi
        ;;
esac

# 8. v3.10.3 BUG-9: bouncer работает на правильном hook (prerouting, не input)
if systemctl is-active --quiet crowdsec-firewall-bouncer; then
    sleep 2  # дать bouncer'у время создать таблицу
    # Bouncer создаёт `table ip crowdsec` (не inet, не наша). Проверяем что
    # цепочка в этой таблице висит на prerouting hook с priority -200.
    if nft list chain ip crowdsec crowdsec-chain-prerouting >/dev/null 2>&1; then
        BOUNCER_PRIO=$(nft list chain ip crowdsec crowdsec-chain-prerouting 2>/dev/null | grep -oE 'priority [a-z]* ?[+-]?[0-9]+' | head -1)
        print_ok "Smoke: bouncer на prerouting hook ($BOUNCER_PRIO) — раньше нашего"
    elif nft list chain ip crowdsec crowdsec-chain-input >/dev/null 2>&1; then
        print_warn "WARN: bouncer всё ещё на input hook — BUG-9 fix не сработал"
        print_info "Проверь /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml"
        print_info "Должно быть: nftables_hooks: - prerouting, priority: -200"
    elif nft list table ip crowdsec >/dev/null 2>&1; then
        print_info "Smoke: bouncer table создана, но цепочка с непредсказуемым именем"
    else
        # Bouncer ещё не успел создать таблицу — возможно CAPI sync в процессе
        print_info "Smoke: bouncer table ещё не создана (вероятно в процессе sync с CAPI)"
    fi
fi

# 9. v3.10.3 BUG-10: bouncer не пытается работать с IPv6 если он отключён
if [ "$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null)" = "1" ]; then
    if [ -f /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml ]; then
        # Проверяем что в config'е ipv6 disabled
        if awk '/^[[:space:]]*ipv6:/{f=1} f && /^[[:space:]]*enabled:[[:space:]]*true/{exit 1} /^[a-zA-Z]/{f=0}' \
            /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml; then
            print_ok "Smoke: bouncer IPv6 disabled (соответствует sysctl)"
        else
            print_warn "WARN: IPv6 disabled в системе, но НЕ в bouncer config — будут ошибки в логе"
        fi
    fi
fi

# 10. v3.10.3 BUG-11: mgmt IPs в CrowdSec whitelist
if [ -n "$MGMT_IPV4" ] && command -v cscli >/dev/null 2>&1; then
    WL_COUNT=$(cscli decisions list --type whitelist -o raw 2>/dev/null | tail -n +2 | wc -l)
    EXPECTED_COUNT=$(echo "$MGMT_IPV4" | tr ',' '\n' | grep -c .)
    if [ "$WL_COUNT" -ge "$EXPECTED_COUNT" ]; then
        print_ok "Smoke: $WL_COUNT mgmt IPs в CrowdSec whitelist"
    else
        print_warn "WARN: только $WL_COUNT из $EXPECTED_COUNT mgmt IPs в whitelist"
    fi
fi

# 11. v3.10.4 BUG-14: SSH acquisition реально работает
if command -v cscli >/dev/null 2>&1; then
    sleep 1
    # cscli metrics show acquisition покажет источники
    SSH_ACQ_LINES=$(cscli metrics show acquisition 2>/dev/null | grep -cE "auth\.log|sshd\.service")
    SSH_ACQ_LINES="${SSH_ACQ_LINES:-0}"
    if [ "$SSH_ACQ_LINES" -gt 0 ]; then
        print_ok "Smoke: SSH acquisition активен ($SSH_ACQ_LINES источников)"
    else
        # Может быть еще не успели получить метрики - не fatal
        print_info "Smoke: SSH acquisition метрики ещё пустые (нет логин-попыток с момента старта)"
    fi
fi

# 12. v3.10.4 BUG-15: CAPI работает → community blocklist приходит
if command -v cscli >/dev/null 2>&1; then
    if cscli capi status >/dev/null 2>&1; then
        # Подсчёт CAPI decisions (community blocklist)
        CAPI_DECISIONS=$(cscli decisions list --origin CAPI -o raw 2>/dev/null | tail -n +2 | wc -l)
        if [ "$CAPI_DECISIONS" -gt 0 ]; then
            print_ok "Smoke: $CAPI_DECISIONS CAPI decisions (community blocklist работает)"
        else
            print_info "Smoke: CAPI registered, но 0 decisions yet (придут через 1-2 часа)"
        fi
    else
        print_warn "WARN: CAPI status не OK — нет community blocklist"
    fi
fi

# 13. v3.10.4 BUG-19: scenarios в simulation mode (не банят, только alerts)
if command -v cscli >/dev/null 2>&1; then
    SIM_COUNT=$(cscli simulation status 2>/dev/null | grep -cE "^\s*-\s+")
    SIM_COUNT="${SIM_COUNT:-0}"
    if [ "$SIM_COUNT" -gt 0 ]; then
        print_info "Smoke: $SIM_COUNT scenarios в simulation mode (alerts only, без bans)"
        print_info "       Список: cscli simulation status"
    fi
fi

# 14. v3.11: Tor blocklist загружен если BLOCK_TOR=1
if [ "$BLOCK_TOR" = "1" ]; then
    TOR_SET_COUNT=$(nft list set inet ddos_protect tor_exit_blocklist_v4 2>/dev/null | \
        tr '\n' ' ' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | wc -l)
    if [ "$TOR_SET_COUNT" -ge 100 ]; then
        print_ok "Smoke: Tor blocklist загружен ($TOR_SET_COUNT exit nodes)"
    elif [ "$TOR_SET_COUNT" -gt 0 ]; then
        print_warn "WARN: Tor blocklist подозрительно мал ($TOR_SET_COUNT IPs, ожидается 1000+)"
        print_info "       Проверь: journalctl -u shieldnode-update@tor -n 30"
    else
        print_error "FAIL: BLOCK_TOR=1 включён, но Tor blocklist пустой"
        print_info "       Проверь: journalctl -u shieldnode-update@tor -n 30"
        SMOKE_FAIL=1
    fi
    # Timer должен быть active (v3.12.0: templated unit)
    if systemctl is-active --quiet shieldnode-update@tor.timer; then
        print_ok "Smoke: shieldnode-update@tor.timer активен (hourly refresh)"
    else
        print_warn "WARN: shieldnode-update@tor.timer не active"
    fi
fi

if [ "$SMOKE_FAIL" -eq 1 ]; then
    print_error ""
    print_error "Smoke-test НЕ ПРОЙДЕН. Защита может работать частично или не работать совсем."
    print_error "Не используй ноду в проде до устранения проблем выше."
    print_error ""
else
    print_ok "Smoke-test пройден"
fi
echo ""

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
    print_warn "Scanner blocklist пуст — проверь journalctl -u shieldnode-update@scanner"
fi

# ==============================================================================
# ШАГ 14: ИТОГИ (v3.12.0 — компактно)
# ==============================================================================

# v1.5 fix: $0 на pipe-mode = /dev/fd/63
SCRIPT_NAME="$0"
case "$SCRIPT_NAME" in
    /dev/fd/*|/proc/*|bash|-bash|sh|-sh) SCRIPT_NAME="shieldnode.sh" ;;
esac

# Метрики для summary
SCANNER_NUM=$(nft list set inet ddos_protect scanner_blocklist_v4 2>/dev/null | tr '\n' ' ' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?' | wc -l)
THREAT_NUM=$(nft list set inet ddos_protect threat_blocklist_v4 2>/dev/null | tr '\n' ' ' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?' | wc -l)
CUSTOM_NUM=$(nft list set inet ddos_protect custom_blocklist_v4 2>/dev/null | tr '\n' ' ' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?' | wc -l)
TOR_NUM=$(nft list set inet ddos_protect tor_exit_blocklist_v4 2>/dev/null | tr '\n' ' ' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | wc -l)
MOBILE_RU_NUM=$(nft list set inet ddos_protect mobile_ru_whitelist_v4 2>/dev/null | tr '\n' ' ' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?' | wc -l)
CS_NUM=0
if [ -r /var/lib/crowdsec/data/crowdsec.db ] && command -v sqlite3 >/dev/null 2>&1; then
    CS_NUM=$(sqlite3 /var/lib/crowdsec/data/crowdsec.db "SELECT COUNT(*) FROM decisions WHERE type='ban' AND until > datetime('now')" 2>/dev/null)
fi
CS_NUM="${CS_NUM:-0}"
TCP_PORTS_COUNT=$(echo "$XRAY_PORTS_TCP" | tr ',' '\n' | grep -c .)

echo ""
echo -e "${CYAN}══════════════════════════════════════════════════════════════════${NC}"
echo -e "  ${GREEN}✓${NC} ${BOLD}shieldnode v3.13.1 установлен${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${BOLD}Защита активна:${NC}"
echo -e "   • TCP-порты:     ${CYAN}${XRAY_PORTS_TCP}${NC} (${TCP_PORTS_COUNT} шт.)"
[ -n "$XRAY_PORTS_UDP" ] && echo -e "   • UDP-порты:     ${CYAN}${XRAY_PORTS_UDP}${NC}"
echo -e "   • CrowdSec:      $(printf "%'d" "$CS_NUM") IPs (community CAPI)"
BL_LINE="scanner=$(printf "%'d" "${SCANNER_NUM:-0}"), threat=$(printf "%'d" "${THREAT_NUM:-0}"), custom=$(printf "%'d" "${CUSTOM_NUM:-0}")"
[ "${TOR_NUM:-0}" -gt 0 ] && BL_LINE="$BL_LINE, tor=$(printf "%'d" "$TOR_NUM")"
echo -e "   • Blocklists:    ${BL_LINE}"
if [ "${MOBILE_RU_NUM:-0}" -gt 0 ]; then
    echo -e "   • Mobile-RU:     $(printf "%'d" "$MOBILE_RU_NUM") CIDRs (relaxed: ct=1000, newconn=2000/min)"
elif [ "${ENABLE_RU_MOBILE_WHITELIST:-1}" = "1" ] && [ -z "${MAXMIND_LICENSE_KEY:-}" ]; then
    echo -e "   • Mobile-RU:     ${YELLOW}отключён${NC} ${DIM}(нет MAXMIND_LICENSE_KEY в shieldnode.conf)${NC}"
fi
echo -e "   • Лимиты:        ct=400, new-conn=500/min ${DIM}(CGNAT-friendly)${NC}"
echo ""
echo -e "  ${BOLD}Команды:${NC}"
echo -e "   ${CYAN}sudo guard${NC}                — дашборд защиты"
echo -e "   ${CYAN}sudo guard --once${NC}         — снимок без меню"
echo -e "   ${CYAN}sudo bash $SCRIPT_NAME --uninstall${NC}  — удалить"
echo ""
if [ "${SSHD_PASSWORD_AUTH_ENABLED:-0}" = "1" ]; then
    echo -e "  ${YELLOW}⚠${NC} SSH password-auth ВКЛЮЧЁН. Для максимальной защиты:"
    echo -e "    ${DIM}1) ssh-keygen → ssh-copy-id → проверь логин по ключу${NC}"
    echo -e "    ${DIM}2) sed -i 's/^[#[:space:]]*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config${NC}"
    echo -e "    ${DIM}3) sshd -t && systemctl reload ssh${NC}"
    echo ""
fi
if [ -d "$BACKUP_DIR" ]; then
    echo -e "  ${DIM}Бэкап: $BACKUP_DIR${NC}"
fi
echo -e "${CYAN}══════════════════════════════════════════════════════════════════${NC}"
echo ""
