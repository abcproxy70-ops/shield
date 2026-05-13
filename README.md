# shieldnode

Bash-скрипт DDoS-защиты для VPN-нод (Reality / Xray / sing-box / Hysteria2).

Стек: **nftables + CrowdSec + UFW**. Целевые ОС: Ubuntu 22.04 / 24.04, Debian 11 / 12.

## Архитектура (v3.21.4)

**Чистое разделение зон ответственности с vpn-node-setup:**

- shieldnode владеет: scanner blocklist, rate-limit, ct count, fib anti-spoof, SSH pre-auth flood защита, CrowdSec, security sysctl (rp_filter, syncookies, redirects, icmp, tcp_rfc1337, log_martians, conntrack UDP timeouts)
- vpn-node-setup владеет: kernel (XanMod LTS), BBR, qdisc fq, buffers, MSS clamp, NIC tuning

Никаких пересечений в netfilter pipeline. Двойного MSS clamp нет.

**Защита для всех IP без whitelists:**

- **conn_flood**: ct count over 5000 (extreme CGNAT support)
- **newconn rate**: 5000/min, burst 8000
- **SYN flood**: 300/sec, burst 500 (kernel rate-limit)
- **UDP flood**: 1500/sec, burst 3000
- **SSH per-IP**: ct count over 3 concurrent + 5/min new connections (v3.21.4, ужесточено с 5+10)

99.5% пользователей не упираются в лимиты. Реальные DDoS-атаки 5000+ concurrent/IP — drop на kernel level. SSH-флуд (десятки тысяч pps от одного IP) дропается на уровне nft до того как пакет дойдёт до sshd. Для SSH-админа из CGNAT — добавить IP в `manual_whitelist_v4`.

## Возможности

- **nftables rate-limit** (kernel-level, IPv4-only): SYN-flood, UDP-flood, conn-flood
- **TCP flag sanity**: drop XMAS, NULL, SYN+FIN, SYN+RST scan-пакетов
- **Anti-spoofing**: fib reverse-path (single-homed VPS)
- **4 blocklist'а**:
  - `scanner` — Shodan, Censys, госсканеры РФ (shadow-netlab + CyberOK_Skipa + MISP)
  - `threat` — Spamhaus DROP + FireHOL Level 1 (high-confidence криминал)
  - `tor` — Tor exit nodes (опционально, `BLOCK_TOR=1`)
  - `custom` — личный список оператора (file-based + URL union)
- **GitHub auto-sync**: `lists/custom.txt` синкается с репо каждые 6ч.
  Локальные дополнения — в `custom-local.txt`, не перезаписываются.
- **CrowdSec** + nftables bouncer (SSH brute-force + community blocklist)
- **guard CLI** — дашборд защиты с ASN/owner column для top attackers
- **Aggregator**: журналы → sqlite events.db с per-IP analytics
- **Auto-detect портов** из UFW + inotify path-watcher (мгновенный sync)

## Установка

```bash
curl -fL https://raw.githubusercontent.com/abcproxy70-ops/shield/main/shieldnode.sh | sudo bash
```

> ⚠️ Use `curl | sudo bash` вместо `bash <(curl ...)` — process substitution не
> работает на OpenVZ/LXC контейнерах и некоторых embedded environments.

## Совместимость

- Работает рядом с **vpn-node-setup v5.0.5+** (рекомендуется порядок: **vpn-node-setup первым, потом shieldnode** — минимизирует окно потери MSS clamp)
- Совместим с UFW (читает open ports автоматически)
- Совместим с любыми VPN-стэками (Xray Reality, sing-box, Hysteria2, WireGuard)

## Удаление

```bash
curl -fL https://raw.githubusercontent.com/abcproxy70-ops/shield/main/shieldnode.sh | sudo bash -s -- --uninstall
```

## guard CLI

```bash
sudo guard          # дашборд защиты с интерактивным меню
sudo guard --once   # снимок без меню (для cron / мониторинга)
sudo guard --json   # JSON-вывод для интеграций (Zabbix, Prometheus)
```

## Версии

- **v3.21.4** — SSH RATE-LIMIT TIGHTENED: на основе production-данных (нода с 345M dropped пакетов / 21 GB за 10 часов) ужесточены SSH per-IP лимиты. `ssh_connlimit_v4`: ct count over 5 → 3 (slowloris ловится в 1.67x агрессивнее, 99.5% дропов на v3.21.0 были именно от ct count, не rate). `ssh_newconn_rate_v4`: 10/min → 5/min, burst 15 без изменений. Для админа из CGNAT — добавить IP в `manual_whitelist_v4`.
- **v3.21.3** — LOG DEDUP + DB CLEANUP + AWK BUGFIX: (1) убрано дублирование kern.* в /var/log/syslog через in-place edit `/etc/rsyslog.d/50-default.conf` с backup и graceful reload (предыдущая drop-in архитектура не работала — rsyslog evaluates все matching rules, не "first wins"). (2) journald drop-in `/etc/systemd/journald.conf.d/shieldnode.conf` с SystemMaxUse=500M вместо 10% /var. (3) shieldnode-cleanup.sh теперь делает реальную чистку sqlite БД: `DELETE events WHERE last_seen < -90d`, `DELETE asn_cache WHERE cached_at < -7d`, `wal_checkpoint(TRUNCATE)`, `VACUUM`. До v3.21.3 cleanup чистил несуществующую директорию /var/lib/shieldnode/asn_cache/. (4) CRITICAL BUGFIX: апостроф в кириллическом комментарии (`whitelist'ы`) внутри `awk '...'` блока aggregator-скрипта закрывал bash single-quoted строку раньше времени → весь awk-код парсился bash как команды → aggregator.service падал с exit 2 на каждом срабатывании таймера (каждую минуту). Защита nft при этом работала, но events.db не пополнялась — дашборд показывал stale данные.
- **v3.21.2** — UX FIX: whitelist add/remove теперь явно триггерит updater, больше не нужно вручную нажимать [f] Force re-sync.
- **v3.21.1** — SSH защита перемещена ПОСЛЕ tor_blocklist/scanner_blocklist drops. Раньше SSH-rate-limit стоял до этих blocklists → Tor exit nodes могли подключаться к SSH при `BLOCK_TOR=1`.
- **v3.21.0** — SSH PRE-AUTH FLOOD DEFENSE: добавлены два rate-limit'а на SSH-порт: `ssh_connlimit_v4` (ct count over 5 concurrent на IP) и `ssh_newconn_rate_v4` (10/min, burst 15). Закрыта дыра: атакующий мог открывать 100+ TCP-коннектов к sshd, забивая softirq на handshake. Реальный кейс: тестовая нода получала 345M dropped пакетов / 21 GB за 10 часов с открытым :22 в публичный интернет — все срезались на nft-уровне до sshd. Рекомендация: SSH на нестандартный порт + per-IP allow.
- **v3.20.7** — WHITELIST CONSISTENCY FIX: единая точка управления whitelist во всех слоях. На установке автоимпортируются UFW `ALLOW from <IP>` правила в `whitelist-local.txt` + `TRUSTED_IPS` в `shieldnode.conf` + применяются через CrowdSec whitelist на 1 год. `BRIDGE_IPS` тоже расширен на все 3 слоя. Раньше IP попадали только в nft set через port-syncer, но UI `guard → Trusted IPs` показывал «пусто» и CrowdSec мог их забанить.
- **v3.20.6** — SMOKE-TEST FIX: убран ложный smoke-test FAIL после v3.20.5. Smoke-test проверял наличие `chain forward` (которая удалена в v3.20.5 by design) → все установки показывали красный FAIL хотя защита работала. Косметика, функциональность не менялась.
- **v3.20.5** — ARCH SIMPLIFICATION: удалён MSS clamp forward chain (зона vpn-node-setup), удалён panel auto-detect через docker ps (нестабильное определение priorities), priorities захардкожены (prerouting -100 standalone, -150 panel-mode через manual override).
- **v3.20.4** — HOTFIX: критический баг в v3.20.3 (backticks в unquoted heredoc).
- **v3.20.3** — DISK USAGE FIX: ротация логов, ограничения на size.
- **v3.20.1** — extreme CGNAT support: conn_flood 3000→5000, newconn 3000/min→5000/min.
- **v3.20.0** — SIMPLIFICATION: убраны mobile-RU и broadband-RU whitelist'ы.
- **v3.18.x** — TRUSTED_IPS feature, UFW-FIX, post-audit hardening.
- **v3.14.0** — GitHub auto-sync custom.txt + version check + guard settings menu.
- **v3.12.0** — blocklists архитектура (universal updater, file+URL union).
- **v3.10.x** — fib anti-spoof, TCP MSS clamping.

## Лицензия

MIT — см. [LICENSE](./LICENSE).
