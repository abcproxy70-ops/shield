# shieldnode

Bash-скрипт DDoS-защиты для VPN-нод (Reality / Xray / sing-box / Hysteria2).

Стек: **nftables + CrowdSec + UFW**. Целевые ОС: Ubuntu 22.04 / 24.04, Debian 11 / 12.

## Архитектура (v3.20.x)

**Простая единая защита** для всех IP без whitelist'ов:

- **conn_flood**: ct count over 5000 (extreme CGNAT support)
- **newconn rate**: 5000/min, burst 8000
- **SYN flood**: 300/sec, burst 500 (kernel rate-limit)
- **UDP flood**: 1500/sec, burst 3000 (поддержка Hysteria2 4K стриминга)

99.5% пользователей не упираются в лимиты. Реальные DDoS атаки 5000+ концурренту/IP — drop в kernel level.

## Возможности

- **nftables rate-limit** (kernel-level, IPv4-only): SYN-flood, UDP-flood, conn-flood
- **TCP flag sanity**: drop XMAS, NULL, SYN+FIN, SYN+RST scan-пакетов
- **Anti-spoofing**: fib reverse-path (single-homed VPS)
- **TCP MSS clamping** для VPN-туннелей
- **4 blocklist'а**:
  - `scanner` — Shodan, Censys, госсканеры РФ (shadow-netlab + CyberOK_Skipa + MISP)
  - `threat` — Spamhaus DROP + FireHOL Level 1 (high-confidence криминал)
  - `tor` — Tor exit nodes (опционально, `BLOCK_TOR=1`)
  - `custom` — личный список оператора (file-based + URL union)
- **GitHub auto-sync**: `lists/custom.txt` синкается с репо каждые 6ч.
  Локальные дополнения — в отдельном `custom-local.txt`, не перезаписываются.
- **Version check**: нода раз в день проверяет github на новую версию,
  показывает `[upgrade] доступна v3.X.Y` в guard CLI
- **CrowdSec** + nftables bouncer (SSH brute-force + community blocklist)
- **guard CLI** — дашборд защиты с ASN/owner column для top attackers
- **Aggregator**: журналы → sqlite events.db с per-IP analytics
- **Auto-detect портов** из UFW + inotify path-watcher (мгновенный sync)

## Установка

```bash
bash <(curl -sL https://raw.githubusercontent.com/abcproxy70-ops/shield/main/shieldnode.sh)
```

Скрипт сам:
- определит порты Xray/Reality из UFW
- настроит nftables таблицу `inet ddos_protect`
- скачает blocklist'ы (scanner, threat, custom) с github
- поставит CrowdSec + bouncer
- создаст команду `guard` для мониторинга

## Конфигурация

Опциональный `/etc/shieldnode/shieldnode.conf` (см. [shieldnode.conf.example](./shieldnode.conf.example)):

```bash
# Tor exit blocklist
BLOCK_TOR=1

# Свои источники
REMOTE_BLOCKLISTS=(
    "threat=https://www.spamhaus.org/drop/drop.txt,https://iplists.firehol.org/files/firehol_level1.netset"
    "custom=https://raw.githubusercontent.com/MY_ORG/MY_REPO/main/blocklist.txt"
)
```

## Файлы blocklist'ов

В папке [`lists/`](./lists/) лежат seed-файлы. На сервере они кладутся в
`/etc/shieldnode/lists/` и автоматически объединяются с URL-источниками.

Чтобы добавить IP в `custom` на работающей ноде:
```bash
echo '198.51.100.42' | sudo tee -a /etc/shieldnode/lists/custom.txt
# inotify path-watcher подхватит за <1 секунды
```

## Удаление

```bash
sudo bash <(curl -sL https://raw.githubusercontent.com/abcproxy70-ops/shield/main/shieldnode.sh) --uninstall
```

## Команда guard

```bash
sudo guard          # дашборд защиты с интерактивным меню
sudo guard --once   # снимок без меню (для cron / мониторинга)
sudo guard --json   # JSON-вывод для интеграций (Zabbix, Prometheus)
```

Главный экран показывает:
- Active threats (confirmed attacks, suspect, crowdsec bans)
- Top attackers за 24h с ASN/owner column (через ipinfo.io, кэш 7 дней)
- Drops since reboot по типам (scanner, threat, custom, tor, attack, rate-limit)
- All-time history из events.db
- Recent events из /var/log/shieldnode/events.log

## Версии

- **v3.20.1** — extreme CGNAT support: conn_flood ct=3000→5000, newconn 3000/min→5000/min. SYN/UDP лимиты без изменений.
- **v3.20.0** — SIMPLIFICATION: убраны mobile-RU и broadband-RU whitelist'ы. Единые лимиты для всех IP: conn_flood ct=3000, newconn 3000/min burst 5000, UDP 1500/sec burst 3000. Архитектура проще, защита эквивалентна, гарантированно не блокирует реальных юзеров.
- **v3.19.0** — broadband-RU whitelist (отменён в v3.20.0)
- **v3.18.13** — поднят non-mobile лимит conn_flood 400→1500 (отменён в v3.20.0)
- **v3.18.12** — HOTFIX для v3.18.11: исправлена двойная закрывающая `}` в `show_settings_menu`.
- **v3.18.11** — POST-AUDIT HARDENING: 16 фиксов после полного аудита кода.
- **v3.18.9** — `--uninstall` теперь явно сбрасывает sysctl-ключи которые писал ТОЛЬКО shieldnode.
- **v3.18.8** — UFW-FIX + security/data-loss hardening (12 фиксов).
- **v3.18.7** — TRUSTED_IPS feature: comma-separated список доверенных IP с trust-stack в 3 слоях (shieldnode whitelist + UFW allow + CrowdSec whitelist на 1 год).
- **v3.18.6** — race condition fix для blocklist updater'ов при первом запуске.
- **v3.18.5** — фикс T-state зависания при установке CrowdSec.
- **v3.18.3** — убрана зависимость от MaxMind.
- **v3.14.0** — GitHub auto-sync custom.txt (каждые 6ч) + version check + guard CLI settings menu `[s]`.
- **v3.13.0** — mobile-RU AS whitelist (отменён в v3.20.0).
- **v3.12.0** — blocklists архитектура (universal updater, file+URL union, ASN guard column).
- **v3.11.x** — Tor exit blocklist, multiline smoke fix.
- v3.10.x — fib anti-spoof, TCP MSS clamping.
- v3.5–v3.9 — HTTP-flood защита, ban-once архитектура, sqlite aggregator.

## Лицензия

MIT — см. [LICENSE](./LICENSE).
