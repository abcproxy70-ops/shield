# shieldnode

Bash-скрипт DDoS-защиты для VPN-нод (Reality / Xray / sing-box / Hysteria) за CGNAT.

Стек: **nftables + CrowdSec + UFW**. Целевые ОС: Ubuntu 22.04 / 24.04, Debian 11 / 12.

## Возможности

- **nftables rate-limit** (kernel-level, IPv4-only): SYN-flood 300/sec, UDP-flood 600/sec
- **HTTP-flood / slowloris защита**: ct-count 400 + new-conn 500/min (CGNAT-friendly)
- **TCP flag sanity**: drop XMAS, NULL, SYN+FIN, SYN+RST scan-пакетов
- **Anti-spoofing**: fib reverse-path (single-homed VPS)
- **TCP MSS clamping** для VPN-туннелей
- **4 blocklist'а**:
  - `scanner` — Shodan, Censys, госсканеры РФ (shadow-netlab + CyberOK_Skipa + MISP)
  - `threat` — Spamhaus DROP + FireHOL Level 1 (high-confidence криминал)
  - `tor` — Tor exit nodes (опционально, `BLOCK_TOR=1`)
  - `custom` — личный список оператора (file-based + URL union)
- **Mobile-RU AS whitelist** (v3.18.3): relaxed limits (ct=1000, newconn=2000/min)
  для МТС / T2 / МегаФон / Билайн. Список CIDR'ов автогенерируется раз в неделю
  через GitHub Actions с помощью публичного RIPEstat API (без MaxMind, без ключей).
- **GitHub auto-sync** (v3.18.3): `lists/custom.txt` синкается с репо каждые 6ч.
  Локальные дополнения — в отдельном `custom-local.txt`, не перезаписываются.
- **Version check** (v3.18.3): нода раз в день проверяет github на новую версию,
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
- скачает blocklist'ы (scanner, threat, mobile-ru) с github
- поставит CrowdSec + bouncer
- создаст команду `guard` для мониторинга

## Конфигурация

Опциональный `/etc/shieldnode/shieldnode.conf` (см. [shieldnode.conf.example](./shieldnode.conf.example)):

```bash
# Mobile-RU whitelist (включён по умолчанию)
ENABLE_RU_MOBILE_WHITELIST=1

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

- **v3.18.5** — security/data-loss hardening: (1) при interactive reinstall настройки оператора в shieldnode.conf (BLOCK_TOR, ENABLE_*) теперь не теряются — merge-aware atomic write; (2) `guard upgrade` качает installer во временный файл с `-fsSL` и валидирует (shebang/version-marker/`bash -n`) ДО `exec` — на 404/MITM не убивает рабочую установку; (3) `.crowdsec_managed` marker — foreign CrowdSec не модифицируется (profiles.yaml, acquis.d, bouncer config, nft tables); (4) early-fail при <500MB/var, <50MB/etc, <50MB/tmp; (5) `prepare_seed_list` детектит header-only stub'ы и ретраится 3× с HTML-detection; (6) `guard rollback` — snapshot перед upgrade'ом, восстановление за одну команду; (7) BOUNCER_KEY валидируется regex'ом и пишется через awk вместо sed; (8) github-sync `mv` теперь same-FS atomic; (9) `MAXMIND_LICENSE_KEY` полностью удалён (deprecated с v3.15.0, не использовался) — устаревшие комментарии тоже почищены.
- **v3.18.3** — убрана зависимость от MaxMind. `lists/mobile-ru.txt` теперь автогенерируется раз в неделю через GitHub Actions из публичного RIPEstat API. Все 13 mobile-RU AS проверены, ~2400 raw CIDR'ов → ~450 финальных после nft auto-merge. Mobile-RU стал обычным blocklist'ом через unified updater.
- **v3.14.1** — hotfix: при reinstall настройки оператора в shieldnode.conf теперь сохраняются (раньше ENABLE_GITHUB_SYNC=0, ENABLE_VERSION_CHECK=0 и др. сбрасывались на дефолты при apply новой версии). Conf загружается ДО объявления дефолтов в установщике.
- **v3.14.0** — GitHub auto-sync custom.txt (каждые 6ч) + version check для shieldnode.sh + guard CLI settings menu `[s]`. Команды `sudo guard upgrade/sync/check`. Двухфайловая модель: `custom.txt` (github sync) + `custom-local.txt` (локальные дополнения)
- **v3.13.2** — hotfix: миграция legacy-артефактов от ≤v3.12.x при reinstall (старые update-scanner-blocklist.sh, scanner-blocklist-update.timer и т.п. чистятся автоматически)
- **v3.13.1** — hotfix: mobile-RU whitelist выше blocklist drops, удалён мёртвый counter, observability `[shield:mobile_ru_drop]`
- **v3.13.0** — mobile-RU AS whitelist (МТС, T2, МегаФон, Билайн через MaxMind)
- **v3.12.0** — blocklists архитектура (universal updater, file+URL union, ASN guard column), CGNAT-fix (ct=400, 500/min, 15min)
- **v3.11.x** — Tor exit blocklist, multiline smoke fix
- v3.10.x — fib anti-spoof, TCP MSS clamping
- v3.5–v3.9 — HTTP-flood защита, ban-once архитектура, sqlite aggregator

## Лицензия

MIT — см. [LICENSE](./LICENSE).
