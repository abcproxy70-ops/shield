# shieldnode

Bash-скрипт DDoS-защиты для VPN-нод (Reality / Xray / sing-box / Hysteria2 / WireGuard).

Стек: **nftables + CrowdSec + UFW**. Целевые ОС: Ubuntu 22.04 / 24.04, Debian 12 / 13.

## Архитектура (v3.23.0)

**Чистое разделение зон ответственности с vpn-node-setup:**

- shieldnode владеет: scanner blocklist, rate-limit, ct count, fib anti-spoof, CrowdSec, security sysctl (rp_filter, syncookies, redirects, icmp, tcp_rfc1337, log_martians, conntrack UDP timeouts)
- vpn-node-setup владеет: kernel (XanMod LTS), BBR, qdisc fq, buffers (TCP+UDP), MSS clamp, NIC tuning, conntrack max + TCP timeouts

Никаких пересечений в netfilter pipeline. Двойного MSS clamp нет.

**Изменения v3.23.0 vs v3.22.0:**

- `log_martians = 0` (было 1) — на VPN forwarder с rp_filter=2 (loose) martians = нормальный шум маршрутизации. Логирование грузило rsyslog/journald, косвенно влияя на softirq scheduling.
- `nf_conntrack_udp_timeout_stream = 600` (было 300) — mobile QUIC/Hysteria2 клиенты в background (Android Doze, iOS suspended) теперь дольше держат state, меньше "freeze on resume" при reconnect.
- `tcp_synack_retries = 3` (было 2) — для intercontinental клиентов (RU/Asia → DE/SE) с RTT 200-400ms и пакетлоссом 2 retry мало (~3 сек до отказа handshake). SYN cookies продолжают защищать от SYN-flood независимо.
- `SHIELDNODE_VERBOSE_LOGS=0` по умолчанию — раньше все drop-rules имели `log prefix [shield:*]` → ~3000 events/hour. Теперь только counter (guard CLI работает как раньше). Для debug: `SHIELDNODE_VERBOSE_LOGS=1 sudo bash shieldnode.sh`.

**Лимиты v3.22.0 рассчитаны на ноду с 500-1000 VPN-клиентами (сохранены в v3.23.0):**

- **conn_flood**: `ct count over 50000` per-IP (CGNAT-провайдеры РФ держат до 200 абонентов за одним public IPv4 через PAT — на peak ~30k entries/IP)
- **newconn rate**: 40000/min, burst 60000 (массовый reconnect 200 юзеров × 50 retry/min = 10000/min sustained)
- **SYN flood**: 2000/sec, burst 3000 (CGNAT × 200 юзеров × 1-2 SYN/sec = 200-400/sec baseline)
- **UDP flood**: 10000/sec, burst 20000 (QUIC/HTTP3 + Hysteria2 + WireGuard handshakes)
- **SSH per-IP**: ct=5 + 8/min burst 20 (CGNAT-админы + ansible deploy на ≤5 нод параллельно)

Реальные DDoS-атаки 50k+ SYN/sec, 100k+ connections — drop на kernel level. Ban-once архитектура: первое нарушение → suspect (30 мин наблюдения без drop), второе → confirmed (15 мин drop).

**Требует:** `net.netfilter.nf_conntrack_max >= 262144` (Ubuntu 24.04 default OK на нодах ≥1GB RAM; vpn-node-setup v5.1.0+ ставит tier-aware значения 262k/786k/1M/2M в зависимости от RAM).

## Возможности

- **nftables rate-limit** (kernel-level, IPv4-only): SYN-flood, UDP-flood, conn-flood, newconn-rate
- **SSH pre-auth flood protection**: ct count + rate limit прямо на nft, защита от slowloris до того как пакеты дойдут до sshd
- **TCP flag sanity**: drop XMAS, NULL, SYN+FIN, SYN+RST, FIN+RST scan-пакетов
- **Anti-spoofing**: fib reverse-path (single-homed VPS)
- **Infrastructure bypass**: ~220 CIDR крупных CDN/cloud (Cloudflare, Google, AWS, Azure, Apple, Meta, Akamai, Fastly, GitHub, Telegram, Yandex, VK, Selectel) проходят без rate-limit и не попадают в events.db как "атакующие"
- **4 blocklist'а**:
  - `scanner` — Shodan, Censys, госсканеры РФ (shadow-netlab + CyberOK_Skipa + MISP)
  - `threat` — Spamhaus DROP + FireHOL Level 1 (high-confidence криминал)
  - `tor` — Tor exit nodes (опционально, `BLOCK_TOR=1`)
  - `custom` — личный список оператора (file-based + URL union)
- **GitHub auto-sync**: `lists/custom.txt` синкается с репо каждые 6ч. Локальные дополнения — в `custom-local.txt`, не перезаписываются.
- **CrowdSec** + nftables bouncer (SSH brute-force + community blocklist ~28k IP)
- **guard CLI** — дашборд защиты с ASN/owner column для top attackers, settings menu, upgrade/rollback
- **Aggregator**: журналы → sqlite events.db с per-IP analytics
- **Auto-detect портов** из UFW + inotify path-watcher (мгновенный sync) + 5-min catch-all timer

## Установка

```bash
curl -fL https://raw.githubusercontent.com/abcproxy70-ops/shield/main/shieldnode.sh | sudo bash
```

> ⚠️ Use `curl | sudo bash` вместо `bash <(curl ...)` — process substitution не
> работает на OpenVZ/LXC контейнерах и некоторых embedded environments.

## Совместимость

- Работает рядом с **vpn-node-setup v5.1.0+** (рекомендуется порядок: **vpn-node-setup первым, потом shieldnode**)
- Совместим с UFW (читает open ports автоматически)
- Совместим с любыми VPN-стэками (Xray Reality, sing-box, Hysteria2, WireGuard, AmneziaWG)

## Удаление

```bash
curl -fL https://raw.githubusercontent.com/abcproxy70-ops/shield/main/shieldnode.sh | sudo bash -s -- --uninstall
```

## guard CLI

```bash
sudo guard            # дашборд защиты с интерактивным меню
sudo guard --once     # снимок без меню (для cron / мониторинга)
sudo guard --json     # JSON-вывод для интеграций (Zabbix, Prometheus)
sudo guard upgrade    # re-install с github (auto-snapshot для rollback)
sudo guard rollback   # откатиться к предыдущему snapshot'у
sudo guard sync       # синк custom.txt прямо сейчас
```

## Версии

- **v3.23.0** — LOG NOISE & UDP UX:
  - `log_martians = 0` (было 1) — на VPN forwarder martians = шум маршрутизации, не сигнал атаки
  - `nf_conntrack_udp_timeout_stream = 600` (было 300) — mobile QUIC/Hysteria background sessions
  - `tcp_synack_retries = 3` (было 2) — intercontinental RTT 200-400ms нужен запас
  - `SHIELDNODE_VERBOSE_LOGS=0` default — counter-only mode без log prefix, ~3k events/hour убираются
- **v3.22.0** — ROBUSTNESS PACK + SECURITY TUNING для 500-1000 клиентов на ноде:
  - **Лимиты подняты под реальный CGNAT load** (МТС/T2/Beeline/Tele2 200+ абонентов/IP): conn_flood 5000→50000, newconn 5000→40000/min, syn 300→2000/sec, udp 1500→10000/sec, ssh ct=3→5
  - **Aggregator robustness**: `journalctl --lines=500000` cap (защита от RAM blow-up под штормом 100k+ events/min), `PRAGMA busy_timeout=5000` (защита от SQLITE_BUSY race с guard)
  - **protected-ports timer 60s → 5min**: path-unit (inotify) ловит изменения мгновенно, timer остался как catch-all, экономия ~15% CPU на 1GB нодах
  - **guard ASN lookup**: curl timeout 2s → 0.5s + offline-mode fallback (top attackers больше не лагает на 40 сек при недоступности ipinfo.io)
  - **cleanup VACUUM**: Nice=19 + IOSchedulingClass=idle (не блокирует sshd/Xray logs на shared-disk VPS)
  - **unban_all**: + `conntrack -D -s <ip>` (FP-разбан реально работает на extreme-CGNAT)
  - **healthcheck timeouts**: `timeout 5 cscli ...` + sqlite fallback (быстрее install на нодах с ~28k CAPI decisions)
  - **Cleanup**: удалены dead counters mobile_ru_*/broadband_ru_*, changelog history >1600 строк (история в git)
- **v3.21.x** — SSH pre-auth flood defense, infrastructure_v4 bypass для CDN/cloud (~220 CIDR), Google 192.178/16 в baseline, log dedup (rsyslog kern.none + journald limits), DB cleanup (events.db + asn_cache).
- **v3.20.x** — SIMPLIFICATION (убраны mobile-RU/broadband-RU whitelist'ы), arch simplification (MSS clamp → vpn-node-setup), WHITELIST CONSISTENCY (TRUSTED_IPS через все 3 слоя), aggressive logrotate.
- **v3.18.x** — TRUSTED_IPS feature, UFW-FIX, post-audit hardening, foreign CrowdSec detection.
- **v3.14.0** — GitHub auto-sync custom.txt + version check + guard settings menu.
- **v3.12.0** — blocklists архитектура (universal updater, file+URL union).
- **v3.10.x** — fib anti-spoof, TCP MSS clamping.

Полная история: https://github.com/abcproxy70-ops/shield/commits/main/shieldnode.sh

## Лицензия

MIT — см. [LICENSE](./LICENSE).
