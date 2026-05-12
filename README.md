# shieldnode

Bash-скрипт DDoS-защиты для VPN-нод (Reality / Xray / sing-box / Hysteria2).

Стек: **nftables + CrowdSec + UFW**. Целевые ОС: Ubuntu 22.04 / 24.04, Debian 11 / 12.

## Архитектура (v3.20.5)

**Чистое разделение зон ответственности с vpn-node-setup:**

- shieldnode владеет: scanner blocklist, rate-limit, ct count, fib anti-spoof, CrowdSec, security sysctl (rp_filter, syncookies, redirects, icmp, tcp_rfc1337, log_martians, conntrack UDP timeouts)
- vpn-node-setup владеет: kernel (XanMod LTS), BBR, qdisc fq, buffers, MSS clamp, NIC tuning

Никаких пересечений в netfilter pipeline. Двойного MSS clamp нет.

**Защита для всех IP без whitelist'ов:**

- **conn_flood**: ct count over 5000 (extreme CGNAT support)
- **newconn rate**: 5000/min, burst 8000
- **SYN flood**: 300/sec, burst 500 (kernel rate-limit)
- **UDP flood**: 1500/sec, burst 3000

99.5% пользователей не упираются в лимиты. Реальные DDoS-атаки 5000+ concurrent/IP — drop на kernel level.

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
bash <(curl -sL https://raw.githubusercontent.com/abcproxy70-ops/shield/main/shieldnode.sh)
```

## Совместимость

- Работает рядом с **vpn-node-setup v5.0.5+** (рекомендуется ставить порядком: shieldnode → vpn-node-setup)
- Совместим с UFW (читает open ports автоматически)
- Совместим с любыми VPN-стэками (Xray Reality, sing-box, Hysteria2, WireGuard)

## Удаление

```bash
sudo bash <(curl -sL https://raw.githubusercontent.com/abcproxy70-ops/shield/main/shieldnode.sh) --uninstall
```

## guard CLI

```bash
sudo guard          # дашборд защиты с интерактивным меню
sudo guard --once   # снимок без меню (для cron / мониторинга)
sudo guard --json   # JSON-вывод для интеграций (Zabbix, Prometheus)
```

## Версии

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
