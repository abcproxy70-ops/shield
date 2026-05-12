# shieldnode blocklists

Seed-файлы для blocklist'ов shieldnode. На ноде они кладутся в
`/etc/shieldnode/lists/` и автоматически объединяются с URL-источниками
(union, дедупликация).

## Структура

```
lists/
├── scanner.txt       — известные сканеры (Shodan, Censys, госсканеры РФ)
├── threat.txt        — high-confidence криминальные IP (botnet C2, ransomware)
├── tor.txt           — Tor exit nodes (применяется только если BLOCK_TOR=1)
└── custom.txt        — личный список оператора (синкается с github каждые 6ч)
```

## Формат файла

Один IP или CIDR на строке. Комментарии через `#`. Пустые строки игнорируются.

```
# Пример
198.51.100.42
203.0.113.0/24
192.0.2.0/28
```

## Custom list

`lists/custom.txt` — особый файл:
- **На GitHub** хранится этот файл (синкается с нодами каждые 6ч)
- **На ноде** автоматически качается в `/etc/shieldnode/lists/custom.txt`
  (read-only от sync — НЕ редактируй вручную, перезатрётся)
- **Локальные дополнения** оператор кладёт в `/etc/shieldnode/lists/custom-local.txt`
  (не синкается, остаётся на ноде)

### Добавить IP в custom на работающей ноде

```bash
# Постоянное добавление (переживает reboot):
echo '198.51.100.42' | sudo tee -a /etc/shieldnode/lists/custom-local.txt
# inotify path-watcher подхватит за <1 секунды

# Временное добавление (до перезагрузки nft):
sudo nft add element inet ddos_protect custom_blocklist_v4 { 198.51.100.42 }
```

### Удалить IP из custom

```bash
# Из локального файла:
sudo sed -i '/^198\.51\.100\.42$/d' /etc/shieldnode/lists/custom-local.txt
# Path-watcher уберёт из nft set за <1 секунды

# Если IP в синкаемом custom.txt — нужен PR в github репо или
# временное удаление до следующего sync:
sudo nft delete element inet ddos_protect custom_blocklist_v4 { 198.51.100.42 }
```

## Default URL-источники

Если seed-файлы пустые, shieldnode скачивает blocklist'ы с публичных URL:

### scanner
- [shadow-netlab/traffic-guard-lists](https://github.com/shadow-netlab/traffic-guard-lists) — общие сканеры (Shodan, Censys)
- [tread-lightly/CyberOK_Skipa_ips](https://github.com/tread-lightly/CyberOK_Skipa_ips) — российские госсканеры (SKIPA, ГРЧЦ, НКЦКИ)

### threat
- [Spamhaus DROP](https://www.spamhaus.org/drop/drop.txt) — high-confidence криминал
- [FireHOL Level 1](https://iplists.firehol.org/files/firehol_level1.netset) — bogon networks + блекхолы

### tor
- [Tor Project exit list](https://check.torproject.org/torbulkexitlist) — официальный список exit-нодов

## Override URL-источников

В `/etc/shieldnode/shieldnode.conf` можно переопределить `REMOTE_BLOCKLISTS`
для использования своих источников. См. [shieldnode.conf.example](../shieldnode.conf.example).

## Sync интервалы

| Set | Интервал | Триггер |
|---|---|---|
| scanner | 6h | systemd timer |
| threat | 1d | systemd timer |
| tor | 1h | systemd timer (только если `BLOCK_TOR=1`) |
| custom | 6h | systemd timer + inotify path-watcher на локальный файл |

## Проверка состояния

```bash
# Сколько IP в каждом set:
sudo nft list set inet ddos_protect scanner_blocklist_v4 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?' | wc -l

# Последний sync:
sudo systemctl status shield-blocklist-update.timer
sudo journalctl -u shield-blocklist-update.service -n 20

# Через guard:
sudo guard --once  # покажет blocklist sizes и last sync time
```
