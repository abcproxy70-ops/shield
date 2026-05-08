# shieldnode blocklists

Файлы в этом каталоге — seed-данные для встроенных blocklist'ов shieldnode.

При установке через `bash <(curl ...)` они автоматически скачиваются в
`/etc/shieldnode/lists/` на сервере. При git-clone установке — копируются
из `./lists/`.

## Файлы

| Файл          | nft set                  | Назначение                                    |
|---------------|--------------------------|-----------------------------------------------|
| `scanner.txt` | `scanner_blocklist_v4`   | Известные сканеры (Shodan, Censys, gov)       |
| `threat.txt`  | `threat_blocklist_v4`    | Spamhaus DROP, FireHOL Level 1                |
| `tor.txt`     | `tor_exit_blocklist_v4`  | Tor exit nodes (активен при `BLOCK_TOR=1`)    |
| `custom.txt`  | `custom_blocklist_v4`    | Личный список оператора                       |

## Формат

Один IP или CIDR на строку. Комментарии начинаются с `#`. Пустые строки
игнорируются.

```
# Это комментарий
8.8.8.8
1.2.3.0/24
192.0.2.5
203.0.113.0/24    # inline-комментарий тоже работает
```

Поддерживаются также форматы:

* **Spamhaus**: `1.2.3.0/24 ; SBL12345` — символ `;` и всё после игнорируется
* **FireHOL**: блоки `# header`-комментариев в начале файла
* **MISP/CIRCL JSON**: `{"list": ["1.2.3.0/24", ...]}` — извлекается через `jq`

## Sanity-фильтр

Updater автоматически отсеивает:

* prefix `< 8` (слишком широко — сотни миллионов IP)
* bogons: `0/8`, `10/8`, `127/8`, `169.254/16`, `172.16-31/12`, `192.168/16`
* multicast и reserved: `224.0.0.0/3`

## Объединение local + URL

Каждый set — это **union** локального файла и (опциональных) URL-источников
из `/etc/shieldnode/shieldnode.conf`. Дефолтные URL'ы:

* `scanner` — shadow-netlab/traffic-guard-lists, tread-lightly/CyberOK_Skipa_ips
* `threat` — Spamhaus DROP, FireHOL Level 1
* `tor` — check.torproject.org/torbulkexitlist
* `custom` — только локальный файл (URL по умолчанию нет)

## Обновление

После изменения `custom.txt` на сервере updater запускается **мгновенно**
через systemd path-watcher (inotify). Остальные blocklist'ы обновляются
по таймеру:

| Set     | Интервал |
|---------|----------|
| scanner | 6 часов  |
| threat  | раз в день |
| tor     | 1 час    |
| custom  | 6 часов + path-watcher |

Принудительно:

```bash
sudo systemctl start shieldnode-update@scanner.service
sudo systemctl start shieldnode-update@threat.service
sudo systemctl start shieldnode-update@tor.service
sudo systemctl start shieldnode-update@custom.service
```

## Защита от corruption

Если все URL'ы недоступны **И** нет локального файла — old set остаётся
как есть. После 3 подряд провалов set очищается (stale-data protection).

Если результат меньше `MIN_ENTRIES_*` — set не обновляется (защита от
supply-chain атаки на upstream).

## Просмотр текущего состояния

```bash
# Сколько IPs в каждом set'е
sudo nft list set inet ddos_protect scanner_blocklist_v4 | wc -l
sudo nft list set inet ddos_protect threat_blocklist_v4  | wc -l
sudo nft list set inet ddos_protect tor_exit_blocklist_v4 | wc -l
sudo nft list set inet ddos_protect custom_blocklist_v4  | wc -l

# Лог последнего обновления
sudo journalctl -t shieldnode-update-scanner --since "1 hour ago"
```

## Edit на проде

Чтобы добавить IP в `custom`-список на работающей ноде:

```bash
echo '198.51.100.42' | sudo tee -a /etc/shieldnode/lists/custom.txt
# inotify подхватит изменение за <1 секунды → updater → nft set
```
