# awgproxy

Серверный (1:N) прокси AmneziaWG для запуска в контейнере **RouterOS 7.23**.
Аналог [amneziawg-mikrotik-c](https://github.com/timbrs/amneziawg-mikrotik-c),
но список клиентов берётся **динамически с самого роутера через REST API**.

## Как работает

```
AWG-клиенты ──(обфусцир. UDP)──▶ awgproxy :AWG_LISTEN ──(чистый WG)──▶ RouterOS WG-сервер :AWG_REMOTE
            ◀─(обфускация назад)── awgproxy ◀──(чистый WG)─────────────┘
```

- Входящий пакет: снимается junk/префиксы `S1/S2`, заголовок `H1..H4` → стандартный тип
  WireGuard, **пересчитывается MAC1** (ключ — pubkey интерфейса роутера), пакет уходит
  на локальный WG-сервер.
- Ответ: тип → `H1..H4`, **MAC1 пересчитывается** под pubkey клиента, добавляется префикс,
  пакет уходит клиенту (адрес из таблицы сессий).
- Каждые `poll_interval_sec` сервис читает с роутера через **REST API** pubkey WG-интерфейса
  и pubkey всех пиров (актуальный список клиентов).

## Конфигурация

Конфиг — файл `config.json`, лежащий **рядом с бинарником** (в контейнере — `/app/config.json`).
Монтируется в режиме **rw** (в дальнейшем его будет править HTTP-сервер/фронтенд настройки).
Образец — [config.example.json](config.example.json).

Рабочий профиль вынесен в секцию `server` (под будущий режим `client`).

| Поле | Обяз. | По умолч. | Назначение |
|---|---|---|---|
| `mode` | | `server` | режим работы (пока только `server`) |
| `web_listen` | | `:8088` | адрес веб-интерфейса настройки |
| `log_level` | | `info` | `debug`/`info`/`warn`/`error`/`none` |
| `server.listen` | | `:51820` | UDP-адрес для клиентов |
| `server.remote_addr` | ✔ | | адрес локального WG-сервера RouterOS, напр. `172.17.0.1` |
| `server.remote_port` | ✔ | | `listen-port` WG-сервера, напр. `13231` |
| `server.public_endpoint` | | | `host:port` прокси; нужен для клиентских конфигов/QR |
| `server.client_dns` | | | DNS в клиентском конфиге (опц.) |
| `server.session_ttl_sec` | | `180` | TTL неактивной сессии |
| `server.poll_interval_sec` | | `30` | период опроса роутера |
| `server.obfuscation.jc/jmin/jmax` | | `4/40/70` | junk-пакеты перед init |
| `server.obfuscation.s1/s2` | | `0/0` | junk-префикс init / response |
| `server.obfuscation.h1..h4` | | `1/2/3/4` | магические заголовки типов |
| `server.router.address` | ✔ | | хост роутера без порта, напр. `172.17.0.1` |
| `server.router.api_port` | | `443` | порт REST API RouterOS |
| `server.router.api_tls` | | `false` | REST API по HTTPS (`www-ssl`) |
| `server.router.user` | | `admin` | пользователь |
| `server.router.password` | ✔ | | пароль |
| `server.router.wg_iface` | ✔ | | имя WG-интерфейса на роутере |

Доступ к роутеру — только через **REST API** RouterOS (`/rest/...`).
Значения `server.obfuscation.*` должны совпадать с настройками AmneziaWG-сервера/клиентов.

## Веб-интерфейс

Сервис поднимает веб-панель настройки на `web_listen` (по умолч. `:8088`), фронтенд
встроен в бинарник, интерфейс на одной странице (en/ru). Через неё правится `config.json`
(rw-монтирование) и виден статус опроса роутера (poll, ключ сервера, число клиентов).
Изменения применяются **сразу** — прокси-стек перезапускается на лету без рестарта
контейнера (кроме смены `web_listen`). Недоступность роутера не роняет сервис.
Опубликуйте порт `web_listen` наружу через dst-nat на адрес veth.

**Вход:** логин/пароль — те же, что у роутера; проверяются REST-запросом
к роутеру (`/rest/system/identity`). Сессия живёт 12 ч (в куке, не переживает рестарт
контейнера). Если `server.router.address` не задан **или роутер недоступен**
(быстрый TCP-пинг перед входом), авторизация отключается и панель открыта без
входа — чтобы не запереть себя при лежащем роутере. Перебор пароля ограничен:
после 5 неудач подряд с одного IP вход блокируется на 5 минут.

### Управление пирами

Вкладка **Пиры** показывает пиров выбранного интерфейса (`wg_iface`) и позволяет
добавлять/править/удалять их и включать-выключать. Операции идут через REST API
(`/rest/interface/wireguard/peers`).
Редактируемые поля: `name`, `comment`, `allowed-address`, `endpoint-address/port`,
`persistent-keepalive`, `preshared-key`. Кнопка **Сгенерировать** создаёт пару ключей
WireGuard локально (curve25519): публичный подставляется в пира, приватный показывается
один раз для передачи клиенту и нигде не сохраняется.

После создания нового пира со сгенерированным ключом открывается окно с **QR-кодом** и
готовым клиентским конфигом AmneziaWG (с параметрами обфускации, `public_endpoint` и
публичным ключом сервера) — его можно отсканировать или скачать `.conf`. Для этого должен
быть задан `server.public_endpoint`.

## Сборка

Через `make` (см. `make` без аргументов для списка целей):

```sh
make tidy             # обновить go.mod/go.sum
make save-amd64       # образ + архив под нужную арку: save-amd64 / save-arm64 / save-arm
```

`save-*` собирает образ (buildx), репакует в классический docker-archive (его понимает
RouterOS) и пишет `awgproxy-<version>-<build>-<arch>.tar.gz`. Номер сборки авто-инкрементится
в файле `.build`; версия/номер видны в футере веб-интерфейса.

Узнать архитектуру роутера: `/system resource print` (поле `architecture-name`):
`arm` → `save-arm` (armv7), `arm64` → `save-arm64`, `x86_64` → `save-amd64`.

## Деплой в RouterOS 7.23 (client-mode)

1. Включить контейнеры: `/system/device-mode/update container=yes` (потребует подтверждения).
2. Cоздаем диск в оперативке для контейнеров
   ```
   /disk add type=tmpfs tmpfs-max-size=100M slot=ram
   ```
3. veth и сеть:
   ```
    /interface/bridge add name=docker port-cost-mode=short
    /ip/address/add address=192.168.100.1/24 interface=docker
   
    /interface/veth add address=192.168.100.3/24 gateway=192.168.100.1 name=awg-proxy-go-client
    /interface/bridge/port add bridge=docker interface=awg-proxy-go-client
   ```
4. Залить `.tar.gz` на роутер (Files/scp) и добавить контейнер:
   ```
    /file/add name=/awg-proxy-go/config-client.json
    /container/mounts/add src=/awg-proxy-go/config-client.json dst=/app/config.json list=awgcfg-client
    /container/add file=awgproxy-0.0.1-0011-amd64.tar.gz interface=awg-proxy-go-client hostname=awg-proxy-go-client root-dir=ram/awg-proxy-client logging=yes start-on-boot=yes workdir=/ name="awg-proxy-go-client" mountlists=awgcfg-client
    /container/start awg-proxy-go-client
   ```
   Без `mounts`/`mountlists` контейнер запустится со встроенным дефолтным
   `config.json` из образа, и веб-настройки не сохранятся между рестартами.

5. Добавляем пользователя с правами на чтение и запись, ограничиваем доступ по ip контейнера
   ```
    /user/add address=192.168.100.2 group=write name=awg-proxy-go password=super_password
   ```
6. Добавляем проброс порта веб-морды к контейнеру
   ```    
    /ip firewall nat add action=dst-nat chain=dstnat dst-port=8089 in-interface=ether1 protocol=tcp to-addresses=192.168.100.3 to-port=8088
   ```

7. На роутере поднять нативный WireGuard-сервер `wg-awg`, настроить ему адрес.
   ```
    /interface/wireguard/add name=wg-awg-client
    /ip/address/add address=172.17.0.1/24 interface=wg-awg-client
   ```
8. Проверить доступ к роутеру по api: включить `/ip/service` `www-ssl` (HTTPS, порт 443) или `www`
   (HTTP, порт 80).
9. зайти в веб панель управления и настроить прокси по http://your-route-address:8088/ 

> ⚠️ Контейнер не проверяет TLS-сертификат REST API (доверенная сеть роутера).


## Деплой в RouterOS 7.23 (server-mode)

1. Включить контейнеры: `/system/device-mode/update container=yes` (потребует подтверждения).
2. Cоздаем диск в оперативке для контейнеров
   ```
   /disk add type=tmpfs tmpfs-max-size=100M slot=ram
   ```
3. veth и сеть:
   ```
    /interface/bridge add name=docker port-cost-mode=short
    /ip/address/add address=192.168.100.1/24 interface=docker
   
    /interface/veth add address=192.168.100.2/24 gateway=192.168.100.1 name=awg-proxy-go
    /interface/bridge/port add bridge=docker interface=awg-proxy-go
   ```
4. Залить `.tar.gz` на роутер (Files/scp) и добавить контейнер:
   ```
    /file/add name=/awg-proxy-go/config.json
    /container/mounts/add src=/awg-proxy-go/config.json dst=/app/config.json list=awgcfg
    /container/add file=awgproxy-0.0.1-0011-amd64.tar.gz interface=awg-proxy-go hostname=awg-proxy-go root-dir=ram/awg-proxy logging=yes start-on-boot=yes workdir=/ name="awg-proxy-go" mountlists=awgcfg
    /container/start awg-proxy-go
   ```
   Без `mounts`/`mountlists` контейнер запустится со встроенным дефолтным
   `config.json` из образа, и веб-настройки не сохранятся между рестартами.

5. Добавляем пользователя с правами на чтение и запись, ограничиваем доступ по ip контейнера
   ```
    /user/add address=192.168.100.2 group=write name=awg-proxy-go password=super_password
   ```
6. Добавляем проброс порта веб-морды к контейнеру
   ```    
    /ip firewall nat add action=dst-nat chain=dstnat dst-port=8088 in-interface=ether1 protocol=tcp to-addresses=192.168.100.2
   ```

7. На роутере поднять нативный WireGuard-сервер `wg-awg`, настроить ему адрес.
   ```
    /interface/wireguard/add name=wg-awg
    /ip/address/add address=172.16.0.1/24 interface=wg-awg
   ```
8. Проверить доступ к роутеру по api: включить `/ip/service` `www-ssl` (HTTPS, порт 443) или `www`
   (HTTP, порт 80).
9. зайти в веб панель управления и настроить прокси по http://your-route-address:8088/

> ⚠️ Контейнер не проверяет TLS-сертификат REST API (доверенная сеть роутера).


## Идентификация клиента (MAC1 ответа)

MAC1 ответа клиенту считается по pubkey конкретного клиента. Прокси определяет его двумя
способами:

- **Точно**, если роутер отдаёт приватный ключ WG-интерфейса (поле `private-key` в
  `/rest/interface/wireguard` или скриптовом `get`): из `init` расшифровывается
  `encrypted_static` → static-pubkey клиента известен сразу, без перебора.
- **Перебором (burst)**, если приватного ключа нет: ответ отправляется копиями под все
  известные pubkey-кандидаты, клиент примет копию с верным MAC1. Срабатывает один раз
  на сессию; при многих клиентах даёт небольшие всплески дублей на каждый handshake.

Поведение стоит проверить на живом AmneziaWG-клиенте.
