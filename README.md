# awgproxy

Прокси AmneziaWG для запуска в контейнере **RouterOS 7.23**, два режима работы:

- **server (1:N)** — точка входа для внешних AmneziaWG-клиентов; за прокси стоит
  нативный WG-сервер RouterOS. Аналог
  [amneziawg-mikrotik-c](https://github.com/timbrs/amneziawg-mikrotik-c), но список
  клиентов берётся **динамически с роутера через REST API**.
- **client (1:1)** — роутер выступает AmneziaWG-клиентом: WG-out с роутера заворачивается
  dst-nat-правилом в контейнер, обфусцируется и уходит во внешний AmneziaWG-сервер.

## Как работает

Режим **server**:
```
AWG-клиенты ──(обфусцир. UDP)──▶ awgproxy :listen ──(чистый WG)──▶ RouterOS WG-сервер :remote_port
            ◀─(обфускация назад)── awgproxy ◀──(чистый WG)─────────┘
```
Режим **client**:
```
RouterOS WG-out ──(dst-nat в контейнер)──▶ awgproxy ──(обфусцир. UDP)──▶ внешний AmneziaWG-сервер
                ◀──(чистый WG обратно)──── awgproxy ◀────(обфускация)────┘
```

- Входящий обфусцированный пакет: снимается junk/префиксы `S1/S2`, заголовок `H1..H4`
  → стандартный тип WireGuard, **пересчитывается MAC1** (ключ — pubkey получателя),
  пакет уходит дальше.
- Ответ: тип → `H1..H4`, **MAC1 пересчитывается** под pubkey второй стороны,
  добавляется префикс, пакет уходит по адресу из таблицы сессий.
- Каждые `poll_interval_sec` сервис читает с роутера через **REST API** pubkey
  WG-интерфейса, список пиров и адреса интерфейсов (для авто-NAT и автоопределения
  параметров).

## Конфигурация

Конфиг — файл `config.json`, лежащий **рядом с бинарником** (в контейнере — `/app/config.json`).
Монтируется в режиме **rw** — его правит веб-интерфейс настройки. Образец —
[config.example.json](config.example.json).

Рабочие профили вынесены в секции `server` и `client`. Активен профиль, указанный в `mode`.
Валидация **по секциям**: сохранять блок «Роутер» можно независимо от остальных полей —
прокси-стек поднимется, как только все нужные данные появятся.

| Поле | Обяз. | По умолч. | Назначение |
|---|---|---|---|
| `mode` | | `server` | `server` или `client` |
| `web_listen` | | `:8088` | адрес веб-интерфейса настройки |
| `log_level` | | `info` | `debug`/`info`/`warn`/`error`/`none` |

**Секция `server`** (когда `mode=server`):

| Поле | Обяз. | По умолч. | Назначение |
|---|---|---|---|
| `server.listen` | | `:51820` | UDP-порт прокси для внешних клиентов |
| `server.remote_addr` | ✔ | | локальный WG-сервер RouterOS, напр. `172.17.0.1` |
| `server.remote_port` | ✔ | | `listen-port` WG-сервера (подставляется автоматически при выборе интерфейса) |
| `server.public_endpoint` | | | `host:port` для генерации клиентских конфигов/QR |
| `server.container_addr` | при `divert` | | IP контейнера на veth — используется как to-address авто-управляемого dst-nat |
| `server.divert` | | `false` | сервис сам создаёт/снимает dst-nat-правило, публикующее `listen` наружу |
| `server.masquerade` | | `false` | сервис сам создаёт srcnat-masquerade для сети WG-интерфейса |
| `server.client_dns` | | | DNS в клиентском конфиге (опц.) |
| `server.session_ttl_sec` | | `180` | TTL неактивной сессии |
| `server.poll_interval_sec` | | `30` | период опроса роутера |
| `server.obfuscation.jc/jmin/jmax` | | `4/40/70` | junk-пакеты перед init |
| `server.obfuscation.s1/s2` | | `0/0` | junk-префикс init / response |
| `server.obfuscation.h1..h4` | | `1/2/3/4` | магические заголовки типов |
| `server.router.*` | | | доступ к роутеру (см. ниже) |
| `server.router.wg_iface` | ✔ | | WG-интерфейс роутера (его пиры обслуживает прокси) |

**Секция `client`** (когда `mode=client`):

| Поле | Обяз. | По умолч. | Назначение |
|---|---|---|---|
| `client.listen` | | `:51820` | UDP-порт прокси, на который указывает dst-nat роутера |
| `client.container_addr` | ✔ | | IP контейнера на veth (to-address dst-nat-правила) |
| `client.divert` | | `true` | сервис сам поддерживает dst-nat (`chain=output`), заворачивающий wg-out в контейнер |
| `client.masquerade` | | `false` | сервис сам создаёт srcnat-masquerade для сети WG-интерфейса |
| `client.session_ttl_sec` | | `180` | TTL неактивной сессии |
| `client.poll_interval_sec` | | `30` | период опроса роутера |
| `client.obfuscation.*` | | | параметры обфускации (берутся из конфига внешнего AmneziaWG-сервера) |
| `client.router.*` | | | доступ к роутеру (см. ниже) |
| `client.router.wg_iface` | ✔ | | клиентский WG-интерфейс роутера — его трафик заворачивается в прокси. Адрес апстрима AmneziaWG берётся из помеченного `[awgproxy]` пира этого интерфейса |

**Подсекция `router`** (одинаковая для `server` и `client`):

| Поле | Обяз. | По умолч. | Назначение |
|---|---|---|---|
| `router.address` | ✔ | | хост роутера без порта (обычно gateway на veth) |
| `router.api_port` | | `443` | порт REST API (`/ip/service www` или `www-ssl`) |
| `router.api_tls` | | `false` | REST API по HTTPS (TLS-сертификат не проверяется) |
| `router.user` | | `admin` | пользователь RouterOS |
| `router.password` | ✔ | | пароль |
| `router.wg_iface` | | | задаётся в секции режима, см. выше |

Доступ к роутеру — только через **REST API** RouterOS (`/rest/...`).
Значения `obfuscation.*` должны совпадать с профилем AmneziaWG второй стороны.

### NAT-правила, которыми управляет сервис

При включённых тогглах сервис сам поддерживает на роутере минимально необходимые
правила и помечает их комментарием с суффиксом по имени WG-интерфейса
(`awgproxy-divert:<iface>` / `awgproxy-masquerade:<iface>`) — поэтому два контейнера
на одном роутере **не мешают** правилам друг друга.

- `divert` (`server`): `chain=dstnat`, внешний порт `public_endpoint` → `container_addr:listen`.
- `divert` (`client`): `chain=output`, исходящий WG-трафик роутера на апстрим
  → `container_addr:listen`.
- `masquerade`: `chain=srcnat`, `src-address` = сеть WG-интерфейса.

## Веб-интерфейс

Сервис поднимает веб-панель настройки на `web_listen` (по умолч. `:8088`), фронтенд
встроен в бинарник, интерфейс на одной странице (en/ru). Через неё правится `config.json`
(rw-монтирование) и виден статус опроса роутера (poll, ключ сервера, число клиентов).
Изменения применяются **сразу** — прокси-стек перезапускается на лету без рестарта
контейнера (кроме смены `web_listen`). Недоступность роутера не роняет сервис.
Опубликуйте порт `web_listen` наружу через dst-nat на адрес veth.

Каждый раздел («Роутер», «Сервис», «Пиры») сохраняется и валидируется **независимо**:
сначала можно подключить роутер — остальная конфигурация подтянется и допишется через UI.

**Вход:** логин/пароль — те же, что у роутера; проверяются REST-запросом
к роутеру (`/rest/system/identity`). Сессия живёт 12 ч (в куке, не переживает рестарт
контейнера). Если `router.address` не задан **или роутер недоступен**
(быстрый TCP-пинг перед входом), авторизация отключается и панель открыта без
входа — чтобы не запереть себя при лежащем роутере. Перебор пароля ограничен:
после 5 неудач подряд с одного IP вход блокируется на 5 минут. На странице «Роутер»
неверные креды **не** редиректят на логин — поля можно поправить и сохранить заново.

### Авто-определение и подстановки

Возле большинства сетевых полей есть пиктограмма **⌖ «определить автоматически»**:

- `router.address`, `server.remote_addr` — gateway контейнера (из `/proc/net/route`);
- `container_addr` — первый IPv4 контейнера;
- `server.remote_port` — `listen-port` выбранного WG-интерфейса (читается с роутера);
- `public_endpoint.host` (кнопка **▾**) — выпадающий список IP-адресов интерфейсов
  роутера (стилизованный, не нативный datalist).

При выборе `wg_iface` сервисный порт подставляется автоматически (можно перебить вручную —
ручное значение не затрагивается).

### Управление пирами

Вкладка **Пиры** показывает пиров выбранного интерфейса (`wg_iface`) и позволяет
добавлять/править/удалять их и включать-выключать. Операции идут через REST API
(`/rest/interface/wireguard/peers`).
Редактируемые поля: `name`, `comment`, `allowed-address`, `endpoint-address/port`,
`persistent-keepalive`, `preshared-key`. Кнопка **Сгенерировать** создаёт пару ключей
WireGuard локально (curve25519): публичный подставляется в пира, приватный показывается
один раз для передачи клиенту и нигде не сохраняется.

При добавлении нового пира `allowed-address` **предлагается автоматически** — берётся
первый свободный IP из подсети WG-интерфейса (учитываются адреса самого интерфейса
и всех существующих пиров). При сохранении проверяется конфликт адресов — пира с уже
занятым IP создать нельзя.

В **client**-режиме пир можно пометить как `[awgproxy]` (тогглом «Через прокси») —
его endpoint становится апстримом, на который прокси шлёт обфусцированный трафик.

После создания нового пира со сгенерированным ключом открывается окно с **QR-кодом** и
готовым клиентским конфигом AmneziaWG (с параметрами обфускации, `public_endpoint` и
публичным ключом сервера) — его можно отсканировать или скачать `.conf`. Для этого должен
быть задан `server.public_endpoint`.

Доступен **импорт** конфига AmneziaWG (.conf / QR-картинка / вставленный текст) для
client-режима — приватный ключ и адрес интерфейса автоматически применяются к выбранному
WG-out (с нормализацией маски `/32 → /24`, чтобы маршрут к соседям по сети поднимался).

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
