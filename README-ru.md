# credrelay

`credrelay` предоставляет freedesktop [Secret Service](https://specifications.freedesktop.org/secret-service/)
(`org.freedesktop.secrets`) на сессионной шине WSL и хранит все секреты в Windows Credential Manager.
Он занимает место gnome-keyring или KeePassXC на Linux-десктопе: Linux-приложения сохраняют через
него секреты так же, как в любом другом хранилище.

Если приложение выпускается для обеих систем и хранит секреты через известную библиотеку, Linux-сборка
видит то, что сохранила Windows-сборка, и наоборот. Сейчас это приложения на
[`zalando/go-keyring`](https://github.com/zalando/go-keyring), среди них `gh` и `glab`: залогинился
с одной стороны — залогинен и с другой.

Без Secret Service в WSL негде безопасно хранить токен: `gh` и `glab` откатываются на открытые файлы
(`~/.config/gh/hosts.yml`, `~/.config/glab-cli/config.yml`) и требуют отдельного логина, независимого
от Windows.

## Архитектура

- **`credrelay-client`** (WSL/Linux) владеет `org.freedesktop.secrets` на сессионной шине. При старте
  он ровно один раз запускает **`credrelay-server.exe`** и отправляет ему каждый запрос к кредам
  через stdin/stdout этого процесса. Запуск Windows-процесса на каждый запрос под нагрузкой упирается
  в баг WSL interop ([microsoft/WSL #7371](https://github.com/microsoft/WSL/issues/7371)). Если
  сервер завершается, клиент тоже завершается, а не перезапускает его; клиента перезапускает systemd.
- **`credrelay-server.exe`** (Windows, кросс-компилируется; WSL запускает его нативно) читает,
  пишет, удаляет и перечисляет generic-креды через `CredReadW`, `CredWriteW`, `CredDeleteW` и
  `CredEnumerateW`. О Secret Service он ничего не знает.
- **`credrelay-protocol`** — то, чем они обмениваются: один JSON-запрос на строку, один JSON-ответ на
  строку, строго по очереди, так что сервер можно гонять руками:

  ```sh
  echo '{"op":"list","prefix":"gh:"}' | credrelay-server.exe
  ```

### Схемы

Item в Secret Service — это набор атрибутов и секрет; креда Windows — это target name, имя
пользователя и blob. *Схема* — это отображение между ними, которое использует одна библиотека
хранения секретов; каждая схема — отдельный модуль в `client/src/schemes/`. Item достаётся первой
схеме, которая его берёт:

| Схема | Берёт | Креда Windows |
| --- | --- | --- |
| go-keyring | атрибуты ровно `{service, username}`, где `service` начинается с одного из `--go-keyring-prefix` | target `service:username`, пользователь `username`, байты секрета как есть |
| credrelay | всё остальное | target `credrelay:`, за ним атрибуты, отсортированные, пары `key,value` через `;`, ключи и значения в percent-encoding |

По одним атрибутам не понять, какая библиотека сохранила item: например, Rust-крейт `keyring`
хранит те же `{service, username}` под другим именем в Windows. Понять можно по сервису: каждое
приложение называет свой (`gh:github.com`, `glab:gitlab.com:token`), поэтому схема go-keyring берёт
только те сервисы, про которые ей сказано, что они принадлежат приложениям на go-keyring. Все
остальные item'ы хранятся под именами `credrelay:`, которые читают только Linux-приложения: у них нет
Windows-аналога, который стал бы их искать.

Заодно это не даёт одному приложению случайно затереть креду другого: item, чьи атрибуты совпали с
чужим target name, попадёт под `credrelay:`.

В кодировке `credrelay:` после префикса нет ни `=`, ни `:`, потому что Credential Manager не
включает target в перечисление, если сразу после его первого двоеточия идёт `service=` или `target=`
(это зафиксировано тестом в `server/src/wincred.rs`).

### Что реализует сервис

- Одну коллекцию, `/org/freedesktop/secrets/collection/login`, доступную также как алиас `default`
  (`ReadAlias`, `/org/freedesktop/secrets/aliases/default`).
- Сессии `plain` и `dh-ietf1024-sha256-aes128-cbc-pkcs7`. libsecret и Rust-крейт `keyring` просят
  вторую, и у Rust-крейта нет отката на `plain`.
- `SearchItems`, `CreateItem`, `GetSecret`, `GetSecrets`, `SetSecret`, `Delete` и свойства item'а
  `Attributes`, `Label`, `Locked`.
- Ничего никогда не заблокировано, и ни один вызов не возвращает prompt: `Unlock` возвращает то, что
  получил.
- Креда хранит один секрет на target, поэтому `CreateItem` заменяет item с точно такими же
  атрибутами независимо от `replace`.
- Не хранятся: метки (`Label` item'а — его target name), время создания и изменения (`0`).
- Не поддерживаются: `CreateCollection`, `SetAlias` и удаление коллекции.

## Настройка

`credrelay-client` в обычном случае не нужны флаги:

```text
credrelay-client
  --server-exe <PATH>           по умолчанию: "credrelay-server.exe", ищется в PATH
  --go-keyring-prefix <PREFIX>  по умолчанию: gh: и glab:; повторите для каждого, это заменяет умолчание
```

`credrelay-server.exe` флагов не принимает: его запускает `credrelay-client`, он же решает, какие
креды трогать.

Подробность логов задаётся `RUST_LOG` (по умолчанию `info`). Клиент пишет в stderr, который systemd
отправляет в журнал, и туда же пересылает stderr сервера:

```sh
journalctl --user -u credrelay
```

## Установка

```sh
./install.sh
```

собирает оба бинарника, ставит их в `/usr/local/bin` и устанавливает systemd user unit
(`$XDG_CONFIG_HOME/systemd/user/credrelay.service`) и файл D-Bus-активации
(`$XDG_DATA_HOME/dbus-1/services/org.freedesktop.secrets.service`). Клиент запускается, когда первое
приложение обращается к Secret Service. Нужен systemd в WSL (`systemd=true` в секции `[boot]` файла
`/etc/wsl.conf`).

Владеть `org.freedesktop.secrets` может только один процесс. Если на той же сессионной шине работает
другой Secret Service, например gnome-keyring, сначала остановите и отключите его; иначе
`systemctl --user status credrelay` покажет ошибку.

### Готовые бинарники

В каждом [релизе](https://github.com/SvarogLab/credrelay/releases) есть клиент для Linux
(`credrelay-client-linux-amd64`, `credrelay-client-linux-arm64`, статические сборки на musl) и
сервер для Windows (`credrelay-server-windows-amd64.exe`, `credrelay-server-windows-arm64.exe`), с
контрольными суммами в `SHA256SUMS`. Установите их в `PATH` как `credrelay-client` и
`credrelay-server.exe`, затем скопируйте `contrib/credrelay.service` и
`contrib/org.freedesktop.secrets.service` туда же, куда их кладёт `install.sh`, заменив `@BINDIR@`
на каталог с `credrelay-client`.

### Перевод gh и glab на keyring

Существующий логин в открытом виде остаётся на месте: приложение читает из keyring только то, что
само туда сохранило. При запущенном credrelay:

- `gh auth status` показывает, где лежит каждый токен. Открытый токен переносится через
  `gh auth login`: он сохраняет в keyring, когда тот доступен. Если Windows-`gh` уже залогинен в тот
  же аккаунт, можно вместо этого удалить `oauth_token` из `~/.config/gh/hosts.yml`, и Linux-`gh`
  подхватит токен Windows.
- `glab auth login` делает пробную запись в keyring и, если она удалась, сохраняет токен туда;
  повторный логин переносит открытый логин.

Теперь обе стороны делят одну креду, поэтому **logout с любой стороны разлогинивает обе**.

`glab` обновляет OAuth-токен под блокировкой в своём каталоге конфигурации, а он у каждой стороны
свой: одновременное обновление с обеих сторон может гонять, и тогда одной стороне придётся
залогиниться заново.

## Сборка

Сервер кросс-компилируется под Windows через [`cargo-xwin`](https://github.com/rust-cross/cargo-xwin);
WSL запускает `.exe` нативно, когда он собран под архитектуру хоста:

```sh
rustup target add aarch64-pc-windows-msvc
cargo install cargo-xwin

cargo build -p credrelay-client
cargo xwin build -p credrelay-server --target aarch64-pc-windows-msvc
```

(`x86_64-pc-windows-msvc` на хосте x86-64.)

## Тестирование

```sh
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Тесты клиента поднимают отдельный `dbus-daemon` на каждый тест и читают часть ответов через
`busctl`, так что оба должны быть установлены. Они гоняют сервис на хранилище в памяти и вызывают его
так же, как `go-keyring`.

Код сервера для Credential Manager собирается только под Windows. Его тесты запускаются там, на
настоящем Credential Manager того, кто их запускает, под target name с префиксом `credrelay-test`, и
удаляют всё, что записали:

```sh
eval "$(cargo xwin env --target aarch64-pc-windows-msvc)"
unset CARGO_TARGET_AARCH64_PC_WINDOWS_MSVC_RUNNER
cargo test -p credrelay-server --target aarch64-pc-windows-msvc
cargo clippy -p credrelay-server --all-targets --target aarch64-pc-windows-msvc
```

`cargo xwin test` выставил бы `CARGO_TARGET_AARCH64_PC_WINDOWS_MSVC_RUNNER=wine`; WSL сам запускает
тестовый бинарник, поэтому runner снимается и используется обычный `cargo test`.

### Релизы

Запустите workflow **Release PR** во вкладке Actions. Он открывает `chore: release vX.Y.Z` с версией,
которую git-cliff вычисляет по коммитам с последнего тега, и перегенерированным `CHANGELOG.md`;
мерж тегирует коммит и публикует релиз.

## Безопасность

- Любой процесс того же пользователя в WSL может прочитать все секреты, которые отдаёт credrelay, как
  на любом Linux-десктопе с разблокированным keyring. Он же может запускать Windows-процессы и читать
  Credential Manager напрямую; credrelay не добавляет нового пути внутрь.
- Префиксы схем защищают креды приложений от случайной перезаписи друг другом; это не контроль
  доступа.
- Креды пишутся с persistence local machine, как их пишет go-keyring: они остаются на этой машине и не
  переезжают вместе с профилем Windows.
- Сессия `plain` передаёт секреты по сессионной шине без шифрования, как допускает спецификация;
  клиент, который просит DH-сессию, получает их зашифрованными.

## Лицензия

На ваш выбор: [Apache License, Version 2.0](LICENSE-APACHE) или [MIT license](LICENSE-MIT).
