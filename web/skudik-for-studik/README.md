# Skudik for Studik

**Категория:** Web  
**Стоимость:** 300

> We installed cameras in the classrooms so that no one could cheat on the exam. But while we were setting them up, we noticed something strange...

## Разбор

В архиве лежал довольно большой Go-бинарь. Сразу ковырять всё подряд смысла не было, поэтому я начал с запросов из фронта и строк в бинаре.

### Авторизация

В приложении было два варианта логина. Ветка Keycloak принимала access token, но подпись нормально не проверялась. Достаточно было JWT с `alg: none`.

Поле `sub` потом попадало в SQL-запрос, поэтому в него положил обычную инъекцию:

```json
{
  "alg": "none"
}
.
{
  "sub": "' OR 1=1 -- ",
  "exp": 9999999999
}
.
```

После `POST /api/system/auth` сервер выдавал админскую сессию.

### Настройки записи

Во фронте нашёл скрытый endpoint:

```text
POST /api/system/settings/video
```

Через него можно менять `videoStorageDir`. При старте записи директория подставлялась в shell-команду проверки диска примерно так:

```sh
df -Pk "<videoStorageDir>"
```

То есть здесь уже видна command injection. Но просто записать `$(cat /flag)` не получается: перед этим приложение вызывает `stat()` для указанного пути, а символ `/` в `RecordID` тоже фильтруется.

Обход получился немного кривой, но рабочий:

1. Сначала выставил нормальную директорию `/var/lib/skudik/archive`.
2. Через WebSocket сделал `camera_photo`, а в `RecordID` передал payload. Камера создала файл с этим именем — теперь `stat()` проходит.
3. Этот реальный путь поставил в `videoStorageDir`.
4. Запустил `camera_record`, чтобы путь попал в `/bin/sh -c`.

Корень без прямого `/` получил через shell parameter expansion:

```sh
r=${PWD%${PWD#?}}
```

Дальше `${r}flag`, `${r}usr${r}share...` и так далее. Для вывода использовал доступный статический `panel.js`: дописал туда содержимое flag-файла и забрал обычным GET-запросом.

WebSocket-команды, которые понадобились:

```text
camera_live_init
camera_photo
camera_ack
camera_record
```

Финальный скрипт: [solve.py](solve.py).

## Флаг

```text
kaspersky{dea30cda-619a-4d0b-8e1b-0a1f1cddc2a7}
```

