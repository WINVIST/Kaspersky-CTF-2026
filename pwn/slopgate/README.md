# SlopGate

**Категория:** Pwn  
**Стоимость:** 258

В задании дали патченный QEMU с собственным PCI-устройством SlopGate. Снаружи это выглядело как обычная очередь запросов: драйвер кладёт descriptor в DMA, устройство обрабатывает профиль и пишет response обратно.

## Разбор

Сначала я посмотрел `slopgate-core.c` и `slopgate-pci.c`. Самое интересное оказалось не в скоринге, а в том, что адрес ответа полностью контролируется гостем. Поэтому response можно направить не в RAM, а прямо в MMIO BAR устройства по адресу `0xfebfe000`.

Если поставить `resp_addr = BAR + 8`, поля response попадают на регистры устройства:

```text
tag        -> DEVICE_STATUS
status     -> CONTROL
score      -> Q_BASE_LO
verdict    -> Q_BASE_HI
generation -> Q_SIZE
out_len    -> Q_HEAD
payload    -> Q_TAIL, PROFILE_COMMAND, ...
```

При `tag = 0` запись в `DEVICE_STATUS` вызывает soft reset. Проблема в том, что reset освобождает текущий `SlopGateActiveRequest`, но функция записи ответа после этого продолжает пользоваться старым указателем. Получился UAF прямо во время обработки response.

Дальше надо было добиться, чтобы на место освобождённого request попал контролируемый объект. Размер `SlopGateActiveRequest` равен `0xc0`. У profile context есть 16 байт заголовка и управляемая длина seed, поэтому context с seed длиной 176 байт тоже занимает `0xc0`.

Я заранее настраивал профиль 1 с `context_len = 176`, а в payload ответа записывал `PROFILE_CMD_REBUILD`. Во время reset request освобождался, затем rebuild создавал новый context и malloc почти всегда возвращал тот же chunk. Поля нового context начинали восприниматься как поля старого request.

Из этого overlap получилось сразу две полезные вещи.

Во-первых, через подменённый `profile_id` функция `record_success()` записывала owner context в статистику выбранного профиля. Запрос `GET_PROFILE_STATS` после этого выдавал адрес `profiles[1]`. Зная смещения из структуры, я получил базу состояния устройства:

```c
core = profiles_1 - 176 - sizeof(SlopGateProfile);
```

Во-вторых, обновление context после запроса делало XOR одного байта по адресу, составленному из `key`, `requested_context_len` и `mode`. Для длины 176 cursor был равен 22, поэтому примитив получился таким:

```text
key  = target - 22
mode = byte_to_xor
```

То есть уже был произвольный однобайтовый XOR в адресном пространстве QEMU.

Для чтения памяти я использовал третий профиль. Обнулил ему `mode` и `key`, а его указатель на context переписал на `core - 16`. Получился фальшивый `SlopGateProfileContext`, у которого поле `buf` указывало на `core`. После `GET_PROFILE_CONTEXT` устройство само отдало мне 1024 байта своего состояния.

В дампе по смещению `0xa0` лежал `core->worker_bh`. Через тот же fake context я прочитал настоящий `QEMUBH` и достал указатель на callback `slopgate_core_worker`. Смещение функции в ELF было `0x53d2a0`, поэтому база PIE считалась напрямую:

```c
pie = worker_cb - 0x53d2a0;
```

Сначала я хотел переписать GOT, но у QEMU был full RELRO. Тогда собрал поддельный `QEMUBH` в свободном chunk прямо перед настоящим worker BH. В callback положил `system`, в opaque — адрес строки `cat /app/flag.txt`, а `core->worker_bh` переключил на fake.

Здесь было два не самых очевидных фейла. Обычный адрес `system@plt` при косвенном вызове не сработал — понадобился IBT-совместимый entry из `.plt.sec` со смещением `0x338150`. Ещё я сначала положил команду по `core + 0x300`, но эта область пересекалась с `in_flight` одного из профилей и занулялась очередным reset. После переноса на `core + 0x310` всё стало стабильно.

Итоговая структура выглядела так:

```text
fake_bh->ctx    = real_bh->ctx
fake_bh->name   = real_bh->name
fake_bh->cb     = pie + 0x338150        // system@plt.sec
fake_bh->opaque = core + 0x310          // "cat /app/flag.txt"
```

Последним XOR я поменял младший байт `core->worker_bh`, отправил уведомление очереди, и QEMU вызвал fake BH. Полный эксплойт лежит в [solve.c](solve.c). Я компилировал его статически и загружал в гостевую систему после прохождения PoW.

## Флаг

```text
kaspersky{I_th1nk_w3_b0th_g0t_dumb3r_wh1l3_s0lvin6_this_t4sk}
```
