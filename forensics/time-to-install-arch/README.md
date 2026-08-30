# Time to Install Arch

**Категория:** Forensics  
**Стоимость:** 285

> Securing Windows is so hard now. No matter how hard we try to secure our servers, our creds get leaked in minutes. Time to dump Windows and install Arch Linux?

В задании дали образ Windows `ctf-disk1.vmdk` и дамп трафика `task.pcap`.

## Разбор

Сначала открыл pcap в Wireshark и посмотрел Conversations. В глаза бросились 450 коротких TLS-соединений от `10.63.208.212` к `158.160.214.233:443`. Все соединения выглядели почти одинаково, но каждый раз создавалась новая TLS-сессия.

В `ClientHello` был нестандартный extension `0x0a0a` длиной 16 байт. Это GREASE-значение, которое нормальный клиент может добавлять для проверки совместимости, но здесь оно присутствовало в каждом пакете и постоянно менялось. В `ServerHello` оказался такой же extension. Похоже на двусторонний скрытый канал.

Дальше понадобился образ диска. В NTFS нашёл подозрительный PE-файл, замаскированный под:

```text
C:\Windows\Microsoft.NET\assembly\GAC_MSIL\Microsoft.Windows.ServerManager.Common\
v4.0_10.0.0.0__31bf3856ad364e35\ntdll.dll
```

После снятия простого XOR со строк конфигурации получились:

```text
C2:       158.160.214.233:443
key:      GREASEchannel!!! + deadbeefcafebabe13374200900df00d
request:  GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n
```

В бинаре также была функция, очень похожая на ChaCha20: 20 раундов и обычные вращения `16, 12, 8, 7`. Отличие было в первых четырёх словах state:

```python
[0xDEADBEEF, 0xCAFEBABE, 0x13371337, 0xC0FFEE42]
```

Nonce лежал прямо в session id клиента:

```text
0aad23b18f07c20ea30a2b49 || uint32_le(packet_number)
```

Для клиентского extension использовался блок `2*i`, а для серверного — соседний нечётный блок `2*i+1`:

```text
client_plain = client_extension XOR chacha_block(2*i)[:16]
server_plain = server_extension XOR chacha_block(2*i+1)[:16]
```

После расшифровки пошли нормальные команды C2:

```text
whoami
echo i found some stealth trick on the net
cd C:\Users >nul 2>&1
dir C:\Users\Public >nul 2>&1
type C:\Users\Public\flag.txt >nul 2>&1
findstr /i "kaspersky{" C:\*.txt >nul 2>&1
echo why there's nothing( >nul 2>&1
echo i give up >nul 2>&1
```

Сам флаг сервер всё-таки отправил последними тремя фреймами. Полный скрипт для разбора pcap лежит в [solve.py](solve.py).

## Флаг

```text
kaspersky{gR34sY_ch4nn3l_n0t_s0_sL1ck}
```


