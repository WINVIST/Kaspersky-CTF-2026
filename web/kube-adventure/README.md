# Kube Adventure

**Категория:** Web  
**Стоимость:** 318

## Разбор

Эту задачу решал в основном руками, поэтому красивого one-click exploit не осталось. Ниже цепочка и команды, которые были важны.

### 1. RCE в loadtester

Снаружи был доступен Flagger loadtester. Его `/` принимает JSON, а при `metadata.type=bash` просто выполняет переданную команду:

```json
{
  "cmd": "id",
  "metadata": {
    "type": "bash",
    "returnCmdOutput": true
  }
}
```

Так получил shell внутри pod'а. ServiceAccount token там специально отсутствовал, поэтому просто пойти в Kubernetes API не вышло.

### 2. Recovery image

Из окружения и доступных сервисов нашёл внутренний registry:

```text
10.244.0.1:5000
```

В нём был образ `edgerollout/node-recovery`. Из слоёв образа достал каталог `/opt/edgerollout/recovery/`, а там kubeadm bootstrap token.

Токен не давал читать секреты напрямую, но позволял создать CSR. Я запросил сертификат kubelet'а с CN вида:

```text
system:node:<node-name>
```

и группой `system:nodes`. CSR с правильными usages автоматически approve'ился. После этого Node Authorizer разрешил читать pod'ы, которые привязаны к этому node, вместе со ссылками на их secrets.

### 3. ServiceAccount и Redis

Из pod spec добрался до токена ServiceAccount `service-publisher`. У него было право создавать Service.

Дальше сделал Service с нужным `externalIPs`:

```yaml
spec:
  externalIPs:
    - 10.250.0.10
  ports:
    - port: 6379
      targetPort: 16379
```

На `16379` поднял `socat`. В итоге трафик `rollout-observer`, который ходил на `10.250.0.10:6379`, прилетел ко мне. В первом же соединении был Redis `AUTH` с паролем.

Оставалось прокинуть соединение в настоящий Redis (`10.0.2.15:6379`) и прочитать ключ:

```text
rollout:production:flag
```

## Флаг

```text
kaspersky{296b482c-7b68-4c53-aeb8-b9adeffbe81a}
```

