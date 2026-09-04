# Security Scan Bot

Telegram-бот и MCP-сервер для проверки безопасности **своих** проектов.

Сканировать чужие сайты, репозитории и образы нельзя. Пустой whitelist = отказ, а не «можно всем».

| Проверка | Что ищет |
|----------|----------|
| Сайт | Уязвимости (Nuclei), только домены из `ALLOWED_DOMAINS` |
| GitHub / архив | Semgrep, Bandit, Trivy fs, ClamAV (+ VirusTotal по хешу, без автозагрузки) |
| Docker | Уязвимости образа (Trivy), только registry из `ALLOWED_DOCKER_REGISTRIES` |

Дополнительно: краткое объяснение (LLM, опционально), отчёты PDF / HTML / Markdown / JSON, очередь Celery + Redis, MCP для ИИ-агентов.

## Важно

- Бот предназначен **только** для проектов, которыми ты владеешь или на проверку которых есть письменное разрешение.
- `ADMIN_IDS` пустой → бот не стартует.
- `ALLOWED_DOMAINS` / `ALLOWED_GITHUB_ORGS` / `ALLOWED_DOCKER_REGISTRIES` пустые → соответствующий тип скана отклоняется.
- Nuclei по чужому URL — это уже несанкционированный пентест.
- VirusTotal и OpenRouter получают фрагменты данных. Не загружай секреты и чужой код.

## Запуск

```bash
cp .env.example .env
# заполни BOT_TOKEN, ADMIN_IDS и whitelist

docker compose up --build -d
```

Нужны: Docker, заполненный `.env`. Redis наружу не публикуется.

Локально (без сканеров в PATH часть шагов пропустится):

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python -m app.main
# в другом терминале, если есть Redis:
celery -A app.celery_app.celery_app worker --loglevel=info
```

Без Redis скан уйдёт в фоновый поток процесса бота — только для отладки.

## MCP-сервер

```bash
python -m app.mcp_server
```

Tools: `scan_url`, `scan_repo`, `scan_docker`, `scan_archive`, `scan_file_virustotal`, `get_scan_capabilities`.

Только stdio. Пример: `mcp_config.example.json`. Те же whitelist, что у бота. `scan_file_virustotal` **не загружает** файл, только ищет хеш.

## Переменные окружения

См. `.env.example`. Обязательные для бота: `BOT_TOKEN`, `ADMIN_IDS`. Для сканов — соответствующие whitelist.

В production webhook-режиме обязателен `WEBHOOK_SECRET`.

## Тесты

```bash
pip install -r requirements.txt pytest
pytest -q
```

## Ограничения

- SQLite делят bot и worker через общий volume. Для нагрузки лучше Postgres.
- Сканеры должны быть в образе / на PATH. Если бинаря нет, шаг пропускается с заметкой.
- LLM не выдумывает находки: в промпт уходит уже отфильтрованный JSON, секреты маскируются.
