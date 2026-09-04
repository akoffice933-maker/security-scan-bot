# Security Scan Bot

Telegram-бот и MCP-сервер для проверки безопасности **своих** проектов.

[![CI](https://github.com/akoffice933-maker/security-scan-bot/actions/workflows/ci.yml/badge.svg)](https://github.com/akoffice933-maker/security-scan-bot/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

English one-liner: *Personal Nuclei / Semgrep / Trivy / ClamAV scanner with a fail-closed allowlist, Telegram UI, and an MCP server for AI agents.*

Сканировать чужие сайты, репозитории и образы **нельзя**. Пустой whitelist = отказ, а не «можно всем».

---

## Что умеет

| Цель | Инструменты | Ограничение |
|------|-------------|-------------|
| Сайт (URL) | Nuclei + заголовки HTTP | только `ALLOWED_DOMAINS` |
| GitHub-репозиторий | Semgrep, Bandit, Trivy fs, ClamAV | только `ALLOWED_GITHUB_ORGS` |
| Архив zip/tar | то же + защита от zip-slip | лимит размера |
| Docker-образ | Trivy image | только `ALLOWED_DOCKER_REGISTRIES` |
| Файл | VirusTotal **по хешу** (без upload) | опционально |

Дополнительно:

- краткое объяснение находок (OpenRouter / любой OpenAI-compatible LLM, опционально);
- отчёты **PDF, HTML, Markdown, JSON** — у каждой находки блок **«Чем опасно»**;
- в чат попадают только важные находки (critical / high / medium);
- очередь **Celery + Redis**;
- **MCP-сервер** (stdio) для других ИИ-агентов;
- CLI: `python scripts/scan_repo.py owner/repo`, `python scripts/scan_url.py https://example.com/`.

---

## Важно (юридическое и security)

- Бот только для проектов, которыми ты **владеешь**, или на проверку которых есть **письменное разрешение**.
- Nuclei по чужому URL — это несанкционированный пентест.
- Пустой `ADMIN_IDS` → процесс не стартует.
- Пустой whitelist → этот тип скана отклоняется.
- Cloud metadata (`169.254.169.254` и аналоги) заблокированы всегда.
- VirusTotal и OpenRouter — сторонние сервисы. Не отправляй туда секреты и чужой код.
- Сканеры запускаются без shell (`subprocess`, `shell=False`).

Подробнее: [SECURITY.md](SECURITY.md).

---

## Быстрый старт (Docker)

```bash
git clone https://github.com/akoffice933-maker/security-scan-bot.git
cd security-scan-bot
cp .env.example .env
```

В `.env` обязательно:

```
BOT_TOKEN=...                 # от @BotFather
ADMIN_IDS=123456789           # твой numeric id (@userinfobot)
ALLOWED_DOMAINS=example.com,localhost
ALLOWED_GITHUB_ORGS=your-github-username
ALLOWED_DOCKER_REGISTRIES=docker.io,ghcr.io
```

```bash
mkdir -p data && sudo chown -R 1000:1000 data
docker compose up --build -d
```

Compose поднимает Postgres + Redis (не публикуются наружу). Контейнер идёт не от root (`USER appuser`). Образ собирается **с ClamAV** (сигнатуры качаются на `docker compose build`). Без антивируса: `docker compose build --build-arg WITH_CLAMAV=0`.

В Telegram открой своего бота и отправь `/start`.

---

## Локальный запуск без Docker

Нужны Python 3.12+ и по возможности бинарники сканеров в `PATH`. Если сканера нет, шаг пропускается с заметкой.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# заполни BOT_TOKEN, ADMIN_IDS, whitelist

python -m app.main
```

Очередь (если есть Redis):

```bash
celery -A app.celery_app.celery_app worker --loglevel=info
```

Без Redis скан уходит в фоновый поток процесса бота — удобно для отладки, не для нагрузки.

### Скан репозитория из CLI (без Telegram)

```bash
python scripts/scan_repo.py your-github-username/your-repo
```

Отчёты пишутся в `data/reports/scan-<id>/`.

---

## Как пользоваться ботом

1. `/start` — меню.
2. **Проверить сайт** — URL из whitelist, затем профиль Nuclei (CVE / misconfig / exposures / all).
3. **Проверить код (GitHub)** — `owner/repo` или `https://github.com/owner/repo`.
4. **Проверить архив** — zip/tar, до `MAX_ARCHIVE_SIZE_MB`.
5. **Проверить Docker-образ** — имя образа с registry из whitelist.
6. **Мои проверки** — история.

---

## MCP-сервер

Только **stdio**, те же whitelist, что у бота.

```bash
python -m app.mcp_server
```

Tools:

| Tool | Назначение |
|------|------------|
| `scan_url` | Nuclei по allowlisted URL |
| `scan_repo` | Semgrep / Trivy / Bandit / ClamAV по GitHub-репо |
| `scan_docker` | Trivy image |
| `scan_archive` | локальный zip/tar |
| `scan_file_virustotal` | lookup хеша, **без загрузки файла** |
| `get_scan_capabilities` | какие сканеры установлены (без секретов) |

Пример конфига: [`mcp_config.example.json`](mcp_config.example.json).

---

## Архитектура

```
Telegram ──► aiogram (polling или webhook)
                 │
                 ├─ AccessMiddleware  (только ADMIN_IDS)
                 ├─ FSM / клавиатуры
                 └─ очередь (Celery или поток)
                        │
                        ▼
              TargetPolicy (fail-closed whitelist)
                        │
          Nuclei / Semgrep / Trivy / ClamAV / Bandit / VT
                        │
              Postgres (compose) / SQLite (local) + отчёты + audit_log

MCP stdio ────────────────────────────────────┘
```

---

## Переменные окружения

Полный список — [`.env.example`](.env.example).

| Переменная | Зачем |
|------------|--------|
| `BOT_TOKEN` | токен Telegram-бота |
| `ADMIN_IDS` | кто может пользоваться (fail-closed) |
| `ALLOWED_DOMAINS` | Nuclei |
| `ALLOWED_GITHUB_ORGS` | clone + SAST |
| `ALLOWED_DOCKER_REGISTRIES` | Trivy image |
| `REDIS_URL` | очередь и FSM |
| `DATABASE_URL` | история сканов |
| `OPENROUTER_API_KEY` | LLM-объяснения (опционально) |
| `VIRUSTOTAL_API_KEY` | lookup хеша (опционально) |
| `WEBHOOK_URL` / `WEBHOOK_SECRET` | production webhook |
| `SCAN_TIMEOUT_SECONDS` | лимит одного скана |

В production webhook-режиме `WEBHOOK_SECRET` обязателен.

---

## Тесты

```bash
pip install -r requirements.txt pytest
pytest -q
```

Покрыты: whitelist (в том числе `example.com.evil.com`), access middleware, zip-slip, sandbox без shell, история, MCP tools.

CI: [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

---

## Ограничения

- `docker compose` использует Postgres. Локально без Docker по умолчанию SQLite.
- Нет сканера в PATH — шаг пропускается, скан не падает целиком.
- Перед сканом проверяется диск и глубина очереди Celery; при >95% диска скан отклоняется.
- LLM не выдумывает CVE: в промпт уходит уже отфильтрованный JSON, секреты маскируются.
- PDF нуждается в DejaVu (`app/assets/DejaVuSans.ttf` уже в репозитории).
- Каждая попытка скана пишется в `audit_log` (кто / что / когда / исход).
- MCP только stdio — не вешай его на HTTP без токена.

---

## Лицензия

Код этого репозитория — **[MIT](LICENSE)**.

Сканеры, которые бот вызывает, и шрифт DejaVu имеют **свои** лицензии. Сводка: [NOTICE.md](NOTICE.md).

```
Copyright (c) 2026 akoffice933-maker
```
