# Security Scan Bot

Простой Telegram-бот для проверки безопасности **своих** проектов.

### Что умеет

| Проверка | Что ищет |
|----------|----------|
| 🌐 Сайт | Уязвимости (Nuclei) |
| 📁 Код / 📦 Архив | **Вирусы (ClamAV + VirusTotal)**, уязвимости, секреты, ошибки конфигурации |
| 🐳 Docker | Уязвимости в образе (Trivy) |

Дополнительно:
- Понятные объяснения простым языком
- Отчёты в PDF, HTML, Markdown, JSON
- В чат попадают только важные находки
- Очередь задач (Celery + Redis)
- **MCP-сервер** для подключения других ИИ-агентов

### Запуск

```bash
cp .env.example .env
# заполни BOT_TOKEN, ADMIN_IDS, OPENROUTER_API_KEY, VIRUSTOTAL_API_KEY (опционально)

docker compose up --build -d
```

### MCP-сервер (для других ИИ-агентов)

```bash
python -m app.mcp_server
```

Tools: `scan_url`, `scan_repo`, `scan_docker`, `scan_file_virustotal`, `get_scan_capabilities`

Пример конфигурации: `mcp_config.example.json`

### Важно

Бот предназначен только для проверки своих проектов. Используй whitelist доменов и GitHub-организаций.
