"""Human-readable 'why this is dangerous' for each finding. No LLM required."""

from __future__ import annotations

from app.services.findings import Finding, ScanResult

_SEV_FALLBACK = {
    "critical": (
        "Критическая уязвимость: её обычно можно использовать удалённо. "
        "Атакующий может захватить систему, украсть данные или остановить сервис. Чинить в первую очередь."
    ),
    "high": (
        "Высокий риск: при удачном сценарии злоумышленник получает серьёзный доступ "
        "или выводит сервис из строя. Закрывать до выкладки в прод."
    ),
    "medium": (
        "Средний риск: сама по себе дыра может не дать полный контроль, но её часто "
        "склеивают с другими ошибками. Лучше закрыть в ближайшем цикле."
    ),
    "low": (
        "Низкий риск: прямой атаки обычно нет, но это ослабляет защиту "
        "и может всплыть на аудите. Исправить, когда будет время."
    ),
    "info": "Информационная находка, не атака. Имеет смысл знать, чинить не обязательно.",
}


def _blob(finding: Finding) -> str:
    return " ".join(
        [
            finding.scanner or "",
            finding.title or "",
            finding.description or "",
            finding.location or "",
        ]
    ).lower()


def explain_danger(finding: Finding) -> str:
    text = _blob(finding)
    scanner = (finding.scanner or "").lower()

    if scanner == "clamav" or "malware" in text or "virus" in text or "eicar" in text:
        return (
            "В файле сигнатура вредоносного ПО. Если такой файл запустить или отдать пользователям, "
            "атакующий может выполнить свой код, украсть данные или зашифровать диск. "
            "Не деплоить, карантин, искать источник."
        )

    if scanner == "virustotal" or "malicious=" in text:
        return (
            "Сторонние антивирусы уже видели этот файл как вредоносный. "
            "Риск — скрытый бэкдор в зависимости или в загруженном архиве. Не игнорировать."
        )

    if "secret" in text or "private key" in text or "api key" in text or "password" in text:
        return (
            "В коде или конфиге лежит секрет. Кто угодно с доступом к репозиторию или образу "
            "может войти в чужой аккаунт, облако или базу. Ключ нужно отозвать и вычистить из git-истории."
        )

    if "github-actions-mutable-action-tag" in text or "mutable tag" in text:
        return (
            "GitHub Action прибит к тегу (v4), а не к коммиту. Владелец экшена может переписать тег "
            "на вредоносный код — так уже взламывали CI (в том числе у Trivy). "
            "Тогда в пайплайне окажется чужой скрипт с твоими секретами."
        )

    if "dependabot-missing-cooldown" in text or "cooldown" in text:
        return (
            "Dependabot может предложить пакет в день публикации. Свежие версии иногда оказываются "
            "скомпрометированы (supply-chain). Без паузы вредоносный релиз быстрее попадёт в прод."
        )

    if any(k in text for k in ("eval", "os.system", "command injection", "code execution", "rce", "remote code")):
        return (
            "Возможно выполнение чужого кода. Это прямой путь к захвату сервера: "
            "чтение секретов, установка бэкдора, атака на соседние сервисы."
        )

    if "xss" in text or "cross-site scripting" in text or "style closing tags" in text:
        return (
            "XSS: в страницу можно внедрить скрипт. Им крадут сессии пользователей, "
            "подменяют интерфейс или проводят действия от чужого имени."
        )

    if "sql injection" in text or "sqli" in text:
        return (
            "SQL-инъекция: запрос к базе можно изменить. Риск — выгрузка всей БД, "
            "подмена данных или вход без пароля."
        )

    if "path traversal" in text or "directory traversal" in text:
        return (
            "Path traversal: можно прочитать файлы вне разрешённой папки "
            "(.env, ключи, исходники). Часто это первый шаг к полному взлому."
        )

    if any(
        k in text
        for k in (
            "denial of service",
            "denial-of-service",
            " dos",
            "infinite loop",
            "event loop",
            "uncontrolled",
        )
    ):
        return (
            "Отказ в обслуживании (DoS): специально сформированные данные заставляют процесс "
            "зациклиться или съесть память. Сервис зависает для всех пользователей."
        )

    if "information disclosure" in text or "info disclosure" in text or "source map" in text:
        return (
            "Утечка информации: наружу могут уйти пути на диске, исходники или внутренние URL. "
            "Этого достаточно, чтобы уточнить следующую атаку."
        )

    if "libvips" in text or "sharp" in text:
        return (
            "Дыра в обработке картинок. Вредоносный файл изображения может уронить воркер "
            "или выполнить код на сервере, который ресайзит загрузки пользователей."
        )

    if "outdated php" in text or "php eol" in text or "php security-only" in text:
        return (
            "Устаревший PHP: дыры больше не закрывают. На ita-подобных стеках это "
            "часто соседствует с древним CMS. Обновить runtime — обязательный шаг, "
            "патчи приложения поверх EOL PHP не спасают."
        )

    if "x-powered-by" in text or "server version disclosure" in text:
        return (
            "Заголовок выдаёт версию стека. Атакующему проще подобрать эксплойт "
            "под конкретный PHP/nginx. Убрать Server/X-Powered-By в конфиге веб-сервера."
        )

    if "missing hsts" in text or "strict-transport-security" in text:
        return (
            "Без HSTS браузер может один раз сходить по HTTP (sslstrip). "
            "Для публичного сайта нужен Strict-Transport-Security с разумным max-age."
        )

    if "healthcheck" in text:
        return (
            "Без HEALTHCHECK оркестратор не узнает, что контейнер уже мёртв, "
            "и будет слать на него трафик. Для атаки это не RCE, для надёжности — плохо."
        )

    if finding.severity in _SEV_FALLBACK:
        extra = (finding.description or "").strip()
        base = _SEV_FALLBACK[finding.severity]
        if extra and extra.lower() not in base.lower():
            return f"{base} Суть находки: {extra[:280]}"
        return base
    return _SEV_FALLBACK["info"]


def enrich_result(result: ScanResult) -> ScanResult:
    for item in result.findings:
        if not item.impact:
            item.impact = explain_danger(item)
    return result
