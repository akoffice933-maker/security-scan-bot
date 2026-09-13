"""Human-readable 'why this is dangerous' for each finding. No LLM required."""

from __future__ import annotations

import re

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


def _has(text: str, *keywords: str) -> bool:
    """Совпадение по границам слова: «eval» не должен ловиться в
    «make_eval_corpus.py», «rce» — внутри «source», «dos» — в «dosomething»."""
    return any(
        re.search(rf"(?<![a-z0-9_]){re.escape(k)}(?![a-z0-9_])", text) for k in keywords
    )


def _blob(finding: Finding) -> str:
    # location сознательно не участвует: путь файла — не признак уязвимости,
    # и «scripts/make_eval_corpus.py» ловил RCE-объяснение из-за «eval».
    return " ".join(
        [
            finding.scanner or "",
            finding.title or "",
            finding.description or "",
        ]
    ).lower()


def explain_danger(finding: Finding) -> str:
    text = _blob(finding)
    scanner = (finding.scanner or "").lower()

    if scanner == "clamav" or _has(text, "malware", "virus", "eicar"):
        return (
            "В файле сигнатура вредоносного ПО. Если такой файл запустить или отдать пользователям, "
            "атакующий может выполнить свой код, украсть данные или зашифровать диск. "
            "Не деплоить, карантин, искать источник."
        )

    if scanner == "virustotal" or _has(text, "malicious="):
        return (
            "Сторонние антивирусы уже видели этот файл как вредоносный. "
            "Риск — скрытый бэкдор в зависимости или в загруженном архиве. Не игнорировать."
        )

    if _has(text, "secret", "private key", "api key", "password"):
        return (
            "В коде или конфиге лежит секрет. Кто угодно с доступом к репозиторию или образу "
            "может войти в чужой аккаунт, облако или базу. Ключ нужно отозвать и вычистить из git-истории."
        )

    if _has(text, "github-actions-mutable-action-tag", "mutable tag"):
        return (
            "GitHub Action прибит к тегу (v4), а не к коммиту. Владелец экшена может переписать тег "
            "на вредоносный код — так уже взламывали CI (в том числе у Trivy). "
            "Тогда в пайплайне окажется чужой скрипт с твоими секретами."
        )

    if _has(text, "dependabot-missing-cooldown", "cooldown"):
        return (
            "Dependabot может предложить пакет в день публикации. Свежие версии иногда оказываются "
            "скомпрометированы (supply-chain). Без паузы вредоносный релиз быстрее попадёт в прод."
        )

    if _has(text, "eval", "os.system", "command injection", "code execution", "rce", "remote code"):
        return (
            "Возможно выполнение чужого кода. Это прямой путь к захвату сервера: "
            "чтение секретов, установка бэкдора, атака на соседние сервисы."
        )

    if _has(text, "xss", "cross-site scripting", "style closing tags"):
        return (
            "XSS: в страницу можно внедрить скрипт. Им крадут сессии пользователей, "
            "подменяют интерфейс или проводят действия от чужого имени."
        )

    if _has(text, "sql injection", "sqli"):
        return (
            "SQL-инъекция: запрос к базе можно изменить. Риск — выгрузка всей БД, "
            "подмена данных или вход без пароля."
        )

    if _has(text, "path traversal", "directory traversal"):
        return (
            "Path traversal: можно прочитать файлы вне разрешённой папки "
            "(.env, ключи, исходники). Часто это первый шаг к полному взлому."
        )

    if _has(
        text,
        "denial of service",
        "denial-of-service",
        "dos",
        "infinite loop",
        "event loop",
        "uncontrolled",
    ):
        return (
            "Отказ в обслуживании (DoS): специально сформированные данные заставляют процесс "
            "зациклиться или съесть память. Сервис зависает для всех пользователей."
        )

    if _has(text, "information disclosure", "info disclosure", "source map"):
        return (
            "Утечка информации: наружу могут уйти пути на диске, исходники или внутренние URL. "
            "Этого достаточно, чтобы уточнить следующую атаку."
        )

    if _has(text, "libvips", "sharp"):
        return (
            "Дыра в обработке картинок. Вредоносный файл изображения может уронить воркер "
            "или выполнить код на сервере, который ресайзит загрузки пользователей."
        )

    if _has(text, "outdated php", "php eol", "php security-only"):
        return (
            "Устаревший PHP: дыры больше не закрывают. На ita-подобных стеках это "
            "часто соседствует с древним CMS. Обновить runtime — обязательный шаг, "
            "патчи приложения поверх EOL PHP не спасают."
        )

    if _has(text, "x-powered-by", "server version disclosure"):
        return (
            "Заголовок выдаёт версию стека. Атакующему проще подобрать эксплойт "
            "под конкретный PHP/nginx. Убрать Server/X-Powered-By в конфиге веб-сервера."
        )

    if _has(text, "missing hsts", "strict-transport-security"):
        return (
            "Без HSTS браузер может один раз сходить по HTTP (sslstrip). "
            "Для публичного сайта нужен Strict-Transport-Security с разумным max-age."
        )

    if _has(text, "healthcheck"):
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
