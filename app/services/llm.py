from __future__ import annotations

import json
import logging

from app.config import get_settings
from app.services.findings import IMPORTANT, ScanResult
from app.services.textutil import mask_secrets

logger = logging.getLogger(__name__)

SYSTEM = (
    "Ты помощник по безопасности. Объясняй находки простым русским языком. "
    "Не выдумывай CVE и не преувеличивай риск. Используй только факты из JSON. "
    "Секреты и ключи не цитируй — они уже скрыты. "
    "По каждой важной находке коротко скажи, чем она опасна (что сможет сделать атакующий). "
    "Структура: 1) кратко что произошло 2) чем опасны главные дыры 3) что починить сначала. "
    "Если находок нет — так и скажи."
)


def render_summary(result: ScanResult, scan_type: str, target: str) -> str:
    important = result.important()
    lines = [
        f"Проверка: {scan_type} → {target}",
        f"Всего находок: {len(result.findings)} (важных: {len(important)})",
    ]
    if result.error:
        lines.append(f"Ошибка: {result.error}")
    if result.notes:
        lines.append("Заметки: " + "; ".join(result.notes[:5]))
    if not result.findings:
        lines.append("Важных проблем не найдено.")
        return "\n".join(lines)

    by_sev: dict[str, int] = {}
    for item in result.findings:
        by_sev[item.severity] = by_sev.get(item.severity, 0) + 1
    lines.append("По серьёзности: " + ", ".join(f"{k}={v}" for k, v in sorted(by_sev.items())))
    lines.append("Первые важные:")
    for item in important[:8]:
        loc = f" ({item.location})" if item.location else ""
        lines.append(f"- [{item.severity}] {item.title}{loc}")
        if item.impact:
            lines.append(f"  Чем опасно: {item.impact}")
    if not important:
        lines.append("Критических/высоких/средних нет — детали в полном отчёте.")
    return mask_secrets("\n".join(lines))


def summarize_sync(result: ScanResult, scan_type: str, target: str) -> str:
    fallback = render_summary(result, scan_type, target)
    settings = get_settings()
    if not settings.llm_enabled or not settings.openrouter_api_key:
        return fallback
    brief = {
        "scan_type": scan_type,
        "target": target,
        "notes": result.notes[:10],
        "error": result.error,
        "findings": [
            {
                "scanner": f.scanner,
                "severity": f.severity,
                "title": f.title,
                "location": f.location,
                "description": (f.description or "")[:400],
                "impact": (f.impact or "")[:400],
            }
            for f in result.findings
            if f.severity in IMPORTANT
        ][:40],
    }
    payload = mask_secrets(json.dumps(brief, ensure_ascii=False)[:8000])
    try:
        from openai import OpenAI

        client = OpenAI(
            api_key=settings.openrouter_api_key,
            base_url=settings.openrouter_base_url,
            timeout=60.0,
        )
        response = client.chat.completions.create(
            model=settings.llm_model,
            messages=[
                {"role": "system", "content": SYSTEM},
                {"role": "user", "content": payload},
            ],
        )
        text = (response.choices[0].message.content or "").strip()
        return mask_secrets(text) if text else fallback
    except Exception:
        logger.exception("LLM summarization failed")
        return fallback


# imported by app.services.__init__ historically
llm_service = type("LLMService", (), {"summarize_sync": staticmethod(summarize_sync)})()
