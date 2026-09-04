from __future__ import annotations

import logging
from openai import AsyncOpenAI
from app.config import get_settings

logger = logging.getLogger(__name__)


class LLMService:
    def __init__(self) -> None:
        settings = get_settings()
        self.enabled = settings.llm_enabled and bool(settings.openrouter_api_key)
        self.model = settings.llm_model
        self.client: AsyncOpenAI | None = None
        if self.enabled:
            self.client = AsyncOpenAI(
                api_key=settings.openrouter_api_key,
                base_url=settings.openrouter_base_url,
            )

    async def analyze_findings(self, raw_report: str, scan_type: str) -> str:
        if not self.enabled or not self.client:
            return raw_report

        system_prompt = (
            "Ты — дружелюбный помощник по безопасности. "
            "Объясняй результаты проверки простым языком, как обычному человеку, а не эксперту. "
            "Избегай сложного жаргона. Если используешь термин — коротко поясни его.\n\n"
            "Структура ответа:\n"
            "1. Сначала напиши общий вывод в 1-2 предложениях (всё хорошо / есть проблемы).\n"
            "2. Если есть важные проблемы — перечисли их простыми словами и скажи, насколько это серьёзно.\n"
            "3. Дай 2-4 конкретные рекомендации, что можно сделать.\n"
            "4. В конце коротко напиши: «Подробности лежат в прикреплённых файлах отчёта».\n\n"
            "Если критичных и высоких проблем нет — так и скажи спокойно и позитивно.\n"
            "Не выдумывай уязвимости."
        )

        type_names = {
            "url": "сайта",
            "repo": "исходного кода",
            "docker": "Docker-образа",
            "archive": "архива с кодом",
        }
        human_type = type_names.get(scan_type, "проекта")

        user_prompt = (
            f"Результаты проверки {human_type}:\n\n"
            f"{raw_report[:11000]}"
        )

        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.3,
                max_tokens=1800,
            )
            return response.choices[0].message.content or raw_report
        except Exception as e:
            logger.exception("LLM analysis failed: %s", e)
            return (
                "Не удалось автоматически объяснить результаты.\n\n"
                "Сырой отчёт:\n" + raw_report[:3000]
            )


llm_service = LLMService()
