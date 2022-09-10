from typing import cast

import aiohttp

from api.settings import settings


def recaptcha_enabled() -> bool:
    return bool(settings.recaptcha_secret and settings.recaptcha_sitekey)


async def check_recaptcha(response: str) -> bool:
    async with aiohttp.ClientSession() as session:
        async with session.post(
            "https://www.google.com/recaptcha/api/siteverify",
            data={"secret": settings.recaptcha_secret, "response": response},
        ) as resp:
            return cast(bool, (await resp.json())["success"])
