from typing import cast

import aiohttp

from ..environment import RECAPTCHA_SECRET, RECAPTCHA_SITEKEY


def recaptcha_enabled() -> bool:
    return bool(RECAPTCHA_SECRET and RECAPTCHA_SITEKEY)


async def check_recaptcha(response: str) -> bool:
    async with aiohttp.ClientSession() as session:
        async with session.post(
            "https://www.google.com/recaptcha/api/siteverify", data={"secret": RECAPTCHA_SECRET, "response": response}
        ) as resp:
            return cast(bool, (await resp.json())["success"])
