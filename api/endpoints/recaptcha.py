"""Endpoints for ReCaptcha configuration"""

from typing import Any, cast

from fastapi import APIRouter

from ..environment import RECAPTCHA_SITEKEY
from ..utils.docs import responses
from ..utils.recaptcha import recaptcha_enabled


router = APIRouter()


@router.get("/recaptcha", responses=responses(cast(type, str | None)))
async def get_recpatcha_sitekey() -> Any:
    """
    Return the public ReCaptcha sitekey.

    If ReCaptcha is disabled, `null` is returned instead.
    """

    return RECAPTCHA_SITEKEY if recaptcha_enabled() else None
