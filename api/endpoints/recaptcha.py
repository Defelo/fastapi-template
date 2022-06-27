from typing import Any, cast

from fastapi import APIRouter

from ..environment import RECAPTCHA_SITEKEY
from ..utils import recaptcha_enabled, responses


router = APIRouter(tags=["recaptcha"])


@router.get("/recaptcha", responses=responses(cast(type, str | None)))
async def get_recpatcha_sitekey() -> Any:
    """Get ReCaptcha sitekey"""

    return RECAPTCHA_SITEKEY if recaptcha_enabled() else None
