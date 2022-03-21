from typing import Any, Optional, cast

from fastapi import APIRouter

from ..environment import RECAPTCHA_SITEKEY
from ..utils import recaptcha_enabled, responses

router = APIRouter(tags=["recaptcha"])


@router.get("/recaptcha", responses=responses(cast(type, Optional[str])))
async def get_recpatcha_sitekey() -> Any:
    """Get ReCaptcha sitekey"""

    return RECAPTCHA_SITEKEY if recaptcha_enabled() else None
