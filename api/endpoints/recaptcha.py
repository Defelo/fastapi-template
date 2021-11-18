from typing import Any, Optional, cast

from fastapi import APIRouter

from api.environment import RECAPTCHA_SITEKEY
from api.exceptions import responses
from api.utils import recaptcha_enabled

router = APIRouter(tags=["recaptcha"])


@router.get("/recaptcha", responses=responses(cast(type, Optional[str])))
async def get_recpatcha_sitekey() -> Any:
    """Get ReCaptcha sitekey"""

    return RECAPTCHA_SITEKEY if recaptcha_enabled() else None
