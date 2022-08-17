from fastapi import APIRouter

from . import oauth, recaptcha, session, test, user


ROUTERS: dict[str, tuple[APIRouter, str | None]] = {
    module.router.tags[0]: (module.router, module.__doc__) for module in [user, session, oauth, recaptcha, test]
}
