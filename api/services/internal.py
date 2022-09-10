from datetime import timedelta
from enum import Enum

from httpx import AsyncClient, Response

from api.logger import get_logger
from api.settings import settings
from api.utils.jwt import encode_jwt


logger = get_logger(__name__)


class InternalServiceError(Exception):
    pass


class InternalService(Enum):
    # SERVICE_XYZ = settings.service_xyz_url

    @classmethod
    def _get_token(cls) -> str:
        return encode_jwt({}, timedelta(seconds=settings.internal_jwt_ttl))

    @classmethod
    async def _handle_error(cls, response: Response) -> None:
        if response.status_code in [401, 403] or response.status_code in range(500, 600):
            await response.aread()
            raise InternalServiceError(response, response.text)

    @property
    def client(self) -> AsyncClient:
        return AsyncClient(
            base_url=self.value.rstrip("/") + "/_internal",
            headers={"Authorization": self._get_token()},
            event_hooks={"response": [self._handle_error]},
        )
