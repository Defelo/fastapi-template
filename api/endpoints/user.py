from fastapi import APIRouter, Query
from sqlalchemy import asc

from .. import models
from ..auth import get_user, admin_auth, is_admin, user_auth
from ..database import db, select, filter_by
from ..exceptions.auth import user_responses, PermissionDeniedError
from ..exceptions.user import UserNotFoundError, UserAlreadyExistsError
from ..schemas.user import User, UsersResponse, CreateUser, UpdateUser

router = APIRouter(tags=["users"])


@router.get("/users", dependencies=[admin_auth], responses=user_responses(UsersResponse))
async def get_users(limit: int = Query(100, ge=1, le=100), offset: int = Query(0, ge=0)):
    """Get all users"""

    total: int = await db.count(select(models.User))
    return {
        "total": total,
        "users": [
            user.serialize
            async for user in await db.stream(
                select(models.User).order_by(asc(models.User.registration)).limit(limit).offset(offset),
            )
        ],
    }


@router.get("/users/{user_id}", responses=user_responses(User, UserNotFoundError))
async def get_user_by_id(user: models.User = get_user(require_self_or_admin=True)):
    """Get user by id"""

    return user.serialize


@router.post("/users", dependencies=[admin_auth], responses=user_responses(User, UserAlreadyExistsError))
async def create_user(data: CreateUser):
    """Create a new user"""

    if await db.exists(filter_by(models.User, name=data.name)):
        raise UserAlreadyExistsError

    user = await models.User.create(data.name, data.password, data.enabled, data.admin)
    return user.serialize


@router.patch("/users/{user_id}", responses=user_responses(User, UserAlreadyExistsError))
async def update_user(
    data: UpdateUser,
    user: models.User = get_user(require_self_or_admin=True),
    admin: bool = is_admin,
    session: models.Session = user_auth,
):
    """Update a user"""

    if data.name is not None and data.name != user.name:
        if not admin:
            raise PermissionDeniedError
        if await db.exists(filter_by(models.User, name=data.name)):
            raise UserAlreadyExistsError

        user.name = data.name

    if data.password is not None:
        await user.change_password(data.password)

    if data.enabled is not None and data.enabled != user.enabled:
        if user.id == session.user_id:
            raise PermissionDeniedError

        user.enabled = data.enabled

    if data.admin is not None and data.admin != user.admin:
        if user.id == session.user_id:
            raise PermissionDeniedError

        user.admin = data.admin

    return user.serialize


@router.delete("/users/{user_id}", responses=user_responses(bool, PermissionDeniedError))
async def delete_user(user: models.User = get_user(models.User.sessions), session: models.Session = admin_auth):
    """Delete a user"""

    if user.id == session.user_id:
        raise PermissionDeniedError

    await user.logout()
    await db.delete(user)
    return True
