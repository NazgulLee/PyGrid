import logging
from datetime import datetime, timedelta
from json import dumps, loads
from json.decoder import JSONDecodeError
from secrets import token_hex

import jwt
from bcrypt import checkpw, gensalt, hashpw
from flask import Response
from flask import current_app as app
from flask import request
from syft.codes import RESPONSE_MSG
from werkzeug.security import check_password_hash, generate_password_hash

from ... import db
from .. import main_routes
from ..core.exceptions import (
    AuthorizationError,
    GroupNotFoundError,
    InvalidCredentialsError,
    MissingRequestKeyError,
    PyGridError,
    RoleNotFoundError,
    UserNotFoundError,
)
from ..database import Group, Role, User, UserGroup


def identify_user(private_key):
    if private_key is None:
        raise MissingRequestKeyError

    user = db.session.query(User).filter_by(private_key=private_key).one_or_none()
    if user is None:
        raise UserNotFoundError

    user_role = db.session.query(Role).get(user.role)
    if user_role is None:
        raise RoleNotFoundError

    return user, user_role


def create_group(current_user, private_key, name):
    user_role = Role.query.get(current_user.role)
    if user_role is None:
        raise RoleNotFoundError

    if not user_role.can_create_groups:
        raise AuthorizationError

    new_group = Group(name=name) 
    db.session.add(new_group)
    db.session.commit()
    return new_group

