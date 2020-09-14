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
from ..auth import error_handler, token_required_factory
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
from ..database.utils import *
from ..users.group_ops import (
    create_group
)


def get_token(*args, **kwargs):
    token = request.headers.get("token")
    if token is None:
        raise MissingRequestKeyError

    return token


def format_result(response_body, status_code, mimetype):
    return Response(dumps(response_body), status=status_code, mimetype=mimetype)


token_required = token_required_factory(get_token, format_result)


@main_routes.route("/groups", methods=["POST"])
@token_required
def create_group_route(current_user):
    def route_logic(current_user):
        data = loads(request.data)
        name = data.get("name")

        private_key = request.headers.get("private-key")

        if name is None or private_key is None:
            raise MissingRequestKeyError
        if private_key != current_user.private_key:
            raise InvalidCredentialsError

        group = create_group(current_user, private_key, name)
        group = model_to_json(group)
        response_body = {RESPONSE_MSG.SUCCESS: True, "group": group}
        return response_body

    status_code, response_body = error_handler(route_logic, current_user)

    return Response(
        dumps(response_body), status=status_code, mimetype="application/json"
    )
