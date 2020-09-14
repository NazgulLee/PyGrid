from json import dumps, loads

import jwt
import pytest
from flask import current_app as app
from src.app.main.database import *

JSON_DECODE_ERR_MSG = (
    "Expecting property name enclosed in " "double quotes: line 1 column 2 (char 1)"
)
owner_role = ("Owner", True, True, True, True, True, True)
user_role = ("User", False, False, False, False, False, False)
admin_role = ("Administrator", True, True, True, True, False, False)

user1 = (
    "tech@gibberish.com",
    "BDEB6E8EE39B6C70835993486C9E65DC",
    "]GBF[R>GX[9Cmk@DthFT!mhloUc%[f",
    "fd062d885b24bda173f6aa534a3418bcafadccecfefe2f8c6f5a8db563549ced",
    1,
)
user2 = (
    "anemail@anemail.com",
    "2amt5MXKdLhEEL8FiQLcl8Mp0FNhZI6",
    "$2b$12$rj8MnLcKBxAgL7GUHrYn6O",
    "acfc10d15d7ec9f7cd05a312489af2794619c6f11e9af34671a5f33da48c1de2",
    2,
)
user3 = (
    "anemail@anemail.com",
    "2amt5MXKdLhEEL8FiQLcl8Mp0FNhZI6",
    "$2b$12$rj8MnLcKBxAgL7GUHrYn6O",
    "acfc10d15d7ec9f7cd05a312489af2794619c6f11e9af34671a5f33da48c1de2",
    3,
)
user4 = (
    "tech@gibberish.com",
    "2amt5MXKdLhEEL8FiQLcl8Mp0FNhZI6",
    "$2b$12$tufn64/0gSIAdprqBrRzC.",
    "fd062d885b24bda173f6aa534a3418bcafadccecfefe2f8c6f5a8db563549ced",
    2,
)


@pytest.fixture
def cleanup(database):
    yield
    try:
        database.session.query(User).delete()
        database.session.query(Role).delete()
        database.session.query(Group).delete()
        database.session.query(UserGroup).delete()
        database.session.commit()
    except:
        database.session.rollback()


# CREATE GROUP


def test_create_group_success(client, database, cleanup):
    new_role = create_role(*admin_role)
    database.session.add(new_role)
    new_user = create_user(*user1)
    database.session.add(new_user)

    database.session.commit()

    token = jwt.encode({"id": 1}, app.config["SECRET_KEY"])
    headers = {
        "private_key": "fd062d885b24bda173f6aa534a3418bcafadccecfefe2f8c6f5a8db563549ced",
        "token": token.decode("UTF-8"),
    }
    payload = {"name": "Hospital X"}
    result = client.post("/groups", data=dumps(payload), headers=headers,
                         content_type="application/json")

    assert result.status_code == 200
    assert result.get_json()["group"]["id"] == 1
    assert result.get_json()["group"]["name"] == "Hospital X" 


def test_create_group_missing_key(client, database, cleanup):
    new_role = create_role(*admin_role)
    database.session.add(new_role)
    new_role = create_role(*user_role)
    database.session.add(new_role)
    new_user = create_user(*user1)
    database.session.add(new_user)
    new_user = create_user(*user2)
    database.session.add(new_user)

    database.session.commit()

    token = jwt.encode({"id": 1}, app.config["SECRET_KEY"])
    headers = {"token": token.decode("UTF-8")}
    payload = {"name": "Hospital X"}
    result = client.post("/groups", data=dumps(payload), headers=headers,
                         content_type="application/json")

    assert result.status_code == 400
    assert result.get_json()["error"] == "Missing request key!"


def test_create_group_missing_token(client, database, cleanup):
    new_role = create_role(*admin_role)
    database.session.add(new_role)
    new_role = create_role(*user_role)
    database.session.add(new_role)
    new_user = create_user(*user1)
    database.session.add(new_user)
    new_user = create_user(*user2)
    database.session.add(new_user)

    database.session.commit()

    headers = {
        "private_key": "fd062d885b24bda173f6aa534a3418bcafadccecfefe2f8c6f5a8db563549ced"
    }
    payload = {"name": "Hospital X"}
    result = client.post("/groups", data=dumps(payload), headers=headers,
                         content_type="application/json")

    assert result.status_code == 400
    assert result.get_json()["error"] == "Missing request key!"


def test_create_group_invalid_key(client, database, cleanup):
    new_role = create_role(*admin_role)
    database.session.add(new_role)
    new_role = create_role(*user_role)
    database.session.add(new_role)
    new_user = create_user(*user1)
    database.session.add(new_user)
    new_user = create_user(*user2)
    database.session.add(new_user)

    database.session.commit()

    token = jwt.encode({"id": 1}, app.config["SECRET_KEY"])
    headers = {
        "private_key": "invalid312987as12they0come",
        "token": token.decode("UTF-8"),
    }
    payload = {"name": "Hospital X"}
    result = client.post("/groups", data=dumps(payload), headers=headers,
                         content_type="application/json")

    assert result.status_code == 403
    assert result.get_json()["error"] == "Invalid credentials!"


def test_create_group_invalid_token(client, database, cleanup):
    new_role = create_role(*admin_role)
    database.session.add(new_role)
    new_role = create_role(*user_role)
    database.session.add(new_role)
    new_user = create_user(*user1)
    database.session.add(new_user)
    new_user = create_user(*user2)
    database.session.add(new_user)

    database.session.commit()

    token = jwt.encode({"id": 1}, "peppperplsiwouldhavesome")
    headers = {
        "private_key": "fd062d885b24bda173f6aa534a3418bcafadccecfefe2f8c6f5a8db563549ced",
        "token": token.decode("UTF-8"),
    }
    payload = {"name": "Hospital X"}
    result = client.post("/groups", data=dumps(payload), headers=headers,
                         content_type="application/json")

    assert result.status_code == 403
    assert result.get_json()["error"] == "Invalid credentials!"


def test_create_group_unauthorized(client, database, cleanup):
    new_role = create_role(*admin_role)
    database.session.add(new_role)
    new_role = create_role(*user_role)
    database.session.add(new_role)
    new_user = create_user(*user1)
    database.session.add(new_user)
    new_user = create_user(*user2)
    database.session.add(new_user)

    database.session.commit()

    token = jwt.encode({"id": 2}, app.config["SECRET_KEY"])
    headers = {
        "private_key": "acfc10d15d7ec9f7cd05a312489af2794619c6f11e9af34671a5f33da48c1de2",
        "token": token.decode("UTF-8"),
    }
    payload = {"name": "Hospital X"}
    result = client.post("/groups", data=dumps(payload), headers=headers,
                         content_type="application/json")

    assert result.status_code == 403
    assert result.get_json()["error"] == "User is not authorized for this operation!"



