from datetime import datetime, timedelta
import json
import logging
import uuid

import colander
from cornice.validators import colander_validator
import jwt
from kinto.core import Service
from kinto.core.errors import ERRORS, http_error, json_error_handler, raise_invalid
from pyramid import httpexceptions
from pyramid.security import NO_PERMISSION_REQUIRED
import requests

from .conf import nexmo_conf

logger = logging.getLogger(__name__)


verify = Service(
    name="nexmo-verify", path="/nexmo/verify", error_handler=json_error_handler
)

check = Service(
    name="nexmo-check", path="/nexmo/verify/check", error_handler=json_error_handler
)

cancel = Service(
    name="nexmo-cancel", path="/nexmo/verify/cancel", error_handler=json_error_handler
)

refresh = Service(
    name="nexmo-refresh", path="/nexmo/verify/refresh", error_handler=json_error_handler
)


def persist_state(request, data):
    """Persist login information in cache
    """
    state = uuid.uuid4().hex
    expiration = float(nexmo_conf(request, "state_ttl_seconds"))
    # Add a couple of minutes to be sure to keep it longer than nexmo
    request.registry.cache.set(state, json.dumps(data), expiration + 120)
    return state


class NexmoVerifyQueryString(colander.MappingSchema):
    number = colander.SchemaNode(colander.Integer())


class NexmoVerifyRequest(colander.MappingSchema):
    querystring = NexmoVerifyQueryString()


@verify.get(
    schema=NexmoVerifyRequest,
    permission=NO_PERMISSION_REQUIRED,
    validators=(colander_validator),
)
def nexmo_verify(request):
    """Ask Nexmo for a verify code."""
    number = request.validated["querystring"]["number"]

    sender_id = nexmo_conf(request, "sender_id")
    params = {
        "api_key": nexmo_conf(request, "api_key"),
        "api_secret": nexmo_conf(request, "api_secret"),
        "sender_id": sender_id,
        "code_length": nexmo_conf(request, "code_length"),
        "pin_expiry": nexmo_conf(request, "state_ttl_seconds"),
        "number": number,
        "brand": nexmo_conf(request, "brand"),
    }

    verify_url = "{}/verify/json".format(
        nexmo_conf(request, "api_endpoint").rstrip("/")
    )

    try:
        resp = requests.get(verify_url, params=params)
    except requests.exceptions.ConnectionError:
        logger.exception(
            "A connection error occured when starting the nexmo auth process"
        )
        error_msg = "The Nexmo API is not ready, please retry later."
        return http_error(
            httpexceptions.HTTPServiceUnavailable(),
            errno=ERRORS.BACKEND,
            message=error_msg,
        )

    try:
        resp.raise_for_status()
    except requests.exceptions.HTTPError:
        logger.exception("An error occured when starting the auth process")
        error_msg = "The Nexmo API is not ready, please retry later."
        return http_error(
            httpexceptions.HTTPServiceUnavailable(),
            errno=ERRORS.BACKEND,
            message=error_msg,
        )

    data = resp.json()

    if data["status"] == "10":
        description = (
            f"An authentication request is already in progress for this number. "
            f"{data['error_text']}"
        )
        error_details = {
            "name": "number",
            "location": "querystring",
            "description": description,
        }
        raise_invalid(request, **error_details)
    elif data["status"] != "0":
        if data["status"] in ["6", "16", "19"]:  # pragma: no cover
            logger.info("Nexmo Verify Request failed: {}".format(data))
        else:
            logger.error("Nexmo Verify Request failed: {}".format(data))
        description = "Something went wrong when trying to authenticate this number."
        error_details = {
            "name": "number",
            "location": "querystring",
            "description": description,
        }
        raise_invalid(request, **error_details)

    state = persist_state(request, {"request_id": data["request_id"], "number": number})

    return {"state": state, "sender_id": sender_id}


class NexmoCheckQueryString(colander.MappingSchema):
    code = colander.SchemaNode(colander.String())
    state = colander.SchemaNode(colander.String())


class NexmoCheckRequest(colander.MappingSchema):
    querystring = NexmoCheckQueryString()


@check.get(
    schema=NexmoCheckRequest,
    permission=NO_PERMISSION_REQUIRED,
    validators=(colander_validator,),
)
def nexmo_check(request):
    """Return OAuth token from authorization code.
    """
    state = request.validated["querystring"]["state"]
    code = request.validated["querystring"]["code"]

    # Require on-going session
    state_info = request.registry.cache.get(state)

    if not state_info:
        error_msg = "The Nexmo session was not found, please re-authenticate."
        return http_error(
            httpexceptions.HTTPRequestTimeout(),
            errno=ERRORS.MISSING_AUTH_TOKEN,
            message=error_msg,
        )
    else:
        state_info = json.loads(state_info)

    params = {
        "api_key": nexmo_conf(request, "api_key"),
        "api_secret": nexmo_conf(request, "api_secret"),
        "request_id": state_info["request_id"],
        "code": code,
    }

    check_url = "{}/verify/check/json".format(
        nexmo_conf(request, "api_endpoint").rstrip("/")
    )

    try:
        resp = requests.get(check_url, params=params)
    except requests.exceptions.ConnectionError:
        logger.exception(
            "A connection error occured when trying to validate the auth code"
        )
        error_msg = "The Nexmo API is not ready, please retry later."
        return http_error(
            httpexceptions.HTTPServiceUnavailable(),
            errno=ERRORS.BACKEND,
            message=error_msg,
        )

    try:
        resp.raise_for_status()
    except requests.exceptions.HTTPError:
        logger.exception("An error occured when trying to validate the auth code")
        error_msg = "The Nexmo API is not ready, please retry later."
        return http_error(
            httpexceptions.HTTPServiceUnavailable(),
            errno=ERRORS.BACKEND,
            message=error_msg,
        )

    data = resp.json()

    if data["status"] != "0":
        logger.info("Nexmo Code Validation Failed: {}".format(data))
        error_details = {
            "name": "code",
            "location": "querystring",
            "description": "Nexmo code validation failed.",
        }
        raise_invalid(request, **error_details)

    # Make sure we cannot try twice with the same state
    request.registry.cache.delete(state)

    exp = datetime.utcnow() + timedelta(
        seconds=int(nexmo_conf(request, "cache_ttl_seconds"))
    )

    # Build JWT Access Token
    access_token = jwt.encode(
        {"number": state_info["number"], "exp": exp},
        nexmo_conf(request, "jwt_secret"),
        algorithm="HS256",
    ).decode("utf-8")

    return {"access_token": access_token}


class NexmoCancelQueryString(colander.MappingSchema):
    state = colander.SchemaNode(colander.String())


class NexmoCancelRequest(colander.MappingSchema):
    querystring = NexmoCancelQueryString()


@cancel.get(
    schema=NexmoCancelRequest,
    permission=NO_PERMISSION_REQUIRED,
    validators=(colander_validator,),
)
def nexmo_cancel(request):
    """Cancel the Nexmo request
    """
    state = request.validated["querystring"]["state"]

    # Require on-going session
    state_info = request.registry.cache.get(state)

    if not state_info:
        error_msg = "The Nexmo session was not found, please re-authenticate."
        return http_error(
            httpexceptions.HTTPRequestTimeout(),
            errno=ERRORS.MISSING_AUTH_TOKEN,
            message=error_msg,
        )
    else:
        state_info = json.loads(state_info)

    params = {
        "api_key": nexmo_conf(request, "api_key"),
        "api_secret": nexmo_conf(request, "api_secret"),
        "request_id": state_info["request_id"],
        "cmd": "cancel",
    }

    cancel_url = "{}/verify/control/json".format(
        nexmo_conf(request, "api_endpoint").rstrip("/")
    )

    try:
        resp = requests.get(cancel_url, params=params)
    except requests.exceptions.ConnectionError:
        logger.exception(
            "A connection error occured when trying to cancel the auth code"
        )
        error_msg = "The Nexmo API is not ready, please retry later."
        return http_error(
            httpexceptions.HTTPServiceUnavailable(),
            errno=ERRORS.BACKEND,
            message=error_msg,
        )

    try:
        resp.raise_for_status()
    except requests.exceptions.HTTPError:
        logger.exception("An error occured when trying to cancel the auth code")
        error_msg = "The Nexmo API is not ready, please retry later."
        return http_error(
            httpexceptions.HTTPServiceUnavailable(),
            errno=ERRORS.BACKEND,
            message=error_msg,
        )

    data = resp.json()

    if data["status"] == "19":
        # Two cases
        # - Cancel too early, please retry later.
        # - Cancel too late, its gone.
        if data["error_text"].endswith(
            "Too many attempts to re-deliver have already been made."
        ):
            logger.info("Nexmo Code Cancelation failed. Too late: {}".format(data))
            return http_error(
                httpexceptions.HTTPGone(),
                errno=ERRORS.BACKEND,
                message="Nexmo code cancelation failed. Too late.",
            )
        else:
            logger.info("Nexmo Code Cancelation too early: {}".format(data))
            return http_error(
                httpexceptions.HTTPBadRequest(),
                errno=ERRORS.BACKEND,
                message="Nexmo code cancelation failed. Too early.",
            )

    if data["status"] != "0":
        logger.info("Nexmo Code Cancelation Failed: {}".format(data))
        error_details = {
            "name": "code",
            "location": "querystring",
            "description": "Nexmo code cancelation failed.",
        }
        raise_invalid(request, **error_details)

    # Make sure we cannot try twice with the same state
    request.registry.cache.delete(state)

    return {"state": state, "status": "canceled"}


@refresh.get(permission=NO_PERMISSION_REQUIRED)
def nexmo_refresh(request):
    """Return a refreshed OAuth token from authorization code.

    Caution, since this endpoint doesn't require permission, it
    will not make sure the token is valid before allowing access.

    """
    authorization = request.headers.get("Authorization", "")
    split_failed = False
    try:
        authmeth, access_token = authorization.split(" ", 1)
    except ValueError:
        split_failed = True

    if split_failed or authmeth.lower() != nexmo_conf(request, "header_type").lower():
        error_details = {
            "name": "Authorization",
            "location": "header",
            "description": "Invalid authentication method for Nexmo Token Refresh.",
        }
        raise_invalid(request, **error_details)

    try:
        payload = jwt.decode(
            access_token, nexmo_conf(request, "jwt_secret"), algorithm="HS256"
        )
    except (
        jwt.ExpiredSignatureError,
        jwt.InvalidSignatureError,
        jwt.DecodeError,
        ValueError,
    ):
        error_details = {
            "name": "Authorization",
            "location": "header",
            "description": "Invalid Nexmo token.",
        }
        raise_invalid(request, **error_details)

    exp = datetime.utcnow() + timedelta(
        seconds=int(nexmo_conf(request, "cache_ttl_seconds"))
    )

    # Build JWT Access Token
    access_token = jwt.encode(
        {"number": payload["number"], "exp": exp},
        nexmo_conf(request, "jwt_secret"),
        algorithm="HS256",
    )

    return {"access_token": access_token.decode("utf-8")}


nexmo_healthz = Service(
    name="__nexmo_balance__",
    description="nexmo balance info",
    path="/__nexmo_balance__",
)


@nexmo_healthz.get(permission=NO_PERMISSION_REQUIRED)
def nexmo_healthz_get(request):
    api_key = nexmo_conf(request, "api_key")
    api_secret = nexmo_conf(request, "api_secret")
    timeout = float(nexmo_conf(request, "heartbeat_timeout_seconds"))

    heartbeat_url = (
        f"https://rest.nexmo.com/account/get-balance?"
        f"api_key={api_key}&api_secret={api_secret}"
    )

    try:
        r = requests.get(heartbeat_url, timeout=timeout)
    except requests.exceptions.ConnectionError as e:
        has_error = True
        response = {"error": f"Connection error: {e}"}
    else:
        try:
            r.raise_for_status()
        except requests.exceptions.HTTPError:
            has_error = True
            response = r.json()
        else:
            has_error = False

            response = r.json()
            balance = response["value"]
            autoReload = response["autoReload"]

            if not autoReload:
                has_error = True

            if balance < 10:
                has_error = True

    if has_error:
        request.response.status = 503

    return response
