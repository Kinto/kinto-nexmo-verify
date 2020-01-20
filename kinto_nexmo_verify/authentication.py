import logging
from uuid import UUID

import jwt
from kinto.core.utils import hmac_digest
from pyramid import authentication as base_auth
from pyramid.interfaces import IAuthenticationPolicy
import requests
from zope.interface import implementer

from .conf import nexmo_conf

logger = logging.getLogger(__name__)

NEXMO_REIFY_KEY = "nexmo_verified_token"
NEXMO_VERIFY_CACHE_KEY = "nexmo:verify:{}"


@implementer(IAuthenticationPolicy)
class PasswordlessAuthenticationPolicy(base_auth.CallbackAuthenticationPolicy):
    name = "nexmo"

    def __init__(self, realm="Realm"):
        self.realm = realm
        self._cache = None

    def unauthenticated_userid(self, request):
        """Return the Nexmo user_id or ``None`` if token could not be verified.
        """
        authorization = request.headers.get("Authorization", "")
        try:
            authmeth, token = authorization.split(" ", 1)
        except ValueError:
            return None
        if authmeth.lower() != nexmo_conf(request, "header_type").lower():
            return None

        user_id = self._verify_token(token, request)
        return user_id

    def _verify_token(self, access_token, request):
        """Verify the token extracted from the Authorization header.
        """
        if NEXMO_REIFY_KEY not in request.bound_data:
            settings = request.registry.settings
            hmac_secret = settings["userid_hmac_secret"]

            hmac_token = hmac_digest(hmac_secret, access_token)
            cache_key = NEXMO_VERIFY_CACHE_KEY.format(hmac_token)
            cache_ttl = float(nexmo_conf(request, "cache_ttl_seconds"))
            user_info = request.registry.cache.get(cache_key)

            if user_info is None:
                try:
                    payload = jwt.decode(
                        access_token,
                        nexmo_conf(request, "jwt_secret"),
                        algorithm="HS256",
                    )
                except (
                    jwt.ExpiredSignatureError,
                    jwt.InvalidSignatureError,
                    jwt.DecodeError,
                    ValueError,
                ):
                    return None

                settings = request.registry.settings
                hmac_secret = settings["userid_hmac_secret"]
                credentials = f"{payload['number']}"
                userid = str(UUID(hmac_digest(hmac_secret, credentials)[:32]))
                user_info = {"user_id": userid, "number": {payload["number"]}}

            # Cache between requests
            request.bound_data["authentication_cache_key"] = cache_key
            request.registry.cache.set(cache_key, user_info, ttl=cache_ttl)

            # Cache for this request
            request.bound_data[NEXMO_REIFY_KEY] = user_info

        return request.bound_data[NEXMO_REIFY_KEY].get("user_id")


def nexmo_ping(request):
    """Verify if the Nexmo API is reachable."""
    api_key = nexmo_conf(request, "api_key")
    api_secret = nexmo_conf(request, "api_secret")
    timeout = float(nexmo_conf(request, "heartbeat_timeout_seconds"))

    heartbeat_url = (
        f"https://api.nexmo.com/verify/json?api_key={api_key}&api_secret={api_secret}"
    )

    try:
        r = requests.get(heartbeat_url, timeout=timeout)
        r.raise_for_status()
    except (requests.exceptions.ConnectionError, requests.exceptions.HTTPError):
        nexmo = False
    else:
        nexmo = True
    return nexmo
