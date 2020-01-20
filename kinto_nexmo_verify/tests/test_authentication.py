from datetime import datetime, timedelta
import time
import unittest
from unittest import mock

import jwt
from kinto.core.cache import memory as memory_backend
from kinto.core.testing import DummyRequest
import requests

from kinto_nexmo_verify import DEFAULT_SETTINGS, authentication

from . import AuthenticationMockMixin


class PasswordlessAuthenticationPolicyTest(AuthenticationMockMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.policy = authentication.PasswordlessAuthenticationPolicy()
        self.backend = memory_backend.Cache(
            cache_prefix="tests", cache_max_size_bytes=float("inf")
        )
        self.request = self._build_request()

    def tearDown(self):
        super().tearDown()
        self.backend.flush()

    def _build_request(self):
        request = DummyRequest()
        request.bound_data = {}
        request.registry.cache = self.backend
        settings = DEFAULT_SETTINGS.copy()
        settings["userid_hmac_secret"] = "1234"
        settings["nexmo.api_key"] = "API KEY"
        settings["nexmo.api_secret"] = "API SECRET"
        settings["nexmo.jwt_secret"] = "JWT SECRET"
        settings["nexmo.cache_ttl_seconds"] = "0.01"
        request.registry.settings = settings
        token = jwt.encode(
            {"number": "+33612345678"}, settings["nexmo.jwt_secret"], algorithm="HS256"
        ).decode("utf-8")
        request.headers["Authorization"] = f"Bearer {token}"
        return request

    def test_returns_none_if_authorization_header_is_missing(self):
        self.request.headers.pop("Authorization")
        user_id = self.policy.unauthenticated_userid(self.request)
        self.assertIsNone(user_id)

    def test_returns_none_if_token_is_malformed(self):
        self.request.headers["Authorization"] = "BearerFoo"
        user_id = self.policy.unauthenticated_userid(self.request)
        self.assertIsNone(user_id)

    def test_returns_none_if_token_is_unknown(self):
        self.request.headers["Authorization"] = "Carrier foo"
        user_id = self.policy.authenticated_userid(self.request)
        self.assertIsNone(user_id)

    def test_returns_none_if_token_is_invalid(self):
        self.request.headers["Authorization"] = "Bearer foo"
        user_id = self.policy.authenticated_userid(self.request)
        self.assertIsNone(user_id)

    def test_returns_nexmo_userid(self):
        user_id = self.policy.authenticated_userid(self.request)
        assert "e4e8103c-001e-e1fd-1904-0187d489574a" == user_id

    def test_returns_nexmo_user_id_in_principals(self):
        principals = self.policy.effective_principals(self.request)
        self.assertIn("e4e8103c-001e-e1fd-1904-0187d489574a", principals)

    def test_policy_handle_invalid_tokens(self):
        token = jwt.encode(
            {"number": "+33612345678", "exp": datetime.now() - timedelta(days=1)},
            self.request.registry.settings["nexmo.jwt_secret"],
            algorithm="HS256",
        ).decode("utf-8")
        self.request.headers["Authorization"] = f"Bearer {token}"
        principals = self.policy.effective_principals(self.request)
        self.assertNotIn("e4e8103c-001e-e1fd-1904-0187d489574a", principals)

    def test_token_verification_is_cached(self):
        # First request from client.
        with mock.patch("kinto_nexmo_verify.authentication.jwt") as mocked_jwt:
            request = self._build_request()
            self.policy.authenticated_userid(request)
            # Second request from same client.
            request = self._build_request()
            self.policy.authenticated_userid(request)
            # Cache backend was used.
        self.assertEqual(1, mocked_jwt.decode.call_count)

    def test_token_verification_is_done_once_per_request(self):
        with mock.patch("kinto_nexmo_verify.authentication.jwt") as mocked_jwt:
            # First request from client.
            self.policy.authenticated_userid(self.request)
            # Within the same request cycle, token won't be verified.
            self.request.headers["Authorization"] = "Bearer another"
            self.policy.authenticated_userid(self.request)
            # Request bound data is used.
        self.assertEqual(1, mocked_jwt.decode.call_count)

    def test_token_verification_uses_cache_by_token(self):
        request1 = self._build_request()
        request2 = self._build_request()
        token = jwt.encode(
            {"number": "+33612345678"},
            self.request.registry.settings["nexmo.jwt_secret"],
            algorithm="HS256",
        ).decode("utf-8")
        request2.headers["Authorization"] = f"Bearer {token}"

        with mock.patch("kinto_nexmo_verify.authentication.jwt") as mocked_jwt:
            # First request from client.
            self.policy.authenticated_userid(request1)
            # Second request from another client.
            self.policy.authenticated_userid(request2)
        # Cache backend key was different.
        self.assertEqual(1, mocked_jwt.decode.call_count)

    def test_token_verification_cache_has_ttl(self):
        request1 = self._build_request()
        request2 = self._build_request()
        # First request from client.
        with mock.patch("kinto_nexmo_verify.authentication.jwt") as mocked_jwt:
            self.policy.authenticated_userid(request1)
            # Second request from same client after TTL.
            time.sleep(0.02)
            self.policy.authenticated_userid(request2)
        # Cache backend key was expired.
        self.assertEqual(2, mocked_jwt.decode.call_count)


class NexmoPingTest(unittest.TestCase):
    def setUp(self):
        self.request = DummyRequest()
        self.request.registry.settings = DEFAULT_SETTINGS

    @mock.patch("requests.get")
    def test_returns_true_if_ok(self, get_mocked):
        httpOK = requests.models.Response()
        httpOK.status_code = 200
        get_mocked.return_value = httpOK
        assert authentication.nexmo_ping(self.request) is True

    @mock.patch("requests.get")
    def test_returns_false_if_ko(self, get_mocked):
        get_mocked.return_value.raise_for_status.side_effect = (
            requests.exceptions.HTTPError
        )
        assert authentication.nexmo_ping(self.request) is False
