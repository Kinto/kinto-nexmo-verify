from datetime import datetime, timedelta
from time import sleep
import unittest
from unittest import mock

import jwt
import kinto.core
from kinto.core.errors import ERRORS
from kinto.core.testing import FormattedErrorMixin
from kinto.core.utils import random_bytes_hex
from pyramid.config import Configurator
from requests.exceptions import ConnectionError, HTTPError

import webtest

from . import AuthenticationMockMixin


def get_request_class(prefix):
    class PrefixedRequestClass(webtest.app.TestRequest):
        @classmethod
        def blank(cls, path, *args, **kwargs):
            path = "/%s%s" % (prefix, path)
            return webtest.app.TestRequest.blank(path, *args, **kwargs)

    return PrefixedRequestClass


class BaseWebTestMixin(AuthenticationMockMixin):
    api_prefix = "v1"
    params = {"number": "33612345678"}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.app = self._get_test_app()

    def setUp(self):
        super().setUp()
        self.settings = self.app.app.registry.settings
        self.settings.update(self.get_app_settings())
        self.access_token = self.build_token()
        self.headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json",
        }

    def _get_test_app(self, settings=None):
        config = self._get_app_config(settings)
        wsgi_app = config.make_wsgi_app()
        app = webtest.TestApp(wsgi_app)
        app.RequestClass = get_request_class(self.api_prefix)
        return app

    def _get_app_config(self, settings=None):
        config = Configurator(settings=self.get_app_settings(settings))
        kinto.core.initialize(config, version="1.0.0")
        return config

    def get_app_settings(self, additional_settings=None):
        settings = kinto.core.DEFAULT_SETTINGS.copy()
        settings["project_name"] = "kinto"
        settings["includes"] = "kinto_nexmo_verify"
        settings["multiauth.policies"] = "nexmo"
        authn = "kinto_nexmo_verify.authentication.PasswordlessAuthenticationPolicy"
        settings["multiauth.policy.nexmo.use"] = authn
        settings["cache_backend"] = "kinto.core.cache.memory"
        settings["userid_hmac_secret"] = random_bytes_hex(16)
        settings["nexmo.jwt_secret"] = "JWT NEXMO TOKEN"
        settings["nexmo.cache_ttl_seconds"] = 30
        settings["email.jwt_secret"] = "JWT EMAIL TOKEN"
        settings["email.reset_jwt_secret"] = "RESET JWT TOKEN"
        settings["email.cache_ttl_seconds"] = 30
        settings["stripe.private_key"] = "sk_test_dTQLzbFC6Y4ygFPE8cm1JBbR"
        settings["stripe.endpoint_secret"] = "secret"
        settings["revenuecat.api_key"] = "revenuecat api key"

        if additional_settings is not None:
            settings.update(additional_settings)
        return settings

    def build_token(self, exp=None):
        return self.build_nexmo_token(exp)

    def build_nexmo_token(self, exp=None):
        if exp is None:
            exp = datetime.utcnow() + timedelta(
                seconds=int(self.settings["nexmo.cache_ttl_seconds"])
            )
        return jwt.encode(
            {"number": self.params["number"], "exp": exp},
            self.settings["nexmo.jwt_secret"],
            algorithm="HS256",
        ).decode("utf-8")


class VerifyViewTest(FormattedErrorMixin, BaseWebTestMixin, unittest.TestCase):
    url = "/nexmo/verify"
    number = "33612345678"
    brand = "ACME Inc."

    def setUp(self):
        super().setUp()
        self.mock_nexmo_verify_call()

    def get_app_settings(self, additional_settings=None):
        additional_settings = additional_settings or {}
        additional_settings.update(
            {
                "nexmo.api_key": "API KEY",
                "nexmo.api_secret": "API SECRET",
                "nexmo.jwt_secret": "JWT SECRET",
            }
        )
        return super().get_app_settings(additional_settings)

    def test_number_parameter_is_mandatory(self):
        r = self.app.get(self.url, params={}, status=400)
        self.assertIn("number", r.json["message"])

    def test_verify_view_persists_state(self):
        r = self.app.get(self.url, params={"number": self.number})
        state = r.json["state"]
        self.assertEqual(
            self.app.app.registry.cache.get(state),
            '{"request_id": "9e59abbe98204a9ebe8a36101383ec20", "number": 33612345678}',
        )

    def test_verify_view_persists_state_with_expiration(self):
        r = self.app.get(self.url, params={"number": self.number})
        state = r.json["state"]
        self.assertGreater(self.app.app.registry.cache.ttl(state), 419)
        self.assertLessEqual(self.app.app.registry.cache.ttl(state), 420)

    def test_verify_view_handle_error_with_the_nexmo_api(self):
        self.mock_nexmo_verify_call({"status": "1", "error_text": "Blah"})
        resp = self.app.get(self.url, params={"number": self.number}, status=400)

        error_msg = "Something went wrong when trying to authenticate this number."
        self.assertFormattedError(
            resp, 400, ERRORS.INVALID_PARAMETERS, "Invalid parameters", error_msg
        )

    def test_verify_view_handle_retry_error_with_the_nexmo_api(self):
        self.mock_nexmo_verify_call({"status": "10", "error_text": "Blah"})
        resp = self.app.get(self.url, params={"number": self.number}, status=400)

        error_msg = (
            "An authentication request is already in progress for this number. Blah"
        )
        self.assertFormattedError(
            resp, 400, ERRORS.INVALID_PARAMETERS, "Invalid parameters", error_msg
        )

    def test_verify_view_handle_http_error_with_the_nexmo_api(self):
        self.nexmo_mock.get.return_value.raise_for_status.side_effect = HTTPError
        self.nexmo_mock.exceptions.HTTPError = HTTPError
        self.app.get(self.url, params={"number": self.number}, status=503)

    def test_verify_view_handle_connection_error_with_the_nexmo_api(self):
        self.nexmo_mock.get.side_effect = ConnectionError
        self.nexmo_mock.exceptions.ConnectionError = ConnectionError
        self.app.get(self.url, params={"number": self.number}, status=503)


class CheckViewTest(FormattedErrorMixin, BaseWebTestMixin, unittest.TestCase):
    login_url = "/nexmo/verify"
    url = "/nexmo/verify/check"
    params = {"number": "33612345678", "brand": "Chefclub"}

    def setUp(self):
        super().setUp()
        self.mock_nexmo_check_call()

    def test_fails_if_no_ongoing_session(self):
        url = "{url}?state=abc&code=1234".format(url=self.url)
        resp = self.app.get(url, status=408)
        error_msg = "The Nexmo session was not found, please re-authenticate."
        self.assertFormattedError(
            resp, 408, ERRORS.MISSING_AUTH_TOKEN, "Request Timeout", error_msg
        )

    def test_fails_if_state_or_code_is_missing(self):
        for params in ["", "?state=abc", "?code=1234"]:
            r = self.app.get(self.url + params, status=400)
            self.assertIn("Required", r.json["message"])

    def test_fails_if_state_does_not_match(self):
        self.app.app.registry.cache.set("def", "http://foobar", ttl=1)
        url = "{url}?state=abc&code=1234".format(url=self.url)
        resp = self.app.get(url, status=408)
        error_msg = "The Nexmo session was not found, please re-authenticate."
        self.assertFormattedError(
            resp, 408, ERRORS.MISSING_AUTH_TOKEN, "Request Timeout", error_msg
        )

    def test_fails_if_state_was_already_consumed(self):
        self.app.app.registry.cache.set(
            "abc",
            '{"number": "33612345678", "request_id": "78d40c21240840209e07a3752db8a5d4"}',
            ttl=1,
        )
        url = "{url}?state=abc&code=1234".format(url=self.url)
        self.app.get(url)
        resp = self.app.get(url, status=408)
        error_msg = "The Nexmo session was not found, please re-authenticate."
        self.assertFormattedError(
            resp, 408, ERRORS.MISSING_AUTH_TOKEN, "Request Timeout", error_msg
        )

    def test_fails_if_state_has_expired(self):
        with mock.patch.dict(
            self.app.app.registry.settings, [("nexmo.state_ttl_seconds", -120.01)]
        ):
            self.mock_nexmo_verify_call()
            r = self.app.get(self.login_url, params=self.params)
        state = r.json["state"]
        sleep(0.02)
        resp = self.app.get(
            self.url, params={"state": state, "code": "1234"}, status=408
        )
        error_msg = "The Nexmo session was not found, please re-authenticate."
        self.assertFormattedError(
            resp, 408, ERRORS.MISSING_AUTH_TOKEN, "Request Timeout", error_msg
        )

    def tests_redirects_with_token_traded_against_code(self):
        self.app.app.registry.cache.set(
            "abc",
            '{"number": "33612345678", "request_id": "78d40c21240840209e07a3752db8a5d4"}',
            ttl=1,
        )
        r = self.app.get(self.url, params={"state": "abc", "code": "1234"})
        self.assertEqual(r.status_code, 200)
        self.assertIn("access_token", r.json)

    def tests_return_503_if_nexmo_auth_server_behaves_badly(self):
        self.nexmo_mock.get.return_value.raise_for_status.side_effect = HTTPError
        self.nexmo_mock.exceptions.HTTPError = HTTPError

        self.app.app.registry.cache.set(
            "abc",
            '{"number": "33612345678", "request_id": "78d40c21240840209e07a3752db8a5d4"}',
            ttl=1,
        )
        self.app.get(self.url, params={"state": "abc", "code": "1234"}, status=503)

    def tests_return_503_if_nexmo_auth_server_is_not_available(self):
        self.nexmo_mock.get.side_effect = ConnectionError
        self.nexmo_mock.exceptions.ConnectionError = ConnectionError

        self.app.app.registry.cache.set(
            "abc",
            '{"number": "33612345678", "request_id": "78d40c21240840209e07a3752db8a5d4"}',
            ttl=1,
        )
        self.app.get(self.url, params={"state": "abc", "code": "1234"}, status=503)

    def tests_return_400_if_client_error_detected(self):
        httpBadRequest = mock.MagicMock()
        httpBadRequest.json.return_value = {"status": "10", "error_text": "blah"}
        self.nexmo_mock.get.return_value = httpBadRequest

        self.app.app.registry.cache.set(
            "abc",
            '{"number": "33612345678", "request_id": "78d40c21240840209e07a3752db8a5d4"}',
            ttl=1,
        )
        self.app.get(self.url, params={"state": "abc", "code": "1234"}, status=400)


class CancelViewTest(FormattedErrorMixin, BaseWebTestMixin, unittest.TestCase):
    login_url = "/nexmo/verify"
    url = "/nexmo/verify/cancel"
    params = {"number": "33612345678", "brand": "Chefclub"}

    def setUp(self):
        super().setUp()
        self.mock_nexmo_cancel_call()

    def get_app_settings(self, additional_settings=None):
        additional_settings = additional_settings or {}
        additional_settings.update(
            {
                "nexmo.api_key": "API KEY",
                "nexmo.api_secret": "API SECRET",
                "nexmo.jwt_secret": "JWT SECRET",
            }
        )
        return super().get_app_settings(additional_settings)

    def test_fails_if_no_ongoing_session(self):
        url = "{url}?state=abc".format(url=self.url)
        resp = self.app.get(url, status=408)
        error_msg = "The Nexmo session was not found, please re-authenticate."
        self.assertFormattedError(
            resp, 408, ERRORS.MISSING_AUTH_TOKEN, "Request Timeout", error_msg
        )

    def test_fails_if_state_or_code_is_missing(self):
        r = self.app.get(self.url, status=400)
        self.assertIn("Required", r.json["message"])

    def test_fails_if_state_does_not_match(self):
        self.app.app.registry.cache.set("def", "http://foobar", ttl=1)
        url = "{url}?state=abc".format(url=self.url)
        resp = self.app.get(url, status=408)
        error_msg = "The Nexmo session was not found, please re-authenticate."
        self.assertFormattedError(
            resp, 408, ERRORS.MISSING_AUTH_TOKEN, "Request Timeout", error_msg
        )

    def test_fails_if_state_was_already_consumed(self):
        self.app.app.registry.cache.set(
            "abc",
            '{"number": "33612345678", "request_id": "78d40c21240840209e07a3752db8a5d4"}',
            ttl=1,
        )
        url = "{url}?state=abc".format(url=self.url)
        self.app.get(url)
        resp = self.app.get(url, status=408)
        error_msg = "The Nexmo session was not found, please re-authenticate."
        self.assertFormattedError(
            resp, 408, ERRORS.MISSING_AUTH_TOKEN, "Request Timeout", error_msg
        )

    def test_fails_if_too_early(self):
        self.app.app.registry.cache.set(
            "abc",
            '{"number": "33612345678", "request_id": "78d40c21240840209e07a3752db8a5d4"}',
            ttl=1,
        )
        self.mock_nexmo_cancel_call(
            {
                "status": "19",
                "error_text": "Verification request ['a6844d6f21294908bf596d15a2e4f2b5'] can't be"
                "cancelled within the first 30 seconds.",
            }
        )

        url = "{url}?state=abc".format(url=self.url)
        resp = self.app.get(url, status=400)
        error_msg = "Nexmo code cancelation failed. Too early."
        self.assertFormattedError(resp, 400, ERRORS.BACKEND, "Bad Request", error_msg)

    def test_fails_if_too_late(self):
        self.app.app.registry.cache.set(
            "abc",
            '{"number": "33612345678", "request_id": "78d40c21240840209e07a3752db8a5d4"}',
            ttl=1,
        )
        self.mock_nexmo_cancel_call(
            {
                "status": "19",
                "error_text": "Verification request ['a6844d6f21294908bf596d15a2e4f2b5'] can't "
                "be cancelled now. Too many attempts to re-deliver have already been made.",
            }
        )

        url = "{url}?state=abc".format(url=self.url)
        resp = self.app.get(url, status=410)
        error_msg = "Nexmo code cancelation failed. Too late."
        self.assertFormattedError(resp, 410, ERRORS.BACKEND, "Gone", error_msg)

    def test_fails_if_state_has_expired(self):
        with mock.patch.dict(
            self.app.app.registry.settings, [("nexmo.state_ttl_seconds", -120.01)]
        ):
            self.mock_nexmo_verify_call()
            r = self.app.get(self.login_url, params=self.params)
        state = r.json["state"]
        sleep(0.02)
        self.mock_nexmo_cancel_call()
        resp = self.app.get(
            self.url, params={"state": state, "code": "1234"}, status=408
        )
        error_msg = "The Nexmo session was not found, please re-authenticate."
        self.assertFormattedError(
            resp, 408, ERRORS.MISSING_AUTH_TOKEN, "Request Timeout", error_msg
        )

    def tests_redirects_with_token_traded_against_code(self):
        self.app.app.registry.cache.set(
            "abc",
            '{"number": "33612345678", "request_id": "78d40c21240840209e07a3752db8a5d4"}',
            ttl=1,
        )
        r = self.app.get(self.url, params={"state": "abc", "code": "1234"})
        self.assertEqual(r.status_code, 200)
        self.assertIn("state", r.json)
        self.assertEqual(r.json["state"], "abc")
        self.assertIn("status", r.json)

    def tests_return_503_if_nexmo_auth_server_behaves_badly(self):
        self.nexmo_mock.get.return_value.raise_for_status.side_effect = HTTPError
        self.nexmo_mock.exceptions.HTTPError = HTTPError

        self.app.app.registry.cache.set(
            "abc",
            '{"number": "33612345678", "request_id": "78d40c21240840209e07a3752db8a5d4"}',
            ttl=1,
        )
        self.app.get(self.url, params={"state": "abc"}, status=503)

    def tests_return_503_if_nexmo_auth_server_is_not_available_badly(self):
        self.nexmo_mock.get.side_effect = ConnectionError
        self.nexmo_mock.exceptions.ConnectionError = ConnectionError

        self.app.app.registry.cache.set(
            "abc",
            '{"number": "33612345678", "request_id": "78d40c21240840209e07a3752db8a5d4"}',
            ttl=1,
        )
        self.app.get(self.url, params={"state": "abc"}, status=503)

    def tests_return_400_if_client_error_detected(self):
        httpBadRequest = mock.MagicMock()
        httpBadRequest.json.return_value = {"status": "10", "error_text": "blah"}
        self.nexmo_mock.get.return_value = httpBadRequest

        self.app.app.registry.cache.set(
            "abc",
            '{"number": "33612345678", "request_id": "78d40c21240840209e07a3752db8a5d4"}',
            ttl=1,
        )
        self.app.get(self.url, params={"state": "abc", "code": "1234"}, status=400)


class RefreshViewTest(FormattedErrorMixin, BaseWebTestMixin, unittest.TestCase):
    url = "/nexmo/verify/refresh"
    params = {"number": "33612345678"}

    def test_fails_if_no_auth(self):
        url = "{url}".format(url=self.url)
        resp = self.app.get(url, status=400)
        error_msg = "Invalid authentication method for Nexmo Token Refresh."
        self.assertFormattedError(
            resp, 400, ERRORS.INVALID_PARAMETERS, "Invalid parameters", error_msg
        )

    def test_fails_if_wrong_auth(self):
        url = "{url}".format(url=self.url)
        headers = {"Authorization": "Basic abcd"}
        resp = self.app.get(url, headers=headers, status=400)
        error_msg = "Invalid authentication method for Nexmo Token Refresh."
        self.assertFormattedError(
            resp, 400, ERRORS.INVALID_PARAMETERS, "Invalid parameters", error_msg
        )

    def test_fails_if_wrong_token(self):
        url = "{url}".format(url=self.url)
        headers = {"Authorization": "Bearer abcd"}
        resp = self.app.get(url, headers=headers, status=400)
        error_msg = "Authorization in header: Invalid Nexmo token."
        self.assertFormattedError(
            resp, 400, ERRORS.INVALID_PARAMETERS, "Invalid parameters", error_msg
        )

    def test_fails_if_token_has_expired(self):
        exp = datetime.utcnow() - timedelta(
            seconds=int(self.settings["nexmo.cache_ttl_seconds"])
        )
        invalid_access_token = self.build_token(exp)
        headers = {"Authorization": f"Bearer {invalid_access_token}"}
        url = "{url}".format(url=self.url)
        resp = self.app.get(url, headers=headers, status=400)
        error_msg = "Authorization in header: Invalid Nexmo token."
        self.assertFormattedError(
            resp, 400, ERRORS.INVALID_PARAMETERS, "Invalid parameters", error_msg
        )

    def test_succeed_if_token_is_valid(self):
        access_token = self.build_token()
        headers = {"Authorization": f"Bearer {access_token}"}
        url = "{url}".format(url=self.url)
        resp = self.app.get(url, headers=headers, status=200)
        self.assertIn("access_token", resp.json)
        payload = jwt.decode(
            resp.json["access_token"],
            self.settings["nexmo.jwt_secret"],
            algorithm="HS256",
        )
        self.assertEqual(payload["number"], self.params["number"])


class CheckBalanceViewTest(FormattedErrorMixin, BaseWebTestMixin, unittest.TestCase):
    url = "/__nexmo_balance__"

    def test_succeed_if_balance_and_autoReload_status_are_correct(self):
        self.nexmo_mock.get.return_value.json.return_value = {
            "value": 10.0,
            "autoReload": True,
        }
        resp = self.app.get(self.url, status=200)
        assert resp.json == {"value": 10.0, "autoReload": True}

    def test_fails_if_balance_is_too_low(self):
        self.nexmo_mock.get.return_value.json.return_value = {
            "value": 2,
            "autoReload": True,
        }
        resp = self.app.get(self.url, status=503)
        assert resp.json == {"value": 2, "autoReload": True}

    def test_fails_if_autoReload_is_false(self):
        self.nexmo_mock.get.return_value.json.return_value = {
            "value": 10,
            "autoReload": False,
        }
        resp = self.app.get(self.url, status=503)
        assert resp.json == {"value": 10, "autoReload": False}

    def test_fails_if_nexmo_is_not_available(self):
        self.nexmo_mock.exceptions.HTTPError = HTTPError
        self.nexmo_mock.exceptions.ConnectionError = ConnectionError
        self.nexmo_mock.get.return_value.json.return_value = {"error": "happened"}
        self.nexmo_mock.get.return_value.raise_for_status.side_effect = HTTPError
        resp = self.app.get(self.url, status=503)
        assert resp.json == {"error": "happened"}

    def test_fails_if_nexmo_is_not_accessible(self):
        self.nexmo_mock.exceptions.ConnectionError = ConnectionError
        self.nexmo_mock.get.side_effect = ConnectionError
        resp = self.app.get(self.url, status=503)
        assert resp.json == {"error": "Connection error: "}
