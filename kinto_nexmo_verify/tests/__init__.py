from unittest import mock


class AuthenticationMockMixin(object):
    nexmo_verify_data = {
        "request_id": "9e59abbe98204a9ebe8a36101383ec20",
        "status": "0",
    }

    nexmo_cancel_data = {"status": "0", "command": "cancel"}

    nexmo_check_data = {
        "currency": "EUR",
        "event_id": "0C000000F2319FC0",
        "price": "0.10000000",
        "request_id": "9e59abbe98204a9ebe8a36101383ec20",
        "status": "0",
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._nexmo_patcher = mock.patch("kinto_nexmo_verify.views.requests")

    def setUp(self):
        super().setUp()
        self.nexmo_mock = self._nexmo_patcher.start()

    def tearDown(self):
        super().tearDown()
        self._nexmo_patcher.stop()

    def mock_nexmo_verify_call(self, verify_data=None):
        if verify_data is None:
            verify_data = self.nexmo_verify_data
        self.nexmo_mock.get.return_value.json.return_value = verify_data

    def mock_nexmo_check_call(self, check_data=None):
        if check_data is None:
            check_data = self.nexmo_check_data
        self.nexmo_mock.get.return_value.json.return_value = check_data

    def mock_nexmo_cancel_call(self, cancel_data=None):
        if cancel_data is None:
            cancel_data = self.nexmo_cancel_data
        self.nexmo_mock.get.return_value.json.return_value = cancel_data
