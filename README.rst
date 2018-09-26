Nexmo Verify support for Kinto
=============================

|travis| |master-coverage|

.. |travis| image:: https://travis-ci.org/Kinto/kinto-nexmo-verify.svg?branch=master
    :target: https://travis-ci.org/Kinto/kinto-nexmo-verify

.. |master-coverage| image::
    https://coveralls.io/repos/Kinto/kinto-nexmo-verify/badge.png?branch=master
    :alt: Coverage
    :target: https://coveralls.io/r/Kinto/kinto-nexmo-verify

*kinto-nexmo-verify* enables authentication in *Kinto* applications using
`*Nexmo Verify* Passwordless Authentication <https://developer.nexmo.com/verify/guides/verify-a-user>`_.

It provides:

* An authentication policy class;
* Integration with *Kinto* cache backend for token verifications;
* Integration with *Kinto* for heartbeat view checks;
* Endpoints to perform the Nexmo dance and grab a JWT authentication token.


* `Kinto documentation <http://kinto.readthedocs.io/en/latest/>`_
* `Issue tracker <https://github.com/Kinto/kinto-nexmo-verify/issues>`_


Installation
------------

Install the Python package:

::

    pip install kinto-nexmo-verify


Include the package in the project configuration:

::

    kinto.includes = kinto_nexmo_verify

And configure authentication policy using `pyramid_multiauth
<https://github.com/mozilla-services/pyramid_multiauth#deployment-settings>`_ formalism:

::

    multiauth.policies = nexmo
    multiauth.policy.nexmo.use = kinto_nexmo_verify.authentication.PasswordlessAuthenticationPolicy

By default, it will rely on the cache configured in *Kinto*.


Configuration
-------------

Fill those settings with the values obtained during the application registration:

::

    nexmo.api_key = 89513028159972bc
    nexmo.api_secret = 9aced230585cc0aaea0a3467dd800
    nexmo.webapp.authorized_domains = *
    # nexmo.cache_ttl_seconds = 300
    # nexmo.state.ttl_seconds = 3600


If necessary, override default values for authentication policy:

::

    # multiauth.policy.nexmo.realm = Realm


Login flow
----------

JWT authentication token
::::::::::::::::::::::::

Use the JWT token with this header:

::

    Authorization: Nexmo <jwt_token>


:notes:

    If the token is not valid, this will result in a ``401`` error response.


Obtain JWT token flow
:::::::::::::::::::::

To initiate a passwordless session, start by sending the mobile phone number to ``POST /v1/nexmo/verify``

.. code-block:: http

    $ http POST http://localhost:8000/v1/nexmo/verify number=447700900000 brand=MyApp -v

    POST /v1/nexmo/verify HTTP/1.1
    Accept: application/json, */*
    Accept-Encoding: gzip, deflate
    Connection: keep-alive
    Content-Length: 44
    Content-Type: application/json
    Host: localhost:8000
    User-Agent: HTTPie/0.9.9
    
    {
        "brand": "MyApp", 
        "number": "447700900000"
    }


    HTTP/1.1 200 OK
    Content-Length: 51
    Content-Type: application/json; charset=UTF-8
    Date: Thu, 21 Feb 2019 09:28:37 GMT
    Server: waitress

    {
        "request_id": "89513028159972bc",
        "number": "verify"
    }


Then, once you receive the message from the number ``verify``, you can read its code and verify it using a ``POST  /v1/nexmo/verify/check``


.. code-block:: http

    $ http POST http://localhost:8000/v1/nexmo/verify/check request_id=89513028159972bc code=5992 -v

    POST /v1/nexmo/verify/check HTTP/1.1
    Accept: application/json, */*
    Accept-Encoding: gzip, deflate
    Connection: keep-alive
    Content-Length: 50
    Content-Type: application/json
    Host: localhost:8000
    User-Agent: HTTPie/0.9.9
    
    {
        "code": "5992", 
        "request_id": "89513028159972bc"
    }


    HTTP/1.1 202 Accepted
    Content-Length: 232
    Content-Type: application/json; charset=UTF-8
    Date: Thu, 21 Feb 2019 09:28:37 GMT
    Server: waitress

    {
        "jwt_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.xOzQ0jczoCaK_6hHUaOfAh8XqU5HRVcIAl-OdXkZVMc",
        "payload": {"number": "447700900000"}
    }
