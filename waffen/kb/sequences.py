"""Built-in multi-request attack sequences.

Each sequence models a realistic multi-step attack pattern that WAFs
inspecting requests independently cannot correlate.
"""
from __future__ import annotations

from ..core.sequence import AttackSequence, RequestStep


# ---------------------------------------------------------------------------
# Built-in sequences
# ---------------------------------------------------------------------------

SEQUENCES: list[AttackSequence] = [
    # 1. Register a user, login to get a JWT, then inject with auth
    AttackSequence(
        name="auth_then_inject",
        description="Register + login + inject with auth token",
        steps=[
            RequestStep(
                method="POST", path="/api/Users",
                body=('{"email":"waffen-seq@test.com","password":"Waffen1234!",'
                      '"passwordRepeat":"Waffen1234!"}'),
                content_type="application/json",
            ),
            RequestStep(
                method="POST", path="/rest/user/login",
                body='{"email":"waffen-seq@test.com","password":"Waffen1234!"}',
                content_type="application/json",
                extract={"token": "$.authentication.token"},
            ),
            RequestStep(
                method="GET", path="/rest/products/search",
                params={"q": "{PAYLOAD}"},
                headers={"Authorization": "Bearer {token}"},
            ),
        ],
    ),

    # 2. Store a payload via feedback, then retrieve it (stored XSS / second-order SQLi)
    AttackSequence(
        name="store_then_trigger",
        description="Store payload in feedback comment, then retrieve it",
        steps=[
            RequestStep(
                method="POST", path="/rest/user/login",
                body='{"email":"waffen-seq@test.com","password":"Waffen1234!"}',
                content_type="application/json",
                extract={"token": "$.authentication.token"},
            ),
            RequestStep(
                method="POST", path="/api/Feedbacks",
                body='{{"UserId":1,"captchaId":0,"captcha":"","comment":"{PAYLOAD}","rating":1}}',
                content_type="application/json",
                headers={"Authorization": "Bearer {token}"},
            ),
            RequestStep(
                method="GET", path="/api/Feedbacks",
                headers={"Authorization": "Bearer {token}"},
            ),
        ],
    ),

    # 3. Cookie setup + injection (get a session, then inject via param with valid session)
    AttackSequence(
        name="cookie_inject",
        description="Obtain session cookie, then inject with valid session",
        steps=[
            RequestStep(
                method="GET", path="/",
                extract={"cookies": "Set-Cookie"},
            ),
            RequestStep(
                method="GET", path="/rest/products/search",
                params={"q": "{PAYLOAD}"},
                headers={"Cookie": "{cookies}"},
            ),
        ],
    ),

    # 4. Two-param fragment: split payload across params (single request but
    #    the WAF may score each param independently)
    AttackSequence(
        name="fragment_params",
        description="Split payload across two query parameters",
        steps=[
            RequestStep(
                method="GET", path="/rest/products/search",
                params={"q": "{PAYLOAD}", "sort": "name"},
            ),
        ],
    ),

    # 5. Preflight + inject: send a benign OPTIONS first (prime the WAF's
    #    connection state), then the real payload
    AttackSequence(
        name="preflight_inject",
        description="OPTIONS preflight to prime connection, then inject",
        steps=[
            RequestStep(
                method="OPTIONS", path="/rest/products/search",
                headers={"Origin": "https://trusted.example.com",
                          "Access-Control-Request-Method": "GET"},
            ),
            RequestStep(
                method="GET", path="/rest/products/search",
                params={"q": "{PAYLOAD}"},
            ),
        ],
    ),

    # 6. POST body + query param (dual injection — WAF may inspect only one)
    AttackSequence(
        name="dual_injection",
        description="Inject in both query param and POST body simultaneously",
        steps=[
            RequestStep(
                method="POST", path="/rest/products/search",
                params={"q": "safe"},
                body="q={PAYLOAD}",
                content_type="application/x-www-form-urlencoded",
            ),
        ],
    ),

    # 7. Rate the payload, then search (order-dependent WAF state)
    AttackSequence(
        name="warmup_inject",
        description="Send benign requests to build trust, then inject",
        steps=[
            RequestStep(method="GET", path="/rest/products/search",
                        params={"q": "apple"}),
            RequestStep(method="GET", path="/rest/products/search",
                        params={"q": "juice"}),
            RequestStep(method="GET", path="/rest/products/search",
                        params={"q": "orange"}),
            RequestStep(method="GET", path="/rest/products/search",
                        params={"q": "{PAYLOAD}"}),
        ],
    ),
]


BY_NAME: dict[str, AttackSequence] = {s.name: s for s in SEQUENCES}


def get_sequence(name: str) -> AttackSequence | None:
    return BY_NAME.get(name)


def all_sequences() -> list[AttackSequence]:
    return list(SEQUENCES)


def sequence_names() -> list[str]:
    return [s.name for s in SEQUENCES]
