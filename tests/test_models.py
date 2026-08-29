import pytest

from cpgvd.models import is_public_route


@pytest.mark.parametrize(
    "path",
    [
        "/login", "/logout", "/sign-in", "/signup", "/register",
        "/auth/google", "/auth/github/callback", "/oauth/callback",
        "/reset-password", "/password/forgot", "/verify-email",
        "/health", "/healthz", "/status", "/metrics", "/ping",
        "/favicon.ico", "/robots.txt", "/.well-known/jwks.json",
        "/static/app.js", "/assets/logo.png", "/public/",
        "/",
    ],
)
def test_is_public_route_true(path):
    assert is_public_route(path)


def test_is_public_route_empty_is_not_public():
    # an unknown / unextracted path must not be treated as public
    assert not is_public_route("")


@pytest.mark.parametrize(
    "path",
    [
        "/admin", "/admin/users", "/users/42", "/users/:id",
        "/profile", "/dashboard", "/api/users", "/orders/17/cancel",
        "/account/settings", "/me", "/notes/5", "/loginHistory",
    ],
)
def test_is_public_route_false(path):
    assert not is_public_route(path)
