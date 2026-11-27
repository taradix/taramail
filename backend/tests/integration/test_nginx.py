"""Integration tests for the nginx service."""

from hamcrest import assert_that, ends_with, has_entries, has_properties, starts_with

from taramail.http import HTTPSession


def test_nginx_redirects_http_to_https(nginx_service):
    """The nginx service should redirect HTTP to HTTPS."""
    http_session = HTTPSession(f"http://{nginx_service.ip}/")
    response = http_session.get("/SOGo", allow_redirects=False)

    assert_that(response, has_properties(
        status_code=301,
        headers=has_entries(location=starts_with("https:")),
    ))


def test_nginx_redirects_root_to_sogo(nginx_session):
    """The nginx service should redirect the root to SOGo, over the self-signed dev cert."""
    response = nginx_session.get("/", allow_redirects=False)

    assert_that(response, has_properties(
        status_code=301,
        headers=has_entries(location=ends_with("/SOGo")),
    ))
