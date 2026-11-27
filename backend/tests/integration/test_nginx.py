"""Integration tests for the nginx service."""

from taramail.http import HTTPSession


def test_nginx_redirects_http_to_https(nginx_service):
    """The nginx service should redirect HTTP to HTTPS."""
    http_session = HTTPSession(f"http://{nginx_service.ip}/")
    response = http_session.get("/SOGo", allow_redirects=False)

    assert response.status_code == 301
    assert response.headers["location"] == f"https://{nginx_service.ip}/SOGo"


def test_nginx_redirects_root_to_sogo(nginx_service):
    """The nginx service should redirect the root to SOGo, over the self-signed dev cert."""
    http_session = HTTPSession(f"https://{nginx_service.ip}/")
    response = http_session.get("/", allow_redirects=False, verify=False)

    assert response.status_code == 301
    assert response.headers["location"] == f"https://{nginx_service.ip}/SOGo"
