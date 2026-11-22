"""Exporter fixtures."""

import pytest
from attrs import define
from prometheus_client.parser import text_string_to_metric_families
from pytest_xdocker.docker import DockerContainer
from yarl import URL

from taramail.http import HTTPSession


@define
class Exporter:

    host: str
    port: int

    @classmethod
    def from_service(cls, service: DockerContainer) -> "Exporter":
        return cls(service.ip, service.exposed_port)

    @property
    def url(self) -> URL:
        return URL.build(scheme="http", host=self.host, port=self.port)

    def get_metrics(self, path="/metrics", params=None):
        session = HTTPSession(self.url)
        response = session.get(path, params=params)
        return list(text_string_to_metric_families(response.text))


@pytest.fixture(scope="session")
def api_exporter(api_service):
    """API exporter fixture."""
    return Exporter(api_service.ip, 80)


@pytest.fixture(scope="session")
def blackbox_exporter(compose_server):
    """Blackbox exporter fixture."""
    server = compose_server("Listening on")
    with server.run("blackbox-exporter") as service:
        yield Exporter.from_service(service)


@pytest.fixture(scope="session")
def custom_exporter(compose_server):
    """Custom exporter fixture."""
    server = compose_server("Application startup complete")
    with server.run("custom-exporter") as service:
        yield Exporter.from_service(service)


@pytest.fixture(scope="session")
def dockerapi_exporter(dockerapi_service):
    """API exporter fixture."""
    return Exporter(dockerapi_service.ip, 80)


@pytest.fixture(scope="session")
def dovecot_exporter(dovecot_service):
    """Dovecot exporter fixture."""
    return Exporter(dovecot_service.ip, 9166)


@pytest.fixture(scope="session")
def mysqld_exporter(compose_server):
    """Mysqld exporter fixture."""
    server = compose_server("Listening on")
    with server.run("mysqld-exporter") as service:
        yield Exporter.from_service(service)


@pytest.fixture(scope="session")
def postfix_exporter(compose_server):
    """Postfix exporter fixture."""
    server = compose_server("Listening on")
    with server.run("postfix-exporter") as service:
        yield Exporter.from_service(service)
