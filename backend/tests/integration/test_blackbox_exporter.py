"""Integration tests for the blackbox exporter."""

from hamcrest import (
    assert_that,
    has_item,
    has_properties,
)


def test_blackbox_exporter_redis_check(blackbox_exporter, redis_service):
    """The blackbox exporter should be ale to probe the api service."""
    target = f"{redis_service.ip}:{redis_service.exposed_port}"
    metrics = blackbox_exporter.get_metrics("/probe", params={
        "module": "redis_check",
        "target": target,
    })

    assert_that(metrics, has_item(has_properties(
        name="probe_success",
        samples=has_item(has_properties(value=1)),
    )))
