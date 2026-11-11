"""Unit tests for the cli module."""

from unittest.mock import Mock, patch

import pytest
import responses
from yarl import URL

from taramail.cli import (
    DEFAULT_API_URL,
    add_command_args,
    call_api,
    get_arg_type,
    get_openapi_schema,
    main,
    make_args_parser,
)
from taramail.http import HTTPSession


@pytest.mark.parametrize(
    "arg, expected",
    [
        ("boolean", bool),
        ("integer", int),
        ("number", float),
        ("string", str),
        ("test", str),
    ],
)
def test_get_arg_type(arg, expected):
    result = get_arg_type(arg)
    assert result == expected


def test_get_openapi_schema():
    """Getting the OpenAPI schema should return the body of openapi.json."""
    body = {"test": True}
    http_session = HTTPSession("http://localhost/")
    with patch.object(http_session, "get") as mock_get:
        mock_get.return_value = Mock(json=Mock(return_value=body))
        result = get_openapi_schema(http_session)

    assert result == body


def test_call_api():
    """Calling the API sould make a request with the given method."""
    body = {"test": True}
    http_session = HTTPSession("http://localhost/")
    with patch.object(http_session, "request") as mock_request:
        mock_request.return_value = Mock(json=Mock(return_value=body))
        result = call_api(http_session, "GET", "/test", {}, {})

    assert result == body


def test_add_command_args():
    """Adding command args should parse commands from the schema."""
    parser = make_args_parser()
    parser = add_command_args(parser, {
        "paths": {
            "test": {
                "get": {},
            },
        },
    })
    args = parser.parse_args(["get_test"])
    assert args.command == "get_test"


@pytest.mark.parametrize(
    "argv, expected",
    [
        (["--sender-acl", "a@b.c", "@d.e"], ["a@b.c", "@d.e"]),
        (["--sender-acl"], []),
        ([], None),
    ],
)
def test_add_command_args_array(argv, expected):
    """Array properties in the request body should parse as lists."""
    parser = make_args_parser()
    parser = add_command_args(parser, {
        "paths": {
            "test": {
                "put": {
                    "requestBody": {"content": {"application/json": {"schema": {
                        "properties": {
                            "sender_acl": {"anyOf": [{"type": "array", "items": {"type": "string"}}, {"type": "null"}]},
                        },
                    }}}},
                },
            },
        },
    })
    args = parser.parse_args(["put_test", *argv])
    assert args.sender_acl == expected


def test_add_command_args_error(capsys):
    """Adding empty command args should raise on unknown commands."""
    parser = make_args_parser()
    parser = add_command_args(parser, {})
    with pytest.raises(SystemExit):
        parser.parse_args(["get_test"])


@responses.activate
def test_main_help(capsys):
    """The main function should output usage when asked for --help."""
    url = URL(DEFAULT_API_URL).with_path("/api/openapi.json")
    responses.add(
        responses.GET,
        str(url),
        json={},
    )
    with pytest.raises(SystemExit):
        main(["--help"])

    captured = capsys.readouterr()
    assert "usage" in captured.out
