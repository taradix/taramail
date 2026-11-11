"""Command-line interface."""

import json
import os
import sys
from argparse import (
    ArgumentParser,
    FileType,
    RawDescriptionHelpFormatter,
)
from collections import defaultdict
from textwrap import dedent

import urllib3
from lookuper import lookup
from more_itertools import bucket, only
from requests.exceptions import RequestException

from taramail.http import HTTPSession

DEFAULT_API_URL = "https://mail.taram.ca/"


def get_arg_type(arg, default=str):
    """OpenAPI data type to arg type."""
    return {
        "boolean": bool,
        "integer": int,
        "number": float,
        "string": str,
    }.get(arg, default)


def get_openapi_schema(session):
    """Get and parse the OpenAPI schema from the API."""
    # Only verify the certificate for the OpenAPI schema when
    # running in production.
    verify = session.origin == DEFAULT_API_URL
    response = session.get("/api/openapi.json", verify=verify)

    return response.json()


def call_api(session, method, path, args, keys):
    """Make an API request with query parameters and request body."""
    values = bucket(args.items(), lambda a: keys.get(a[0]))
    values = defaultdict(dict, {k: dict(values[k]) for k in values})

    headers = {"Content-Type": "application/json"} if values["body"] else {}
    response = session.request(
        method.upper(),
        path.format(**values["path"]),
        params=values["query"],
        json=values["body"],
        headers=headers,
        verify=not args.get("no_verify", False),
    )

    return response.json()


def make_args_parser():
    epilog = dedent(f"""\
    environments:
      TARAMAIL_API_URL     URL of the API (default: {DEFAULT_API_URL})
    """)
    args_parser = ArgumentParser(
        epilog=epilog,
        formatter_class=RawDescriptionHelpFormatter,
    )
    args_parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Do not verify the SSL certificate.",
    )
    args_parser.add_argument(
        "--output",
        type=FileType("w"),
        default=sys.stdout,
        help="output file (default: stdout)",
    )

    return args_parser


def add_parameter_args(command_parser, parameters):
    """Add query/path parameters to command parser."""
    keys = {}
    for param in parameters:
        keys[param["name"]] = param["in"]
        required = param.get("required", False)
        param_name = param["name"] if required else f"--{param['name']}"
        param_type = get_arg_type(param["schema"].get("type"))
        command_parser.add_argument(
            param_name,
            type=param_type,
            help=param["schema"].get("title"),
        )

    return keys


def add_body_args(command_parser, content_schema, required_fields):
    """Add request body properties to command parser."""
    keys = {}
    for prop_name, prop_details in content_schema.get("properties", {}).items():
        keys[prop_name] = "body"
        required = prop_name in required_fields
        arg_name = prop_name if required else f"--{prop_name}"
        arg_default = prop_details.get("default")
        arg_type = get_arg_type(prop_details.get("type"))

        kwargs = {}
        types = [prop_details.get("type")] + [s.get("type") for s in prop_details.get("anyOf", [])]
        if "array" in types:
            kwargs["nargs"] = "*"
        elif arg_type is bool:
            if arg_default:
                arg_name = arg_name.replace(prop_name, f"no_{prop_name}")
                kwargs["action"] = "store_false"
            else:
                kwargs["action"] = "store_true"
        else:
            kwargs["type"] = arg_type

        if not required:
            arg_name = arg_name.replace("_", "-")
            kwargs["dest"] = prop_name

        command_parser.add_argument(
            arg_name,
            default=arg_default,
            help=prop_details.get("title"),
            **kwargs,
        )

    return keys


def resolve_schema_ref(schema, content_schema):
    """Resolve $ref in schema to actual schema definition."""
    if ref := content_schema.get("$ref"):
        return only(lookup(schema, *ref.split("/")[1:]))
    return content_schema


def add_command_args(args_parser, schema):
    command = args_parser.add_subparsers(dest="command")

    for path, methods in schema.get("paths", {}).items():
        for method, details in methods.items():
            if method == "head":
                continue

            default_name = f"{method}_{path.strip('/').replace('/', '_')}"
            command_name = details.get("operationId", default_name)
            command_parser = command.add_parser(
                command_name,
                help=details.get("summary", "No summary available"),
            )

            keys = add_parameter_args(command_parser, details.get("parameters", []))

            if content_schema := only(lookup(details, "requestBody", "content", "application/json", "schema")):
                content_schema = resolve_schema_ref(schema, content_schema)
                required_fields = content_schema.get("required", [])
                keys.update(add_body_args(command_parser, content_schema, required_fields))

            command_parser.set_defaults(
                func=lambda session, args, m=method, p=path, keys=keys: call_api(session, m, p, args, keys),
            )

    return args_parser


def main(argv=None):
    """Entry point to the taramail command-line interface."""
    api_url = os.getenv("TARAMAIL_API_URL", DEFAULT_API_URL)
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    parser = make_args_parser()
    session = HTTPSession(api_url)
    try:
        schema = get_openapi_schema(session)
    except RequestException as e:
        parser.error(e)

    parser = add_command_args(parser, schema)
    args = parser.parse_args(argv)
    try:
        data = args.func(session, vars(args))
    except AttributeError:
        parser.print_usage()
        sys.exit(2)
    except RequestException as e:
        message = e.response.json()
        parser.error(message.get('detail') or message['error'])

    output = json.dumps(data, indent=2)
    args.output.write(output)
