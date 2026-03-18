#! /usr/bin/python3

import argparse
import logging
import sys
from getpass import getpass
from pprint import pprint

import globalnoc.wsc
from globalnoc.wsc import LoginFailure, RemoteMethodException


def kv(value):
    if "=" not in value:
        raise argparse.ArgumentTypeError("%s is a key=value" % value)
    return value


def parse_arguments():
    parser = argparse.ArgumentParser()

    authgroup = parser.add_argument_group()
    authgroup.add_argument("-u", "--username", help="Username for basic auth or ECP")
    authgroup.add_argument("-P", "--password", help="Password for basic auth or ECP")
    authgroup.add_argument(
        "-r",
        "--realm",
        help="Realm For ECP requests (e.g. https://server/idp/profile/SAML2/SOAP/ECP)",
    )

    URLgroup = parser.add_mutually_exclusive_group(required=True)
    URLgroup.add_argument("-U", "--url", help="URL to request")
    URLgroup.add_argument("-S", "--service", help="URN of Service to request")

    parser.add_argument(
        "-a",
        "--args",
        action="append",
        default=[],
        type=kv,
        help="Arguments to send to remote service in key=value form",
    )

    parser.add_argument("-c", "--servicecache", help="Path to name service cache file")
    parser.add_argument("-D", "--debug", action="store_true", help="Print debug logs")

    parser.add_argument(
        "-l",
        "--cookies",
        help="Path to cookies file to read on load, and write before exit",
    )

    parser.add_argument(
        "-m",
        "--method",
        default="help",
        help="GlobalNOC WS 'method' parameter. Default: 'help'",
    )

    parser.add_argument(
        "-o",
        "--raw",
        action="store_true",
        help="Pass raw output rather than decode JSON",
    )

    parser.add_argument("-t", "--timeout", type=int, help="Timeout in seconds")

    parser.add_argument(
        "-X",
        "--noresult",
        action="store_true",
        help="Do not print the results of the webservice call",
    )

    return parser.parse_args()


def main():
    args = parse_arguments()

    logging.basicConfig(
        format="%(levelname)s:%(message)s",
        level=logging.DEBUG if args.debug else logging.WARN,
    )

    w = globalnoc.wsc.WSC()

    if args.username:
        if not args.password:
            args.password = getpass()

        w.username = args.username
        w.password = args.password

        if args.realm:
            w.realm = args.realm

    if args.url:
        w.url = args.url
    else:
        if args.servicecache:
            w.ns = args.servicecache
        w.urn = args.service

    if args.timeout:
        w.timeout = args.timeout

    w.raw = args.raw

    if args.cookies:
        try:
            w._load(args.cookies)
        except Exception:
            if not args.noresult:
                print("Problem loading cookies. Continuing without any.")

    try:
        res = getattr(w, args.method)(**dict([a.split("=", 1) for a in args.args]))
    except (LoginFailure, RemoteMethodException) as e:
        print(f"Error: {e}")
        return 1

    if not args.noresult:
        if args.raw:
            print(res)
        else:
            pprint(res)

    if args.cookies:
        try:
            w._save(args.cookies)
        except Exception:
            if not args.noresult:
                print("Problem saving cookies.")


if __name__ == "__main__":
    sys.exit(main())
