# -*- coding: utf-8 -*-

import argparse
import traceback

from server import ChatBot


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-p',
        '--proxy',
        help='Use a proxy. Format: protocol://user:pass@ip:port',
        required=False,
        type=str,
        default=None,
    )
    parser.add_argument(
        '-s',
        '--server',
        help='Specific server bind. Format: ip:port, default: 127.0.0.1:8018',
        required=False,
        type=str,
        default='0.0.0.0:8018',
    )
    parser.add_argument(
        '--threads',
        help='Define the number of server workers, default: 4',
        required=False,
        type=int,
        default=4,
    )
    parser.add_argument(
        '--sentry',
        help='Enable sentry to send error reports when errors occur.',
        action='store_true',
    )
    parser.add_argument(
        '-v',
        '--verbose',
        help='Show exception traceback.',
        action='store_true',
    )
    parser.add_argument(
        '-pwd',
        '--password',
        help='Set Password.',
        required=False,
        type=str,
        default='Zanzan,2020',
    )

    parser.add_argument(
        '-t',
        '--token_file',
        help='Specify an access token file and login with your access token.',
        required=False,
        type=str,
        default=None,
    )
    args, _ = parser.parse_known_args()

    try:
        print(args.password)
        print(args.token_file)
        return ChatBot(args.proxy, args.verbose, args.sentry, True, args.password, args.token_file).run(args.server,
                                                                                                        args.threads)
    except (ImportError, ModuleNotFoundError):
        pass


def run():
    try:
        main()
    except Exception as e:
        print(traceback.format_exc())


if __name__ == "__main__":
    run()
