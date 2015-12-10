import argparse
import functools
import logging
import os
import sys

from werkzeug.debug import DebuggedApplication
from werkzeug.serving import run_simple

from satosa.proxy_server import ToBytesMiddleware, WsgiApplication
from satosa.satosa_config import SATOSAConfig

stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setLevel(logging.DEBUG)

for logger_name in ["", "satosa", "saml2"]:
    logger = logging.getLogger(logger_name)
    logger.addHandler(stdout_handler)
    logger.setLevel(logging.DEBUG)

config_file = os.environ.get("SAAS_CONFIG", "proxy_conf.yaml")
server_config = SATOSAConfig(config_file)
app = ToBytesMiddleware(WsgiApplication(server_config).run_server)


def main():
    global app

    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('port', type=int)
    parser.add_argument('--keyfile', type=str)
    parser.add_argument('--certfile', type=str)
    parser.add_argument('-d', action='store_true', dest="debug",
                        help="enable debug mode.")
    args = parser.parse_args()

    if (args.keyfile and not args.certfile) or (args.certfile and not args.keyfile):
        print("Both keyfile and certfile must be specified for HTTPS.")
        sys.exit()

    if args.debug:
        app.app = functools.partial(app.app, debug=True)
        app = DebuggedApplication(app)

    if (args.keyfile and args.certfile):
        ssl_context = (args.certfile, args.keyfile)
    else:
        ssl_context = None

    run_simple('localhost', args.port, app, ssl_context=ssl_context)


if __name__ == '__main__':
    main()
