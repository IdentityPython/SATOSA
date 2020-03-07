import argparse
import os
import sys

from werkzeug.serving import run_simple

from satosa.proxy_server import make_app
from satosa.satosa_config import SATOSAConfig

config_file = os.environ.get("SATOSA_CONFIG", "proxy_conf.yaml")
satosa_config = SATOSAConfig(config_file)
app = make_app(satosa_config)


def main():
    global app

    parser = argparse.ArgumentParser(description="Process some integers.")
    parser.add_argument("port", type=int)
    parser.add_argument("--keyfile", type=str)
    parser.add_argument("--certfile", type=str)
    parser.add_argument("--host", type=str)
    args = parser.parse_args()

    if (args.keyfile and not args.certfile) or (args.certfile and not args.keyfile):
        print("Both keyfile and certfile must be specified for HTTPS.")
        sys.exit(1)

    ssl_context = (
        (args.certfile, args.keyfile)
        if args.keyfile and args.certfile
        else None
    )
    host = args.host or "localhost"
    run_simple(host, args.port, app, ssl_context=ssl_context)


if __name__ == "__main__":
    main()
