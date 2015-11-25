import argparse
import json
import os
import sys
import yaml

__author__ = 'haho0032'


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(dest="json_file",
                        help="Json file.")
    parser.add_argument(dest="yaml_file",
                        help="Yaml file.")
    args = parser.parse_args()
    sys.path.insert(0, os.getcwd())

    if os.path.isfile(args.json_file):
            json_file = open(args.json_file, "r")
            config = json_file.read()
            json_file.close()
            config = json.loads(config)
            config = yaml.dump(config)
            yaml_file = open(args.yaml_file, "w")
            yaml_file.write(config)
            yaml_file.close()