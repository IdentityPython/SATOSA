import argparse
import json
import os
import sys
import yaml

__author__ = 'haho0032'


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(dest="yaml_file1",
                        help="Yaml file.")
    parser.add_argument(dest="yaml_file2",
                        help="Yaml file.")
    args = parser.parse_args()
    sys.path.insert(0, os.getcwd())

    if os.path.isfile(args.yaml_file1):
            yaml_file1 = open(args.yaml_file1, "r")
            config = yaml_file1.read()
            yaml_file1.close()
            config = yaml.load(config)
            config = yaml.dump(config)
            yaml_file2 = open(args.yaml_file2, "w")
            yaml_file2.write(config)
            yaml_file2.close()