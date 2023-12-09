import os

import requests
import json
import argparse

YARA_TYPE = 1
CAPA_TYPE = 2
SIGMA_TYPE = 3

main_api_url = "https://unprotect.it/api/detection_rules/"


def parse_rule_types(p_rule_type):
    if p_rule_type == "yara":
        return YARA_TYPE
    if p_rule_type == "capa":
        return CAPA_TYPE
    if p_rule_type == "sigma":
        return SIGMA_TYPE
    if p_rule_type == "all":
        return None


def get_rule_ext(rule_id):
    if rule_id == YARA_TYPE:
        return ".yar"
    if rule_id == CAPA_TYPE or rule_id == SIGMA_TYPE:
        return ".yaml"


def save_rule(save_dir_path, rule, rule_key, rule_ext):
    with open(os.path.join(save_dir_path, rule_key + rule_ext), "w") as rule_file:
        rule_file.write(rule)
        rule_file.close()


def get_rules(json_content, dir_path, rule_type):
    for rule in json_content["results"]:
        if not rule_type:
            save_rule(dir_path, rule["rule"], rule["key"], get_rule_ext(rule["type"]["id"]))
        elif rule["type"]["id"] == rule_type:
            save_rule(dir_path, rule["rule"], rule["key"], get_rule_ext(rule["type"]["id"]))
    return json_content["next"]


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Download rules from unprotect.it')
    parser.add_argument('-t', "--rule_type", dest='type', type=str, default='all',
                        choices=["sigma", "yara", "capa", "all"], required=False, help='type of rules')
    parser.add_argument('-p', "--path", dest='path', type=str, default='rules', required=False,
                        help='path to save rules')
    args = parser.parse_args()

    req = requests.api.get(main_api_url)
    rule_type = parse_rule_types(args.type)
    if req.status_code == 200:
        if not os.path.exists(args.path):
            os.mkdir(args.path)
        content = json.loads(req.text)
        while True:
            next_rules = get_rules(content, args.path, rule_type)
            if next_rules:
                content = json.loads(requests.api.get(next_rules).text)
            else:
                break
