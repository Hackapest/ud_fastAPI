import json

def load_json(config_path="cfg.json"):
    with open(config_path, "r") as file:
        res = json.load(file)
    return res