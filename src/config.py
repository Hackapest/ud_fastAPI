from utils import load_json


cfg = load_json("cfg.json")
SERVER_UNREACHABLE_MESSAGE = cfg["server-unreachable-message"]
API_KEY = cfg["api-key"]