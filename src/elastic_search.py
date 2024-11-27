from config import DB_URL
from elasticsearch import Elasticsearch


client = Elasticsearch(DB_URL)

