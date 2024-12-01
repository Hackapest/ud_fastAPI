from elasticsearch import Elasticsearch
from datetime import datetime, timedelta
import json

class VulnerabilityDatabase:
    def __init__(self, elastic_url="http://localhost:9200",
                 index_name="vulnerabilities", clear_index=False):
        
        self.es = Elasticsearch(hosts=[elastic_url])
        self.index_name = index_name

        if self.es.indices.exists(index=self.index_name):
            if clear_index:
                self.es.indices.delete(index=self.index_name)
                print(f"Index '{self.index_name}' cleared.")
                self.es.indices.create(index=self.index_name)
                print(f"Index '{self.index_name}' created.")
        else:
            self.es.indices.create(index=self.index_name)
            print(f"Index '{self.index_name}' created.")

    def initialize_database(self, json_file_path):
        with open(json_file_path, "r") as file:
            data = json.load(file)
            for vulnerability in data.get("vulnerabilities", []):
                cve_id = vulnerability.get("cveID")
                if not cve_id:
                    print("Skipping entry without CVEID")
                    continue
                response = self.es.index(index=self.index_name,
                                         id=cve_id, document=vulnerability)
    
    def get_all(self, start_date=None, end_date=None):
        if not end_date:
            end_date = datetime.now()
        if not start_date:
            start_date = end_date - timedelta(days=20)
        
        query = {
            "range": {
                "dateAdded": {
                    "gte": start_date.strftime('%Y-%m-%d'),
                    "lte": end_date.strftime('%Y-%m-%d')
                }
            }
        }
        result = self.es.search(index=self.index_name, query=query, size=40)
        return {"result": [hit["_source"] for hit in result["hits"]["hits"]]}

    def get_new(self):
        query = {
            "match_all": {}
        }
        result = self.es.search(
            index=self.index_name,
            query=query,
            sort=[{"dateAdded": {"order": "desc"}}],
            size=10
        )
        return {"result": [hit["_source"] for hit in result["hits"]["hits"]]}

    def get_known(self):
        query = {
            "term": {
                "knownRansomwareCampaignUse.keyword": "Known"
            }
        }
        result = self.es.search(
            index=self.index_name,
            query=query,
            sort=[{"dateAdded": {"order": "desc"}}],
            size=10
        )
        return {"result": [hit["_source"] for hit in result["hits"]["hits"]]}

    def get_by_query(self, query_string):
        query = {
            "query_string": {
                "query": query_string,
                "fields": [
                    "cveID",
                    "vendorProject",
                    "product",
                    "vulnerabilityName",
                    "shortDescription"
                ]
            }
        }
        result = self.es.search(index=self.index_name, query=query)
        return {"result": [hit["_source"] for hit in result["hits"]["hits"]]}


if __name__ == "__main__":
    #test
    db = VulnerabilityDatabase()
    #print(db.get_new())
    #db.initialize_database("cves.json")
    print(json.dumps(db.get_new(), indent=4))