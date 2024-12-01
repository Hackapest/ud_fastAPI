from datetime import datetime, timedelta

class CVEParser:
    def __init__(self, data):
        self.vulnerabilities = data.get('vulnerabilities', [])
        
    def get_all(self, end_date = datetime.now(),
                start_date=(datetime.now() - timedelta(days=20))):
        
        recent_cves = []
        for cve in self.vulnerabilities:
            try:
                date_added = datetime.strptime(cve['dateAdded'], '%Y-%m-%d')
                if (date_added >= start_date) and (date_added <= end_date):
                    recent_cves.append(cve)
            except (ValueError, KeyError):
                continue
                
        return {"result" : recent_cves[:40]}
    
    def get_new(self):
        sorted_cves = sorted(
            self.vulnerabilities,
            key=lambda x: datetime.strptime(x['dateAdded'], '%Y-%m-%d'),
            reverse=True
        )
        return {"result" : sorted_cves[:10]}
    
    def get_known(self):        
        known_cves = []
        for cve in self.vulnerabilities:
            if cve["knownRansomwareCampaignUse"] == "Known":
                known_cves.append(cve)
                
        return {"result" : sorted(
            known_cves,
            key=lambda x: datetime.strptime(x['dateAdded'], '%Y-%m-%d'),
            reverse=True
        )[:10]}
    
    def get_by_query(self, query: str):
        query = query.lower()
        matching_cves = []
        
        for cve in self.vulnerabilities:
            searchable_text = ' '.join([
                cve['cveID'],
                cve['vendorProject'],
                cve['product'],
                cve['vulnerabilityName'],
                cve['shortDescription']
            ]).lower()
            
            if query in searchable_text:
                matching_cves.append(cve)
                
        return {"result" : matching_cves}


if __name__ == "__main__":
    #testing
    from utils import load_json
    sample_data = load_json("cves.json")
    
    parser = CVEParser(sample_data)
    recent_cves = parser.get_all()
    new_cves = parser.get_new()
    search_results = parser.get_by_query("linux")