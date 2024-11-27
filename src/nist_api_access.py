from datetime import datetime, timedelta, timezone
import requests


class NISTAPI:
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def __init__(self, api_key=None):
        self.session = requests.Session()
        self.api_key = api_key
        if api_key == None:
            self.headers = None
        else:
            self.headers = {"api-key": api_key}
        
    
    def _make_request(self, params):
        try:
            response = self.session.get(self.BASE_URL,
                                        headers=self.headers, params=params)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            print(f"Error making request: {e}")
            return response.status_code
    
    def get_all(self, results_per_page=40, start_index=0):
        end_date = datetime.now(timezone.utc)
        five_days_ago = end_date - timedelta(days=5)
        params = {
            'pubStartDate': five_days_ago.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
            'pubEndDate': end_date.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
            'resultsPerPage': results_per_page,
            'startIndex': start_index
        }
        return self._make_request(params)
    
    def get_new(self, results_per_page=10, start_index=0):
        params = {
            'resultsPerPage': results_per_page,
            'startIndex': start_index
        }
        return self._make_request(params)
    
    def get_critical(self, results_per_page=10, start_index=0):
        params = {
            'cvssV3Severity': 'CRITICAL',
            'resultsPerPage': results_per_page,
            'startIndex': start_index
        }
        return self._make_request(params)
    
    def get_by_keyword(self, keyword, results_per_page=20, start_index=0):
        params = {
            'keywordSearch': keyword,
            'resultsPerPage': results_per_page,
            'startIndex': start_index
        }
        return self._make_request(params)


if __name__ == "__main__":
    import time
    testobj = NISTAPI()
    print((testobj.get_all()))
    time.sleep(20)
    print((testobj.get_new()))
    time.sleep(20)
    print((testobj.get_critical()))
    time.sleep(20)
    print((testobj.get_by_keyword("linux windows macos")))
