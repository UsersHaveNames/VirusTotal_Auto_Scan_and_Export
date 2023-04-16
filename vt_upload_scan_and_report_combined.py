import os
import time
import requests
import json
from tqdm import tqdm
from pathlib import Path
import threading
from queue import Queue
from threading import Lock
from concurrent.futures import ThreadPoolExecutor, as_completed

class VirusTotalAnalyzer:
    def __init__(self, api_key):
        self.api_key = api_key
        self.source_folder = Path(__file__).resolve().parent
        self.output_file = self.source_folder / "vt_analysis_urls.json"
        self.headers = {'accept': 'application/json', 'x-apikey': self.api_key}
        self.delay = 16
        self.base_url = "https://www.virustotal.com/api/v3"
        self.last_api_call = time.time()
        self.api_call_lock = Lock()
    
    def check_quota(self):
        self.wait_for_next_api_call()
        response = requests.get(f'{self.base_url}/users/{self.api_key}/overall_quotas', headers=self.headers)
        quotas = response.json()

        api_requests_hourly = quotas['data']['api_requests_hourly']['user']
        api_requests_daily = quotas['data']['api_requests_daily']['user']
        api_requests_monthly = quotas['data']['api_requests_monthly']['user']

        # Checks that no API quotas have been exhausted
        if (api_requests_hourly['used'] >= api_requests_hourly['allowed'] or
            api_requests_daily['used'] >= api_requests_daily['allowed'] or
            api_requests_monthly['used'] >= api_requests_monthly['allowed']):
            return False

        return True

    def wait_for_next_api_call(self):
        with self.api_call_lock:
            time_since_last_call = time.time() - self.last_api_call
            if time_since_last_call < self.delay:
                time.sleep(self.delay - time_since_last_call)
            self.last_api_call = time.time()

    def process_file(self, file, analysis_results, queue):
        if not self.check_quota():
            print("Quota exceeded. The script will not execute.")
            return
        
        # Upload file to VirusTotal for analysis
        self.wait_for_next_api_call()  # Ensures API calls happen at a pre-defined rate
        with open(file, 'rb') as file_data:
            response = requests.post(f'{self.base_url}/files', headers=self.headers, files={'file': file_data})
        upload_response = response.json()

        # Check if upload was successful
        if not upload_response.get('data'):
            print(f"\nError uploading file: {file}")
            queue.put(1)  # Update the progress in the queue
            return

        # Get analysis URL and ID
        url = upload_response['data']['links']['self']
        analysis_id = upload_response['data']['id']
        analysis_url = f"{self.base_url}/analyses/{analysis_id}"

        # Wait for analysis completion
        while True:
            self.wait_for_next_api_call()  # Ensures API calls happen at a pre-defined rate
            response = requests.get(analysis_url, headers=self.headers)
            response_data = response.json()
            status = response_data['data']['attributes']['status']
            if status == "completed":
                break

        # Store analysis attributes in results
        attributes = response_data['data']['attributes']
        attributes['file_name'], attributes['url'] = str(file), url
        analysis_results[str(file)] = attributes
        queue.put(1)  # Update the progress in the queue

    def process_files(self):
        files = [f for f in self.source_folder.glob('**/*') if f.is_file() and not f.suffix.lower() in ('.txt', '.zip', '.json', '.py')]
        total_files = len(files)

        analysis_results = {}
        q = Queue()

        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = {executor.submit(self.process_file, file, analysis_results, q): file for file in files}

            with tqdm(total=total_files, desc="Processing files", unit="file") as pbar:
                for future in as_completed(futures):
                    pbar.update(q.get())  # Update progress bar

        # Save analysis results to output file
        with open(self.output_file, 'w', encoding='utf8') as f:
            json.dump(analysis_results, f, ensure_ascii=False, indent=4)

        # Print summary information
        print(f"\nTotal files found: {total_files}")
        print(f"Successful uploads: {len(analysis_results)}")
        print(f"Responses received: {len(analysis_results)}")

if __name__ == '__main__':
    api_key = os.environ['VT_API_KEY']
    analyzer = VirusTotalAnalyzer(api_key)
    analyzer.process_files()
