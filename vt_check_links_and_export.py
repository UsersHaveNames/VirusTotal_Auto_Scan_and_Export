import os
import time
import requests
import json
from tqdm import tqdm
from pathlib import Path
import shutil

def read_input_file(file_path):
    with open(file_path, 'r') as f:
        return json.load(f)

def save_output_file(file_path, results):
    with open(file_path, 'w') as f:
        json.dump(results, f, indent=4)

def get_analysis_result(api_key, url):
    headers = {
        'accept': 'application/json',
        'x-apikey': api_key
    }
    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        raise Exception(f"Error retrieving analysis result for URL: {url}. Status code: {response.status_code}")

    return response.json()

def main():
    script_location = Path(__file__).resolve().parent
    input_file = script_location / "vt_analysis_urls.json"
    backup_file = script_location / "vt_analysis_urls_backup.json"

    # Create a backup of the input file
    shutil.copy2(input_file, backup_file)

    analysis_urls = read_input_file(input_file)
    total_urls = len(analysis_urls)
    analysis_results = {}
    delay = 16
    api_key = os.environ['VT_API_KEY']

    try:
        for file_name, url in tqdm(analysis_urls.items(), desc="Processing URLs", unit="url"):
            url = url.strip()

            try:
                response_data = get_analysis_result(api_key, url)

                if response_data['data']:
                    attributes = response_data['data']['attributes']
                    if attributes['stats']['harmless'] > 0 or attributes['stats']['type-unsupported'] > 0:
                        attributes.pop('results', None)
                    attributes['file_name'] = file_name
                    attributes['url'] = url
                    analysis_results[file_name] = attributes

            except Exception as e:
                print(str(e))

            time.sleep(delay)

        # Save results to the input file
        save_output_file(input_file, analysis_results)
        print(f"Analysis results saved to: {input_file}")

    except Exception as e:
        # Restore the input file from the backup
        shutil.copy2(backup_file, input_file)
        print(f"Warning: Script failed. The original contents of the JSON file have been restored. Error: {str(e)}")

    finally:
        # Remove the backup file
        os.remove(backup_file)

if __name__ == "__main__":
    main()
