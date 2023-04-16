# VirusTotalAnalyzer

VirusTotalAnalyzer is a Python script that scans and analyzes files in the current directory and its subdirectories using the VirusTotal API. The analysis results are saved to a JSON file named "vt_analysis_urls.json".

## Features

- Scans files in the current directory and its subdirectories, excluding files with extensions .txt, .zip, .json, and .py
- Uploads files to VirusTotal for analysis
- Waits for the analysis to complete and retrieves the results
- Saves the analysis results to a JSON file
- Multi-threaded approach to process multiple files concurrently
- Ensures API calls happen at a pre-defined rate to respect the API rate limits

## Usage

To use the script, you need to provide your VirusTotal API key as an environment variable named `VT_API_KEY`. Run the script in your desired directory to start the scanning and analysis process.

```bash
export VT_API_KEY=your_api_key_here
python vt_analyzer.py
```

Dependencies
Python 3.6 or higher
requests library
tqdm library
You can install the dependencies using the following command:

```bash
pip install requests tqdm
```
Note: The API call rate is defined by the delay attribute in the VirusTotalAnalyzer class. Adjust it according to your API key's rate limits.
