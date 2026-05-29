
import os
import time
import requests
from urllib.parse import urljoin
import sys
import os
from dotenv import load_dotenv




sys.setrecursionlimit(20000)



# Constants
GITHUB_API_URL = "https://api.github.com/search/code"
GITHUB_REPO_API_URL = "https://api.github.com/repos"
SOLIDITY_FILE_EXTENSION = ".sol"
OUTPUT_DIR = "erc_GIT_source_code"


# GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
# print(f"GITHUB_TOKEN : {GITHUB_TOKEN}")

load_dotenv()

# Get API key from environment variable
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")


# ERC_STANDARDS = [
#     "ERC20", "ERC721", "ERC998", "ERC1155", "ERC1261", "ERC1363", "ERC1948", "ERC2020", "ERC2309", "ERC2612"]
# List of ERCs to scrape (all prefixed with "ERC")
ERC_STANDARDS = [
     "ERC2981", "ERC3135",
    "ERC3440", "ERC3525", "ERC3643", "ERC3754", "ERC4400", "ERC4494", "ERC4626", "ERC4906", "ERC4907", "ERC4910", "ERC4955",
    "ERC5006", "ERC5007", "ERC5023", "ERC5169", "ERC5192", "ERC5267", "ERC5375", "ERC5380", "ERC5484", "ERC5507", "ERC5521",
    "ERC5570", "ERC5679", "ERC5725", "ERC6059", "ERC6066", "ERC6105", "ERC6220", "ERC6381", "ERC6454", "ERC6672", "ERC6808",
    "ERC6982", "ERC7160", "ERC7231", "ERC7401", "ERC7409"
]

# Folders to include (only look in these folders)
INCLUDE_FOLDERS = ["src", "main", "contracts"]

# Folders to exclude (skip these folders)
EXCLUDE_FOLDERS = ["data", "test", "inputs", "mocks", "scripts", "docs", "lib"]

# Create output directory if it doesn't exist
if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

def search_github_for_erc(erc_standard):
    """
    Search GitHub for Solidity files related to a specific ERC standard using the GitHub API.
    """
    print(f"Searching GitHub for {erc_standard} implementations...")
    
    # GitHub API search query for Solidity files containing the ERC standard
    query = f"{erc_standard} extension:sol"
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json",
    }
    params = {
        "q": query,
        "per_page": 100,  # Maximum number of results per page
    }
    
    # Send GET request to GitHub API
    response = requests.get(GITHUB_API_URL, headers=headers, params=params)
    if response.status_code != 200:
        print(f"Failed to search GitHub for {erc_standard}. Status code: {response.status_code}")
        return []
    
    # Parse the search results
    results = response.json().get("items", [])
    
    # Extract repository URLs
    repo_urls = set()
    for result in results:
        repo_url = result["repository"]["html_url"]
        repo_urls.add(repo_url)
    
    return list(repo_urls)

def get_repo_file_tree(repo_owner, repo_name):
    """
    Fetch the file tree of a repository using the GitHub API.
    Only include files in the specified folders (e.g., src, main, contracts).
    """
    url = f"{GITHUB_REPO_API_URL}/{repo_owner}/{repo_name}/git/trees/main?recursive=1"
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json",
    }
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        print(f"Failed to fetch file tree for {repo_owner}/{repo_name}. Status code: {response.status_code}")
        return []
    
    # Filter files to include only those in the specified folders
    file_tree = response.json().get("tree", [])
    filtered_files = []
    for file in file_tree:
        # Check if the file is in an included folder and not in an excluded folder
        if any(folder in file["path"] for folder in INCLUDE_FOLDERS and not EXCLUDE_FOLDERS) :
            filtered_files.append(file)
    
    return filtered_files

def download_solidity_files(repo_url, erc_standard):
    """
    Download Solidity files from a GitHub repository and save them in a repository-specific folder.
    Only download files related to the specific ERC standard and located in the specified folders.
    """
    print(f"Downloading Solidity files from {repo_url}...")
    
    # Extract repository owner and name from the URL
    parts = repo_url.split("/")
    repo_owner = parts[-2]
    repo_name = parts[-1]
    
    # Create a folder for the ERC standard
    erc_folder = os.path.join(OUTPUT_DIR, erc_standard)
    if not os.path.exists(erc_folder):
        os.makedirs(erc_folder)
    
    # Create a folder for the repository
    repo_folder = os.path.join(erc_folder, f"{repo_owner}_{repo_name}")
    if not os.path.exists(repo_folder):
        os.makedirs(repo_folder)
    
    # Fetch the repository's file tree (filtered to include only relevant folders)
    file_tree = get_repo_file_tree(repo_owner, repo_name)
    
    # Download Solidity files related to the ERC standard
    for file in file_tree:
        if file["path"].endswith(SOLIDITY_FILE_EXTENSION):
            # Check if the file contains the ERC standard name
            raw_url = f"https://raw.githubusercontent.com/{repo_owner}/{repo_name}/main/{file['path']}"
            file_response = requests.get(raw_url)
            if file_response.status_code == 200:
                file_content = file_response.text
                if erc_standard.lower() in file_content.lower():
                    file_name = os.path.basename(file["path"])
                    file_path = os.path.join(repo_folder, file_name)
                    
                    # Download the file
                    with open(file_path, "wb") as f:
                        f.write(file_response.content)
                    print(f"Downloaded {file_name} to {file_path}")
                else:
                    print(f"Skipping {file['path']} (not related to {erc_standard})")
            else:
                print(f"Failed to download {file['path']}. Status code: {file_response.status_code}")

def crawl_erc_source_code():
    """
    Crawl GitHub for Solidity source code files related to ERC standards.
    """
    for erc_standard in ERC_STANDARDS:
        print(f"Processing {erc_standard}...")
        
        # Search GitHub for repositories containing the ERC standard
        repo_urls = search_github_for_erc(erc_standard)
        
        # Limit downloads to 3 repositories per ERC
        repo_urls = repo_urls[:3]
        
        # Download Solidity files from each repository
        for repo_url in repo_urls:
            download_solidity_files(repo_url, erc_standard)
        
        # Add a delay to avoid hitting GitHub's rate limits
        time.sleep(10)  # 10-second delay between ERC standards

if __name__ == "__main__":
    crawl_erc_source_code()