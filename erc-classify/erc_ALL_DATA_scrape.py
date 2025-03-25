import requests
from bs4 import BeautifulSoup
import pandas as pd
import re
import os

from dotenv import load_dotenv

import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# load_env = load_dotenv("/home/ashok/ERC-analysis/.env")
load_env = load_dotenv()
# Verify if .env is loaded
print(f"✅ .env Loaded: {load_env}")

# Get API key from environment variable
API_KEY = os.getenv("OPENAI_API_TOKEN")

if not API_KEY:
    raise ValueError("⚠️ API Key not found! Make sure to set OPENAI_API_TOKEN in your .env file.")

print(f"🔑 Using API Key: {API_KEY[:5]}****** (Hidden for security)")

# # List of token ERCs
token_ercs = {
    "ERC20", "ERC165", "ERC173", "ERC721", "ERC223", "ERC777", "ERC1155", "ERC884", "ERC998", 
    "ERC875", "ERC1046", "ERC1363", "ERC2135", "ERC2309", "ERC2612", "ERC1948", "ERC1261", 
    "ERC1271", "ERC1337", "ERC1820", "ERC2021", "ERC2018", "ERC2019", "ERC1996", "ERC2020", 
    "ERC2981", "ERC3135", "ERC3440", "ERC3589", "ERC3754", "ERC4494", "ERC4524", "ERC4675", 
    "ERC3525", "ERC3643", "ERC4400", "ERC4519", "ERC4626", "ERC4906", "ERC4907", "ERC4337", 
    "ERC4910", "ERC4955", "ERC5006", "ERC5007", "ERC5023", "ERC5169", "ERC5192", "ERC5267", 
    "ERC5375", "ERC5380", "ERC5484", "ERC5489", "ERC5507", "ERC5521", "ERC5528", "ERC5570", 
    "ERC5585", "ERC5606", "ERC5615", "ERC5646", "ERC5679", "ERC5725", "ERC5773", "ERC6059", 
    "ERC6066", "ERC6105", "ERC6147", "ERC6150", "ERC6220", "ERC6239", "ERC6381", "ERC6454", 
    "ERC6492", "ERC6551", "ERC6672", "ERC6808", "ERC6809", "ERC6982", "ERC7160", "ERC7231", 
    "ERC7401", "ERC7409"
}

# List of token ERCs
# token_ercs = {"ERC223", "ERC165"}

# Base URL for EIPs
base_url = "https://eips.ethereum.org/EIPS/eip-"

API_ENDPOINT = "https://api.openai.com/v1/chat/completions"

# Define the columns for the DataFrame
columns = [
    "ERC", "Description", "Requires", "Table of Contents", "Abstract", "Motivation",
    "Specification", "Rationale", "Backwards Compatibility", "Security Considerations"
]




def insights_from_scrape_data(csv_path, output_path, api_key):
    

    def analyze_erc_row(row):
        """
        Sends a row's data to an NLP API to generate insights.
        """
        # Construct prompts for the API based on your CSV columns
        token_prompt = f"""
        Analyze the following ERC standard data and answer concisely:
        - Description: {row['Description']}
        - Abstract: {row['Abstract']}
        - Motivation: {row['Motivation']}
        
        Questions:
        1. Is this ERC a token standard? Answer 'Yes' or 'No'.
        2. What is the main objective of this ERC? Provide a crisp summary.
        Return the answer in the format: "Is Token: [Yes/No]. Objective: [Summary]"
        """

        issues_prompt = f"""
        Analyze the following ERC specifications:
        - Specifications: {row['Specification']}
        - Rationale: {row['Rationale']}
        - Backwards Compatibility: {row['Backwards Compatibility']}
        
        Extract all critical points (e.g., 'Must', 'Must Not', 'Should', 'Should Not', 'Enforce', 'If not implemented correctly').
        List potential bugs, vulnerabilities, or issues if these are not followed. Be concise.
        """

        security_prompt = f"""
        Analyze the security considerations:
        - Security Considerations: {row['Security Considerations']}
        
        List security issues that may arise if these are not followed. Include advanced reasoning (e.g., reentrancy, access control flaws).
        Be detailed but concise.
        """

        def call_api(prompt):
            """
            Helper function to call the API and handle errors.
            """
            try:
                response = requests.post(
                    API_ENDPOINT,
                    headers={"Authorization": f"Bearer {api_key}"},
                    json={
                        "model": "gpt-4-turbo",
                        "messages": [{"role": "user", "content": prompt}]
                    }
                )
                response.raise_for_status()  # Raise an error for bad status codes
                return response.json()
            except requests.exceptions.RequestException as e:
                logger.error(f"API request failed: {e}")
                return None

        # Call API for token insights
        token_response = call_api(token_prompt)
        if token_response and "choices" in token_response:
            token_insights = token_response['choices'][0]['message']['content']
        else:
            logger.error(f"Failed to get token insights for row: {row['ERC']}")
            token_insights = "Error: API request failed"

        # Call API for potential issues
        issues_response = call_api(issues_prompt)
        if issues_response and "choices" in issues_response:
            issues_analysis = issues_response['choices'][0]['message']['content']
        else:
            logger.error(f"Failed to get potential issues for row: {row['ERC']}")
            issues_analysis = "Error: API request failed"

        # Call API for security issues
        security_response = call_api(security_prompt)
        if security_response and "choices" in security_response:
            security_analysis = security_response['choices'][0]['message']['content']
        else:
            logger.error(f"Failed to get security issues for row: {row['ERC']}")
            security_analysis = "Error: API request failed"

        return {
            "ERC Token Insights": token_insights,
            "Potential Issues": issues_analysis,
            "Security Issues": security_analysis
        }

    # Read the CSV file
    df = pd.read_csv(csv_path)
    
    # Apply the analysis to each row
    results = df.apply(analyze_erc_row, axis=1)
    
    # Add new columns to the DataFrame
    df["ERC Token Insights"] = results.apply(lambda x: x["ERC Token Insights"])
    df["Potential Issues"] = results.apply(lambda x: x["Potential Issues"])
    df["Security Issues"] = results.apply(lambda x: x["Security Issues"])
    
    # Save to new CSV
    df.to_csv(output_path, index=False)
    logger.info(f"Processed data saved to: {output_path}")




def requires_insights(csv_path, output_path, api_key):
   

    def analyze_erc_row(row):
       
        requires_prompt = f"""
        Analyze this ERC standard's requirements and security considerations:

        ERC: {row['ERC']}
        Requires: {row['Requires']}
        Specifications: {row['Specification']}
        Rationale: {row['Rationale']}
        Security Considerations: {row['Security Considerations']}

        Answer these questions in detail:
        1. Which requirements are absolutely mandatory vs optional? Why?
        2. What security risks exist if mandatory requirements aren't implemented?
        3. What functionality breaks if requirements are partially implemented?
        4. Are there any backward compatibility issues if requirements are ignored?
        5. Could omitting requirements lead to malicious exploits? How?
        6. Does the standard explicitly mention any requirements as optional?
        
        For each required EIP/ERC:
        - Explain its criticality to this standard
        - Describe potential vulnerabilities if omitted
        - List any explicit warnings in the specification
        - Note any conditional requirements ("should" vs "must")
        
        Format your response with clear sections for:
        - Critical Requirements (Must Implement)
        - Optional Requirements (Can Omit)
        - Security Implications
        - Functional Consequences
        - Malicious Exploit Potential
        """

        def call_api(prompt):
            try:
                response = requests.post(
                    API_ENDPOINT,
                    headers={"Authorization": f"Bearer {api_key}"},
                    json={
                        "model": "gpt-4-turbo",
                        "messages": [{"role": "user", "content": prompt}],
                        "temperature": 0.3  # More deterministic output
                    }
                )
                response.raise_for_status()
                return response.json()
            except requests.exceptions.RequestException as e:
                logger.error(f"API request failed: {e}")
                return None

        # Get requirements analysis
        requires_response = call_api(requires_prompt)
        if requires_response and "choices" in requires_response:
            requires_analysis = requires_response['choices'][0]['message']['content']
        else:
            requires_analysis = "Error: Failed to analyze requirements"
            logger.error(f"Requires analysis failed for {row['ERC']}")

        # Get security impact analysis
        security_prompt = f"""
        For ERC {row['ERC']} with requirements {row['Requires']}, analyze:
        
        1. Security vulnerabilities that may emerge if requirements are ignored
        2. Specific attack vectors that could be enabled
        3. Any historical incidents related to incomplete implementations
        4. Worst-case scenarios from requirement omission
        5. Recommended mitigation strategies
        
        Reference these sections specifically:
        Security Considerations: {row['Security Considerations']}
        Specification: {row['Specification']}
        """
        
        security_response = call_api(security_prompt)
        if security_response and "choices" in security_response:
            security_analysis = security_response['choices'][0]['message']['content']
        else:
            security_analysis = "Error: Failed to analyze security implications"
            logger.error(f"Security analysis failed for {row['ERC']}")

        return {
            "Requirements Analysis": requires_analysis,
            "Security Impact Analysis": security_analysis,
            "Critical Requirements": extract_critical_requirements(row),
            "Optional Requirements": extract_optional_requirements(row)
        }

    def extract_critical_requirements(row):
        """Extract MUST-implement requirements from specification text"""
        spec_text = str(row['Specification'])
        must_requirements = re.findall(r'(MUST|REQUIRED|SHALL)[^\.]+\.', spec_text)
        return " | ".join(must_requirements[:3])  # Return first 3 for brevity

    def extract_optional_requirements(row):
        """Extract SHOULD/MAY requirements from specification text"""
        spec_text = str(row['Specification'])
        optional_requirements = re.findall(r'(SHOULD|MAY|OPTIONAL)[^\.]+\.', spec_text)
        return " | ".join(optional_requirements[:3])  # Return first 3 for brevity

    # Read and process data
    df = pd.read_csv(csv_path)
    results = df.apply(analyze_erc_row, axis=1)
    
    # Add new analysis columns
    df = pd.concat([
        df,
        pd.DataFrame(results.tolist())
    ], axis=1)
    
    # Save enriched data
    df.to_csv(output_path, index=False)
    logger.info(f"Saved analyzed data to {output_path}")
    return df



def extract_section_content(section_title, soup):
    
    section_header = soup.find(lambda tag: tag.name in ["h2"] and re.search(section_title, tag.text, re.IGNORECASE))

    if not section_header:
        return {"Section not found": ""}

    # Initialize a dictionary to store sub-sections and their content
    section_data = {}
    current_subsection = "Main Content"  # Default sub-section for content before any sub-headings

    # Iterate through siblings of the section header
    for sibling in section_header.find_next_siblings():
        # Stop if we encounter the next main section (h2 or h3)
        if sibling.name in ["h2"]:
            break

        # Detect sub-section headers (e.g., h3, h4, h5)
        if sibling.name in ["h3", "h4", "h5"]:
            
            # Extract the sub-section title
            current_subsection = sibling.text.strip()
            section_data[current_subsection] = []  # Initialize a list for sub-section content
        else:
            # Add content to the current sub-section
            if current_subsection not in section_data:
                section_data[current_subsection] = []  # Initialize if not already present

            if sibling.name == "p":  # Handle paragraphs
                section_data[current_subsection].append(sibling.text.strip())
            elif sibling.name == "pre":  # Handle code snippets directly under <pre>
                section_data[current_subsection].append(sibling.text.strip())
            elif sibling.name == "div" and "highlight" in sibling.get("class", []):  # Handle code snippets in <div class="highlight">
                code = sibling.find("pre")
                if code:
                    section_data[current_subsection].append(code.text.strip())
            elif sibling.name == "ol":  # Handle ordered lists
                for li in sibling.find_all("li"):
                    section_data[current_subsection].append(f"- {li.text.strip()}")
            elif sibling.name == "ul":  # Handle unordered lists
                for li in sibling.find_all("li"):
                    section_data[current_subsection].append(f"• {li.text.strip()}")
            elif sibling.name == "div":  # Handle nested content
                for p in sibling.find_all("p"):
                    section_data[current_subsection].append(p.text.strip())
                for pre in sibling.find_all("pre"):
                    section_data[current_subsection].append(pre.text.strip())
                for ol in sibling.find_all("ol"):
                    for li in ol.find_all("li"):
                        section_data[current_subsection].append(f"- {li.text.strip()}")
                for ul in sibling.find_all("ul"):
                    for li in ul.find_all("li"):
                        section_data[current_subsection].append(f"• {li.text.strip()}")

    # Join lists of content into strings for each sub-section
    for subsection, content_list in section_data.items():
        section_data[subsection] = "\n".join(content_list)

    return section_data


def scrape_ALL_data():
    
    df = pd.DataFrame(columns=columns)

    # Iterate through each ERC in the list
    for erc in token_ercs:
        url = base_url + erc[3:]  # Remove "ERC" prefix to get the EIP number
        response = requests.get(url)
        
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, "html.parser")
            
            # Extract Description (first title)
            description = soup.find("h1").text.strip() +" : "+ soup.find("h3").text.strip()
            
            # Extract Requires
            requires = ""
            requires_section = soup.find("th", string="Requires")
            if requires_section:
                requires = requires_section.find_next("td").text.strip()
            
            # Extract Table of Contents
            toc = []
            toc_section = soup.find("h2", string="Table of Contents")
            if toc_section:
                toc = [li.text.strip() for li in toc_section.find_next("ul").find_all("li")]
            
            # Extract other sections
            abstract = extract_section_content("Abstract", soup)
            
            
            motivation = extract_section_content("Motivation", soup)
            specification = extract_section_content("Specification", soup)
            
              
            rationale = extract_section_content("Rationale", soup)
            backwards_compatibility = extract_section_content("Backwards Compatibility", soup)
            security_considerations = extract_section_content("Security|Security Considerations", soup)  # Handle variations in title

            # Append data to DataFrame using pd.concat
            new_row = pd.DataFrame([{
                "ERC": erc,
                "Description": description,
                "Requires": requires,
                "Table of Contents": "; ".join(toc),
                "Abstract": abstract,
                "Motivation": motivation,
                "Specification": specification,
                "Rationale": rationale,
                "Backwards Compatibility": backwards_compatibility,
                "Security Considerations": security_considerations
            }])
            df = pd.concat([df, new_row], ignore_index=True)
        else:
            print(f"Failed to fetch data for {erc}")

    # Extract ERC number for sorting
    df['ERC_Number'] = df['ERC'].str.extract('(\d+)').astype(int)

    # Sort DataFrame by ERC number
    df = df.sort_values('ERC_Number')

    # Drop the temporary ERC_Number column
    df = df.drop(columns=['ERC_Number'])

    # Save the sorted DataFrame to a CSV file
    df.to_csv("erc_ALL_DATA_scrape.csv", index=False)
    print("Data saved to erc_ALL_DATA_scrape.csv (sorted by ERC number)")



def main():
    
    # scrape_ALL_data()
    

    insights_from_scrape_data(
        "/Users/ashokk/Documents/ERC-analysis-master/erc-classify/erc_ALL_DATA_scrape.csv",  # Input CSV
        "/Users/ashokk/Documents/ERC-analysis-master/erc-classify/erc_ALL_DATA_insights.csv",  # Output CSV
        API_KEY
    )

    
if __name__ == "__main__":
    main()