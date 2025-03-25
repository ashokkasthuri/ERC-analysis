import requests
from bs4 import BeautifulSoup
import pandas as pd
import re
import os

from dotenv import load_dotenv

import logging

import networkx as nx
import plotly.graph_objects as go
from pyvis.network import Network
import matplotlib.pyplot as plt
import pandas as pd

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
# token_ercs = {"ERC20"}

# Base URL for EIPs
base_url = "https://eips.ethereum.org/EIPS/eip-"

API_ENDPOINT = "https://api.openai.com/v1/chat/completions"


# Define the dependencies for each ERC standard
erc_dependencies = {
    "ERC20": [],
    "ERC165": ["ERC214"],
    "ERC173": ["ERC165"],
    "ERC721": ["ERC165"],
    "ERC223": [],
    "ERC777": ["ERC1820"],
    "ERC1155": ["ERC165"],
    "ERC884": [],
    "ERC998": ["ERC20", "ERC165", "ERC721"],
    "ERC875": [],
    "ERC1046": ["ERC20", "ERC721", "ERC1155"],
    "ERC1363": ["ERC20", "ERC165"],
    "ERC2135": ["ERC165", "ERC721", "ERC1155"],
    "ERC2309": ["ERC721"],
    "ERC2612": ["ERC20", "ERC712"],
    "ERC1948": ["ERC721"],
    "ERC1261": ["ERC165", "ERC173"],
    "ERC1271": [],
    "ERC1337": ["ERC20", "ERC165"],
    "ERC1820": ["ERC165", "ERC214"],
    "ERC2021": ["ERC20", "ERC1066", "ERC1996"],
    "ERC2018": ["ERC1996"],
    "ERC2019": ["ERC20"],
    "ERC1996": ["ERC20"],
    "ERC2020": ["ERC20", "ERC1066", "ERC1996", "ERC2009", "ERC2018", "ERC2019", "ERC2021"],
    "ERC2981": ["ERC165"],
    "ERC3135": ["ERC20"],
    "ERC3440": ["ERC712", "ERC721"],
    "ERC3589": ["ERC721"],
    "ERC3754": [],
    "ERC4494": ["ERC165", "ERC712", "ERC721"],
    "ERC4524": ["ERC20", "ERC165"],
    "ERC4675": ["ERC165", "ERC721"],
    "ERC3525": ["ERC20", "ERC165", "ERC721"],
    "ERC3643": ["ERC20", "ERC173"],
    "ERC4400": ["ERC165", "ERC721"],
    "ERC4519": ["ERC165", "ERC721"],
    "ERC4626": ["ERC20", "ERC2612"],
    "ERC4906": ["ERC165", "ERC721"],
    "ERC4907": ["ERC165", "ERC721"],
    "ERC4337": ["ERC712", "ERC7562"],
    "ERC4910": ["ERC165", "ERC721"],
    "ERC4955": ["ERC721", "ERC1155"],
    "ERC5006": ["ERC165", "ERC1155"],
    "ERC5007": ["ERC165", "ERC721"],
    "ERC5023": ["ERC165"],
    "ERC5169": ["ERC20", "ERC165", "ERC721", "ERC777", "ERC1155"],
    "ERC5192": ["ERC165", "ERC721"],
    "ERC5267": ["ERC155", "ERC712", "ERC2612"],
    "ERC5375": ["ERC55", "ERC155", "ERC712", "ERC721", "ERC1155"],
    "ERC5380": ["ERC165", "ERC721", "ERC1046"],
    "ERC5484": ["ERC165", "ERC721"],
    "ERC5489": ["ERC165", "ERC721"],
    "ERC5507": ["ERC20", "ERC165", "ERC721", "ERC1155"],
    "ERC5521": ["ERC165", "ERC721"],
    "ERC5528": ["ERC20"],
    "ERC5570": ["ERC721"],
    "ERC5585": ["ERC721"],
    "ERC5606": ["ERC721", "ERC1155"],
    "ERC5615": ["ERC1155"],
    "ERC5646": ["ERC165"],
    "ERC5679": ["ERC20", "ERC165", "ERC721", "ERC1155"],
    "ERC5725": ["ERC721"],
    "ERC5773": ["ERC165", "ERC721"],
    "ERC6059": ["ERC165", "ERC721"],
    "ERC6066": ["ERC165", "ERC721", "ERC1155", "ERC1271", "ERC5750"],
    "ERC6105": ["ERC20", "ERC165", "ERC721", "ERC2981"],
    "ERC6147": ["ERC165", "ERC721"],
    "ERC6150": ["ERC165", "ERC721"],
    "ERC6220": ["ERC165", "ERC721", "ERC5773", "ERC6059"],
    "ERC6239": ["ERC165", "ERC721", "ERC5192"],
    "ERC6381": ["ERC165"],
    "ERC6454": ["ERC165", "ERC721"],
    "ERC6492": ["ERC1271"],
    "ERC6551": ["ERC165", "ERC721", "ERC1167", "ERC1271"],
    "ERC6672": ["ERC165", "ERC721"],
    "ERC6808": ["ERC20"],
    "ERC6809": ["ERC721"],
    "ERC6982": ["ERC165", "ERC721"],
    "ERC7160": ["ERC165", "ERC721"],
    "ERC7231": ["ERC165", "ERC721", "ERC1271"],
    "ERC7401": ["ERC165", "ERC721"],
    "ERC7409": ["ERC165"]
}

optional_erc_dependencies = {
    "ERC4626": ["ERC2612"],  # EIP-2612 permit() is optional for ERC4626 vaults
    "ERC5267": ["ERC712"],   # EIP-712 signatures are optional for ERC5267
    "ERC6551": ["ERC721"],   # Can work with just ERC1167 minimal proxies
    "ERC4337": ["ERC7562"]   # ERC7562 is for advanced account abstraction features
}

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
        
        EIP_requires_prompt = f"""
        Conduct a thorough analysis of ERC {row['ERC']} with required EIPs {row['Requires']} by examining:

        1. Specification: {row['Specification']}
        2. Rationale: {row['Rationale']} 
        3. Security Considerations: {row['Security Considerations']}

        Answer in precise technical detail:

        ### Mandatory vs Optional Requirements Analysis
        1. For each required, dependent, underlying EIP for an ERC:
        - Is all EIP absolutely mandatory (MUST implement) or optional (MAY implement)?
        - Cite specific language from the specification that proves its status (e.g., "MUST implement" vs "SHOULD implement")
        - Explain why the standard authors made this EIP requirement mandatory/optional

        2. For mandatory EIPs:
        - What core functionality would break if omitted the requires, dependent, underlying EIP?
        - What specific security mechanisms would be compromised?
        - Would the ERC still be considered compliant without it?

        3. For optional EIPs:
        - What additional benefits do they provide?
        - Why were they included as ERC requirements or dependency (as EIP) if not mandatory?
        - Under what conditions would you recommend implementing them?

        ### Consequences of Non-Compliance
        1. Security Impact:
        - List specific software bugs that would emerge
        - List specific vulnerabilities that would emerge 
        - List specific malicious activities that would emerge 
        - Known historical exploits related to omitting these EIP requirements for an ERC
        - Worst-case attack scenarios

        2. Functional Impact:
        - Which features would become unusable?
        - How would interoperability be affected?
        - Would the contract still pass standard compliance checks?

        3. Ecosystem Impact:
        - How would wallets/exchanges/DApps handle non-compliant implementations?
        - Would the contract still work with major infrastructure?

        Format your response with clear technical justification for each point, quoting relevant specification text when possible.
        """
       
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
            
        # Get EIP requirements analysis
        EIP_requires_response = call_api(EIP_requires_prompt)
        if EIP_requires_response and "choices" in EIP_requires_response:
            EIP_requires_analysis = EIP_requires_response['choices'][0]['message']['content']
        else:
            EIP_requires_analysis = "Error: Failed to analyze EIP requirements"
            logger.error(f"EIP Requires analysis failed for {row['ERC']}")

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
            "EIP_Requirements Analysis": EIP_requires_analysis,
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
    # df = pd.read_csv(csv_path)
    df1 = pd.read_csv(csv_path)
    df = df1.head(2).copy()
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
            token = extract_section_content("Token", soup)
            if(len(specification) == 0) and (len(token) != 0):
                # print(f"specification : {specification}")
                # print(f"specification : {len(token)}")
                specification = token
                
            
              
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


def graph_erc_requires():
    # Create a directed graph
    G = nx.DiGraph()

    # Add nodes and edges
    for erc, deps in erc_dependencies.items():
        G.add_node(erc, size=20, title=erc)
        for dep in deps:
            G.add_edge(dep, erc)

    # Calculate node importance metrics
    betweenness = nx.betweenness_centrality(G)
    degree = dict(G.degree())
    pagerank = nx.pagerank(G)

    # Add metrics to node attributes
    for node in G.nodes():
        G.nodes[node]['betweenness'] = betweenness[node]
        G.nodes[node]['degree'] = degree[node]
        G.nodes[node]['pagerank'] = pagerank[node]
        
    
    
    # Create interactive visualization with PyVis
    def create_pyvis_network():
        net = Network(height="750px", width="100%", directed=True, notebook=True)
        net.from_nx(G)
        
        # Customize node appearance based on importance
        for node in net.nodes:
            node['size'] = 10 + 15 * G.nodes[node['id']]['pagerank']
            node['title'] = (
                f"ERC: {node['id']}<br>"
                f"Dependencies: {', '.join(erc_dependencies.get(node['id'], []))}<br>"
                f"Betweenness: {G.nodes[node['id']]['betweenness']:.3f}<br>"
                f"Degree: {G.nodes[node['id']]['degree']}<br>"
                f"PageRank: {G.nodes[node['id']]['pagerank']:.3f}"
            )
            # Color core standards differently
            if G.nodes[node['id']]['degree'] > 5:
                node['color'] = '#FF7F0E'  # Orange for high-degree nodes
            elif node['id'] in ['ERC20', 'ERC721', 'ERC1155', 'ERC165']:
                node['color'] = '#1F77B4'  # Blue for foundational standards
        
        # Physics layout configuration
        net.set_options("""
        {
        "physics": {
            "forceAtlas2Based": {
            "gravitationalConstant": -100,
            "centralGravity": 0.01,
            "springLength": 200,
            "springConstant": 0.08
            },
            "minVelocity": 0.75,
            "solver": "forceAtlas2Based"
        }
        }
        """)
        
        return net

    def create_plotly_figure():
        pos = nx.spring_layout(G, k=0.5, iterations=50)
        
        edge_x = []
        edge_y = []
        for edge in G.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])

        edge_trace = go.Scatter(
            x=edge_x, y=edge_y,
            line=dict(width=0.5, color='#888'),
            hoverinfo='none',
            mode='lines')

        node_x = []
        node_y = []
        node_text = []
        node_size = []
        node_color = []
        for node in G.nodes():
            x, y = pos[node]
            node_x.append(x)
            node_y.append(y)
            node_text.append(
                f"<b>{node}</b><br>"
                f"Dependencies: {len(erc_dependencies.get(node, []))}<br>"
                f"Used by: {G.degree(node)} standards"
            )
            node_size.append(10 + 20 * G.nodes[node]['pagerank'])
            node_color.append(G.nodes[node]['pagerank'])

        node_trace = go.Scatter(
            x=node_x, y=node_y,
            mode='markers+text',
            text=list(G.nodes()),
            textposition="top center",
            hovertext=node_text,
            hoverinfo='text',
            marker=dict(
                showscale=True,
                colorscale='YlGnBu',
                size=node_size,
                color=node_color,
                colorbar=dict(
                    thickness=15,
                    title='PageRank',
                    xanchor='left',
                    title_side='right'
                ),
                line_width=2))

        fig = go.Figure(data=[edge_trace, node_trace],
                    layout=go.Layout(
                        title_text='<b>ERC Standards Dependency Network</b>',  # Changed from title
                        title_font_size=16,  # Changed from titlefont_size
                        showlegend=False,
                        hovermode='closest',
                        margin=dict(b=20,l=5,r=5,t=40),
                        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False))
                    )
        return fig   
   
   
    # Generate both visualizations
    pyvis_net = create_pyvis_network()
    plotly_fig = create_plotly_figure()

    # Save outputs
    pyvis_net.show("erc_dependencies.html")  # Interactive HTML
    plotly_fig.write_html("erc_dependencies_plotly.html")  # Publication-quality
    plotly_fig.show()


def main():
    
    # Generate both visualizations
    graph_erc_requires()
    
    
    # scrape_ALL_data()
    

    # insights_from_scrape_data(
    #     "/Users/ashokk/Documents/ERC-analysis-master/erc-classify/erc_ALL_DATA_scrape.csv",  # Input CSV
    #     "/Users/ashokk/Documents/ERC-analysis-master/erc-classify/erc_ALL_DATA_insights.csv",  # Output CSV
    #     API_KEY
    # )
    
    
    # requires_insights(
    #     "/home/ashok/ERC-analysis/erc-classify/erc_ALL_DATA_scrape.csv",  # Input CSV
    #     "/home/ashok/ERC-analysis/erc-classify/erc_REQUIRES_insights.csv",  # Output CSV
    #     API_KEY
    # )
    
    # requires_insights(
    #     "/Users/ashokk/Documents/ERC-analysis-master/erc-classify/erc_ALL_DATA_scrape.csv",  # Input CSV
    #     "/Users/ashokk/Documents/ERC-analysis-master/erc-classify/erc_REQUIRES_insights.csv",  # Output CSV
    #     API_KEY
    # )

    
if __name__ == "__main__":
    main()