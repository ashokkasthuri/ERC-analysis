import requests
from bs4 import BeautifulSoup
import pandas as pd
import re

# # List of token ERCs
# token_ercs = {
#     "ERC20", "ERC165", "ERC173", "ERC721", "ERC223", "ERC777", "ERC1155", "ERC884", "ERC998", 
#     "ERC875", "ERC1046", "ERC1363", "ERC2135", "ERC2309", "ERC2612", "ERC1948", "ERC1261", 
#     "ERC1271", "ERC1337", "ERC1820", "ERC2021", "ERC2018", "ERC2019", "ERC1996", "ERC2020", 
#     "ERC2981", "ERC3135", "ERC3440", "ERC3589", "ERC3754", "ERC4494", "ERC4524", "ERC4675", 
#     "ERC3525", "ERC3643", "ERC4400", "ERC4519", "ERC4626", "ERC4906", "ERC4907", "ERC4337", 
#     "ERC4910", "ERC4955", "ERC5006", "ERC5007", "ERC5023", "ERC5169", "ERC5192", "ERC5267", 
#     "ERC5375", "ERC5380", "ERC5484", "ERC5489", "ERC5507", "ERC5521", "ERC5528", "ERC5570", 
#     "ERC5585", "ERC5606", "ERC5615", "ERC5646", "ERC5679", "ERC5725", "ERC5773", "ERC6059", 
#     "ERC6066", "ERC6105", "ERC6147", "ERC6150", "ERC6220", "ERC6239", "ERC6381", "ERC6454", 
#     "ERC6492", "ERC6551", "ERC6672", "ERC6808", "ERC6809", "ERC6982", "ERC7160", "ERC7231", 
#     "ERC7401", "ERC7409"
# }

# List of token ERCs
token_ercs = {"ERC223"}

# Base URL for EIPs
base_url = "https://eips.ethereum.org/EIPS/eip-"

# Columns for the CSV file
columns = [
    "ERC", "Description", "Requires", "Table of Contents", "Abstract", "Abstract insights",
    "Motivation", "Motivation insights", "Specification", "Specification insights",
    "Rationale", "Rationale insights", "Backward Compatibility", "Backward Compatibility insights",
    "Security Considerations", "Security Considerations insights"
]

# Initialize an empty DataFrame
df = pd.DataFrame(columns=columns)

# Function to extract insights from a section
def extract_insights(text):
    important_keywords = ["must", "must not", "should", "should not", "recommended", "not recommended", "important"]
    insights = []
    for line in text.split("\n"):
        if any(keyword in line.lower() for keyword in important_keywords):
            insights.append(line.strip())
    return "\n".join(insights)

# Function to extract section content
def extract_section_content(section_title, soup):
    # Search for both <h2> and <h3> headers with similar section titles
    section_header = soup.find(lambda tag: tag.name in ["h2", "h3"] and re.search(section_title, tag.text, re.IGNORECASE))

    # Debug: Print the section header found
    print(f"Section found for '{section_title}': {section_header}")

    if section_header:
        # Get all sibling elements after the section header until the next header
        content = []
        for sibling in section_header.find_next_siblings():
            if sibling.name in ["h2", "h3"]:
                break  # Stop at the next section
            if sibling.name == "p":
                content.append(sibling.text.strip())
            elif sibling.name == "div":  # Handle nested content in <div> tags
                for p in sibling.find_all("p"):
                    content.append(p.text.strip())
        
        return " ".join(content)
    
    return "Section not found"

# Iterate through each ERC in the list
for erc in token_ercs:
    url = base_url + erc[3:]  # Remove "ERC" prefix to get the EIP number
    response = requests.get(url)
    
    if response.status_code == 200:
        soup = BeautifulSoup(response.content, "html.parser")
        
        # Extract Description (first title)
        description = soup.find("h1").text.strip()
        
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
        print(f"abstract: {abstract}")
        
        motivation = extract_section_content("Motivation", soup)
        
        specification = extract_section_content("Specification", soup)
        
        rationale = extract_section_content("Rationale", soup)
        
        backward_compatibility = extract_section_content("Backward Compatibility", soup)
        
        security_considerations = extract_section_content("Security|Security Considerations", soup)  # Handle variations in title

        # Append data to DataFrame using pd.concat
        new_row = pd.DataFrame([{
            "ERC": erc,
            "Description": description,
            "Requires": requires,
            "Table of Contents": "; ".join(toc),
            "Abstract": abstract,
            "Abstract insights": extract_insights(abstract),
            "Motivation": motivation,
            "Motivation insights": extract_insights(motivation),
            "Specification": specification,
            "Specification insights": extract_insights(specification),
            "Rationale": rationale,
            "Rationale insights": extract_insights(rationale),
            "Backward Compatibility": backward_compatibility,
            "Backward Compatibility insights": extract_insights(backward_compatibility),
            "Security Considerations": security_considerations,
            "Security Considerations insights": extract_insights(security_considerations)
        }])
        df = pd.concat([df, new_row], ignore_index=True)
    else:
        print(f"Failed to fetch data for {erc}")

# Save the DataFrame to a CSV file
df.to_csv("erc_ALL_DATA_scrape.csv", index=False)
print("Data saved to erc_ALL_DATA_scrape.csv")
