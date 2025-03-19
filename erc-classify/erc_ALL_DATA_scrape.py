import requests
from bs4 import BeautifulSoup
import pandas as pd

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
token_ercs = {
    "ERC20"}

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
        abstract = ""
        abstract_insights = ""
        motivation = ""
        motivation_insights = ""
        specification = ""
        specification_insights = ""
        rationale = ""
        rationale_insights = ""
        backward_compatibility = ""
        backward_compatibility_insights = ""
        security_considerations = ""
        security_considerations_insights = ""
        
        for section in toc:
            section_title = section.lower()
            section_content = soup.find("h2", string=section)
            if section_content:
                section_text = section_content.find_next("p").text.strip()
                
                if "abstract" in section_title:
                    abstract = section_text
                    abstract_insights = extract_insights(section_text)
                elif "motivation" in section_title:
                    motivation = section_text
                    motivation_insights = extract_insights(section_text)
                elif "specification" in section_title:
                    specification = section_text
                    specification_insights = extract_insights(section_text)
                elif "rationale" in section_title:
                    rationale = section_text
                    rationale_insights = extract_insights(section_text)
                elif "backward compatibility" in section_title:
                    backward_compatibility = section_text
                    backward_compatibility_insights = extract_insights(section_text)
                elif "security considerations" in section_title:
                    security_considerations = section_text
                    security_considerations_insights = extract_insights(section_text)
        
        # Append data to DataFrame using pd.concat
        new_row = pd.DataFrame([{
            "ERC": erc,
            "Description": description,
            "Requires": requires,
            "Table of Contents": "; ".join(toc),
            "Abstract": abstract,
            "Abstract insights": abstract_insights,
            "Motivation": motivation,
            "Motivation insights": motivation_insights,
            "Specification": specification,
            "Specification insights": specification_insights,
            "Rationale": rationale,
            "Rationale insights": rationale_insights,
            "Backward Compatibility": backward_compatibility,
            "Backward Compatibility insights": backward_compatibility_insights,
            "Security Considerations": security_considerations,
            "Security Considerations insights": security_considerations_insights
        }])
        df = pd.concat([df, new_row], ignore_index=True)
    else:
        print(f"Failed to fetch data for {erc}")

# Save the DataFrame to a CSV file
df.to_csv("erc_ALL_DATA_scrape.csv", index=False)
print("Data saved to erc_data.csv")