import requests
from bs4 import BeautifulSoup
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score

# Base URL for Ethereum ERCs
EIPS_BASE_URL = "https://eips.ethereum.org/EIPS/eip-"

# List of ERCs to classify
ERC_NUMBERS = [
    20, 721, 1155, 777, 1363, 2612, 3525, 3643, 4626, 4907, 5192, 5380, 6809, 7409
]

# Updated labeled data (Token: 1, Non-Token: 0)
LABELED_DATA = {
    20: 1,  # ERC-20 (Token)
    721: 1,  # ERC-721 (Token)
    1155: 1,  # ERC-1155 (Token)
    777: 1,  # ERC-777 (Token)
    1363: 1,  # ERC-1363 (Token)
    2612: 1,  # ERC-2612 (Token)
    3525: 1,  # ERC-3525 (Token)
    3643: 1,  # ERC-3643 (Token)
    4626: 1,  # ERC-4626 (Token)
    4907: 1,  # ERC-4907 (Token)
    5192: 1,  # ERC-5192 (Token)
    5380: 1,  # ERC-5380 (Token)
    6809: 1,  # ERC-6809 (Token)
    7409: 1,  # ERC-7409 (Token)
}

def fetch_erc_data(erc_number):
    """Fetch the content of an ERC page."""
    url = f"{EIPS_BASE_URL}{erc_number}"
    response = requests.get(url)
    if response.status_code != 200:
        print(f"⚠️ Unable to fetch ERC-{erc_number}")
        return None
    soup = BeautifulSoup(response.text, "html.parser")
    return soup.get_text()

def extract_features(text):
    """Extract features from the ERC text."""
    features = {}
    
    # Check for keywords
    features["contains_token"] = int("token" in text.lower())
    features["contains_erc20"] = int("erc-20" in text.lower())
    features["contains_erc721"] = int("erc-721" in text.lower())
    features["contains_erc1155"] = int("erc-1155" in text.lower())
    features["contains_fungible"] = int("fungible" in text.lower())
    features["contains_non_fungible"] = int("non-fungible" in text.lower())
    features["contains_standard"] = int("standard" in text.lower())
    
    # Check for the keyword "requires"
    features["contains_requires"] = int("requires" in text.lower())
    
    # Extract dependencies
    dependencies = re.findall(r"Required\ ERCs:(.*?)\n", text, re.IGNORECASE)
    features["requires_erc20"] = int("ERC-20" in str(dependencies))
    features["requires_erc721"] = int("ERC-721" in str(dependencies))
    features["requires_erc1155"] = int("ERC-1155" in str(dependencies))
    
    return features

def prepare_dataset():
    """Prepare the dataset for training."""
    X = []
    y = []
    
    for erc_number in ERC_NUMBERS:
        text = fetch_erc_data(erc_number)
        if text:
            features = extract_features(text)
            X.append(list(features.values()))
            y.append(LABELED_DATA[erc_number])
    
    return X, y

def train_model(X, y):
    """Train a binary classification model."""
    # Split the data into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Train a Random Forest classifier
    model = RandomForestClassifier(random_state=42)
    model.fit(X_train, y_train)
    
    # Evaluate the model
    y_pred = model.predict(X_test)
    print("Classification Report:")
    print(classification_report(y_test, y_pred))
    print(f"Accuracy: {accuracy_score(y_test, y_pred):.2f}")
    
    return model

def classify_ercs(model):
    """Classify ERCs using the trained model."""
    for erc_number in ERC_NUMBERS:
        text = fetch_erc_data(erc_number)
        if text:
            features = extract_features(text)
            prediction = model.predict([list(features.values())])
            print(f"ERC-{erc_number} is classified as {'Token' if prediction[0] == 1 else 'Non-Token'}")

if __name__ == "__main__":
    # Prepare the dataset
    X, y = prepare_dataset()
    
    # Train the model
    model = train_model(X, y)
    
    # Classify ERCs
    classify_ercs(model)