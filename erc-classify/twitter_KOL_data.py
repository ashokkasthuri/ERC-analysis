# requirements: pip install snscrape pandas tqdm python-dotenv
import snscrape.modules.twitter as sntwitter
import pandas as pd
import re
import json
import time
from tqdm import tqdm
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv

# Load environment variables (for proxy/config)
load_dotenv()

# 1) Updated list of top 20 crypto KOL Twitter handles
KOL_HANDLES = [
    "CryptoKaleo", "Pentosh1", "HsakaTrades", "TheCryptoLark", 
    "CryptoWendyO", "CryptoCred", "blknoiz06", "CryptoGodJohn",
    "CryptoBirb", "MoonOverlord", "ansem", "CryptoDonAlt",
    "TheCryptoDog", "rektcapital", "CryptoMichNL", "WolfOfPoloniex",
    "CryptoISO", "CryptoJelleNL", "CryptoNTez", "0xGumshoe"
]

# 2) Enhanced keyword pattern with crypto-specific terms
KEYWORD_PATTERN = re.compile(
    r'\b(pre[- ]?market|pre[- ]?launch|alpha|gem|low[ -]?cap|'
    r'seed|private[ -]?sale|ido|tge|airdrop|whitelist|'
    r'high[ -]?return|100x|potential|narrative|vc[ -]?backed)\b', 
    flags=re.IGNORECASE
)

# 3) Time constraints (only get tweets from last X days)
DAYS_TO_SCRAPE = 30
start_date = datetime.now() - timedelta(days=DAYS_TO_SCRAPE)

def scrape_kol_tweets(handle, max_tweets=500, delay=2):
    """Enhanced scraper with error handling and rate limiting"""
    tweets = []
    scraper = sntwitter.TwitterUserScraper(handle)
    
    try:
        for i, tweet in enumerate(scraper.get_items()):
            # Exit conditions
            if i >= max_tweets or tweet.date < start_date:
                break
                
            # Skip retweets and replies for cleaner data
            if tweet.inReplyToTweetId or hasattr(tweet, 'retweetedTweet'):
                continue
                
            # Check for keywords and crypto tickers ($ETH, #BTC etc)
            content = tweet.rawContent
            if (KEYWORD_PATTERN.search(content) or 
                re.search(r'(?<!\w)\$[A-Za-z]{2,8}(?!\w)|#\w+', content)):
                
                tweets.append({
                    "kol": handle,
                    "date": tweet.date.isoformat(),
                    "content": content,
                    "url": f"https://twitter.com/{handle}/status/{tweet.id}",
                    "retweets": tweet.retweetCount,
                    "likes": tweet.likeCount,
                    "quotes": tweet.quoteCount,
                    "views": getattr(tweet, 'viewCount', None),
                    "has_media": bool(tweet.media),
                    "has_poll": bool(tweet.poll),
                    "mentioned_coins": extract_crypto_symbols(content)
                })
                
            # Respectful delay between requests
            time.sleep(delay)
            
    except Exception as e:
        print(f"⚠️ Error scraping @{handle}: {str(e)[:100]}...")
        
    return tweets

def extract_crypto_symbols(text):
    """Extract crypto tickers like $ETH or #BTC from text"""
    symbols = re.findall(r'(?<!\w)\$[A-Za-z]{2,8}(?!\w)', text)
    hashtags = re.findall(r'#\w+', text)
    return list(set(symbols + hashtags))  # Remove duplicates

def save_results(data, format='all'):
    """Save data in multiple formats with timestamp"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    os.makedirs('data', exist_ok=True)
    
    if format in ('json', 'all'):
        with open(f'data/crypto_kols_{timestamp}.json', 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    
    if format in ('csv', 'all'):
        df = pd.DataFrame(data)
        # Expand the mentioned_coins list into separate columns
        coins_df = pd.json_normalize(df['mentioned_coins'].explode()).notna()
        coins_df.columns = [f'coin_{col}' for col in coins_df.columns]
        df = pd.concat([df.drop('mentioned_coins', axis=1), coins_df], axis=1)
        df.to_csv(f'data/crypto_kols_{timestamp}.csv', index=False)
    
    if format in ('excel', 'all'):
        df = pd.DataFrame(data)
        df.to_excel(f'data/crypto_kols_{timestamp}.xlsx', index=False)

def main():
    all_results = []
    print(f"🚀 Scraping {len(KOL_HANDLES)} crypto KOLs (last {DAYS_TO_SCRAPE} days)")
    
    for handle in tqdm(KOL_HANDLES, desc="Processing KOLs"):
        try:
            tweets = scrape_kol_tweets(handle)
            all_results.extend(tweets)
            print(f"  ✔ @{handle}: {len(tweets)} relevant tweets")
        except Exception as e:
            print(f"  ❌ @{handle} failed: {str(e)[:100]}...")
    
    # Save results
    save_results(all_results)
    
    # Print summary
    print(f"\n✅ Done! Collected {len(all_results)} tweets total")
    print(f"📊 Top mentioned coins:")
    coin_counts = pd.Series([coin for sublist in [t['mentioned_coins'] for t in all_results for coin in sublist]]).value_counts()
    print(coin_counts.head(10))

if __name__ == "__main__":
    main()