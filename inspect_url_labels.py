
import pandas as pd
from urllib.parse import urlparse

df = pd.read_csv("data/phishing_site_urls.csv")

df = df.dropna(subset=["URL", "Label"]).copy()
df["URL"] = df["URL"].astype(str).str.strip()
df["Label"] = df["Label"].astype(str).str.strip().str.lower()
df = df[df["URL"] != ""]

# 1. Find URLs that have conflicting labels
print("=== URLS WITH CONFLICTING LABELS ===")

label_counts = df.groupby("URL")["Label"].nunique()
conflicting_urls = label_counts[label_counts > 1].index

if len(conflicting_urls) == 0:
    print("No conflicting URLs found.")
else:
    for url in conflicting_urls:
        print("\nURL:", url)
        print(
            df.loc[df["URL"] == url, ["URL", "Label"]]
            .to_string(index=False)
        )

# 2. Extract actual hostnames
def get_hostname(url):
    try:
        parsed = urlparse(
            url if "://" in url else "//" + url
        )
        return (parsed.hostname or "").lower().rstrip(".")
    except ValueError:
        return ""

df["hostname"] = df["URL"].apply(get_hostname)

# 3. Check Google hostnames, not just text mentions
print("\n=== GOOGLE HOSTNAME ANALYSIS ===")

google_rows = df[
    df["hostname"].apply(
        lambda host: host == "google.com"
        or host.endswith(".google.com")
    )
]

print("Rows with google.com as actual hostname:", len(google_rows))
print(google_rows["Label"].value_counts())

print("\nExamples labeled bad:")
print(
    google_rows.loc[google_rows["Label"] == "bad", ["URL", "Label"]]
    .head(10)
    .to_string(index=False)
)

# 4. Check repeated URLs and label consistency
print("\n=== DUPLICATE LABEL CONSISTENCY ===")

duplicate_counts = df.groupby("URL").agg(
    row_count=("Label", "size"),
    unique_labels=("Label", "nunique")
)

repeated_urls = duplicate_counts[
    duplicate_counts["row_count"] > 1
]

print("URLs appearing more than once:", len(repeated_urls))
print(
    "Repeated URLs with consistent labels:",
    int((repeated_urls["unique_labels"] == 1).sum())
)
print(
    "Repeated URLs with conflicting labels:",
    int((repeated_urls["unique_labels"] > 1).sum())
)
