
import pandas as pd
from pathlib import Path

df = pd.read_csv("data/phishing_site_urls.csv")

df = df.dropna(subset=["URL", "Label"]).copy()
df["URL"] = df["URL"].astype(str)
df["Label"] = df["Label"].astype(str).str.strip().str.lower()

print("=== LABEL COUNTS ===")
print(df["Label"].value_counts())

print("\n=== EXACT DUPLICATE URL ROWS ===")
print("Duplicate rows:", df.duplicated(subset=["URL"]).sum())

print("\n=== URLS WITH CONFLICTING LABELS ===")
labels_per_url = df.groupby("URL")["Label"].nunique()
print("URLs with multiple labels:", (labels_per_url > 1).sum())

print("\n=== LABEL COUNTS FOR TEST DOMAINS ===")
domains = [
    "example.com",
    "google.com",
    "wikipedia.org",
]

lower_urls = df["URL"].str.lower()

for domain in domains:
    matches = lower_urls.str.contains(
        domain, regex=False, na=False
    )
    subset = df.loc[matches, ["URL", "Label"]]

    print(f"\n{domain}: {len(subset)} matching rows")
    if not subset.empty:
        print(subset["Label"].value_counts())
        print(subset.head(3).to_string(index=False))

print("\n=== URL LENGTH BY LABEL ===")
print(
    df.assign(url_length=df["URL"].str.len())
      .groupby("Label")["url_length"]
      .describe()
      .round(2)
)
