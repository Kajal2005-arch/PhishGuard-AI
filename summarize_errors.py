
import pandas as pd
from urllib.parse import urlparse

ERRORS_PATH = "models/unseen_domain_errors.csv"

df = pd.read_csv(ERRORS_PATH)

def parse_url(url):
    url = str(url).strip()
    try:
        parsed = urlparse(url if "://" in url else "//" + url)
        return parsed.hostname or "", parsed.path or "", parsed.query or ""
    except ValueError:
        return "", "", ""

parts = df["URL"].apply(parse_url)
df["hostname"] = parts.apply(lambda x: x[0].lower())
df["path"] = parts.apply(lambda x: x[1].lower())
df["query"] = parts.apply(lambda x: x[2].lower())

df["url_length"] = df["URL"].astype(str).str.len()
df["path_length"] = df["path"].str.len()
df["query_length"] = df["query"].str.len()

df["has_ip_like_text"] = df["hostname"].str.match(
    r"^\d{1,3}(?:\.\d{1,3}){3}$"
)

df["has_brand_in_path"] = df["path"].str.contains(
    r"google|paypal|microsoft|apple|amazon|facebook|instagram|"
    r"outlook|gmail|irs|bank|login|verify|secure",
    regex=True,
    na=False,
)

print("=== ERROR COUNTS ===")
print(df["error_type"].value_counts())

print("\n=== URL LENGTH BY ERROR TYPE ===")
print(
    df.groupby("error_type")["url_length"]
    .describe()
    .round(2)
)

print("\n=== PATH LENGTH BY ERROR TYPE ===")
print(
    df.groupby("error_type")["path_length"]
    .describe()
    .round(2)
)

print("\n=== COMMON HOSTNAMES IN ERRORS ===")
for error_type, group in df.groupby("error_type"):
    print(f"\n{error_type}:")
    print(group["hostname"].value_counts().head(10).to_string())

print("\n=== BRAND/SECURITY TERMS IN PATH ===")
print(
    pd.crosstab(
        df["error_type"],
        df["has_brand_in_path"],
        normalize="index",
    ).round(3)
)

print("\n=== LONGEST FALSE NEGATIVES ===")
false_negatives = df[df["error_type"] == "false_negative"]
print(
    false_negatives.sort_values("url_length", ascending=False)[
        ["URL", "hostname", "url_length", "path_length", "query_length"]
    ].head(10).to_string(index=False)
)

print("\n=== LONGEST FALSE POSITIVES ===")
false_positives = df[df["error_type"] == "false_positive"]
print(
    false_positives.sort_values("url_length", ascending=False)[
        ["URL", "hostname", "url_length", "path_length", "query_length"]
    ].head(10).to_string(index=False)
)
