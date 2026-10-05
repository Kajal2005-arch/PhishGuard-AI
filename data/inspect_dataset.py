
import pandas as pd
from pathlib import Path

data_path = Path("data/phishing_site_urls.csv")

if not data_path.exists():
    print("CSV not found!")
    print("Expected location:", data_path.resolve())
else:
    df = pd.read_csv(data_path)

    print("Dataset shape:", df.shape)
    print("\nColumn names:")
    print(df.columns.tolist())

    print("\nFirst five rows:")
    print(df.head())

    print("\nMissing values:")
    print(df.isnull().sum())
    
print("\nLabel distribution:")
print(df["Label"].value_counts())

print("\nUnique labels:")
print(df["Label"].unique())

print("\nSample URLs from each label:")
for label in df["Label"].unique():
    print(f"\n{label.upper()} examples:")
    print(df.loc[df["Label"] == label, "URL"].head(3).to_list())

