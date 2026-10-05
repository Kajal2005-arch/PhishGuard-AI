
import json
import os
from pathlib import Path


DEFAULT_REGISTRY_PATH = Path("data") / "threat_registry.json"


def load_registry(path=DEFAULT_REGISTRY_PATH):
    """Load stored signed threat records from a JSON file."""
    path = Path(path)

    if not path.exists():
        return []

    try:
        with path.open("r", encoding="utf-8") as file:
            records = json.load(file)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(
            f"Registry file is invalid JSON: {path}"
        ) from exc

    if not isinstance(records, list):
        raise ValueError("Registry must contain a JSON list.")

    return records


def save_registry(records, path=DEFAULT_REGISTRY_PATH):
    """Save signed threat records using an atomic file replacement."""
    if not isinstance(records, list):
        raise TypeError("Records must be provided as a list.")

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    temp_path = path.with_name(path.name + ".tmp")

    try:
        with temp_path.open("w", encoding="utf-8", newline="\n") as file:
            json.dump(
                records,
                file,
                indent=2,
                ensure_ascii=False,
                allow_nan=False,
            )
            file.write("\n")
            file.flush()
            os.fsync(file.fileno())

        os.replace(temp_path, path)
    finally:
        if temp_path.exists():
            temp_path.unlink()
