import sys
import os
import subprocess
import requests
import csv
from typing import Optional
from pypeid import PEiDScanner, format_as_katc_peid


script_dir: str = os.path.dirname(os.path.abspath(__file__))


def get_katc_peid() -> None:
    try:
        res = requests.get(
            "https://github.com/K-atc/PEiD/releases/download/v0.1.1/PEiD"
        )
        with open(os.path.join(script_dir, "bin/PEiD"), "wb") as fout:
            fout.write(res.content)
    except requests.exceptions.RequestException as err:
        print("Error occurs", file=sys.stderr)
        print(f"{err}", file=sys.stderr)
        sys.exit(1)


def katc_peid_exists() -> bool:
    return os.path.exists(os.path.join(script_dir, "bin/PEiD"))


def is_katc_peid_prepared() -> bool:
    return (
        os.path.exists(os.path.join(os.getcwd(), "rules.zip"))
        and os.path.exists(os.path.join(os.getcwd(), "rules"))
        and os.path.exists(os.path.join(os.getcwd(), "yara"))
    )


def get_katc_peid_output(path: str) -> Optional[str]:
    peid_exe = os.path.join(script_dir, "bin/PEiD")
    output_lines = (
        subprocess.run([peid_exe, path], stdout=subprocess.PIPE, check=True)
        .stdout.decode("utf-8")
        .split("\n")[:-1]
    )

    if any("WARN" in l for l in output_lines):
        print("Error occurs.", file=sys.stderr)
        return None

    return "\n".join(
        l
        for l in output_lines
        if "INFO" not in l and "=>" not in l and "RULES_FILE" not in l
    )


def _main() -> None:
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} input_csv")
        sys.exit(1)

    if not katc_peid_exists():
        get_katc_peid()

    if not is_katc_peid_prepared():
        subprocess.run([os.path.join(script_dir, "bin/PEiD"), "--prepare"], check=True)

    target_csv = sys.argv[1]
    peid_scanner = PEiDScanner()
    with open(target_csv, "r") as fin:
        reader = csv.reader(fin)
        next(reader)
        for path, _, _ in reader:
            expected = get_katc_peid_output(path)
            actual = format_as_katc_peid(peid_scanner.scan_file(path))
            if expected != actual:
                print(f"different from Katc version of PEiD @ {path}")
    print("OK!")


if __name__ == "__main__":
    _main()
