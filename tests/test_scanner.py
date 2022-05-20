#
# (c) FFRI Security, Inc., 2020-2022 / Author: FFRI Security, Inc.
#
import os
import pytest
from pypeid import PEiDScanner, format_as_katc_peid


@pytest.fixture
def scanner() -> PEiDScanner:
    peid_scanner = PEiDScanner()
    return peid_scanner


@pytest.mark.parametrize(
    "test_bin", ["TestExe_x64.exe", "TestExe_x86.exe", "TestDotNet.dll"]
)
def test_pypeid(scanner: PEiDScanner, test_bin: str) -> None:
    script_dir: str = os.path.dirname(os.path.abspath(__file__))
    test_bin_dir: str = os.path.join(script_dir, "bin")
    expected_file_dir: str = os.path.join(script_dir, "expected")
    expected_file: str = f"{test_bin}.txt"

    test_bin = os.path.join(test_bin_dir, test_bin)
    expected_file = os.path.join(expected_file_dir, expected_file)
    with open(expected_file, "r") as fin:
        assert format_as_katc_peid(scanner.scan_file(test_bin)) == fin.read()
