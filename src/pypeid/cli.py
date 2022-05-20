#
# (c) FFRI Security, Inc., 2020-2022 / Author: FFRI Security, Inc.
#
def main() -> None:
    import sys
    from .scanner import PEiDScanner, format_as_katc_peid

    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} input_file")
        return
    peid_scanner = PEiDScanner()
    scan_result = peid_scanner.scan_file(sys.argv[1])
    print(format_as_katc_peid(scan_result))


if __name__ == "__main__":
    main()
