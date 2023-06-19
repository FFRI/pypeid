#
# (c) FFRI Security, Inc., 2020-2023 / Author: FFRI Security, Inc.
#
import yara
import logging
import traceback
import os
from typing import List, Dict, Union, Optional


ScanResultType = Dict[str, Union[str, List[str]]]


class PEiDScanner:
    def __init__(self, logger: Optional[logging.Logger] = None) -> None:
        script_dir: str = PEiDScanner.get_script_dir()
        self._yara_rules: List[yara.Rules] = [
            yara.compile(filepath=os.path.join(script_dir, "rules/Packers/peid.yar")),
            yara.compile(filepath=os.path.join(script_dir, "rules/Packers/packer.yar")),
            yara.compile(
                filepath=os.path.join(
                    script_dir, "rules/Packers/packer_compiler_signatures.yar"
                )
            ),
            yara.compile(
                filepath=os.path.join(
                    script_dir, "rules/Antidebug_AntiVM/antidebug_antivm.yar"
                )
            ),
            yara.compile(filepath=os.path.join(script_dir, "rules/Crypto/base64.yar")),
        ]
        self._logger = logger

    def match_one_rule(self, filepath: str, yara_rule: yara.Rules) -> List[yara.Match]:
        matched_rules: List[yara.Match] = list()
        try:
            matched_rules = yara_rule.match(filepath=filepath)
        except yara.Error as err:
            err_msg: str = f"yara scan failed. {traceback.format_exc()}"
            if self._logger:
                self._logger.warning(err_msg)
            else:
                print(err_msg)
        except:
            err_msg: str = f"unknown exception is thrown {traceback.format_exc()}"
            if self._logger:
                self._logger.error(err_msg)
            else:
                print(err_msg)
        return matched_rules

    def scan_file(self, filepath: str) -> ScanResultType:
        matched_rules: List[yara.Match] = list()
        for yara_rule in self._yara_rules:
            matched_rules += self.match_one_rule(filepath, yara_rule)
        return PEiDScanner.format_result(matched_rules)

    @staticmethod
    def get_script_dir() -> str:
        return os.path.dirname(os.path.abspath(__file__))

    @staticmethod
    def format_result(raw_matched_rules: List[yara.Match]) -> ScanResultType:
        matched_rule_names: List[str] = [str(rule) for rule in raw_matched_rules]

        result: ScanResultType = dict()

        result["PE"] = PEiDScanner.check_pe_rule(matched_rule_names)
        if result["PE"] == "32 bit" or result["PE"] == "64 bit":
            result["DLL"] = "yes" if "IsDLL" in matched_rule_names else "no"
            result["Packed"] = "yes" if "IsPacked" in matched_rule_names else "no"
            is_packed = result["Packed"] == "yes"

            result["Anti-Debug"] = (
                "yes"
                if "anti_dbg" in matched_rule_names
                else "no (yes)"
                if is_packed
                else "no"
            )
            result["GUI Program"] = (
                "yes"
                if "IsWindowsGUI" in matched_rule_names
                else "no (yes)"
                if is_packed
                else "no"
            )
            result["Console Program"] = (
                "yes"
                if "IsConsole" in matched_rule_names
                else "no (yes)"
                if is_packed
                else "no"
            )
            result["mutex"] = "yes" if "win_mutex" in matched_rule_names else "no"

        result["contains base64"] = (
            "yes" if "contentis_base64" in matched_rule_names else "no"
        )
        result["PEiD"] = [
            str(rule) for rule in raw_matched_rules if "PEiD" in rule.tags
        ]
        result["AntiDebug"] = [
            str(rule) for rule in raw_matched_rules if "AntiDebug" in rule.tags
        ]

        return result

    @staticmethod
    def check_pe_rule(matched_rule_names: List[str]) -> str:
        if "IsPE32" in matched_rule_names:
            return "32 bit"
        elif "IsPE64" in matched_rule_names:
            return "64 bit"
        else:
            return "no"


# NOTE: show the same output as https://github.com/K-atc/PEiD
def format_as_katc_peid(scan_result: ScanResultType) -> str:
    result = ""
    if scan_result["PE"] == "32 bit" or scan_result["PE"] == "64 bit":
        result += "  PE : " + scan_result["PE"] + "\n"
        result += "  DLL : " + scan_result["DLL"] + "\n"
        result += "  Packed : " + scan_result["Packed"] + "\n"
        result += "  Anti-Debug : " + scan_result["Anti-Debug"] + "\n"
        result += "  GUI Program : " + scan_result["GUI Program"] + "\n"
        result += "  Console Program : " + scan_result["Console Program"] + "\n"
        if scan_result["mutex"] == "yes":
            result += "  mutex : " + scan_result["mutex"] + "\n"
    if scan_result["contains base64"] == "yes":
        result += "  contains base64\n"
    if scan_result["PEiD"]:
        result += "  PEiD : [{0}]\n".format(
            " ".join('"{0}"'.format(i) for i in scan_result["PEiD"])
        )
    if scan_result["AntiDebug"]:
        result += "  AntiDebug : [{0}]\n".format(
            " ".join('"{0}"'.format(i) for i in scan_result["AntiDebug"])
        )
    return result
