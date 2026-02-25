from .rule_evade_encoding import check as check_01
from .rule_evade_process_hide import check as check_02
from .rule_evade_base64 import check as check_03
from .rule_evade_encrypted import check as check_04
from .rule_evade_suppress_error import check as check_05
from .rule_evade_silent_exit import check as check_06
from .rule_evade_obfuscation import check as check_07
from .rule_evade_ascii_art import check as check_08

EVASION_RULES = [
    check_01,
    check_02,
    check_03,
    check_04,
    check_05,
    check_06,
    check_07,
    check_08
]
