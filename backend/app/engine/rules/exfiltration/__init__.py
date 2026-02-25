from .rule_exfil_data_send import check as check_02
from .rule_exfil_file_upload import check as check_03
from .rule_exfil_env_vars import check as check_04
from .rule_exfil_webhook import check as check_05
from .rule_exfil_pastebin import check as check_06

EXFILTRATION_RULES = [
    check_02,
    check_03,
    check_04,
    check_05,
    check_06
]
