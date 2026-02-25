from .rule_file_sensitive_read import check as check_01
from .rule_file_write_generic import check as check_02
from .rule_file_write_sensitive import check as check_03
from .rule_file_delete import check as check_04
from .rule_file_startup_modify import check as check_05
from .rule_file_env_hijack import check as check_06

FILE_OPS_RULES = [
    check_01,
    check_02,
    check_03,
    check_04,
    check_05,
    check_06
]
