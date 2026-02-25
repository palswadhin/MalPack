from .rule_recon_system_fingerprint import check as check_01
from .rule_recon_directory_enum import check as check_02
from .rule_recon_sensitive_read import check as check_03

RECON_RULES = [
    check_01,
    check_02,
    check_03
]
