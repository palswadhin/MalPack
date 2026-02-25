from .rule_meta_typosquatting import check as check_01
from .rule_meta_combosquatting import check as check_02
from .rule_meta_author import check as check_03
from .rule_meta_description_empty import check as check_04
from .rule_meta_description_mismatch import check as check_05
from .rule_meta_dependency import check as check_06

METADATA_RULES = [
    check_01,
    check_02,
    check_03,
    check_04,
    check_05,
    check_06
]
