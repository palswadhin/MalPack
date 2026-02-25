from .rule_inst_01_exec_during_setup import check as check_01
from .rule_inst_03_exec_during_import import check as check_03
from .rule_inst_04_dynamic_pip_install import check as check_04
from .rule_inst_05_dynamic_import import check as check_05

INSTALLATION_RULES = [
    check_01,
    check_03,
    check_04,
    check_05
]
