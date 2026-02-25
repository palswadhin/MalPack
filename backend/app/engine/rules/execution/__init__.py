from .rule_exec_setup_cmdclass import check as check_01
from .rule_exec_import_hooks import check as check_02
from .rule_exec_subprocess import check as check_03
from .rule_exec_eval_dynamic import check as check_04
from .rule_exec_shell_command import check as check_05
from .rule_exec_binary_file import check as check_06
from .rule_exec_script_file import check as check_07
from .rule_exec_hidden_code import check as check_08

EXECUTION_RULES = [
    check_01,
    check_02,
    check_03,
    check_04,
    check_05,
    check_06,
    check_07,
    check_08
]
