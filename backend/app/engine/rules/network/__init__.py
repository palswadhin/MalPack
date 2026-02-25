from .rule_net_download_file import check as check_01
from .rule_net_reverse_shell_socket import check as check_02
from .rule_net_download_payload import check as check_03
from .rule_net_download_executable import check as check_04
from .rule_net_download_archive import check as check_05
from .rule_net_reverse_shell_subprocess import check as check_06
from .rule_net_suspicious_domain import check as check_07
from .rule_net_ssl_disabled import check as check_08
from .rule_net_http_unencrypted import check as check_09
from .rule_net_dns_tunneling import check as check_10

NETWORK_RULES = [
    check_01,
    check_02,
    check_03,
    check_04,
    check_05,
    check_06,
    check_07,
    check_08,
    check_09,
    check_10
]
