"""
Metadata Analysis for Supply Chain Attack Detection

This module provides functions to detect typosquatting, combosquatting,
and other metadata-based malicious indicators in package names and metadata.

Research basis:
- Levenshtein distance detection (used by npm, PyPI)
- Combosquatting patterns (academic research: Vu et al.)
- Author validation (disposable email detection)
"""

import re
from typing import List, Dict, Tuple, Optional


def levenshtein_distance(s1: str, s2: str) -> int:
    """
    Calculate Levenshtein (edit) distance between two strings.
    
    The Levenshtein distance is the minimum number of single-character edits
    (insertions, deletions, or substitutions) required to change one string into another.
    
    Used for typosquatting detection: small distance indicates similar package names.
    
    Args:
        s1: First string
        s2: Second string
        
    Returns:
        Edit distance (integer)
        
    Examples:
        >>> levenshtein_distance("requests", "requets")
        2
        >>> levenshtein_distance("numpy", "nunpy")
        1
    """
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    
    if len(s2) == 0:
        return len(s1)
    
    # Initialize distance matrix
    previous_row = range(len(s2) + 1)
    
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            # Cost of insertions, deletions, or substitutions
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    
    return previous_row[-1]


def check_typosquatting(package_name: str, popular_packages: List[str], threshold: int = 2) -> Dict[str, any]:
    """
    Check if a package name is a typosquatting attempt.
    
    Typosquatting: Creating packages with names similar to popular ones
    to trick users into installing malware.
    
    Detection methods:
    1. Levenshtein distance < threshold
    2. Character substitutions (e.g., 'l' -> 'i', '0' -> 'O')
    3. Added/removed hyphens, underscores
    
    Args:
        package_name: Package name to check
        popular_packages: List of known popular package names
        threshold: Maximum edit distance to consider typosquatting (default: 2)
        
    Returns:
        Dictionary with results:
        {
            'is_typosquatting': bool,
            'similar_to': list of similar package names,
            'min_distance': int,
            'severity': 'CRITICAL' | 'WARNING' | 'INFO'
        }
    """
    similar_packages = []
    min_distance = float('inf')
    
    package_lower = package_name.lower()
    
    for popular in popular_packages:
        popular_lower = popular.lower()
        
        # Skip if exact match
        if package_lower == popular_lower:
            continue
        
        distance = levenshtein_distance(package_lower, popular_lower)
        
        if distance <= threshold:
            similar_packages.append({
                'name': popular,
                'distance': distance
            })
            min_distance = min(min_distance, distance)
    
    # Check for homoglyphs (visually similar characters)
    homoglyphs_detected = check_homoglyphs(package_name, popular_packages)
    
    is_typosquatting = len(similar_packages) > 0 or homoglyphs_detected['detected']
    
    # Determine severity
    severity = 'INFO'
    if min_distance == 1 or homoglyphs_detected['detected']:
        severity = 'CRITICAL'  # Very likely malicious
    elif min_distance == 2:
        severity = 'WARNING'
    
    return {
        'is_typosquatting': is_typosquatting,
        'similar_to': similar_packages,
        'min_distance': int(min_distance) if min_distance != float('inf') else None,
        'homoglyphs': homoglyphs_detected,
        'severity': severity
    }


def check_homoglyphs(package_name: str, popular_packages: List[str]) -> Dict[str, any]:
    """
    Check for homoglyph attacks (using visually similar Unicode characters).
    
    Examples:
    - Cyrillic 'а' (U+0430) vs Latin 'a' (U+0061)
    - Greek 'ο' (U+03BF) vs Latin 'o' (U+006F)
    
    Args:
        package_name: Package name to check
        popular_packages: List of popular package names
        
    Returns:
        Dictionary with detection results
    """
    # Common homoglyph mappings
    homoglyph_map = {
        'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',  # Cyrillic
        'ο': 'o', 'ν': 'v', 'α': 'a',  # Greek
        '０': '0', '１': '1', 'Ｏ': 'O', 'Ｉ': 'I'  # Fullwidth
    }
    
    # Normalize by replacing homoglyphs
    normalized = package_name
    homoglyphs_found = []
    
    for char in package_name:
        if char in homoglyph_map:
            homoglyphs_found.append(char)
            normalized = normalized.replace(char, homoglyph_map[char])
    
    # Check if normalized version matches a popular package
    matches = []
    for popular in popular_packages:
        if normalized.lower() == popular.lower():
            matches.append(popular)
    
    return {
        'detected': len(homoglyphs_found) > 0,
        'characters': homoglyphs_found,
        'matches': matches
    }


def check_combosquatting(package_name: str, popular_packages: List[str]) -> Dict[str, any]:
    """
    Check for combosquatting (legitimate name + suffix/prefix).
    
    Examples:
    - "requests-secure", "requests-helper"
    - "numpy-extended", "pandas-utils"
    
    Args:
        package_name: Package name to check
        popular_packages: List of popular package names
        
    Returns:
        Dictionary with detection results:
        {
            'is_combosquatting': bool,
            'base_package': str (if detected),
            'pattern': 'prefix' | 'suffix' | 'both'
        }
    """
    package_lower = package_name.lower()
    
    # Common combosquatting patterns
    common_additions = [
        '-', '_', 'v2', '2', 'py', 'python', 
        'helper', 'utils', 'tool', 'tools', 'lib', 'library',
        'secure', 'safe', 'plus', 'extended', 'pro'
    ]
    
    for popular in popular_packages:
        popular_lower = popular.lower()
        
        # Check if package name contains popular name
        if popular_lower in package_lower and package_lower != popular_lower:
            # Check if it's a simple addition (not a legitimate related package)
            # This is combosquatting if:
            # 1. Popular name is at start or end
            # 2. Addition is a common combosquatting pattern
            
            if package_lower.startswith(popular_lower):
                suffix = package_lower[len(popular_lower):]
                if any(suffix.startswith(add) or suffix == add for add in common_additions):
                    return {
                        'is_combosquatting': True,
                        'base_package': popular,
                        'pattern': 'suffix',
                        'addition': suffix
                    }
            
            if package_lower.endswith(popular_lower):
                prefix = package_lower[:-len(popular_lower)]
                if any(prefix.endswith(add) or prefix == add for add in common_additions):
                    return {
                        'is_combosquatting': True,
                        'base_package': popular,
                        'pattern': 'prefix',
                        'addition': prefix
                    }
    
    return {
        'is_combosquatting': False,
        'base_package': None,
        'pattern': None
    }


def validate_author_info(author: str, email: str) -> Dict[str, any]:
    """
    Validate package author information for suspicious patterns.
    
    Checks for:
    1. Generic/test names
    2. Invalid email format
    3. Disposable email providers
    4. Missing information
    
    Args:
        author: Author name
        email: Author email
        
    Returns:
        Dictionary with validation results:
        {
            'is_suspicious': bool,
            'issues': list of issue descriptions,
            'severity': 'CRITICAL' | 'WARNING' | 'INFO'
        }
    """
    issues = []
    
    # Check for generic names
    generic_names = [
        'admin', 'test', 'user', 'developer', 'dev', 'root',
        'author', 'owner', 'maintainer', 'example', 'demo'
    ]
    
    if author:
        author_lower = author.lower().strip()
        if author_lower in generic_names:
            issues.append(f"Generic author name: '{author}'")
        elif len(author) < 2:
            issues.append("Very short author name")
    else:
        issues.append("Missing author name")
    
    # Validate email format
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
    if email:
        if not re.match(email_regex, email):
            issues.append(f"Invalid email format: '{email}'")
        else:
            # Check for disposable email providers
            disposable_domains = [
                'tempmail.com', 'guerrillamail.com', '10minutemail.com',
                'mailinator.com', 'throwaway.email', 'temp-mail.org',
                'sharklasers.com', 'guerrillamail.info'
            ]
            
            email_domain = email.split('@')[-1].lower()
            if email_domain in disposable_domains:
                issues.append(f"Disposable email provider: {email_domain}")
    else:
        issues.append("Missing author email")
    
    # Determine severity
    severity = 'INFO'
    if len(issues) >= 3:
        severity = 'CRITICAL'
    elif len(issues) >= 2:
        severity = 'WARNING'
    
    return {
        'is_suspicious': len(issues) > 0,
        'issues': issues,
        'severity': severity
    }


def validate_description(description: str, package_name: str) -> Dict[str, any]:
    """
    Validate package description for anomalies.
    
    Args:
        description: Package description
        package_name: Package name
        
    Returns:
        Dictionary with validation results
    """
    issues = []
    
    if not description or len(description.strip()) == 0:
        issues.append("Empty description")
        severity = 'WARNING'
    elif len(description.strip()) < 10:
        issues.append(f"Very short description ({len(description)} chars)")
        severity = 'WARNING'
    elif description.strip().lower() == package_name.lower():
        issues.append("Description identical to package name")
        severity = 'WARNING'
    else:
        severity = 'INFO'
    
    return {
        'is_suspicious': len(issues) > 0,
        'issues': issues,
        'severity': severity
    }


# Top 100 PyPI packages (for typosquatting detection)
# Source: https://hugovk.github.io/top-pypi-packages/
TOP_PACKAGES = [
    'requests', 'urllib3', 'boto3', 'botocore', 'setuptools', 'certifi', 'python-dateutil',
    'six', 'pip', 's3transfer', 'pyyaml', 'charset-normalizer', 'numpy', 'idna', 'wheel',
    'cryptography', 'pyasn1', 'rsa', 'awscli', 'typing-extensions', 'jmespath', 'colorama',
    'cffi', 'click', 'packaging', 'pycparser', 'attrs', 'pytz', 'pandas', 'jinja2',
    'markupsafe', 'importlib-metadata', 'protobuf', 'zipp', 'oauthlib', 'pillow', 'pyjwt',
    'jsonschema', 'filelock', 'platformdirs', 'werkzeug', 'scipy', 'soupsieve', 'beautifulsoup4',
    'wrapt', 'pyparsing', 'google-api-core', 'pyarrow', 'sqlalchemy', 'tomli', 'pluggy',
    'pytest', 'grpcio', 'pygments', 'tqdm', 'importlib-resources', 'Flask', 'mypy-extensions',
    'itsdangerous', 'exceptiongroup', 'iniconfig', 'docutils', 'fsspec', 'markdown',
    'pyasn1-modules', 'greenlet', 'trio', 'wcwidth', 'django', 'decorator', 'contourpy',
    'toml', 'aiohttp', 'google-auth', 'async-timeout', 'pydantic', 'google-cloud-storage',
    'redis', 'aiobotocore', 'tabulate', 'psutil', 'ruamel-yaml', 'yarl', 'frozenlist',
    'multidict', 'h11', 'tornado', 'anyio', 'pyOpenSSL', 'cachetools', 'smmap', 'gitdb',
    'gitpython', 'entrypoints', 'httpx', 'lxml', 'coverage', 'prometheus-client', 'google-api-python-client'
]
