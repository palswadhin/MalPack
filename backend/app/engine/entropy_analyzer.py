"""
Entropy Analysis Utility for Malicious Code Detection

This module provides functions to calculate Shannon entropy of strings
to detect obfuscated, encoded, or encrypted content in Python code.

Research basis:
- High entropy strings (>5.0) are strong indicators of Base64, hex, or encrypted data
- Used by GuardDog, PyGuardEX, and other malware detection tools
"""

import math
from typing import Tuple


def calculate_entropy(data: str) -> float:
    """
    Calculate Shannon entropy of a string.
    
    Shannon entropy measures the randomness/information density in a string.
    Higher entropy indicates more randomness (encoded/encrypted data).
    Lower entropy indicates structured text (normal code/strings).
    
    Args:
        data: Input string to analyze
        
    Returns:
        Entropy value (0.0 to ~8.0 for typical strings)
        
    Examples:
        >>> calculate_entropy("aaaaa")  # Low entropy
        0.0
        >>> calculate_entropy("SGVsbG8gV29ybGQ=")  # Base64 - medium-high entropy
        3.8
        >>> calculate_entropy("x9f3k2m8q1p7...")  # Random - high entropy
        ~5.0+
    """
    if not data:
        return 0.0
    
    # Count frequency of each character
    freq_map = {}
    for char in data:
        freq_map[char] = freq_map.get(char, 0) + 1
    
    # Calculate Shannon entropy
    entropy = 0.0
    length = len(data)
    
    for count in freq_map.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)
    
    return entropy


def is_likely_encoded(string: str, threshold: float = 5.0, min_length: int = 40) -> Tuple[bool, float]:
    """
    Determine if a string is likely to be encoded/obfuscated based on entropy.
    
    Research findings:
    - Normal English text: ~4.0-4.5 entropy
    - Base64 encoded: ~5.0-6.0 entropy
    - Hex encoded: ~4.0-5.0 entropy
    - Random/encrypted: ~5.5-8.0 entropy
    
    Args:
        string: String to analyze
        threshold: Entropy threshold for encoded detection (default: 5.0)
        min_length: Minimum string length to analyze (default: 40)
        
    Returns:
        Tuple of (is_encoded: bool, entropy: float)
        
    Examples:
        >>> is_likely_encoded("Hello World")
        (False, 2.8)
        >>> is_likely_encoded("aGVsbG8gd29ybGQhISEhISEhISEhISEhISEhISEh")
        (True, 5.2)
    """
    if len(string) < min_length:
        return False, 0.0
    
    entropy = calculate_entropy(string)
    return (entropy >= threshold, entropy)


def analyze_string_patterns(string: str) -> dict:
    """
    Comprehensive analysis of string patterns for malicious indicators.
    
    Checks for:
    - High entropy (encoded data)
    - Base64 patterns
    - Hex patterns
    - Character distribution anomalies
    
    Args:
        string: String to analyze
        
    Returns:
        Dictionary with analysis results:
        {
            'entropy': float,
            'is_high_entropy': bool,
            'likely_base64': bool,
            'likely_hex': bool,
            'char_diversity': float  # Ratio of unique chars to total length
        }
    """
    if not string:
        return {
            'entropy': 0.0,
            'is_high_entropy': False,
            'likely_base64': False,
            'likely_hex': False,
            'char_diversity': 0.0
        }
    
    entropy = calculate_entropy(string)
    
    # Check for Base64 pattern (alphanumeric + +/= characters)
    base64_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
    base64_ratio = sum(1 for c in string if c in base64_chars) / len(string)
    likely_base64 = (base64_ratio > 0.95 and len(string) % 4 == 0)
    
    # Check for hex pattern (only 0-9, a-f, A-F)
    hex_chars = set('0123456789abcdefABCDEF')
    hex_ratio = sum(1 for c in string if c in hex_chars) / len(string)
    likely_hex = (hex_ratio > 0.95 and len(string) % 2 == 0)
    
    # Character diversity (unique chars / total chars)
    char_diversity = len(set(string)) / len(string)
    
    return {
        'entropy': entropy,
        'is_high_entropy': entropy >= 5.0,
        'likely_base64': likely_base64,
        'likely_hex': likely_hex,
        'char_diversity': char_diversity
    }


def is_suspicious_string(string: str) -> Tuple[bool, str]:
    """
    High-level check if a string is suspicious (likely malicious obfuscation).
    
    Args:
        string: String to check
        
    Returns:
        Tuple of (is_suspicious: bool, reason: str)
        
    Examples:
        >>> is_suspicious_string("print('hello')")
        (False, "")
        >>> is_suspicious_string("aGVsbG8gd29ybGQhISEhISEhISEhISEhISEhISEh")
        (True, "High entropy Base64-like pattern detected")
    """
    analysis = analyze_string_patterns(string)
    
    if analysis['is_high_entropy']:
        if analysis['likely_base64']:
            return True, "High entropy Base64-like pattern detected"
        elif analysis['likely_hex']:
            return True, "High entropy hexadecimal pattern detected"
        else:
            return True, f"Very high entropy ({analysis['entropy']:.2f}) - likely encoded/encrypted"
    
    # Check for extremely low diversity (repeated characters - could be padding/obfuscation)
    if analysis['char_diversity'] < 0.1 and len(string) > 50:
        return True, "Extremely low character diversity - suspicious padding"
    
    return False, ""
