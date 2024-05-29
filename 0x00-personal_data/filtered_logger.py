#!/usr/bin/env python3
"""
Module for handling Personal Data
"""
from typing import List
import re


def filter_datum(
        fields: List[str],
        redaction: str,
        message: str,
        separator: str) -> str:
    """
    Returns a log message with specified fields obfuscated.

    Args:
        fields (List[str]): List of strings representing fields to obfuscate.
        redaction (str): String representing the redaction for the field.
        message (str): String representing the log line.
        separator (str): String representing the character separating all
        fields in the log line.

    Returns:
        str: Log message with specified fields obfuscated.
    """
    for field in fields:
        pattern = re.compile(fr'{field}=[^{separator}]*')
        message = re.sub(pattern, f'{field}={redaction}', message)
    return message
