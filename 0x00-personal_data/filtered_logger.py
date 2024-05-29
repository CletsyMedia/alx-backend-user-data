#!/usr/bin/env python3
"""
Module for filtering log data.
"""

import re


def filter_datum(fields, redaction, message, separator):
    """
    Replace occurrences of certain field values in a log message with
    redaction.

    Args:
        fields (list): List of strings representing fields to obfuscate.
        redaction (str): String representing the redaction for the field.
        message (str): String representing the log line.
        separator (str): String representing the character separating all
        fields in the log line.

    Returns:
        str: Log message with specified fields obfuscated.
    """
    for field in fields:
        pattern = re.compile(r'(?<={}=).*?(?={}|$)'.format(field, separator))
        message = re.sub(pattern, redaction, message)
    return message
