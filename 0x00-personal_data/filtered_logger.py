#!/usr/bin/env python3
"""
Module for handling Personalize Data
"""
import logging
from typing import List
import re
import mysql.connector
from os import environ


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """
        Initialize RedactingFormatter instance.

        Args:
            fields (list): List of strings representing fields to redact.
        """
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """
        Format the specified record as text.

        Args:
            record (logging.LogRecord): The LogRecord to be formatted.

        Returns:
            str: Formatted log message.
        """
        message = super().format(record)
        for field in self.fields:
            pattern = re.compile(fr'{field}=[^;]*')
            message = re.sub(pattern, f'{field}={self.REDACTION}', message)
        return message


PII_FIELDS = ("name", "email", "phone", "ssn", "password")


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


def get_logger() -> logging.Logger:
    """ Returns a Logger Object """
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(RedactingFormatter(list(PII_FIELDS)))
    logger.addHandler(stream_handler)

    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """ Returns a connector to a MySQL database """
    username = environ.get("PERSONAL_DATA_DB_USERNAME", "root")
    password = environ.get("PERSONAL_DATA_DB_PASSWORD", "")
    host = environ.get("PERSONAL_DATA_DB_HOST", "localhost")
    db_name = environ.get("PERSONAL_DATA_DB_NAME")

    cnx = mysql.connector.connection.MySQLConnection(user=username,
                                                     password=password,
                                                     host=host,
                                                     database=db_name)
    return cnx


def main():
    """ Main function to read and filter data """
    logger = get_logger()
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users;")
    for row in cursor.fetchall():
        filtered_row = filter_datum(
            list(PII_FIELDS),
            RedactingFormatter.REDACTION, ';'.join(map(str, row)), ';')
        logger.info(filtered_row)


if __name__ == "__main__":
    main()
