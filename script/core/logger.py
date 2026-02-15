import logging
import os
import sys
from .console import Colors

class ColoredFormatter(logging.Formatter):
    def format(self, record):
        message = super().format(record)
        if record.levelno == logging.INFO:
            return f"{Colors.GREEN}{message}{Colors.RESET}"
        elif record.levelno == logging.WARNING:
            return f"{Colors.YELLOW}{message}{Colors.RESET}"
        elif record.levelno == logging.ERROR:
            return f"{Colors.RED}{message}{Colors.RESET}"
        elif record.levelno == logging.CRITICAL:
            return f"{Colors.RED}{Colors.BOLD}{message}{Colors.RESET}"
        elif record.levelno == logging.DEBUG:
            return f"{Colors.BLUE}{message}{Colors.RESET}"
        return message

class Logger:
    def __init__(self, log_path, console_output=True):
        self.log_path = log_path
        # Use a safe name for the logger to avoid potential issues with paths as names
        logger_name = f"logger_{hash(log_path)}"
        self.logger = logging.getLogger(logger_name)
        self.logger.setLevel(logging.DEBUG)
        
        # Clear existing handlers to avoid duplicates if logger is reused
        if self.logger.handlers:
            self.logger.handlers = []
        
        # File handler
        try:
            fh = logging.FileHandler(log_path, mode='w', encoding='utf-8')
            fh.setLevel(logging.DEBUG)
            file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            fh.setFormatter(file_formatter)
            self.logger.addHandler(fh)
            # print(f"DEBUG: Logging to file {log_path}")
        except Exception as e:
            print(f"ERROR: Failed to create log file handler for {log_path}: {e}")
        
        if console_output:
            # Console handler
            ch = logging.StreamHandler(sys.stdout)
            ch.setLevel(logging.INFO)
            console_formatter = ColoredFormatter('%(asctime)s - %(levelname)s - %(message)s')
            ch.setFormatter(console_formatter)
            self.logger.addHandler(ch)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        for handler in self.logger.handlers:
            handler.flush()
            handler.close()
            self.logger.removeHandler(handler)

    def info(self, msg):
        self.logger.info(msg)
        # Flush handlers to ensure immediate write
        for h in self.logger.handlers:
            h.flush()

    def error(self, msg):
        self.logger.error(msg)
    
    def debug(self, msg):
        self.logger.debug(msg)
