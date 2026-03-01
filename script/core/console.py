import sys
import os

# ANSI escape codes
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

def supports_color():
    """
    Returns True if the running system's terminal supports color, and False
    otherwise.
    """
    plat = sys.platform
    supported_platform = plat != 'Pocket PC' and (plat != 'win32' or 'ANSICON' in os.environ)
    # isatty is not always present, #62
    is_a_tty = hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()
    return supported_platform or is_a_tty

# Global flag to enable/disable color
USE_COLOR = True
LOGGER = None

def set_color(enabled: bool):
    global USE_COLOR
    USE_COLOR = enabled

def set_logger(logger):
    global LOGGER
    LOGGER = logger

def log_to_file(msg, level='info'):
    if LOGGER:
        # Strip ANSI codes for file logging
        clean_msg = msg
        for color in [Colors.RESET, Colors.BOLD, Colors.RED, Colors.GREEN, Colors.YELLOW, Colors.BLUE, Colors.MAGENTA, Colors.CYAN, Colors.WHITE]:
            clean_msg = clean_msg.replace(color, "")
        
        if level == 'info':
            LOGGER.info(clean_msg)
        elif level == 'error':
            LOGGER.error(clean_msg)
        elif level == 'debug':
            LOGGER.debug(clean_msg)

def colorize(text, color_code):
    if not USE_COLOR:
        return text
    return f"{color_code}{text}{Colors.RESET}"

def print_pass(msg):
    log_to_file(f"[PASS] {msg}")
    print(colorize(f"[PASS] {msg}", Colors.GREEN), flush=True)

def print_fail(msg, input_val=None, expected=None, got=None):
    log_to_file(f"[FAIL] {msg}", level='error')
    print(colorize(f"[FAIL] {msg}", Colors.RED), flush=True)
    if input_val is not None:
        log_to_file(f"       Input:    {input_val}", level='error')
        print(colorize(f"       Input:    {input_val}", Colors.YELLOW), flush=True)
    if expected is not None:
        log_to_file(f"       Expected: {expected}", level='error')
        print(colorize(f"       Expected: {expected}", Colors.CYAN), flush=True)
    if got is not None:
        log_to_file(f"       Got:      {got}", level='error')
        print(colorize(f"       Got:      {got}", Colors.RED), flush=True)

def print_info(msg):
    log_to_file(f"[INFO] {msg}")
    print(colorize(f"[INFO] {msg}", Colors.BLUE), flush=True)

def print_warn(msg):
    log_to_file(f"[WARN] {msg}")
    print(colorize(f"[WARN] {msg}", Colors.YELLOW), flush=True)

def print_header(msg):
    log_to_file(f"=== {msg} ===")
    print(colorize(f"\n=== {msg} ===", Colors.MAGENTA + Colors.BOLD), flush=True)

def print_step(msg):
    log_to_file(f"-> {msg}")
    print(colorize(f"-> {msg}", Colors.CYAN), flush=True)

def log_data(key, value=None):
    """Log structured data.  Can be called as:
      log_data(label, value)  -> prints '[INFO] label: value'
      log_data(message)       -> prints '[INFO] message'  (PoW / legacy callers)
    """
    if value is None:
        msg = str(key)
    else:
        msg = f"{key}: {value}"
    log_to_file(f"[INFO] {msg}")
    print(colorize(f"[INFO] {msg}", Colors.BLUE), flush=True)
