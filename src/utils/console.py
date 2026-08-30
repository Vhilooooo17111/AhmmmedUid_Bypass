"""
Professional Console Logger with ANSI Color Support
Provides clean, technical console output for mitmproxy interceptor
Responsive to terminal width
"""

from datetime import datetime
import shutil


class Console:
    """Professional console logger with ANSI color support"""
    
    # ANSI Color Codes
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    
    # Colors
    CYAN = "\033[36m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    RED = "\033[31m"
    MAGENTA = "\033[35m"
    BLUE = "\033[34m"
    WHITE = "\033[37m"
    GRAY = "\033[90m"
    
    # Background
    BG_GREEN = "\033[42m"
    BG_RED = "\033[41m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"
    
    @staticmethod
    def get_width():
        """Get terminal width dynamically, with fallback"""
        try:
            width = shutil.get_terminal_size().columns
            # Ensure minimum width and leave some margin
            return max(40, width - 4)
        except:
            return 70
    
    @staticmethod
    def timestamp():
        return datetime.now().strftime("%H:%M:%S")
    
    @staticmethod
    def info(msg, **kwargs):
        ts = Console.timestamp()
        prefix = f"{Console.GRAY}[{ts}]{Console.RESET} {Console.GREEN}[INFO]{Console.RESET}"
        print(f"{prefix} {Console.WHITE}{msg}{Console.RESET}")
        for key, value in kwargs.items():
            print(f"         {Console.CYAN}├─ {key}:{Console.RESET} {Console.WHITE}{value}{Console.RESET}")
    
    @staticmethod
    def success(msg, **kwargs):
        ts = Console.timestamp()
        prefix = f"{Console.GRAY}[{ts}]{Console.RESET} {Console.GREEN}{Console.BOLD}[SUCCESS]{Console.RESET}"
        print(f"{prefix} {Console.GREEN}{msg}{Console.RESET}")
        for key, value in kwargs.items():
            print(f"         {Console.CYAN}├─ {key}:{Console.RESET} {Console.GREEN}{value}{Console.RESET}")
    
    @staticmethod
    def warn(msg, **kwargs):
        ts = Console.timestamp()
        prefix = f"{Console.GRAY}[{ts}]{Console.RESET} {Console.YELLOW}[WARN]{Console.RESET}"
        print(f"{prefix} {Console.YELLOW}{msg}{Console.RESET}")
        for key, value in kwargs.items():
            print(f"         {Console.CYAN}├─ {key}:{Console.RESET} {Console.YELLOW}{value}{Console.RESET}")
    
    @staticmethod
    def error(msg, **kwargs):
        ts = Console.timestamp()
        prefix = f"{Console.GRAY}[{ts}]{Console.RESET} {Console.RED}[ERROR]{Console.RESET}"
        print(f"{prefix} {Console.RED}{msg}{Console.RESET}")
        for key, value in kwargs.items():
            print(f"         {Console.CYAN}├─ {key}:{Console.RESET} {Console.RED}{value}{Console.RESET}")
    
    @staticmethod
    def debug(msg, **kwargs):
        ts = Console.timestamp()
        prefix = f"{Console.GRAY}[{ts}]{Console.RESET} {Console.MAGENTA}[DEBUG]{Console.RESET}"
        print(f"{prefix} {Console.DIM}{msg}{Console.RESET}")
        for key, value in kwargs.items():
            print(f"         {Console.CYAN}├─ {key}:{Console.RESET} {Console.DIM}{value}{Console.RESET}")
    
    @staticmethod
    def mutation(field, value):
        """Log mutation without timestamp - for use inside divider sections"""
        width = Console.get_width()
        max_value_len = width - len(field) - 12  # Account for prefix chars
        truncated = str(value)[:max_value_len] + "..." if len(str(value)) > max_value_len else str(value)
        print(f"    {Console.CYAN}├─{Console.RESET} {Console.MAGENTA}{field}{Console.RESET} {Console.GRAY}→{Console.RESET} {Console.WHITE}{truncated}{Console.RESET}")
    
    @staticmethod
    def request(endpoint, method="POST"):
        ts = Console.timestamp()
        width = Console.get_width()
        print(f"\n{Console.GRAY}{'─' * width}{Console.RESET}")
        print(f"{Console.GRAY}[{ts}]{Console.RESET} {Console.BLUE}{Console.BOLD}[REQUEST]{Console.RESET} {Console.CYAN}{method}{Console.RESET} → {Console.WHITE}{endpoint}{Console.RESET}")
        print(f"{Console.GRAY}{'─' * width}{Console.RESET}")
    
    @staticmethod
    def response(status="OK"):
        ts = Console.timestamp()
        color = Console.GREEN if status == "OK" else Console.RED
        print(f"{Console.GRAY}[{ts}]{Console.RESET} {color}{Console.BOLD}[RESPONSE]{Console.RESET} {color}{status}{Console.RESET}")
    
    @staticmethod
    def proto_field(field_num, name, value):
        width = Console.get_width()
        max_value_len = width - len(f"Field[{field_num}]") - len(name) - 15
        truncated = str(value)[:max_value_len] + "..." if len(str(value)) > max_value_len else str(value)
        print(f"    {Console.CYAN}├─ Field[{field_num}]{Console.RESET} {Console.GRAY}{name}:{Console.RESET} {Console.WHITE}{truncated}{Console.RESET}")
    
    @staticmethod
    def divider(title=""):
        width = Console.get_width()
        if title:
            # Rounded corner titled divider
            title_text = f" ▸ {title.upper()} ▸ "
            inner_width = width - 2  # Account for border chars
            padding_left = (inner_width - len(title_text)) // 2
            padding_right = inner_width - padding_left - len(title_text)
            print(f"\n{Console.GRAY}╭{'─' * inner_width}╮{Console.RESET}")
            print(f"{Console.GRAY}│{Console.RESET}{' ' * padding_left}{Console.CYAN}{Console.BOLD}{title_text}{Console.RESET}{' ' * padding_right}{Console.GRAY}│{Console.RESET}")
            print(f"{Console.GRAY}├{'─' * inner_width}┤{Console.RESET}")
        else:
            # Simple line divider
            print(f"{Console.GRAY}├{'─' * (width - 2)}┤{Console.RESET}")
    
    @staticmethod
    def divider_end():
        """Close a divider section with rounded bottom corners"""
        width = Console.get_width()
        inner_width = width - 2
        print(f"{Console.GRAY}╰{'─' * inner_width}╯{Console.RESET}\n")
    
    @staticmethod
    def section_start(title=""):
        """Section header with rounded top border"""
        width = Console.get_width()
        inner_width = width - 2
        print(f"\n{Console.BLUE}╭{'─' * inner_width}╮{Console.RESET}")
        if title:
            title_text = f" ▸ {title.upper()} ▸ "
            padding_left = (inner_width - len(title_text)) // 2
            padding_right = inner_width - padding_left - len(title_text)
            print(f"{Console.BLUE}│{Console.RESET}{' ' * padding_left}{Console.CYAN}{Console.BOLD}{title_text}{Console.RESET}{' ' * padding_right}{Console.BLUE}│{Console.RESET}")
            print(f"{Console.BLUE}├{'─' * inner_width}┤{Console.RESET}")
    
    @staticmethod
    def section_end():
        """Section footer with rounded bottom border"""
        width = Console.get_width()
        inner_width = width - 2
        print(f"{Console.BLUE}╰{'─' * inner_width}╯{Console.RESET}\n")
