import threading
import itertools
import time
import sys
import os
from contextlib import contextmanager

class Spinner:
    """
    A simple spinner class that provides a loading animation in the terminal
    """
    def __init__(self, message="Loading...", delay=0.1, symbols=None):
        """
        Initialize the spinner
        
        Args:
            message: Message to display next to the spinner
            delay: Delay between spinner updates in seconds
            symbols: List of symbols to use for the spinner, defaults to a simple spinner
        """
        self.message = message
        self.delay = delay
        self.symbols = symbols or ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        self.spinner_cycle = itertools.cycle(self.symbols)
        self.stop_event = threading.Event()
        self.spinner_thread = None
        
        # Get terminal width to prevent wrapping if message is too long
        try:
            self.term_width = os.get_terminal_size().columns
        except (AttributeError, OSError):
            self.term_width = 80
    
    def spin(self):
        """Main spinning function that runs in a separate thread"""
        while not self.stop_event.is_set():
            symbol = next(self.spinner_cycle)
            
            # Calculate total output length to avoid line wrapping
            total_len = len(self.message) + 3  # 3 for space + symbol + space
            display_msg = self.message
            if total_len > self.term_width:
                display_msg = self.message[:self.term_width - 3 - 3] + "..."
            
            display = f"\r{symbol} {display_msg}"
            sys.stdout.write(display)
            sys.stdout.flush()
            time.sleep(self.delay)
    
    def start(self, message=None):
        """
        Start the spinner
        
        Args:
            message: Optional message to override the initial message
        """
        if message:
            self.message = message
        
        self.stop_event.clear()
        self.spinner_thread = threading.Thread(target=self.spin)
        self.spinner_thread.daemon = True
        self.spinner_thread.start()
    
    def stop(self):
        """Stop the spinner and clear the line"""
        if self.spinner_thread and self.spinner_thread.is_alive():
            self.stop_event.set()
            self.spinner_thread.join()
            
            # Clear the line
            sys.stdout.write("\r" + " " * (len(self.message) + 3) + "\r")
            sys.stdout.flush()
    
    def update(self, message):
        """
        Update the spinner message
        
        Args:
            message: New message to display
        """
        self.message = message

@contextmanager
def spinning_cursor(message="Loading...", delay=0.1):
    """
    Context manager for the spinner
    
    Usage:
        with spinning_cursor("Fetching data..."):
            # Do some long-running task
    
    Args:
        message: Message to display next to the spinner
        delay: Delay between spinner updates in seconds
    """
    spinner = Spinner(message, delay)
    try:
        spinner.start()
        yield spinner
    finally:
        spinner.stop() 