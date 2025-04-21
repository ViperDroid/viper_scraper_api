import tkinter as tk
import customtkinter as ctk
from tkinter import filedialog, messagebox, Menu, ttk # Import ttk here
import threading
import queue
import asyncio
import json
import logging
import re
import time
import random
from urllib.parse import urlparse, urljoin, quote
import os
import base64
import csv
import sys
import binascii
import traceback # Import for logging tracebacks

from playwright.async_api import async_playwright, Error as PlaywrightError, Page, Locator, TimeoutError as PlaywrightTimeoutError
from pyfiglet import Figlet


__version__ = "3.4.0-viper-enhanced" # Updated version
TOOL_NAME = "Viper API Interceptor"
DEFAULT_OUTPUT_FILE = "viper_discovered_apis.json"

# --- Appearance ---
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")

# --- Logging Setup ---
log_formatter = logging.Formatter('%(asctime)s [%(levelname)-7s] %(message)s', datefmt='%H:%M:%S')
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG) # Default level, GUI can override

# --- Constants ---
RESOURCE_TYPES = ["xhr", "fetch", "document", "script", "stylesheet", "image", "font", "media", "websocket", "other"]
MONOSPACE_FONT = ("Consolas", 11) if sys.platform == "win32" else ("monospace", 10)
DEFAULT_IGNORE_PATTERNS = [
    'google-analytics.com', 'googletagmanager.com', 'facebook.net', 'connect.facebook.net',
    'fbcdn.net', 'doubleclick.net', 'googleadservices.com', 'adservice.google.com',
    'googlesyndication.com', 'fonts.googleapis.com', 'fonts.gstatic.com',
    'gstatic.com/recaptcha', 'criteo.com', 'scorecardresearch.com', 'krxd.net',
    'cdn-cgi/challenge-platform', 'cdn-cgi/rum', 'cdn.jsdelivr.net', 'cdnjs.cloudflare.com',
    '.js', '.css', '.woff', '.woff2', '.ttf', '.svg', '.png', '.jpg', '.jpeg',
    '.gif', '.ico', '.webp', '.avif', '.mp4', '.webm', '.css.map', '.js.map',
    'google.com/ads', 'youtube.com/api/stats', 'googlevideo.com', 'ytimg.com',
    'imasdk.googleapis.com', '/beacon', '/track', '/pixel', 'analytics', 'metrics', 'segment.com'
]
INTERESTING_HEADERS = ['authorization', 'set-cookie', 'cookie', 'x-csrf-token', 'x-api-key', 'x-auth-token', 'bearer', 'jwt', 'api-key', 'apikey']
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Mobile Safari/537.36",
    "Custom"
]

# --- Tooltip Widget ---
class ToolTip:
    """ Creates a tooltip for a given widget. """
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tooltip = None
        self.widget.bind("<Enter>", self.show_tip, add='+')
        self.widget.bind("<Leave>", self.hide_tip, add='+')

    def show_tip(self, event=None):
        try:
             if not self.widget.winfo_exists(): return
        except tk.TclError:
             return # Widget likely destroyed

        # Position relative to the event or widget root
        if event:
            x = event.x_root + 20
            y = event.y_root + 20
        else: # Fallback
            x = self.widget.winfo_rootx() + 20
            y = self.widget.winfo_rooty() + 20

        # Destroy existing tooltip if it exists
        if self.tooltip:
            try: self.tooltip.destroy()
            except tk.TclError: pass
            self.tooltip = None

        # Create the tooltip window
        self.tooltip = tk.Toplevel(self.widget)
        self.tooltip.wm_overrideredirect(True) # No window decorations
        self.tooltip.wm_geometry(f"+{x}+{y}")
        self.tooltip.attributes("-topmost", True) # Keep on top

        # Create the label inside the tooltip (using standard tkinter Label)
        label = tk.Label(self.tooltip, text=self.text, justify='left',
                         background="#333333", foreground="#E0E0E0", relief='solid', borderwidth=1,
                         font=("Segoe UI", 9, "normal"), wraplength=350, padx=5, pady=3) # Use padx/pady
        label.pack(ipadx=1, ipady=1) # ipadx/y controls internal padding within the label

    def hide_tip(self, event=None):
        if self.tooltip:
            try:
                 self.tooltip.destroy()
            except tk.TclError:
                 pass # Window might already be destroyed
            self.tooltip = None

# --- Queue Handler for Logging ---
class QueueHandler(logging.Handler):
    """ Sends log records to a queue for processing by the GUI thread. """
    def __init__(self, log_queue):
        super().__init__()
        self.log_queue = log_queue

    def emit(self, record):
        # Put the log record itself onto the queue
        self.log_queue.put({'type': 'log_record', 'record': record})

# --- GUI Application Class ---
class ViperApiGuiPro(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title(f"{TOOL_NAME} v{__version__}")
        self.geometry("1500x1000") # Default size
        self.minsize(1200, 700) # Minimum size

        # --- State Variables ---
        self.scan_thread = None
        self.stop_event = threading.Event() # Used to signal the scan thread to stop
        self.result_queue = queue.Queue() # For results and thread->GUI communication
        self.log_queue = queue.Queue() # For log messages from thread->GUI
        self.api_results_data = {} # Holds {api_key: api_data} for all found APIs
        self.current_selection_iid = None # iid of selected item in Treeview
        self.user_ignore_list = [] # Custom ignore patterns from user
        self.allowed_resource_types = set(RESOURCE_TYPES) # Initialize with all types
        self.allowed_status_codes = set() # Empty means default (allow <400)

        # --- Logging Setup ---
        self.queue_handler = QueueHandler(self.log_queue)
        self.queue_handler.setFormatter(log_formatter)
        log.addHandler(self.queue_handler) # Add handler to the root logger
        log.setLevel(logging.DEBUG) # Let handler filter later if needed by GUI setting

        # --- GUI Variables ---
        self.output_file_var = tk.StringVar(value=DEFAULT_OUTPUT_FILE)

        # --- Build UI ---
        self.create_widgets()
        self.configure_styles()
        self.display_banner_in_log()
        self.update_status("Idle. Configure and click Start Scan.")

        # Start polling the queues
        self.after(100, self.process_gui_queue)

        # Handle window close event gracefully
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    def on_closing(self):
        """ Handle window closing: stop scan if running. """
        if self.scan_thread and self.scan_thread.is_alive():
             # Ask user only if a scan is actively running
             if messagebox.askyesno("Scan Running", "A scan is currently running. Do you want to stop it and exit?", parent=self):
                 self.stop_scan()
                 # Give a brief moment for the stop signal to potentially be processed
                 # Note: The thread might not stop instantly.
                 self.after(500, self.destroy) # Schedule destroy after a delay
             else:
                 return # Don't close if user cancels
        else:
             self.destroy() # Close normally if no scan is running

    def display_banner_in_log(self):
        """ Displays the tool banner in the log text area using pyfiglet. """
        try:
            f = Figlet(font='larry3d') # Or choose another font like 'standard', 'slant'
            banner = f.renderText("Viper API")
        except Exception: # Fallback if pyfiglet fails or font missing
             banner = f"{TOOL_NAME}\n"
        powered_by = "Powered By Viper Droid"
        version_info = f"Version: {__version__}\n"
        separator = "█" * 70 + "\n"
        # Log banner components with specific tags for styling
        self.log_message_direct(banner, level="INFO", tags=('banner',))
        self.log_message_direct(powered_by, level="INFO", tags=('banner_sub',))
        self.log_message_direct(version_info, level="INFO", tags=('banner_sub',))
        self.log_message_direct(separator, level="INFO", tags=('separator',))

    def configure_styles(self):
        """ Configures styles for CTk and ttk widgets. """
        # --- Log Textbox Tags (No font setting here due to CTk limitations) ---
        self.log_textbox.tag_config('banner', justify='center')
        self.log_textbox.tag_config('banner_sub', justify='center')
        self.log_textbox.tag_config('separator', justify='center', foreground='#00FF00') # Green separator
        self.log_textbox.tag_config('INFO', foreground='#00FFFF') # Cyan
        self.log_textbox.tag_config('WARNING', foreground='#FFFF00') # Yellow
        self.log_textbox.tag_config('ERROR', foreground='#FF6347') # Tomato Red
        self.log_textbox.tag_config('DEBUG', foreground='#A9A9A9') # Dark Gray
        self.log_textbox.tag_config('SUCCESS', foreground='#32CD32') # Lime Green

        # --- Treeview Styling (using ttk.Style) ---
        style = ttk.Style(self)
        style.theme_use("default") # Start with a default theme

        # Define colors based on CTk theme if possible, otherwise use fallbacks
        try:
            tree_bg = self._apply_appearance_mode(ctk.ThemeManager.theme["CTkFrame"]["fg_color"][1])
            tree_fg = self._apply_appearance_mode(ctk.ThemeManager.theme["CTkLabel"]["text_color"][1])
            tree_field_bg = self._apply_appearance_mode(ctk.ThemeManager.theme["CTkEntry"]["fg_color"][1])
            tree_select_bg = self._apply_appearance_mode(ctk.ThemeManager.theme["CTkButton"]["fg_color"][1])
            tree_select_fg = "#FFFFFF" # White text on selection is usually clear
            heading_bg = self._apply_appearance_mode(ctk.ThemeManager.theme["CTkButton"]["hover_color"][1])
            heading_fg = "#00FF00" # Keep headings green
        except (AttributeError, KeyError, IndexError, TypeError):
            # Fallback dark theme colors
            tree_bg = "#1c1c1c"; tree_fg = "#E0E0E0"; tree_field_bg = "#2a2a2a"
            tree_select_bg = "#005f5f"; tree_select_fg = "#FFFFFF"
            heading_bg = "#3a3a3a"; heading_fg = "#00FF00"

        # Configure the main Treeview appearance
        style.configure("Treeview",
                        background=tree_bg,
                        foreground=tree_fg,
                        fieldbackground=tree_field_bg,
                        rowheight=25, # Adjust row height if needed
                        font=('Segoe UI', 9)) # Use a common system font
        # Configure the appearance of selected items
        style.map('Treeview',
                  background=[('selected', tree_select_bg)],
                  foreground=[('selected', tree_select_fg)])

        # Configure the Treeview headings
        style.configure("Treeview.Heading",
                        background=heading_bg,
                        foreground=heading_fg,
                        font=(MONOSPACE_FONT[0], 10, 'bold'), # Use monospace bold for headings
                        relief="flat",
                        padding=(5, 5)) # Padding within heading cells
        # Configure heading appearance when hovered/active
        style.map("Treeview.Heading",
                  background=[('active', "#4f4f4f")]) # Slightly lighter when clicked

        # Remove default borders potentially added by the theme for a cleaner look
        style.layout("Treeview", [('Treeview.treearea', {'sticky': 'nsew'})])

        # --- CTk Textbox Styling ---
        text_bg = "#202020"; text_fg = "#CCCCCC"; text_border = "#444444"
        # Common options for most textboxes
        common_textbox_opts = {
            "font": MONOSPACE_FONT, "text_color": text_fg, "fg_color": text_bg,
            "border_color": text_border, "border_width": 1,
            "scrollbar_button_color": heading_bg, "scrollbar_button_hover_color": "#5f5f5f"
        }
        # Base options for details panes (will override wrap individually)
        details_textbox_opts = common_textbox_opts.copy()

        # Apply styles, setting wrap explicitly
        self.req_headers_text.configure(**details_textbox_opts, wrap="none")
        self.req_body_text.configure(**details_textbox_opts, wrap="word")
        self.resp_headers_text.configure(**details_textbox_opts, wrap="none")
        self.resp_body_text.configure(**details_textbox_opts, wrap="word")
        self.raw_body_text.configure(**details_textbox_opts, wrap="none")

        # Log textbox specific styling (set initial state to disabled)
        self.log_textbox.configure(**common_textbox_opts, wrap="word")
        self.log_textbox.configure(state=tk.DISABLED)

        # Form and Ignore Textboxes styling
        self.form_values_textbox.configure(font=MONOSPACE_FONT, border_width=1, fg_color=text_bg, text_color=text_fg, border_color=text_border)
        self.ignore_textbox.configure(font=MONOSPACE_FONT, border_width=1, fg_color=text_bg, text_color=text_fg, border_color=text_border)


    def create_widgets(self):
        """ Creates and arranges all the GUI widgets. """
        # --- Main Layout Grid ---
        self.grid_columnconfigure(0, weight=3) # Left pane (options, log)
        self.grid_columnconfigure(1, weight=5) # Right pane (results, details)
        self.grid_rowconfigure(0, weight=1)    # Main content row (expands)
        self.grid_rowconfigure(1, weight=0)    # Bottom controls row (fixed height)
        self.grid_rowconfigure(2, weight=0)    # Status bar row (fixed height)

        # --- Left Pane ---
        left_pane = ctk.CTkFrame(self, fg_color="transparent")
        left_pane.grid(row=0, column=0, rowspan=2, padx=(10, 5), pady=10, sticky="nsew")
        left_pane.grid_rowconfigure(0, weight=0) # Options frame (fixed)
        left_pane.grid_rowconfigure(1, weight=1) # Log frame (expandable)
        left_pane.grid_columnconfigure(0, weight=1) # Allow content to expand horizontally

        # --- Options Frame ---
        options_frame = ctk.CTkFrame(left_pane, corner_radius=5)
        options_frame.grid(row=0, column=0, padx=0, pady=(0, 10), sticky="new")
        options_frame.grid_columnconfigure(1, weight=1) # Allow entry fields to expand

        row_idx = 0 # Row counter for options_frame grid

        # Target URL
        lbl_url = ctk.CTkLabel(options_frame, text="Target URL:", anchor="w"); lbl_url.grid(row=row_idx, column=0, padx=(10,5), pady=3, sticky="w")
        self.url_entry = ctk.CTkEntry(options_frame, placeholder_text="https://example.com", width=300)
        self.url_entry.grid(row=row_idx, column=1, columnspan=3, padx=5, pady=3, sticky="ew")
        ToolTip(lbl_url, "Enter the full starting URL (include http/https).")
        ToolTip(self.url_entry, "The initial URL to navigate to and scan.")
        row_idx += 1

        # User Agent
        lbl_ua = ctk.CTkLabel(options_frame, text="User Agent:", anchor="w"); lbl_ua.grid(row=row_idx, column=0, padx=(10,5), pady=3, sticky="w")
        self.user_agent_var = tk.StringVar(value=USER_AGENTS[0])
        self.user_agent_menu = ctk.CTkOptionMenu(options_frame, variable=self.user_agent_var, values=USER_AGENTS, command=self.on_user_agent_change, dynamic_resizing=False, width=150)
        self.user_agent_menu.grid(row=row_idx, column=1, padx=5, pady=3, sticky="w")
        self.custom_ua_entry = ctk.CTkEntry(options_frame, placeholder_text="Enter Custom User Agent", width=200)
        self.custom_ua_entry.grid(row=row_idx, column=2, columnspan=2, padx=5, pady=3, sticky="ew")
        self.custom_ua_entry.grid_remove() # Hide initially
        ToolTip(lbl_ua, "Select or provide a User-Agent string.")
        ToolTip(self.user_agent_menu, "Select a preset User-Agent or 'Custom'.")
        ToolTip(self.custom_ua_entry, "Enter the full custom User-Agent string if 'Custom' is selected.")
        row_idx += 1

        # Proxy
        lbl_prx = ctk.CTkLabel(options_frame, text="Proxy (host:port):", anchor="w"); lbl_prx.grid(row=row_idx, column=0, padx=(10,5), pady=3, sticky="w")
        self.proxy_entry = ctk.CTkEntry(options_frame, placeholder_text="Optional, e.g., 127.0.0.1:8080", width=180)
        self.proxy_entry.grid(row=row_idx, column=1, padx=5, pady=3, sticky="ew")
        lbl_prxtype = ctk.CTkLabel(options_frame, text="Type:"); lbl_prxtype.grid(row=row_idx, column=2, padx=(10,5), pady=3, sticky="w")
        self.proxy_type_var = tk.StringVar(value="http")
        self.proxy_type_menu = ctk.CTkOptionMenu(options_frame, variable=self.proxy_type_var, values=["http", "socks5"], width=90)
        self.proxy_type_menu.grid(row=row_idx, column=3, padx=5, pady=3, sticky="w")
        ToolTip(lbl_prx, "Optional HTTP/SOCKS5 proxy server.")
        ToolTip(self.proxy_entry, "Proxy server address and port.")
        ToolTip(self.proxy_type_menu, "Select the proxy type.")
        row_idx += 1

        # Navigation Timing
        lbl_wait = ctk.CTkLabel(options_frame, text="Wait Until:", anchor="w"); lbl_wait.grid(row=row_idx, column=0, padx=(10,5), pady=3, sticky="w")
        self.wait_strategy_var = tk.StringVar(value="networkidle")
        self.wait_strategy_menu = ctk.CTkOptionMenu(options_frame, variable=self.wait_strategy_var, values=["load", "domcontentloaded", "networkidle"], width=140)
        self.wait_strategy_menu.grid(row=row_idx, column=1, padx=5, pady=3, sticky="w")
        lbl_nav_to = ctk.CTkLabel(options_frame, text="Nav Timeout(ms):", anchor="w"); lbl_nav_to.grid(row=row_idx, column=2, padx=(10,5), pady=3, sticky="w")
        self.nav_timeout_var = tk.IntVar(value=60000)
        self.nav_timeout_entry = ctk.CTkEntry(options_frame, textvariable=self.nav_timeout_var, width=70)
        self.nav_timeout_entry.grid(row=row_idx, column=3, padx=5, pady=3, sticky="w")
        ToolTip(lbl_wait, "Playwright page load strategy (waitUntil).")
        ToolTip(self.wait_strategy_menu, "'networkidle' is often best for dynamic sites.")
        ToolTip(lbl_nav_to, "Max time (ms) for page navigation.")
        ToolTip(self.nav_timeout_entry, "Timeout in milliseconds (e.g., 60000 = 60s).")
        row_idx += 1

        # Action Timing
        lbl_act_to = ctk.CTkLabel(options_frame, text="Action Timeout(ms):", anchor="w"); lbl_act_to.grid(row=row_idx, column=0, padx=(10,5), pady=3, sticky="w")
        self.action_timeout_var = tk.IntVar(value=30000)
        self.action_timeout_entry = ctk.CTkEntry(options_frame, textvariable=self.action_timeout_var, width=70)
        self.action_timeout_entry.grid(row=row_idx, column=1, padx=5, pady=3, sticky="w")
        lbl_xtra_wait = ctk.CTkLabel(options_frame, text="Extra Wait (s):", anchor="w"); lbl_xtra_wait.grid(row=row_idx, column=2, padx=(10,5), pady=3, sticky="w")
        self.wait_time_var = tk.DoubleVar(value=2.0)
        self.wait_time_entry = ctk.CTkEntry(options_frame, textvariable=self.wait_time_var, width=60)
        self.wait_time_entry.grid(row=row_idx, column=3, padx=5, pady=3, sticky="w")
        ToolTip(lbl_act_to, "Default timeout (ms) for actions like click, fill.")
        ToolTip(self.action_timeout_entry, "Timeout in milliseconds (e.g., 30000 = 30s).")
        ToolTip(lbl_xtra_wait, "Additional static wait time after load/interactions (s).")
        ToolTip(self.wait_time_entry, "Seconds to wait after main load and interaction phases.")
        row_idx += 1

        # --- Configuration Tabs ---
        config_tabs = ctk.CTkTabview(options_frame, border_width=1, border_color="#444444")
        config_tabs.grid(row=row_idx, column=0, columnspan=4, padx=10, pady=5, sticky="ew")
        tab_interact = config_tabs.add("Interaction")
        tab_filter = config_tabs.add("Filtering")
        row_idx += 1 # Increment row index after adding tabs

        # --- Interaction Tab Content ---
        tab_interact.grid_columnconfigure(1, weight=1) # Allow slider/entries to expand

        _row = 0 # Use local row counter for items within the tab
        # Scrolling Options
        lbl_scrolls = ctk.CTkLabel(tab_interact, text="Scrolls:"); lbl_scrolls.grid(row=_row, column=0, padx=(10,5), pady=5, sticky="w")
        self.scrolls_var = tk.IntVar(value=3)
        ctk.CTkSlider(tab_interact, from_=0, to=20, variable=self.scrolls_var, number_of_steps=20).grid(row=_row, column=1, padx=5, pady=5, sticky="ew")
        ctk.CTkLabel(tab_interact, textvariable=self.scrolls_var, width=25).grid(row=_row, column=2, padx=5, pady=5)
        ToolTip(lbl_scrolls, "Number of times to scroll down the page.")
        _row += 1
        lbl_scroll_delay = ctk.CTkLabel(tab_interact, text="Delay (s):"); lbl_scroll_delay.grid(row=_row, column=0, padx=(10,5), pady=5, sticky="w")
        self.scroll_delay_var = tk.DoubleVar(value=1.5)
        self.scroll_delay_entry = ctk.CTkEntry(tab_interact, textvariable=self.scroll_delay_var, width=60)
        self.scroll_delay_entry.grid(row=_row, column=1, padx=5, pady=5, sticky="w")
        ToolTip(lbl_scroll_delay, "Delay (seconds) between each scroll action.")
        ToolTip(self.scroll_delay_entry, "Time in seconds.")
        _row += 1

        # Clicking Options
        lbl_click = ctk.CTkLabel(tab_interact, text="Click Selectors (CSV):"); lbl_click.grid(row=_row, column=0, padx=(10,5), pady=5, sticky="w")
        self.click_selectors_entry = ctk.CTkEntry(tab_interact, placeholder_text="e.g., button.load-more, a:contains('Next')")
        self.click_selectors_entry.grid(row=_row, column=1, columnspan=2, padx=5, pady=5, sticky="ew")
        ToolTip(lbl_click, "CSS selectors for elements to click (comma-separated).")
        ToolTip(self.click_selectors_entry, "Examples: button#id, a.classname, [data-attr='value']")
        _row += 1
        self.hover_var = tk.BooleanVar(value=False)
        cb_hover = ctk.CTkCheckBox(tab_interact, text="Hover before Click", variable=self.hover_var)
        cb_hover.grid(row=_row, column=0, columnspan=3, padx=10, pady=5, sticky="w")
        ToolTip(cb_hover, "Simulate mouse hover before clicking the element.")
        _row += 1

        # Form Input Options
        lbl_form_sel = ctk.CTkLabel(tab_interact, text="Form Input Selector:"); lbl_form_sel.grid(row=_row, column=0, padx=(10,5), pady=5, sticky="w")
        self.form_selector_entry = ctk.CTkEntry(tab_interact, placeholder_text="CSS Selector (e.g., #search-input)")
        self.form_selector_entry.grid(row=_row, column=1, columnspan=2, padx=5, pady=5, sticky="ew")
        ToolTip(lbl_form_sel, "CSS selector for the input field to type into.")
        ToolTip(self.form_selector_entry, "Selector for the target input (e.g., search box).")
        _row += 1
        lbl_form_vals = ctk.CTkLabel(tab_interact, text="Input Values (one per line):"); lbl_form_vals.grid(row=_row, column=0, padx=(10,5), pady=5, sticky="nw")
        self.form_values_textbox = ctk.CTkTextbox(tab_interact, height=60, border_width=1)
        self.form_values_textbox.grid(row=_row, column=1, columnspan=2, padx=5, pady=5, sticky="ew")
        ToolTip(lbl_form_vals, "Values to type into the selected input, one per line.")
        ToolTip(self.form_values_textbox, "List of values to input sequentially.")
        _row += 1
        self.form_submit_var = tk.BooleanVar(value=True)
        cb_submit = ctk.CTkCheckBox(tab_interact, text="Submit (Enter) after each", variable=self.form_submit_var)
        cb_submit.grid(row=_row, column=0, padx=10, pady=5, sticky="w")
        ToolTip(cb_submit, "Press Enter after typing each value.")
        lbl_form_delay = ctk.CTkLabel(tab_interact, text="Delay (s) between items:"); lbl_form_delay.grid(row=_row, column=1, padx=(10,5), pady=5, sticky="w")
        self.form_delay_var = tk.DoubleVar(value=2.0)
        self.form_delay_entry = ctk.CTkEntry(tab_interact, textvariable=self.form_delay_var, width=60)
        self.form_delay_entry.grid(row=_row, column=2, padx=5, pady=5, sticky="w")
        ToolTip(lbl_form_delay, "Delay (s) between processing each input value.")
        ToolTip(self.form_delay_entry, "Time in seconds.")
        _row += 1

        # --- Filtering Tab Content ---
        tab_filter.grid_columnconfigure(1, weight=1) # Allow entries/textboxes to expand

        _row = 0 # Reset row counter for this tab
        # Status Codes Filter
        lbl_status = ctk.CTkLabel(tab_filter, text="Allowed Status Codes:"); lbl_status.grid(row=_row, column=0, padx=(10,5), pady=5, sticky='w')
        self.status_code_entry = ctk.CTkEntry(tab_filter, placeholder_text="e.g., 200,302 or 2xx,3xx (empty = <400)")
        self.status_code_entry.grid(row=_row, column=1, padx=5, pady=5, sticky="ew")
        ToolTip(lbl_status, "Filter intercepted requests by HTTP status code.")
        ToolTip(self.status_code_entry, "Comma-separated codes (200, 201), ranges (2xx), or empty to allow only <400 codes.")
        _row += 1

        # Resource Types Filter
        ctk.CTkLabel(tab_filter, text="Allowed Resource Types:").grid(row=_row, column=0, columnspan=2, padx=10, pady=(5,0), sticky="w")
        _row += 1
        self.resource_type_vars = {}
        res_frame = ctk.CTkScrollableFrame(tab_filter, fg_color="transparent", height=80, border_width=0)
        res_frame.grid(row=_row, column=0, columnspan=2, padx=10, pady=0, sticky="ew")
        num_cols = 4 # Adjust number of columns for checkboxes
        for i, res_type in enumerate(RESOURCE_TYPES):
            var = tk.BooleanVar(value=(res_type in ["xhr", "fetch"])) # Default check common API types
            cb = ctk.CTkCheckBox(res_frame, text=res_type, variable=var, command=self.update_allowed_resource_types)
            cb.grid(row=i // num_cols, column=i % num_cols, padx=5, pady=2, sticky="w")
            ToolTip(cb, f"Include requests of type '{res_type}'.")
            self.resource_type_vars[res_type] = var
        self.update_allowed_resource_types() # Set initial state based on defaults
        _row += 1

        # Ignore Patterns Filter
        lbl_ignore = ctk.CTkLabel(tab_filter, text="Custom Ignore Patterns (one per line):"); lbl_ignore.grid(row=_row, column=0, columnspan=2, padx=10, pady=(5,0), sticky="w")
        ToolTip(lbl_ignore, "Add custom URL fragments or domains (case-insensitive) to ignore.")
        _row += 1
        self.ignore_textbox = ctk.CTkTextbox(tab_filter, height=100, border_width=1)
        self.ignore_textbox.grid(row=_row, column=0, columnspan=2, padx=10, pady=5, sticky="ew")
        self.ignore_textbox.insert("1.0", "") # Start empty
        ToolTip(self.ignore_textbox, "Enter parts of URLs or domains (one per line) to ignore. Lines starting with # are comments. Defaults are also applied.")
        _row += 1

        # --- Log Frame ---
        log_frame = ctk.CTkFrame(left_pane, corner_radius=5)
        log_frame.grid(row=1, column=0, padx=0, pady=0, sticky="nsew")
        log_frame.grid_rowconfigure(1, weight=1) # Textbox should expand vertically
        log_frame.grid_columnconfigure(0, weight=1) # Textbox should expand horizontally

        # Log Header (Title + Level Selector)
        log_header_frame = ctk.CTkFrame(log_frame, fg_color="transparent")
        log_header_frame.grid(row=0, column=0, sticky="ew", padx=5, pady=(5,0))
        ctk.CTkLabel(log_header_frame, text="Scan Log:", font=ctk.CTkFont(weight="bold")).pack(side=tk.LEFT, padx=(5,0))
        # Log level menu on the right
        self.log_level_var = tk.StringVar(value="INFO")
        self.log_level_menu = ctk.CTkOptionMenu(log_header_frame, variable=self.log_level_var,
                                                 values=["DEBUG", "INFO", "WARNING", "ERROR", "SUCCESS"], # Added Success visibility option
                                                 command=self.set_log_level, width=110)
        self.log_level_menu.pack(side=tk.RIGHT, padx=(0, 5))
        ctk.CTkLabel(log_header_frame, text="Level:").pack(side=tk.RIGHT, padx=(10, 5))
        ToolTip(log_header_frame, "Controls the verbosity of messages shown below.")
        ToolTip(self.log_level_menu, "Select the minimum log level to display.")

        # Log Textbox
        self.log_textbox = ctk.CTkTextbox(log_frame, wrap=tk.WORD) # Initial state set in configure_styles
        self.log_textbox.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")
        # Make log selectable for copy/paste
        self.log_textbox.bind("<1>", lambda event: self.log_textbox.focus_set()) # Allow focus for selection

        # --- Right Pane ---
        right_pane = ctk.CTkFrame(self, fg_color="transparent")
        right_pane.grid(row=0, column=1, padx=(5, 10), pady=10, sticky="nsew")
        right_pane.grid_rowconfigure(0, weight=2) # Results table (takes more space initially)
        right_pane.grid_rowconfigure(1, weight=3) # Details tabs (takes more space initially)
        right_pane.grid_columnconfigure(0, weight=1) # Allow content to expand horizontally

        # --- Results Table Frame ---
        table_frame = ctk.CTkFrame(right_pane, corner_radius=5)
        table_frame.grid(row=0, column=0, padx=0, pady=(0, 10), sticky="nsew")
        table_frame.grid_rowconfigure(1, weight=1) # Treeview expands vertically
        table_frame.grid_columnconfigure(0, weight=1) # Treeview expands horizontally

        # Filter Entry for Table
        filter_frame = ctk.CTkFrame(table_frame, fg_color="transparent")
        filter_frame.grid(row=0, column=0, columnspan=2, padx=5, pady=5, sticky="ew") # Span scrollbar column
        lbl_filter = ctk.CTkLabel(filter_frame, text="Filter Results:"); lbl_filter.pack(side=tk.LEFT, padx=(0,5))
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", self.apply_filter) # Filter as user types
        self.filter_entry = ctk.CTkEntry(filter_frame, textvariable=self.filter_var, placeholder_text="Filter by URL, Method, Status...")
        self.filter_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ToolTip(lbl_filter, "Filter the discovered API table below.")
        ToolTip(self.filter_entry, "Type text to filter results (case-insensitive).")

        # Treeview (Results Table using ttk)
        self.tree = ttk.Treeview(table_frame, columns=("Method", "Status", "URL", "ContentType"), show="headings") # Style set in configure_styles
        self.tree.heading("Method", text="Method", command=lambda: self.sort_treeview("Method", False))
        self.tree.heading("Status", text="Status", command=lambda: self.sort_treeview("Status", False))
        self.tree.heading("URL", text="URL", command=lambda: self.sort_treeview("URL", False))
        self.tree.heading("ContentType", text="Content-Type", command=lambda: self.sort_treeview("ContentType", False))
        # Adjust column widths
        self.tree.column("Method", width=80, anchor=tk.W, stretch=False)
        self.tree.column("Status", width=70, anchor=tk.CENTER, stretch=False)
        self.tree.column("URL", width=500, anchor=tk.W, stretch=True) # Give URL most space
        self.tree.column("ContentType", width=200, anchor=tk.W, stretch=False)

        # Scrollbars for Treeview
        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        # Grid layout for Treeview and Scrollbars
        self.tree.grid(row=1, column=0, sticky="nsew")
        vsb.grid(row=1, column=1, sticky="ns")
        hsb.grid(row=2, column=0, sticky="ew") # Horizontal scrollbar below tree

        # Treeview Bindings
        self.tree.bind("<<TreeviewSelect>>", self.on_tree_select)
        self.tree.bind("<Button-3>", self.show_tree_menu) # Right-click menu

        # Treeview Context Menu
        self.tree_menu = Menu(self, tearoff=0, background="#2b2b2b", foreground="#E0E0E0", activebackground="#005f5f", font=MONOSPACE_FONT)
        self.tree_menu.add_command(label="Copy URL", command=self.copy_selected_url)
        self.tree_menu.add_command(label="Copy as cURL (Basic)", command=self.copy_as_curl)

        ToolTip(self.tree, "Discovered API endpoints. Click headers to sort. Right-click for options.")

        # --- Details Tabs Frame ---
        details_frame = ctk.CTkFrame(right_pane, corner_radius=5)
        details_frame.grid(row=1, column=0, padx=0, pady=0, sticky="nsew")
        details_frame.grid_rowconfigure(0, weight=1) # Tabview expands vertically
        details_frame.grid_columnconfigure(0, weight=1) # Tabview expands horizontally
        ToolTip(details_frame, "Details of the selected API call from the table above.")

        # Details TabView Widget
        self.details_tabview = ctk.CTkTabview(details_frame, border_width=1, border_color="#444444")
        self.details_tabview.pack(fill="both", expand=True, padx=5, pady=5)
        # Add tabs
        tab_req = self.details_tabview.add("Request")
        tab_resp = self.details_tabview.add("Response")
        tab_raw = self.details_tabview.add("Raw Body")

        # --- Request Tab Content ---
        tab_req.grid_columnconfigure(0, weight=1)
        tab_req.grid_rowconfigure(1, weight=1) # Headers textbox expands
        tab_req.grid_rowconfigure(3, weight=1) # Body textbox expands
        ctk.CTkLabel(tab_req, text="Request Headers:", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, sticky="w", padx=5, pady=(5,0))
        self.req_headers_text = ctk.CTkTextbox(tab_req, height=120)
        self.req_headers_text.grid(row=1, column=0, sticky="nsew", padx=5, pady=2)
        ctk.CTkLabel(tab_req, text="Request Body:", font=ctk.CTkFont(weight="bold")).grid(row=2, column=0, sticky="w", padx=5, pady=(5,0))
        self.req_body_text = ctk.CTkTextbox(tab_req, height=100)
        self.req_body_text.grid(row=3, column=0, sticky="nsew", padx=5, pady=(2,5))
        ToolTip(self.req_headers_text, "Headers sent with the request. Interesting headers highlighted.")
        ToolTip(self.req_body_text, "Body/Payload sent with the request (e.g., for POST). JSON is pretty-printed.")

        # --- Response Tab Content ---
        tab_resp.grid_columnconfigure(0, weight=1)
        tab_resp.grid_rowconfigure(1, weight=1) # Headers textbox expands
        tab_resp.grid_rowconfigure(3, weight=3) # Body snippet textbox expands more
        ctk.CTkLabel(tab_resp, text="Response Headers:", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, sticky="w", padx=5, pady=(5,0))
        self.resp_headers_text = ctk.CTkTextbox(tab_resp, height=120)
        self.resp_headers_text.grid(row=1, column=0, sticky="nsew", padx=5, pady=2)
        ctk.CTkLabel(tab_resp, text="Formatted Response Body Snippet:", font=ctk.CTkFont(weight="bold")).grid(row=2, column=0, sticky="w", padx=5, pady=(5,0))
        self.resp_body_text = ctk.CTkTextbox(tab_resp, height=150)
        self.resp_body_text.grid(row=3, column=0, sticky="nsew", padx=5, pady=(2,5))
        ToolTip(self.resp_headers_text, "Headers received from the server. Interesting headers highlighted.")
        ToolTip(self.resp_body_text, "A snippet of the response body, formatted if possible (JSON/Text). Max 300 chars.")

        # --- Raw Body Tab Content ---
        tab_raw.grid_columnconfigure(0, weight=1)
        tab_raw.grid_rowconfigure(0, weight=1) # Textbox expands fully
        self.raw_body_text = ctk.CTkTextbox(tab_raw)
        self.raw_body_text.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        ToolTip(self.raw_body_text, "The full raw response body. JSON is pretty-printed, text shown directly, binary shown as Base64.")

        # --- Bottom Controls Row ---
        bottom_controls = ctk.CTkFrame(self, fg_color="transparent")
        bottom_controls.grid(row=1, column=0, columnspan=2, padx=10, pady=(5, 5), sticky="ew")

        # Start/Stop Buttons
        self.start_button = ctk.CTkButton(bottom_controls, text="Start Scan", command=self.start_scan, width=120, fg_color="#008000", hover_color="#006400")
        self.start_button.pack(side=tk.LEFT, padx=(0, 10))
        ToolTip(self.start_button, "Begin the scan with current settings.")
        self.stop_button = ctk.CTkButton(bottom_controls, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED, width=120, fg_color="#B22222", hover_color="#8B0000")
        self.stop_button.pack(side=tk.LEFT, padx=10)
        ToolTip(self.stop_button, "Attempt to gracefully stop the running scan.")

        # Progress Bar (New)
        self.progress_bar = ttk.Progressbar(bottom_controls, orient='horizontal', mode='indeterminate', length=150)
        # Don't pack initially, pack/forget in start/stop methods

        # Clear Button
        btn_clear = ctk.CTkButton(bottom_controls, text="Clear All", command=self.clear_results_and_log, width=100)
        btn_clear.pack(side=tk.LEFT, padx=10)
        ToolTip(btn_clear, "Clear results table, details panels, and log messages.")

        # Export Button (Menu - New Options Added)
        export_options = ["Export Visible JSON", "Export Visible CSV", "Export All JSON", "Export All CSV"]
        self.export_menu_button = ctk.CTkOptionMenu(bottom_controls, values=export_options, command=self.export_data, width=170)
        self.export_menu_button.pack(side=tk.RIGHT, padx=(10, 0))
        self.export_menu_button.set("Export...") # Default text
        ToolTip(self.export_menu_button, "Save discovered API data (visible or all).")

        # --- Status Bar Row ---
        self.status_label = ctk.CTkLabel(self, text="Status: Idle", anchor="w", height=20, font=(MONOSPACE_FONT[0], 9))
        self.status_label.grid(row=2, column=0, columnspan=2, padx=10, pady=(0,5), sticky="ew")

    # --- GUI Logic Methods ---

    def set_log_level(self, choice):
        """Sets the logging level based on dropdown selection."""
        level_map = {
             "DEBUG": logging.DEBUG, "INFO": logging.INFO, "WARNING": logging.WARNING,
             "ERROR": logging.ERROR, "SUCCESS": logging.INFO # Treat SUCCESS as INFO for filtering level
         }
        level = level_map.get(choice.upper(), logging.INFO)
        log.setLevel(level) # Set root logger level - affects what's processed by handlers
        # Queue handler doesn't need level set usually, GUI handles filtering display
        self.log_message_direct(f"Log level set to display {choice} and higher.", level="INFO")

    def on_user_agent_change(self, choice):
        """Shows/hides the custom User Agent entry based on selection."""
        if choice == "Custom":
            self.custom_ua_entry.grid()
        else:
            self.custom_ua_entry.grid_remove()
            self.custom_ua_entry.delete(0, tk.END)

    def get_selected_user_agent(self):
        """Returns the selected or custom User Agent string."""
        choice = self.user_agent_var.get()
        if choice == "Custom":
            custom_ua = self.custom_ua_entry.get().strip()
            # Fallback to default Chrome UA if custom is empty
            return custom_ua if custom_ua else USER_AGENTS[0]
        return choice

    def get_proxy_config(self):
        """Constructs the proxy dictionary for Playwright from GUI inputs."""
        proxy_str = self.proxy_entry.get().strip()
        if not proxy_str: return None
        proxy_type = self.proxy_type_var.get().lower() # Ensure lowercase
        # Ensure scheme is added if not present (e.g., user enters 127.0.0.1:8080)
        server = f"{proxy_type}://{proxy_str}" if not proxy_str.startswith(('http://', 'https://', 'socks5://')) else proxy_str
        # Basic validation
        try:
            parsed = urlparse(server)
            if not parsed.hostname or not parsed.port:
                 raise ValueError("Invalid hostname or port")
        except ValueError as e:
             log.warning(f"Invalid proxy format: {proxy_str}. Error: {e}. Ignoring proxy.")
             self.log_message_direct(f"Invalid proxy format ignored: {proxy_str}", level="WARNING")
             return None
        return {"server": server}

    def update_user_ignore_list(self):
        """Updates the list of custom patterns to ignore from the textbox."""
        self.user_ignore_list = [
            line.strip().lower()
            for line in self.ignore_textbox.get("1.0", tk.END).splitlines()
            if line.strip() and not line.strip().startswith('#') # Ignore empty lines and comments
        ]
        log.info(f"Using {len(self.user_ignore_list)} custom ignore patterns.")

    def update_allowed_resource_types(self):
        """Updates the set of allowed resource types based on checkboxes."""
        self.allowed_resource_types = {res_type for res_type, var in self.resource_type_vars.items() if var.get()}
        log.debug(f"Allowed resource types updated: {self.allowed_resource_types}")

    def parse_status_codes(self):
        """Parses the status code entry to create a set of allowed codes."""
        code_input = self.status_code_entry.get().strip().lower()
        self.allowed_status_codes = set() # Reset first

        if not code_input:
            log.debug("Status code filter empty. Defaulting to allow <400 codes.")
            # No specific codes means we use the default logic in is_likely_api_call
            return

        parts = code_input.split(',')
        try:
            for part in parts:
                part = part.strip()
                if not part: continue
                if 'x' in part: # Handle ranges like 2xx, 4xx
                    if len(part) == 3 and part.endswith('xx') and part[0].isdigit():
                        base = int(part[0])
                        if 1 <= base <= 5:
                            self.allowed_status_codes.update(range(base * 100, (base + 1) * 100))
                        else: raise ValueError(f"Invalid range base: {part}")
                    else: raise ValueError(f"Invalid range format: {part}. Use '1xx' to '5xx'.")
                elif part.isdigit(): # Handle specific codes
                     code = int(part)
                     if 100 <= code <= 599:
                         self.allowed_status_codes.add(code)
                     else: raise ValueError(f"Status code out of range (100-599): {part}")
                else: raise ValueError(f"Invalid status code format: {part}")

            log.info(f"Explicit allowed status codes set: {sorted(list(self.allowed_status_codes))}")

        except ValueError as e:
             log.warning(f"Invalid status code input '{code_input}': {e}. Reverting to default (<400).")
             self.log_message_direct(f"Invalid status code input: {e}. Using default.", level="WARNING")
             self.allowed_status_codes = set() # Revert to default behavior on error


    def browse_output_file(self):
        """Opens a save dialog to choose the output JSON/CSV file (placeholder)."""
        # Currently unused, but kept for potential future use (e.g., setting default save path)
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile=os.path.basename(self.output_file_var.get()),
            initialdir=os.path.dirname(self.output_file_var.get()) or "."
        )
        if filename:
             self.output_file_var.set(filename)

    def log_message_direct(self, message, level="INFO", tags=()):
        """
        Directly inserts a message into the log textbox in a thread-safe way.
        Ensures the textbox is temporarily enabled for insertion.
        """
        try:
            # Ensure the textbox is normal before inserting
            self.log_textbox.configure(state=tk.NORMAL)

            level_tag = level.upper()
            # Make sure the level tag exists, otherwise use default 'INFO'
            if level_tag not in self.log_textbox.tag_names():
                level_tag = 'INFO'

            # Combine level tag with any other custom tags
            all_tags = (level_tag,) + tuple(tags)
            self.log_textbox.insert(tk.END, f"{message}\n", all_tags)
            self.log_textbox.see(tk.END) # Scroll to the end

            # Set back to disabled *after* insert, making it read-only
            self.log_textbox.configure(state=tk.DISABLED)

        except Exception as e:
             # Fallback print if GUI logging fails catastrophically
             print(f"Direct Log Error ({level}): {message}\nError: {e}", file=sys.stderr)


    def update_status(self, text):
        """Updates the status bar text."""
        self.status_label.configure(text=f"Status: {text}")

    def show_progress(self, start=True):
        """ Starts or stops the indeterminate progress bar. """
        try:
            if start:
                self.progress_bar.pack(side=tk.LEFT, padx=(10, 0), pady=(0, 2)) # Show progress bar
                self.progress_bar.start(10) # Start animation (10ms interval)
            else:
                self.progress_bar.stop() # Stop animation
                self.progress_bar.pack_forget() # Hide progress bar
        except tk.TclError:
            pass # Ignore errors if widget doesn't exist/window closing

    def clear_log(self):
        """Clears the log textbox and redisplays the banner."""
        try:
            self.log_textbox.configure(state=tk.NORMAL) # Enable for deletion
            self.log_textbox.delete("1.0", tk.END)
            # Banner will re-disable it via log_message_direct
            self.display_banner_in_log()
        except tk.TclError:
             pass # Ignore if widget is destroyed

    def clear_results_and_log(self):
        """Clears results table, detail panes, and the log."""
        if self.scan_thread and self.scan_thread.is_alive():
             messagebox.showwarning("Scan Running", "Cannot clear results while a scan is running.", parent=self)
             return

        # Clear Treeview
        try:
            for item in self.tree.get_children():
                self.tree.delete(item)
        except tk.TclError:
            log.warning("Error clearing Treeview items (widget might be closing).")

        # Clear internal data store
        self.api_results_data = {}
        self.current_selection_iid = None

        # Clear detail textboxes safely
        for textbox in [self.req_headers_text, self.req_body_text, self.resp_headers_text, self.resp_body_text, self.raw_body_text]:
            try:
                textbox.configure(state=tk.NORMAL)
                textbox.delete("1.0", tk.END)
                textbox.configure(state=tk.DISABLED)
            except tk.TclError: pass # Ignore errors if widgets are destroyed
            except AttributeError: pass # Ignore if widget doesn't exist yet

        # Clear filter entry
        self.filter_var.set("")

        # Clear and reset log
        self.clear_log()
        self.update_status("Cleared.")
        log.info("Results and log cleared.")

    def apply_filter(self, *args):
        """Filters the Treeview based on the filter entry content."""
        filter_term = self.filter_var.get().lower()
        # Detach all items first for cleaner filtering when items are *removed* by the filter
        try:
            all_tree_items = self.tree.get_children('')
            if all_tree_items: # Only detach if there are items
                self.tree.detach(*all_tree_items)
        except tk.TclError:
            log.warning("Error detaching Treeview items during filter (widget might be closing).")
            return # Avoid further processing if tree is unusable

        items_to_show_ids = []
        # Iterate through internal data, not the tree itself, for filtering logic
        for api_key, api_data in self.api_results_data.items():
            # Check if any relevant field contains the filter term
            match = ( not filter_term or # Show all if filter is empty
                      filter_term in api_data.get('method', '').lower() or
                      filter_term in str(api_data.get('status', '')).lower() or
                      filter_term in api_data.get('url', '').lower() or
                      filter_term in api_data.get('content_type', '').lower() )
            if match:
                items_to_show_ids.append(api_key)

        # Re-insert matched items in their original order (or sorted order if preferred)
        # Maintaining original insertion order might feel more natural during filtering
        # sorted_items_to_show = sorted(items_to_show, key=lambda k: list(self.api_results_data.keys()).index(k))
        for i, api_key in enumerate(items_to_show_ids):
             try:
                  # Re-attach/move the item to the correct filtered position
                  self.tree.move(api_key, '', i)
             except tk.TclError:
                  # This might happen if the item was somehow deleted between internal check and move
                  log.warning(f"Error moving filtered item {api_key} (might have been deleted).")
                  # Try to re-insert if it doesn't exist (should be rare)
                  if not self.tree.exists(api_key) and api_key in self.api_results_data:
                      self.add_api_to_tree(api_key, self.api_results_data[api_key], index=i)

             except Exception as e:
                  log.error(f"Unexpected error applying filter to item {api_key}: {e}", exc_info=True)

        # Clear selection if the selected item is filtered out
        if self.current_selection_iid and self.current_selection_iid not in items_to_show_ids:
             try:
                 self.tree.selection_set(()) # Empty selection
             except tk.TclError: pass # Ignore if tree closed
             self.clear_details_panes() # Clear details


    def sort_treeview(self, col, reverse):
        """Sorts the Treeview column based on the underlying data."""
        col_map = {"Method": "method", "Status": "status", "URL": "url", "ContentType": "content_type"}
        data_key = col_map.get(col)
        if not data_key: return # Should not happen with current columns

        # Get data only for items *currently visible* in the tree
        try:
            items_to_sort = self.tree.get_children('')
        except tk.TclError:
             log.warning("Cannot sort, Treeview widget likely closed.")
             return
        if not items_to_sort: return # Nothing visible to sort

        # Create a list of tuples (value_to_sort_by, item_id)
        data_list = []
        for item_id in items_to_sort:
            api_data = self.api_results_data.get(item_id) # Get data from internal store
            if api_data:
                 # Use a default value for sorting if key is missing or None
                 sort_val = api_data.get(data_key)
                 data_list.append((sort_val, item_id))
            else:
                # Should not happen if tree is synced with data, but handle defensively
                data_list.append((None, item_id))


        # Determine sort type (numeric for Status, string otherwise)
        is_numeric = (col == "Status")

        # Define a robust sort key function
        def sort_key(item_tuple):
            val, _ = item_tuple
            if val is None: # Handle missing values (sort Nones last)
                return float('inf') if not reverse else float('-inf')
            if is_numeric:
                try: return int(val)
                except (ValueError, TypeError): return float('inf') if not reverse else float('-inf') # Non-numeric status codes last
            else:
                return str(val).lower() # Case-insensitive string sort

        # Perform the sort
        try:
             data_list.sort(key=sort_key, reverse=reverse)
        except Exception as e:
             log.error(f"Error during tree sort: {e}", exc_info=True)
             return # Abort sort on error

        # Reorder items in the treeview
        try:
            for index, (val, item_id) in enumerate(data_list):
                self.tree.move(item_id, '', index)
        except tk.TclError:
             log.warning("Could not move item during sort (widget might be closing).")

        # Update the heading command to reverse sort next time
        self.tree.heading(col, command=lambda: self.sort_treeview(col, not reverse))

    def show_tree_menu(self, event):
        """Displays the right-click context menu for the Treeview."""
        iid = self.tree.identify_row(event.y) # Get item id under cursor
        if iid:
            if iid not in self.tree.selection(): # Select if not already selected
                self.tree.selection_set(iid)
            self.on_tree_select(None) # Update details pane for the selection
            try:
                 # Position and show the menu
                 self.tree_menu.tk_popup(event.x_root, event.y_root)
            finally:
                 # Ensure the menu doesn't block other events
                 self.tree_menu.grab_release()

    def copy_selected_url(self):
        """Copies the URL of the selected Treeview item to the clipboard."""
        if self.current_selection_iid and self.current_selection_iid in self.api_results_data:
            url = self.api_results_data[self.current_selection_iid].get('url', 'N/A')
            try:
                self.clipboard_clear()
                self.clipboard_append(url)
                self.log_message_direct(f"Copied URL: {url}", level="DEBUG")
                self.update_status("URL copied to clipboard.")
            except tk.TclError:
                log.warning("Could not access clipboard.")
                self.update_status("Error: Could not copy URL.")
        else:
            self.log_message_direct("No item selected to copy URL.", level="WARNING")

    def copy_as_curl(self):
        """Generates and copies a basic cURL command for the selected request."""
        if not (self.current_selection_iid and self.current_selection_iid in self.api_results_data):
            self.log_message_direct("No item selected to copy cURL.", level="WARNING")
            self.update_status("Select an item to copy cURL.")
            return

        data = self.api_results_data[self.current_selection_iid]
        url = data.get('url')
        method = data.get('method', 'GET').upper()
        headers = data.get('request_headers', {})
        req_body_bytes = data.get('request_body') # Raw bytes

        if not url:
            self.log_message_direct("Cannot generate cURL: URL missing.", level="ERROR")
            self.update_status("Error: Cannot generate cURL (missing URL).")
            return

        try:
            # Start building the command, quote the URL for shell safety
            # Use single quotes around URL, requires escaping single quotes within it
            url_escaped = url.replace("'", "'\\''")
            curl_cmd = f"curl '{url_escaped}'"

            # Add method if not GET
            if method != 'GET':
                curl_cmd += f" -X {method}"

            # Add headers, escaping single quotes in values
            has_content_type = False
            for key, value in headers.items():
                # Skip headers cURL often handles automatically or are problematic
                if key.lower() in ['content-length', 'host', 'connection', 'transfer-encoding', 'accept-encoding']:
                    continue
                if key.lower() == 'content-type':
                    has_content_type = True
                # Escape single quotes for shell safety
                header_value_escaped = str(value).replace("'", "'\\''")
                curl_cmd += f" -H '{key}: {header_value_escaped}'"

            # Add request body if present
            if req_body_bytes:
                try:
                    # Try decoding as UTF-8 first
                    body_str = req_body_bytes.decode('utf-8')
                    # Escape single quotes for --data-raw
                    body_escaped = body_str.replace("'", "'\\''")
                    # Use --data-raw to prevent cURL's @ processing and send as is
                    curl_cmd += f" --data-raw '{body_escaped}'"

                    # Add common Content-Type if missing and body seems like JSON/form
                    if not has_content_type:
                        if body_str.strip().startswith(('{', '[')):
                             curl_cmd += " -H 'Content-Type: application/json'"
                        # Basic check for form data might be needed here if applicable
                        # elif '=' in body_str and '&' in body_str:
                        #    curl_cmd += " -H 'Content-Type: application/x-www-form-urlencoded'"

                except UnicodeDecodeError:
                    # If it's not UTF-8, treat as binary. Provide user hint.
                    log.warning(f"Request body for {url} is binary. cURL command will need manual handling for '--data-binary'.")
                    curl_cmd += " --data-binary @'<request_body.bin>'" # Placeholder
                    # Maybe suggest Content-Type if missing
                    if not has_content_type:
                         curl_cmd += " -H 'Content-Type: application/octet-stream'"

                except Exception as e:
                     log.error(f"Error processing request body for cURL: {e}")
                     curl_cmd += " --data '[Error processing body]'"

            # Add compression flag if client accepted encoding
            if 'accept-encoding' in {h.lower() for h in headers}:
                 curl_cmd += " --compressed"

            # Copy to clipboard
            self.clipboard_clear()
            self.clipboard_append(curl_cmd)
            self.log_message_direct("Copied basic cURL command.", level="DEBUG")
            self.update_status("cURL command copied to clipboard.")

        except tk.TclError:
            log.warning("Could not access clipboard.")
            self.update_status("Error: Could not copy cURL.")
        except Exception as e:
             log.error(f"Unexpected error generating cURL: {e}", exc_info=True)
             self.update_status("Error generating cURL command.")

    def on_tree_select(self, event):
        """Handles item selection in the Treeview, displays details."""
        try:
            selected_items = self.tree.selection()
            if not selected_items:
                # If selection cleared, maybe clear details or do nothing
                # self.current_selection_iid = None
                # self.clear_details_panes() # Option: clear details when selection is lost
                return

            self.current_selection_iid = selected_items[0]
            self.show_details(self.current_selection_iid)
        except tk.TclError:
            log.warning("Error during tree selection (widget might be closing).")

    def clear_details_panes(self):
         """Clears all detail text boxes safely."""
         for textbox in [self.req_headers_text, self.req_body_text, self.resp_headers_text, self.resp_body_text, self.raw_body_text]:
             try:
                 if textbox.winfo_exists(): # Check if widget exists
                     textbox.configure(state=tk.NORMAL)
                     textbox.delete("1.0", tk.END)
                     textbox.configure(state=tk.DISABLED)
             except Exception: pass # Ignore other potential errors

    def show_details(self, api_key):
        """Populates the detail tabs based on the selected API key."""
        if api_key not in self.api_results_data:
            self.clear_details_panes()
            log.debug(f"No data found for selected key: {api_key}")
            return

        data = self.api_results_data[api_key]

        # --- Helper to populate a textbox ---
        def populate_textbox(textbox, content, highlight_keys=None):
            try:
                if not textbox.winfo_exists(): return
                textbox.configure(state=tk.NORMAL)
                textbox.delete("1.0", tk.END)
                if content:
                    if isinstance(content, dict) and highlight_keys: # For headers
                        for key, value in sorted(content.items()):
                             tag = "interesting_header" if key.lower() in highlight_keys else "normal_header"
                             textbox.insert(tk.END, f"{key}: {value}\n", (tag,))
                        textbox.tag_config("interesting_header", foreground="#FFFF00") # Yellow
                        textbox.tag_config("normal_header", foreground="#CCCCCC") # Default
                    elif isinstance(content, str): # For body text/snippets
                         textbox.insert("1.0", content)
                    else: # Fallback for unexpected types
                         textbox.insert("1.0", str(content))
                else: # Handle empty content
                    textbox.insert("1.0", "[No Content]")
                textbox.configure(state=tk.DISABLED)
            except Exception as e:
                log.error(f"Error populating textbox: {e}", exc_info=True)
                try: # Try to disable textbox even on error
                    textbox.configure(state=tk.DISABLED)
                except: pass

        # --- Populate Textboxes ---
        populate_textbox(self.req_headers_text, data.get('request_headers'), INTERESTING_HEADERS)
        populate_textbox(self.resp_headers_text, data.get('response_headers'), INTERESTING_HEADERS)

        # Process and display request body
        req_body_bytes = data.get('request_body')
        req_body_display = "[No Request Body]"
        if req_body_bytes:
            try:
                req_body_text = req_body_bytes.decode('utf-8', errors='replace')
                # Try pretty-printing JSON
                if req_body_text.strip().startswith(('{', '[')):
                    try: req_body_display = json.dumps(json.loads(req_body_text), indent=2, ensure_ascii=False)
                    except json.JSONDecodeError: req_body_display = req_body_text # Show raw if not valid JSON
                else: req_body_display = req_body_text # Show as text
            except Exception as e:
                log.debug(f"Could not decode request body for display: {e}")
                req_body_display = "[Binary or Undecodable Request Body]"
        populate_textbox(self.req_body_text, req_body_display)

        # Display response snippet (already formatted)
        populate_textbox(self.resp_body_text, data.get('response_snippet', '[N/A]'))

        # Process and display raw response body
        raw_body_b64 = data.get('raw_response_body_bytes')
        raw_body_display = "[No Response Body Captured]"
        if raw_body_b64:
            try:
                raw_body_bytes = base64.b64decode(raw_body_b64)
                content_type = data.get('content_type', '').lower()
                # Try decoding JSON/Text types
                if 'json' in content_type:
                    try:
                        json_text = raw_body_bytes.decode('utf-8', errors='replace')
                        raw_body_display = json.dumps(json.loads(json_text), indent=2, ensure_ascii=False)
                    except Exception: raw_body_display = raw_body_bytes.decode('utf-8', errors='replace') # Fallback to raw text
                elif content_type.startswith('text/') or any(sub in content_type for sub in ['xml', 'javascript', 'html']):
                    try: raw_body_display = raw_body_bytes.decode('utf-8', errors='replace')
                    except Exception: raw_body_display = f"[Binary or Undecodable Text]\n--- Base64 ---\n{raw_body_b64}"
                else: # Assume binary
                     raw_body_display = f"[Binary Data ({content_type or 'Unknown Type'})]\n--- Base64 ---\n{raw_body_b64}"
            except (binascii.Error, ValueError) as b64_err:
                 log.error(f"Base64 decode error for raw body: {b64_err}")
                 raw_body_display = f"[Error decoding Base64: {b64_err}]\n--- Original Data ---\n{raw_body_b64}"
            except Exception as e:
                log.error(f"Error decoding/displaying raw body: {e}", exc_info=True)
                raw_body_display = f"[Error decoding/displaying raw body]\n--- Base64 ---\n{raw_body_b64}"
        populate_textbox(self.raw_body_text, raw_body_display)


    def sanitize_url(self, url_str: str) -> str:
        """Adds scheme if missing and validates basic structure."""
        url_str = url_str.strip()
        if not url_str: raise ValueError("URL cannot be empty.")
        # Prepend https:// if no scheme is present
        if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', url_str):
            log.debug(f"Prepending https:// to URL: {url_str}")
            url_str = 'https://' + url_str
        try:
            parsed = urlparse(url_str)
            # Basic check for scheme and netloc (domain)
            if not parsed.scheme or not parsed.netloc:
                 # Try to handle cases like "https:example.com"
                 if parsed.scheme and not parsed.netloc and parsed.path:
                      url_str = f"{parsed.scheme}://{parsed.path}"
                      parsed = urlparse(url_str) # Reparse

                 # If still invalid, raise error
                 if not parsed.scheme or not parsed.netloc:
                     raise ValueError("Invalid URL format. Ensure it includes scheme and domain.")
            # Reconstruct to ensure clean format (e.g., handles ports correctly)
            return parsed.geturl()
        except Exception as e: # Catch potential errors during parsing
            raise ValueError(f"Invalid URL structure: {e}")


    def start_scan(self):
        """Validates inputs and starts the Playwright scan in a separate thread."""
        url = self.url_entry.get()
        if not url: messagebox.showerror("Input Error", "Target URL is required.", parent=self); return
        try:
             # Sanitize and update the entry field
             target_url = self.sanitize_url(url);
             self.url_entry.delete(0, tk.END); self.url_entry.insert(0, target_url)
        except ValueError as e: messagebox.showerror("Input Error", str(e), parent=self); return

        # Prevent starting multiple scans
        if self.scan_thread and self.scan_thread.is_alive():
            messagebox.showwarning("Scan Running", "A scan is already in progress.", parent=self)
            return

        # --- Prepare Scan Parameters ---
        self.update_status(f"Initializing scan: {target_url}")
        self.show_progress(start=True) # Show progress bar
        log.info(f"Scan initiated for: {target_url}")
        self.stop_event.clear() # Reset stop signal
        self.update_user_ignore_list()
        self.update_allowed_resource_types()
        self.parse_status_codes() # Updates self.allowed_status_codes

        # Combine default and custom ignore lists, remove duplicates
        combined_ignore_list = list(set(DEFAULT_IGNORE_PATTERNS + self.user_ignore_list))
        log.debug(f"Using {len(combined_ignore_list)} combined ignore patterns.")

        # Get form values (filter out empty lines)
        form_values = [line.strip() for line in self.form_values_textbox.get("1.0", tk.END).splitlines() if line.strip()]

        # Build parameter dictionary to pass to the thread
        scan_params = {
            "url": target_url,
            "output_file": self.output_file_var.get(), # Not used by thread, but maybe later
            "scrolls": self.scrolls_var.get(),
            "scroll_delay": self.scroll_delay_var.get(),
            "wait_time": self.wait_time_var.get(),
            "click_selectors": [s.strip() for s in self.click_selectors_entry.get().split(',') if s.strip()],
            "hover_before_click": self.hover_var.get(),
            "form_selector": self.form_selector_entry.get().strip(),
            "form_values_list": form_values,
            "form_submit": self.form_submit_var.get(),
            "form_delay": self.form_delay_var.get(),
            "wait_strategy": self.wait_strategy_var.get(),
            "user_agent": self.get_selected_user_agent(),
            "proxy_config": self.get_proxy_config(),
            "combined_ignore_list": combined_ignore_list,
            "allowed_resource_types": self.allowed_resource_types,
            "allowed_status_codes": self.allowed_status_codes,
            "navigation_timeout": self.nav_timeout_var.get(),
            "action_timeout": self.action_timeout_var.get(),
            "use_stealth": False, # Keep False unless playwright-stealth is explicitly integrated
            "queue": self.result_queue, # Queue for thread communication
            "stop_event": self.stop_event # Event to signal termination
        }

        # --- Update GUI State ---
        self.start_button.configure(state=tk.DISABLED, text="Scanning...")
        self.stop_button.configure(state=tk.NORMAL)
        self.clear_results_and_log() # Clear previous results before new scan

        # --- Start Scan Thread ---
        self.scan_thread = threading.Thread(target=run_playwright_discover_thread, args=(scan_params,), daemon=True)
        self.scan_thread.start()

    def stop_scan(self):
        """Signals the running scan thread to stop."""
        if self.scan_thread and self.scan_thread.is_alive():
            if not self.stop_event.is_set(): # Prevent multiple signals
                log.warning(">>> Stop signal sent by user <<<")
                self.update_status("Attempting to stop scan...")
                self.stop_event.set() # Signal the thread
                self.stop_button.configure(state=tk.DISABLED, text="Stopping...") # Update button state
                # Optionally add a timeout here to join the thread, or let it finish cleanup
            else:
                 log.debug("Stop signal already sent.")
        else:
            log.info("No active scan to stop.")


    def process_gui_queue(self):
        """ Processes messages from the result and log queues to update the GUI. """
        try:
            processed_count = 0
            max_process = 25 # Process up to N messages per cycle to keep GUI responsive

            # Process Log Queue first
            while not self.log_queue.empty() and processed_count < max_process:
                message = self.log_queue.get_nowait()
                if message.get('type') == 'log_record':
                    record = message.get('record')
                    if record:
                         # Check if the record level is sufficient based on GUI setting
                         if record.levelno >= log.getEffectiveLevel():
                             # Format and log the message using the direct method
                             self.log_message_direct(self.queue_handler.format(record), level=record.levelname)
                processed_count += 1

            # Process Result Queue (for status, results, finish signals)
            while not self.result_queue.empty() and processed_count < max_process:
                 message = self.result_queue.get_nowait()
                 msg_type = message.get('type')

                 if msg_type == 'log':
                     # Log messages coming through the result queue (less common now)
                     level_name = message.get('level', 'INFO').upper()
                     level_num = getattr(logging, level_name, logging.INFO)
                     if level_num >= log.getEffectiveLevel():
                          self.log_message_direct(message.get('message', ''), level=level_name)

                 elif msg_type == 'status':
                     # Update status bar and progress indicator
                     self.update_status(message.get('message', ''))
                     self.show_progress(start=message.get('progress', False))

                 elif msg_type == 'api_found':
                     # Add a newly found API to the internal store and potentially the treeview
                     api_data = message.get('data')
                     if api_data:
                         # Create a unique key (e.g., METHOD + URL)
                         # Consider adding a counter for truly identical requests if needed
                         api_key = f"{api_data['method']} {api_data['url']}"
                         if api_key not in self.api_results_data: # Avoid exact duplicates
                             self.api_results_data[api_key] = api_data
                             # Add to tree only if it matches the current filter
                             if self.filter_matches(api_data):
                                 self.add_api_to_tree(api_key, api_data)
                         else:
                             # Log duplicate detection if needed (can be noisy)
                             log.debug(f"Duplicate API key ignored: {api_key}")

                 elif msg_type == 'finished':
                     # Handle scan completion (success)
                     self.scan_finished(success=True, message=message.get('message', 'Scan complete.'))

                 elif msg_type == 'error':
                     # Handle scan failure/error
                     self.scan_finished(success=False, message=message.get('message', 'Scan failed.'))

                 processed_count += 1

        except queue.Empty:
            pass # No messages left in the queue for now
        except Exception as e:
            # Log unexpected errors during queue processing
            log.error(f"Error processing GUI queue: {e}", exc_info=True)
            # Use fallback print to avoid potential recursion if logging itself fails
            print(f"FATAL GUI Error processing queue: {e}", file=sys.stderr)
        finally:
            # Reschedule the check to keep processing queues periodically
            self.after(100, self.process_gui_queue) # Check every 100ms

    def filter_matches(self, api_data):
        """Checks if the api_data dictionary matches the current filter term."""
        filter_term = self.filter_var.get().lower()
        if not filter_term: return True # No filter means always match

        # Check if filter term is present in key fields (case-insensitive)
        return ( filter_term in api_data.get('method', '').lower() or
                 filter_term in str(api_data.get('status', '')).lower() or
                 filter_term in api_data.get('url', '').lower() or
                 filter_term in api_data.get('content_type', '').lower() )


    def add_api_to_tree(self, api_key, api_data, index=tk.END):
        """Adds or updates a single API entry in the Treeview."""
        try:
            if not self.tree.exists(api_key): # Check if item already exists
                method = api_data.get('method', 'N/A')
                url = api_data.get('url', 'N/A')
                status = api_data.get('status', 'N/A')
                content_type = api_data.get('content_type', '').split(';')[0].strip() # Get main type

                # Shorten long URLs for display in the table column
                max_url_len = 80
                display_url = url if len(url) <= max_url_len else url[:max_url_len-3] + "..."

                # Insert the new item at the specified index (or end)
                self.tree.insert("", index, iid=api_key, values=(method, status, display_url, content_type))
                # Optional: Scroll to show the newly added item if desired
                # self.tree.see(api_key)
            else:
                # Item already exists, potentially update it if needed (optional)
                log.debug(f"Item {api_key} already in tree, not re-adding.")

        except tk.TclError as e:
            log.warning(f"TclError adding item {api_key} to tree (widget might be closing): {e}")
        except Exception as e:
            log.error(f"Error adding {api_key} to table: {e}", exc_info=True)


    def scan_finished(self, success=True, message=""):
        """Handles GUI updates when the scan finishes or fails."""
        self.show_progress(start=False) # Stop and hide progress bar
        self.update_status(message)

        # Log final status message with appropriate level and GUI tag
        if success:
            log.info(message) # Log as INFO
            self.log_message_direct(message, level="SUCCESS") # Display with SUCCESS tag (green)
        else:
            log.error(message) # Log as ERROR
            self.log_message_direct(message, level="ERROR") # Display with ERROR tag (red)

        # Reset button states
        self.start_button.configure(state=tk.NORMAL, text="Start Scan")
        self.stop_button.configure(state=tk.DISABLED, text="Stop Scan") # Disable stop, reset text

        # Clear thread reference (important!)
        self.scan_thread = None

        # Determine if results should be saved (only if successful and not stopped)
        should_save = success and self.api_results_data and not self.stop_event.is_set()

        # Optional: Ask to save partial results if stopped manually
        # if success and self.api_results_data and self.stop_event.is_set():
        #    if messagebox.askyesno("Save Partial Results?", "Scan was stopped. Save discovered APIs?", parent=self):
        #        should_save = True

        if should_save:
             output_file = self.output_file_var.get()
             if not output_file: output_file = DEFAULT_OUTPUT_FILE
             # Use save_results_gui which logs via the queue
             save_results_gui(self.api_results_data, output_file, self.result_queue)


    def export_data(self, export_type):
        """Handles exporting data based on the selected menu option."""
        export_all = "All" in export_type
        is_csv = "CSV" in export_type

        data_to_export = {}
        if export_all:
            data_to_export = self.api_results_data # Use all collected data
            log.info(f"Preparing to export all {len(data_to_export)} discovered items.")
        else: # Export only visible items
            try:
                visible_items = self.tree.get_children('')
                if not visible_items:
                    messagebox.showinfo("Export", "No API data currently visible in the table to export.", parent=self)
                    return
                data_to_export = {iid: self.api_results_data[iid] for iid in visible_items if iid in self.api_results_data}
                if not data_to_export:
                     messagebox.showinfo("Export", "Could not retrieve data for visible items.", parent=self)
                     return
                log.info(f"Preparing to export {len(data_to_export)} visible items.")
            except tk.TclError:
                 log.error("Failed to get visible items from Treeview (widget might be closed).")
                 messagebox.showerror("Export Error", "Failed to retrieve visible items from the table.", parent=self)
                 return

        # Determine file extension and dialog title
        file_ext = ".csv" if is_csv else ".json"
        file_type_descr = "CSV files" if is_csv else "JSON files"
        dialog_title = f"Export {'All' if export_all else 'Visible'} Data as {file_type_descr.split(' ')[0]}"

        # Suggest filename based on current output file variable or default
        initial_name_base = os.path.splitext(os.path.basename(self.output_file_var.get()) or DEFAULT_OUTPUT_FILE)[0]
        initial_name = f"{initial_name_base}_{'all' if export_all else 'visible'}{file_ext}"
        initial_dir = os.path.dirname(self.output_file_var.get()) or "."

        # Ask user for save location
        filename = filedialog.asksaveasfilename(
            defaultextension=file_ext,
            filetypes=[(file_type_descr, f"*{file_ext}"), ("All files", "*.*")],
            initialfile=initial_name,
            initialdir=initial_dir,
            title=dialog_title,
            parent=self
        )
        if not filename: return # User cancelled

        # Reset export menu text
        self.export_menu_button.set("Export...")

        # Perform the export
        try:
            if is_csv:
                self.export_to_csv(filename, data_to_export) # Pass the selected data
            else:
                # Use save_results_gui for JSON as it handles logging via queue
                save_results_gui(data_to_export, filename, self.result_queue)
                # Provide feedback (save_results_gui logs, but popup is good UX)
                messagebox.showinfo("Export Complete", f"Data saved as JSON to:\n{filename}", parent=self)
        except Exception as e:
             log.error(f"Error during data export to {filename}: {e}", exc_info=True)
             messagebox.showerror("Export Error", f"An error occurred during export:\n{e}", parent=self)


    def export_to_csv(self, filename, data_to_export):
        """Exports the provided dictionary of API data to a CSV file."""
        if not data_to_export:
            log.warning("No data provided for CSV export.")
            messagebox.showwarning("Export Warning", "No data available to export to CSV.", parent=self)
            return

        try:
            data_list = list(data_to_export.values()) # Get list of api_data dicts
            if not data_list: return # Should not happen if data_to_export is not empty

            # Define primary headers and find others dynamically
            # Include more potentially relevant fields for CSV export
            headers = ['method', 'status', 'url', 'content_type', 'request_body', 'raw_response_body_bytes']
            all_keys = set().union(*(d.keys() for d in data_list))
            # Exclude complex dicts/lists and the snippet which is derived
            excluded_keys = {'request_headers', 'response_headers', 'response_snippet'}
            extra_headers = sorted([k for k in all_keys if k not in headers and k not in excluded_keys])
            final_headers = headers + extra_headers

            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=final_headers, extrasaction='ignore', quoting=csv.QUOTE_ALL) # Quote all fields
                writer.writeheader()
                for item in data_list:
                    row_data = item.copy()
                    # Decode request body for CSV readability if possible
                    if isinstance(row_data.get('request_body'), bytes):
                        try: row_data['request_body'] = row_data['request_body'].decode('utf-8', errors='replace')
                        except: row_data['request_body'] = "[Binary Data]"
                    # Truncate potentially long base64 body in CSV
                    if row_data.get('raw_response_body_bytes') and len(row_data['raw_response_body_bytes']) > 1000: # Limit length in CSV
                         row_data['raw_response_body_bytes'] = row_data['raw_response_body_bytes'][:1000] + "...(truncated)"
                    else: # Ensure it's a string or None for the writer
                         row_data['raw_response_body_bytes'] = row_data.get('raw_response_body_bytes', None)

                    writer.writerow(row_data)

            msg = f"Data exported as CSV to {filename}"
            log.info(msg)
            messagebox.showinfo("Export Complete", f"{msg}", parent=self) # Use log message in popup

        except IOError as e:
            log.error(f"Error writing CSV file {filename}: {e}")
            messagebox.showerror("Export Error", f"Could not write CSV file:\n{e}", parent=self)
        except Exception as e:
            log.error(f"Unexpected error during CSV export: {e}", exc_info=True)
            messagebox.showerror("Export Error", f"An unexpected error occurred during CSV export:\n{e}", parent=self)


# --- Playwright Logic (Adapted for Threading/Queue Communication) ---

def is_likely_api_call_pro_thread(request, response, queue, ignore_list, allowed_types, allowed_codes):
    """
    Checks if a request/response pair looks like an API call based on configured filters.
    This version includes slightly looser heuristics for xhr/fetch types.
    """
    # Early exit checks
    if not request or not response: return False
    if request.method == 'OPTIONS': return False # Ignore OPTIONS preflight requests

    url = request.url # Keep case for potential future use, compare lower
    method = request.method
    status = response.status
    resource_type = request.resource_type or 'other' # Default to 'other' if None

    # --- Filtering Logic ---
    # 1. Resource Type Filter
    if allowed_types and resource_type not in allowed_types:
        # q_log(f"Ignoring (type filter): {resource_type} {url}", "DEBUG") # Can be noisy
        return False

    # 2. Status Code Filter
    if allowed_codes: # If specific codes are provided, ONLY allow those
        if status not in allowed_codes:
            # q_log(f"Ignoring (status filter): {status} {url}", "DEBUG")
            return False
    elif status >= 400: # Default: If no specific codes, ignore errors (>=400)
        # q_log(f"Ignoring (default status >=400): {status} {url}", "DEBUG")
        return False

    # 3. Ignore List Filter (Combined default + custom)
    url_lower = url.lower()
    parsed_url = urlparse(url_lower) # Parse the lowercase URL
    url_path = parsed_url.path
    url_domain = parsed_url.netloc
    if any((ignore_frag in url_domain or ignore_frag in url_path) for ignore_frag in ignore_list if ignore_frag):
        # q_log(f"Ignoring (ignore list): {url}", "DEBUG")
        return False

    # --- API Heuristics ---
    headers = response.headers # Playwright headers are dict-like, case-insensitive access
    content_type = headers.get('content-type', '').lower()

    # Strong indicators: Specific API content types
    if any(api_ct in content_type for api_ct in ['application/json', 'application/xml', 'text/xml', 'application/javascript', 'text/javascript', 'application/vnd.api+json']):
        return True

    # Strong indicator: Non-GET successful requests are often API calls
    if method != 'GET' and status < 400:
        return True

    # Moderate indicator (Looser Heuristic): xhr/fetch types that passed other filters
    # This helps catch APIs that don't use standard content types but are requested via XHR/Fetch
    if resource_type in ["xhr", "fetch"]:
        log.debug(f"Including based on resource type filter pass: {method} {status} {resource_type} {url}")
        return True

    # If it passed filters but didn't match strong or moderate heuristics, exclude it.
    # This avoids including many standard document/script/css loads that might pass basic filters.
    log.debug(f"Excluding (passed filters but no strong API heuristic): {method} {status} {resource_type} {url}")
    return False


def format_response_snippet_pro_thread(body_bytes, content_type):
    """ Generates a display snippet from the response body (UTF-8 focused). """
    if body_bytes is None: return "[No Response Body Captured]"
    if not body_bytes: return "[Empty Response Body]"

    limit = 300 # Max characters for snippet
    try:
        content_type = content_type.lower() if content_type else ''
        # Try decoding as UTF-8 if it's likely text
        is_text_based = content_type.startswith('text/') or any(sub in content_type for sub in ['json', 'xml', 'javascript', 'html'])

        if is_text_based:
            text = body_bytes.decode('utf-8', errors='replace')
            # Try to pretty-print JSON within the snippet
            if 'json' in content_type:
                try:
                    # Attempt to load only the beginning to avoid parsing huge responses
                    potential_json = text[:limit*2] # Load slightly more than limit for parsing
                    data = json.loads(potential_json + ('}' if potential_json.strip().startswith('{') else ']' if potential_json.strip().startswith('[') else '')) # Attempt to close if truncated
                    pretty_text = json.dumps(data, indent=2, ensure_ascii=False)
                    # Truncate *after* pretty printing
                    snippet = pretty_text
                except json.JSONDecodeError:
                    # Show raw text if JSON parsing fails but content-type suggested it
                    snippet = text
            else:
                 # Just return truncated text for other text types
                 snippet = text

            # Truncate the final snippet
            return snippet[:limit] + ('...' if len(snippet) > limit else '')
        else:
            # For binary or unknown, show type and size
            size_kb = len(body_bytes) / 1024
            return f"[Binary Data ({content_type or 'Unknown Type'}), Size: {size_kb:.2f} KB]"
    except Exception as e:
        # Log the error? maybe just return a placeholder
        log.debug(f"Error formatting snippet (size {len(body_bytes)}): {e}")
        return f"[Error formatting snippet, Size: {len(body_bytes)} bytes]"


async def discover_apis_async(params: dict):
    """ The core Playwright automation logic running in the worker thread. """
    # --- Extract parameters for easier access ---
    url = params['url']; queue = params['queue']; stop_event = params['stop_event']
    scrolls = params['scrolls']; scroll_delay = params['scroll_delay']
    wait_time = params['wait_time']; click_selectors = params['click_selectors']
    hover_before_click = params['hover_before_click']
    form_selector = params['form_selector']; form_values_list = params['form_values_list']
    form_submit = params['form_submit']; form_delay = params['form_delay']
    wait_strategy = params['wait_strategy']; user_agent = params['user_agent']
    proxy_config = params['proxy_config']; combined_ignore_list = params['combined_ignore_list']
    allowed_resource_types = params['allowed_resource_types']
    allowed_status_codes = params['allowed_status_codes']
    navigation_timeout = params['navigation_timeout']
    action_timeout = params['action_timeout']
    use_stealth = params.get('use_stealth', False)

    # --- State Variables ---
    processed_req_keys = set() # Use set of (method, url) tuples for faster lookups
    browser = None
    context = None
    page = None

    # --- Helper Functions for Queue Communication ---
    def q_log(message, level="INFO", exc_info=False):
         """ Safely put a log message onto the queue. """
         log_msg = {'type': 'log', 'level': level, 'message': message}
         # Optionally include traceback string for errors
         if exc_info and getattr(logging, level.upper(), 0) >= logging.ERROR:
              log_msg['message'] += f"\n{traceback.format_exc()}"
         try:
             queue.put_nowait(log_msg)
         except queue.Full:
             print(f"Warning: Log queue full. Dropping message: {message}", file=sys.stderr)

    def q_status(message, progress=False):
        """ Safely put a status update onto the queue. """
        try:
            queue.put_nowait({'type': 'status', 'message': message, 'progress': progress})
        except queue.Full:
            print(f"Warning: Result queue full. Dropping status: {message}", file=sys.stderr)


    # --- Main Async Automation Block ---
    try:
        async with async_playwright() as p:
            q_status("Launching browser...", progress=True)
            try:
                 # Launch browser (consider adding channel="chrome" or "msedge" if needed)
                 browser = await p.chromium.launch(headless=True, proxy=proxy_config)
                 q_log(f"Browser launched successfully.", level="DEBUG")
            except PlaywrightError as launch_err:
                 q_log(f"Failed to launch browser: {launch_err}", level="CRITICAL")
                 q_log("Check if Playwright browsers are installed ('playwright install --with-deps')", level="ERROR")
                 queue.put({'type': 'error', 'message': f"Browser Launch Error: {launch_err}"})
                 return # Critical error, cannot proceed
            except Exception as e: # Catch other potential launch errors
                 q_log(f"Unexpected browser launch error: {e}", level="CRITICAL", exc_info=True)
                 queue.put({'type': 'error', 'message': f"Unexpected Launch Error: {e}"})
                 return

            # Check stop event *after* launching browser but *before* context
            if stop_event.is_set(): raise asyncio.CancelledError("Scan stopped before context creation.")

            q_log("Creating browser context.", level="DEBUG")
            try:
                context = await browser.new_context(
                    user_agent=user_agent,
                    viewport={'width': 1920, 'height': 1080}, # Common desktop size
                    java_script_enabled=True,
                    accept_downloads=False, # Don't automatically download files
                    ignore_https_errors=True, # Useful for sites with self-signed certs
                    bypass_csp=True, # Can help scripts load/run, but use cautiously
                    locale="en-US", # Set locale/language
                    timezone_id="America/New_York" # Set timezone
                )
                # Set default timeouts for the context
                context.set_default_navigation_timeout(navigation_timeout)
                context.set_default_timeout(action_timeout) # Default for actions like click, fill
                page = await context.new_page()
                q_log(f"Browser context and page created.", level="DEBUG")
            except Exception as context_err:
                 q_log(f"Failed to create browser context or page: {context_err}", level="CRITICAL", exc_info=True)
                 queue.put({'type': 'error', 'message': f"Context/Page Error: {context_err}"})
                 # Cleanup browser if context failed
                 if browser: await browser.close()
                 return

            # Apply stealth patches if enabled (requires playwright-stealth installed)
            if use_stealth:
                 try:
                     from playwright_stealth import stealth_async
                     q_log("Applying playwright-stealth patches...", level="DEBUG")
                     await stealth_async(page) # Note: stealth often modifies the page object
                     q_log("Stealth patches applied.", level="DEBUG")
                 except ImportError: q_log("playwright-stealth not installed. Skipping stealth.", level="WARNING")
                 except Exception as stealth_err: q_log(f"Could not apply stealth: {stealth_err}", level="WARNING")


            # --- Response Handler ---
            async def handle_response(response):
                """ Callback function executed for each network response. """
                # Check stop event frequently inside the handler
                if stop_event.is_set(): return

                request = response.request # Define request early for logging
                req_url = "unknown_request_url" # Default for logging if request is invalid
                try:
                    # Basic check if request/response objects are valid
                    if not request or not response: return

                    req_url = request.url; req_method = request.method
                    # Use tuple key for faster lookups in the processed set
                    req_key = (req_method, req_url)
                    if req_key in processed_req_keys:
                        # q_log(f"Skipping already processed: {req_method} {req_url}", "DEBUG")
                        return # Already processed this exact request/URL pair

                    # Perform the check using parameters passed to the main function
                    if is_likely_api_call_pro_thread(request, response, queue, combined_ignore_list, allowed_resource_types, allowed_status_codes):
                        # Mark as processed *after* passing the check
                        processed_req_keys.add(req_key)

                        # --- Gather Details (best effort) ---
                        response_body_bytes = None; response_headers = {}; request_headers = {}; request_body_bytes = None
                        try: response_body_bytes = await response.body()
                        except PlaywrightError as e: q_log(f"Could not get response body for {req_url}: {e}", "DEBUG")
                        try: response_headers = dict(await response.all_headers())
                        except PlaywrightError as e: q_log(f"Could not get response headers for {req_url}: {e}", "DEBUG")
                        try: request_headers = dict(await request.all_headers())
                        except PlaywrightError as e: q_log(f"Could not get request headers for {req_url}: {e}", "DEBUG")
                        try:
                            request_body_bytes = request.post_data_buffer # Access attribute directly
                        except PlaywrightError as e: q_log(f"Could not get request post data buffer for {req_url}: {e}", "DEBUG")
                        except Exception as e_body: q_log(f"Unexpected error getting request post data buffer for {req_url}: {e_body}", "DEBUG")

                        content_type = response_headers.get('content-type', '')
                        response_snippet_formatted = format_response_snippet_pro_thread(response_body_bytes, content_type)

                        # Prepare data dictionary for the queue
                        api_key = f"{req_method} {req_url}" # Unique string key for GUI dictionary
                        api_details = {
                            "method": req_method, "url": req_url, "status": response.status,
                            "content_type": content_type, "response_snippet": response_snippet_formatted,
                            "request_headers": request_headers,
                            "request_body": request_body_bytes, # Store raw bytes (or None)
                            "response_headers": response_headers,
                            # Encode raw body bytes to Base64 string for JSON compatibility & display
                            "raw_response_body_bytes": base64.b64encode(response_body_bytes).decode('ascii') if response_body_bytes else None
                        }
                        # Put the found API details onto the queue for the GUI thread
                        try:
                            queue.put_nowait({'type': 'api_found', 'data': api_details})
                            q_log(f"API Found: {req_method} {req_url} ({response.status})", level="SUCCESS") # Log success via queue
                        except queue.Full:
                            q_log(f"Warning: Result queue full. Dropping API data for {req_url}", "WARNING")


                except Exception as e:
                    # Log errors occurring within the handler itself
                    url_for_log = req_url if 'req_url' in locals() and req_url != "unknown_request_url" else response.url if response else "unknown URL"
                    q_log(f"Error processing response {url_for_log}: {e}", level="ERROR", exc_info=True)

            # --- Attach Event Handlers ---
            page.on("response", handle_response)
            # Optional: Add other handlers if needed for deep debugging
            # page.on("request", lambda request: q_log(f">> REQ: {request.method} {request.resource_type} {request.url}", "DEBUG"))
            # page.on("framenavigated", lambda frame: q_log(f"Frame Nav: {frame.url}", "DEBUG"))
            # page.on("load", lambda: q_log("Page Load event fired", "DEBUG"))
            # page.on("domcontentloaded", lambda: q_log("DOM Content Loaded event fired", "DEBUG"))
            # page.on("console", lambda msg: q_log(f"CONSOLE ({msg.type()}): {msg.text()}", "DEBUG"))
            # page.on("pageerror", lambda exc: q_log(f"PAGE ERROR: {exc}", "ERROR"))

            # --- Initial Navigation ---
            q_log(f"Navigating to {url} [UA: {user_agent[:50]}...]", level="INFO")
            try:
                q_status(f"Loading page (wait: {wait_strategy}, timeout: {navigation_timeout}ms)...", progress=True)
                await page.goto(url, wait_until=wait_strategy) # Uses context default timeout
                q_status(f"Page loaded. Initial wait {wait_time}s...", progress=True)
                await asyncio.sleep(wait_time) # Initial settle time after load
            except PlaywrightTimeoutError as e: q_log(f"Navigation timeout for {url}: {e}", level="ERROR")
            except PlaywrightError as e: q_log(f"Navigation/load error for {url}: {e}", level="ERROR")
            except Exception as e: q_log(f"Unexpected error during page load for {url}: {e}", level="ERROR", exc_info=True)
            # Check stop event after initial load attempt
            if stop_event.is_set(): raise asyncio.CancelledError("Scan stopped during initial load.")

            # --- Interaction Phase ---
            q_status("Performing interactions...", progress=True)
            interactions_performed = 0

            # Form Interactions
            if form_selector and form_values_list:
                q_log(f"Attempting form input on '{form_selector}'...", level="INFO")
                for i, form_value in enumerate(form_values_list):
                    if stop_event.is_set(): break # Check stop event between inputs
                    q_log(f"Form Input {i+1}/{len(form_values_list)}: Filling '{form_selector}' with '{form_value[:30]}...'")
                    try:
                        form_input = page.locator(form_selector).first # Target the first match
                        await form_input.scroll_into_view_if_needed(timeout=action_timeout // 2) # Ensure visible first
                        await form_input.fill(form_value, timeout=action_timeout) # Use context default
                        interactions_performed += 1
                        await asyncio.sleep(0.1 + random.uniform(0, 0.2)) # Tiny delay after fill

                        if form_submit:
                            q_log(f"Submitting form via Enter key on '{form_selector}'")
                            await form_input.press("Enter", delay=random.uniform(100, 300))
                            interactions_performed += 1
                            q_status(f"Waiting after submit {i+1} (networkidle)...", progress=True)
                            try:
                                 # Wait for network to likely settle after submission
                                 await page.wait_for_load_state('networkidle', timeout=action_timeout)
                            except PlaywrightTimeoutError: q_log("Timeout waiting network idle after form submit", "WARNING")
                            except PlaywrightError as e: q_log(f"Error waiting after form submit: {e}", "WARNING")
                        # Wait specified delay between form submissions/inputs
                        await asyncio.sleep(form_delay + random.uniform(0, 0.5))
                    except PlaywrightTimeoutError as e: q_log(f"Timeout interacting with form '{form_selector}' for value '{form_value[:30]}...': {e}", level="WARNING")
                    except PlaywrightError as e: q_log(f"Playwright error on form '{form_selector}': {e}", level="WARNING")
                    except Exception as e: q_log(f"Unexpected error during form interaction '{form_selector}': {e}", level="ERROR", exc_info=True)
                # Wait after completing all form interactions
                if interactions_performed > 0 and not stop_event.is_set():
                    q_status("Form input phase finished. Waiting...", progress=True);
                    await asyncio.sleep(wait_time) # Wait specified time after all form fills

            # Check stop event
            if stop_event.is_set(): raise asyncio.CancelledError("Scan stopped after form input.")

            # Click Interactions
            if click_selectors:
                q_log(f"Attempting clicks based on {len(click_selectors)} selector(s)...", level="INFO")
                clicks_done_in_phase = 0
                for selector in click_selectors:
                     if stop_event.is_set(): break # Check stop event between clicks
                     q_log(f"Attempting click: {selector}", level="DEBUG")
                     try:
                         elements = page.locator(selector)
                         count = await elements.count()
                         if count == 0:
                             q_log(f"No elements found for click selector: {selector}", level="DEBUG")
                             continue

                         # Try to click the first visible, enabled element
                         element_to_click = None
                         # Check first few matches for visibility/enabled state
                         for i in range(min(count, 5)): # Limit checks for performance
                             el = elements.nth(i)
                             try:
                                 if await el.is_visible() and await el.is_enabled():
                                    element_to_click = el
                                    break
                             except PlaywrightError as vis_err:
                                 q_log(f"Error checking visibility/enabled for {selector} nth({i}): {vis_err}", level="DEBUG")
                                 continue # Try next element

                         if element_to_click:
                            q_log(f"Found visible/enabled element for {selector}. Attempting click.", level="DEBUG")
                            await element_to_click.scroll_into_view_if_needed(timeout=action_timeout // 2)
                            if hover_before_click:
                                q_log(f"Hovering over {selector}", level="DEBUG")
                                try:
                                    await element_to_click.hover(timeout=action_timeout // 3) # Shorter hover timeout
                                    await asyncio.sleep(0.2 + random.uniform(0, 0.3)) # Short pause after hover
                                except PlaywrightError as hover_err: q_log(f"Hover failed for {selector}: {hover_err}", level="WARNING")

                            # Perform the click with slight random delay
                            await element_to_click.click(delay=random.uniform(50, 200), timeout=action_timeout)
                            q_log(f"Clicked element matching {selector}", level="INFO")
                            clicks_done_in_phase += 1
                            interactions_performed += 1
                            # Wait briefly after click to allow potential async operations
                            await asyncio.sleep(1.0 + random.uniform(0, 0.5))

                            # Optional: Wait for network idle after *each* click? Can be slow.
                            # try:
                            #    q_status(f"Waiting after click {selector} (networkidle)...", progress=True)
                            #    await page.wait_for_load_state('networkidle', timeout=action_timeout // 2)
                            # except PlaywrightTimeoutError: q_log(f"Timeout waiting network idle after clicking {selector}", "DEBUG")

                         else: q_log(f"No visible/enabled element found for click selector: {selector}", level="DEBUG")

                     except PlaywrightTimeoutError as e: q_log(f"Timeout clicking {selector}: {e}", level="WARNING")
                     except PlaywrightError as e: q_log(f"Playwright error clicking {selector}: {e}", level="WARNING")
                     except Exception as e_click: q_log(f"Unexpected error clicking {selector}: {e_click}", level="ERROR", exc_info=True)

                # Wait after completing all click interactions if any were performed
                if clicks_done_in_phase > 0 and not stop_event.is_set():
                     q_status("Click phase finished. Waiting for network...", progress=True)
                     try: await page.wait_for_load_state('networkidle', timeout=action_timeout)
                     except PlaywrightTimeoutError: q_log("Timeout waiting network idle after clicks", "WARNING")
                     except PlaywrightError as e: q_log(f"Error waiting after clicks: {e}", "WARNING")
                     await asyncio.sleep(wait_time) # Additional wait

            # Check stop event
            if stop_event.is_set(): raise asyncio.CancelledError("Scan stopped after clicks.")

            # Scroll Interactions
            if scrolls > 0:
                q_log(f"Performing {scrolls} scroll(s)...", level="INFO")
                for i in range(scrolls):
                    if stop_event.is_set(): break # Check stop event between scrolls
                    q_log(f"Scroll {i+1}/{scrolls}", level="DEBUG")
                    try:
                         # Scroll down the page using JavaScript
                         await page.evaluate('window.scrollTo(0, document.body.scrollHeight)')
                         interactions_performed += 1
                         # Wait specified delay between scrolls
                         await asyncio.sleep(scroll_delay + random.uniform(0, 0.2))
                    except PlaywrightError as e: q_log(f"Error during scroll {i+1}: {e}", level="WARNING")
                    except Exception as e: q_log(f"Unexpected error during scroll {i+1}: {e}", level="ERROR", exc_info=True)

                # Wait after completing all scrolls
                if scrolls > 0 and not stop_event.is_set():
                    q_status("Scrolling finished. Waiting for network...", progress=True)
                    try: await page.wait_for_load_state('networkidle', timeout=action_timeout)
                    except PlaywrightTimeoutError: q_log("Timeout waiting network idle after scroll", "WARNING")
                    except PlaywrightError as e: q_log(f"Error waiting after scroll: {e}", "WARNING")
                    await asyncio.sleep(wait_time) # Final wait after scrolling phase

            # --- Final Wait & Cleanup ---
            if interactions_performed > 0: q_log("Interaction phase complete.", level="INFO")
            else: q_log("No interactions were performed based on settings.", level="INFO")

            if not stop_event.is_set():
                q_log("Allowing final 5s for network settlement before closing...", level="DEBUG")
                await asyncio.sleep(5) # Extra final wait

            if stop_event.is_set(): raise asyncio.CancelledError("Scan stopped after interactions.")
            q_log("Async discovery phase complete.", level="INFO")

    # --- Exception Handling for the entire async block ---
    except asyncio.CancelledError:
         q_log("Scan process was stopped by user signal.", level="WARNING")
         # Results collected so far are already in the queue

    except PlaywrightError as e:
        # Log Playwright-specific errors that weren't caught deeper
        q_log(f"A Playwright error occurred: {e}", level="ERROR", exc_info=True)
        try: queue.put_nowait({'type': 'error', 'message': f"Playwright Error: {e}"})
        except queue.Full: pass

    except Exception as e:
        # Log any other unexpected errors
        q_log(f"An unexpected error occurred during the scan: {e}", level="CRITICAL", exc_info=True)
        try: queue.put_nowait({'type': 'error', 'message': f"Unexpected Scan Error: {e}"})
        except queue.Full: pass

    # --- Cleanup ---
    finally:
        q_log("Closing browser context and browser.", level="INFO")
        # Close page, context, and browser safely
        if page:
             try: await page.close()
             except Exception as e: q_log(f"Error closing page: {e}", "DEBUG")
        if context:
            try: await context.close()
            except Exception as e: q_log(f"Error closing context: {e}", "DEBUG")
        if browser:
            try:
                 await browser.close()
                 q_log("Browser closed.", level="INFO")
            except Exception as e: q_log(f"Error closing browser: {e}", "DEBUG")
        q_log("Async function finished.", level="DEBUG")


def run_playwright_discover_thread(params: dict):
    """ Wrapper function to run the async Playwright logic in a separate thread. """
    queue = params['queue']
    stop_event = params['stop_event']
    try:
        # Create a new event loop for this thread
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        # Run the main async function until it completes or is cancelled
        loop.run_until_complete(discover_apis_async(params))
        loop.close() # Clean up the loop

        # Check if the scan was stopped *before* sending the final finished message
        if not stop_event.is_set():
            # Send a 'finished' message if the scan completed normally
            try: queue.put_nowait({'type': 'finished', 'message': f"Scan finished. Check results table."})
            except queue.Full: log.warning("Result queue full, couldn't send 'finished' message.")
        else:
             # Send appropriate message if stopped by user
             try: queue.put_nowait({'type': 'finished', 'message': f"Scan stopped by user. Check results table."})
             except queue.Full: log.warning("Result queue full, couldn't send 'stopped' message.")


    except Exception as e:
        # Log the error in the main thread's logger as well for visibility
        log.exception("Error in worker thread execution")
        # Send error message to the GUI queue
        try: queue.put_nowait({'type': 'error', 'message': f"Worker thread error: {e}"})
        except queue.Full: pass


def save_results_gui(apis_data_dict, filename, queue):
    """ Saves the provided API data dictionary to a JSON file. Logs messages via the queue. """
    if not apis_data_dict:
        try: queue.put_nowait({'type': 'log', 'level': 'WARNING', 'message': "No API data provided to save."})
        except queue.Full: pass
        return

    # Convert the dictionary values (which contain the API details) to a list
    data_to_save = list(apis_data_dict.values())

    # Remove fields not suitable for basic JSON export if necessary
    # (e.g., complex objects, or derived fields like response_snippet)
    # Keep raw request/response bodies (base64 encoded) for potential analysis
    for item in data_to_save:
        item.pop('response_snippet', None) # Remove snippet as it's derived/truncated

    try:
        with open(filename, 'w', encoding='utf-8') as f:
            # Use ensure_ascii=False for proper UTF-8 output without escaping non-ASCII chars
            json.dump(data_to_save, f, indent=2, ensure_ascii=False)
        # Log success via queue
        try: queue.put_nowait({'type': 'log', 'level': 'SUCCESS', 'message': f"API details saved to {filename}"})
        except queue.Full: pass
    except IOError as e:
        try: queue.put_nowait({'type': 'log', 'level': 'ERROR', 'message': f"Error writing results to {filename}: {e}"})
        except queue.Full: pass
    except TypeError as e:
         # This might happen if data isn't JSON serializable (e.g., raw bytes left somehow)
         try: queue.put_nowait({'type': 'log', 'level': 'ERROR', 'message': f"Error serializing results to JSON: {e}"})
         except queue.Full: pass
    except Exception as e:
        try: queue.put_nowait({'type': 'log', 'level': 'ERROR', 'message': f"Unexpected error saving results: {e}"})
        except queue.Full: pass


# --- Main Execution Block ---
if __name__ == "__main__":
    # Setup basic console logging first for early errors during startup
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(log_formatter)
    console_handler.setLevel(logging.INFO) # Show INFO level and above on console initially
    log.addHandler(console_handler)

    try:
        # Check if running in a virtual environment (recommended)
        if sys.prefix == sys.base_prefix:
             log.warning("Consider running in a Python virtual environment (venv) for better dependency management.")

        # Initialize and run the application
        app = ViperApiGuiPro()
        # Remove console handler once GUI is up and QueueHandler takes over logging to the GUI
        log.removeHandler(console_handler)
        app.mainloop() # Start the Tkinter event loop

    except ImportError as e:
         # Handle missing critical dependencies
         log.critical(f"ImportError: Required library not found - {e}. Please install requirements.", exc_info=True)
         # Try to show a messagebox if tkinter is available, otherwise print to stderr
         if 'messagebox' in globals() and 'tk' in globals():
            try:
                root = tk.Tk(); root.withdraw() # Create hidden root window for messagebox
                messagebox.showerror("Dependency Error", f"Failed to import required library: {e}\n\nPlease install the necessary requirements (e.g., pip install -r requirements.txt).")
                root.destroy()
            except: # Fallback if even basic Tkinter fails
                print(f"FATAL: Failed to import required library: {e}. Please install requirements.", file=sys.stderr)
         else:
             print(f"FATAL: Failed to import required library: {e}. Please install requirements.", file=sys.stderr)
         sys.exit(1) # Exit with error code

    except Exception as main_err:
         # Catch any other unexpected fatal errors during initialization
         log.critical(f"Fatal error initializing Viper API Interceptor: {main_err}", exc_info=True)
         try:
             # Attempt to show a simple Tkinter error box if possible
             root = tk.Tk(); root.withdraw()
             messagebox.showerror("Fatal Error", f"Failed to start Viper API Interceptor:\n\n{main_err}\n\nCheck console/logs for details.")
             root.destroy()
         except Exception:
             # Ultimate fallback if GUI cannot be shown
             print(f"FATAL: Failed to start Viper API Interceptor: {main_err}", file=sys.stderr)
         sys.exit(1) # Exit with error code