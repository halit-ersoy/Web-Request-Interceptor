from seleniumwire import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.options import Options
import time
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import threading
import json
import os
import pyperclip
import datetime
import chardet
import base64
import gzip
import mimetypes

class RequestInterceptorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Web Request Interceptor")
        self.root.geometry("1280x720")

        self.driver = None
        self.monitoring = False
        self.monitor_thread = None
        self.captured_requests = []
        self.view_mode = tk.StringVar(value="text")
        self.format_json = tk.BooleanVar(value=True)

        self.setup_ui()

    def setup_ui(self):
        # Top control frame
        control_frame = ttk.Frame(self.root, padding=10)
        control_frame.pack(fill=tk.X)

        # URL input
        ttk.Label(control_frame, text="URL:").pack(side=tk.LEFT, padx=(0, 5))
        self.url_var = tk.StringVar(value="https://www.google.com")
        ttk.Entry(control_frame, textvariable=self.url_var, width=50).pack(side=tk.LEFT, padx=(0, 10))

        # Filter input
        ttk.Label(control_frame, text="Filter:").pack(side=tk.LEFT, padx=(0, 5))
        self.filter_var = tk.StringVar(value="")
        ttk.Entry(control_frame, textvariable=self.filter_var, width=30).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Label(control_frame, text="(comma separated, leave empty for all)").pack(side=tk.LEFT, padx=(0, 5))

        # Buttons
        self.start_btn = ttk.Button(control_frame, text="Start Monitoring", command=self.start_monitoring)
        self.start_btn.pack(side=tk.LEFT, padx=5)

        self.stop_btn = ttk.Button(control_frame, text="Stop", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        # Notebook with tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Requests list tab
        self.requests_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.requests_frame, text="Captured Requests")

        # Create copy URL button above tree
        copy_frame = ttk.Frame(self.requests_frame)
        copy_frame.pack(fill=tk.X, pady=(0, 5))
        ttk.Button(copy_frame, text="Copy URL", command=self.copy_selected_url).pack(side=tk.LEFT)

        # Create treeview for requests
        columns = ("timestamp", "url", "type", "size")
        self.tree = ttk.Treeview(self.requests_frame, columns=columns, show="headings")

        self.tree.heading("timestamp", text="Time")
        self.tree.heading("url", text="URL")
        self.tree.heading("type", text="Content Type")
        self.tree.heading("size", text="Size")

        self.tree.column("timestamp", width=150)
        self.tree.column("url", width=450)
        self.tree.column("type", width=150)
        self.tree.column("size", width=100)

        scrollbar = ttk.Scrollbar(self.requests_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree.bind("<Double-1>", self.show_content)
        self.setup_url_copying()

        # Content view tab
        self.content_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.content_frame, text="Content Viewer")

        # View control frame
        view_control_frame = ttk.Frame(self.content_frame)
        view_control_frame.pack(fill=tk.X, pady=5)

        ttk.Label(view_control_frame, text="View as:").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(view_control_frame, text="Text", variable=self.view_mode, value="text",
                        command=lambda: self.refresh_content_view()).pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(view_control_frame, text="Hex", variable=self.view_mode, value="hex",
                        command=lambda: self.refresh_content_view()).pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(view_control_frame, text="Base64", variable=self.view_mode, value="base64",
                        command=lambda: self.refresh_content_view()).pack(side=tk.LEFT, padx=5)

        # Add JSON formatting checkbox
        ttk.Checkbutton(view_control_frame, text="Format JSON", variable=self.format_json,
                        command=lambda: self.refresh_content_view()).pack(side=tk.LEFT, padx=10)

        self.encoding_var = tk.StringVar(value="auto")
        ttk.Label(view_control_frame, text="Encoding:").pack(side=tk.LEFT, padx=5)
        encodings = ["auto", "utf-8", "latin-1", "ascii", "utf-16", "cp1252"]
        encoding_combo = ttk.Combobox(view_control_frame, textvariable=self.encoding_var, values=encodings, width=10)
        encoding_combo.pack(side=tk.LEFT, padx=5)
        encoding_combo.bind("<<ComboboxSelected>>", lambda e: self.refresh_content_view())

        # Add content text area
        self.content_text = scrolledtext.ScrolledText(self.content_frame, wrap=tk.WORD)
        self.content_text.pack(fill=tk.BOTH, expand=True)

        # Headers tab
        self.headers_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.headers_frame, text="Headers")

        # Add headers text area
        self.headers_text = scrolledtext.ScrolledText(self.headers_frame, wrap=tk.WORD)
        self.headers_text.pack(fill=tk.BOTH, expand=True)

        # Bottom button frame
        bottom_frame = ttk.Frame(self.root, padding=10)
        bottom_frame.pack(fill=tk.X)

        ttk.Button(bottom_frame, text="Save Raw Content", command=self.save_raw_content).pack(side=tk.RIGHT)
        ttk.Button(bottom_frame, text="Save Content", command=self.save_content).pack(side=tk.RIGHT, padx=10)
        ttk.Button(bottom_frame, text="Clear All", command=self.clear_all).pack(side=tk.RIGHT, padx=10)

        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W).pack(fill=tk.X, side=tk.BOTTOM)

    def setup_url_copying(self):
        # Add right-click context menu
        self.context_menu = tk.Menu(self.tree, tearoff=0)
        self.context_menu.add_command(label="Copy URL", command=self.copy_selected_url)

        # Bind right-click to show context menu
        self.tree.bind("<Button-3>", self.show_context_menu)

        # Bind Ctrl+C to copy URL
        self.tree.bind("<Control-c>", lambda event: self.copy_selected_url())

    def show_context_menu(self, event):
        # Check if anything is selected
        if self.tree.selection():
            # Show context menu at mouse position
            self.context_menu.post(event.x_root, event.y_root)

    def copy_selected_url(self):
        selected_items = self.tree.selection()
        if not selected_items:
            self.status_var.set("No item selected")
            return

        selected_item = selected_items[0]
        idx = self.tree.index(selected_item)

        if 0 <= idx < len(self.captured_requests):
            url = self.captured_requests[idx]["url"]
            pyperclip.copy(url)
            self.status_var.set(f"URL copied to clipboard: {url}")

    def start_monitoring(self):
        if self.driver:
            self.stop_monitoring()

        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status_var.set("Starting browser...")

        # Start monitoring in a separate thread
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self.monitor_requests)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()

    def monitor_requests(self):
        try:
            # Chrome options
            chrome_options = Options()
            chrome_options.add_argument("--start-maximized")

            # Disable browser debugging detection
            chrome_options.add_argument("--disable-blink-features=AutomationControlled")
            chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
            chrome_options.add_experimental_option('useAutomationExtension', False)

            # Add CDP command to disable JavaScript debugger statements
            chrome_options.add_experimental_option("prefs", {
                "custom_handlers.protocol_handler": {
                    "excluded_schemes": {
                        "javascript": True
                    }
                }
            })

            # Initialize driver
            self.driver = webdriver.Chrome(
                service=Service(ChromeDriverManager().install()),
                options=chrome_options
            )

            # Execute script to bypass debugger statements
            self.driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {
                "source": """
                    // Overwrite the debugger function
                    Object.defineProperty(window, 'debugger', {
                        get: function() {
                            return function() {};
                        }
                    });
    
                    // Override the Function constructor to disable debugger statements
                    const originalFunction = Function;
                    Function = function() {
                        const args = Array.from(arguments);
                        const functionBody = args.pop();
                        if (functionBody && functionBody.includes('debugger')) {
                            const cleanBody = functionBody.replace(/debugger/g, '// debugger disabled');
                            return originalFunction(...args, cleanBody);
                        }
                        return originalFunction(...arguments);
                    };
                    Function.prototype = originalFunction.prototype;
    
                    // Notify DevTools that this page has been modified
                    delete window.__webdriver_script_fn;
                """
            })

            # Navigate to URL
            url = self.url_var.get()
            self.root.after(0, lambda: self.status_var.set(f"Navigating to {url}..."))
            self.driver.get(url)

            # Get filters - if empty, capture all requests
            filter_text = self.filter_var.get().strip()
            filters = [f.strip().lower() for f in filter_text.split(",")] if filter_text else []

            # Monitor requests
            self.root.after(0, lambda: self.status_var.set("Monitoring for requests..."))

            # Use a more reliable tracking system for processed requests
            processed_urls = set()  # Track processed URLs

            while self.monitoring:
                for req in self.driver.requests:
                    if not req.response:
                        continue  # Skip requests that haven't completed yet

                    url = req.url.lower()

                    # Create a unique identifier for this request
                    # Use url + method + response status to identify unique requests
                    req_identifier = f"{req.method}:{url}:{req.response.status_code if req.response else 0}"

                    if req_identifier in processed_urls:
                        continue  # Skip already processed requests

                    # Check if this request matches our filters or if no filters are specified
                    if not filters or any(f in url for f in filters):
                        processed_urls.add(req_identifier)  # Mark as processed

                        # Get response data and headers
                        raw_content = b""
                        request_headers = {}
                        response_headers = {}

                        # Capture request headers
                        if req.headers:
                            request_headers = dict(req.headers)

                        # Capture response and its headers
                        if req.response:
                            if req.response.body:
                                raw_content = req.response.body
                            if req.response.headers:
                                response_headers = dict(req.response.headers)

                        # Determine content type from headers or file extension
                        content_type = "Unknown"
                        if "content-type" in response_headers:
                            content_type = response_headers["content-type"].split(";")[0]
                        else:
                            # Try to guess from URL
                            content_type, _ = mimetypes.guess_type(url)
                            if not content_type:
                                content_type = "Unknown"

                        # Create request entry with info
                        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        size = len(raw_content) if raw_content else 0

                        entry = {
                            "timestamp": timestamp,
                            "url": url,
                            "type": content_type,
                            "size": f"{size} bytes",
                            "content_loaded": False,
                            "raw_content": raw_content,
                            "request_headers": request_headers,
                            "response_headers": response_headers,
                            "path": req.path,
                            "method": req.method,
                        }

                        self.captured_requests.append(entry)
                        self.root.after(0, lambda e=entry: self.add_request_to_tree(e))

                time.sleep(0.5)  # Check more frequently but don't overwhelm the CPU

        except Exception as e:
            self.root.after(0, lambda: self.status_var.set(f"Error: {str(e)}"))
        finally:
            if not self.monitoring:
                self.close_driver()

    def add_request_to_tree(self, entry):
        self.tree.insert("", "end", values=(
            entry["timestamp"],
            entry["url"],
            entry["type"],
            entry["size"]
        ))
        self.status_var.set(f"Captured request: {entry['url']}")

    def show_content(self, event):
        selected_items = self.tree.selection()
        if not selected_items:
            return

        selected_item = selected_items[0]
        idx = self.tree.index(selected_item)
        if 0 <= idx < len(self.captured_requests):
            entry = self.captured_requests[idx]

            # Load content if not already loaded
            if not entry["content_loaded"]:
                self.status_var.set(f"Loading content for request: {entry['url']}")
                self.load_request_content(idx)

            # Show headers
            self.headers_text.delete("1.0", tk.END)

            # Display request headers
            req_headers = entry.get("request_headers", {})
            if req_headers:
                self.headers_text.insert(tk.END, "=== REQUEST HEADERS ===\n")
                for key, value in req_headers.items():
                    self.headers_text.insert(tk.END, f"{key}: {value}\n")

                self.headers_text.insert(tk.END, f"\n{entry.get('method', 'GET')} {entry.get('path', '')}\n\n")

            # Display response headers
            resp_headers = entry.get("response_headers", {})
            if resp_headers:
                self.headers_text.insert(tk.END, "=== RESPONSE HEADERS ===\n")
                for key, value in resp_headers.items():
                    self.headers_text.insert(tk.END, f"{key}: {value}\n")

            self.current_content_idx = idx
            self.refresh_content_view()
            self.notebook.select(1)  # Switch to content viewer tab

    def load_request_content(self, idx):
        """Process content for the specified request"""
        entry = self.captured_requests[idx]
        raw_content = entry.get("raw_content", b"")
        response_headers = entry.get("response_headers", {})

        # Check if content is gzip encoded
        if "content-encoding" in response_headers and "gzip" in response_headers["content-encoding"].lower():
            try:
                # Decompress gzip content
                raw_content = gzip.decompress(raw_content)
                entry["raw_content"] = raw_content  # Store decompressed content
                entry["decompressed"] = True
            except Exception as e:
                # Some servers incorrectly mark content as gzip when it's not
                self.status_var.set(f"Warning: Content marked as gzip but failed to decompress: {str(e)}")
                # Continue with the original raw content
                entry["decompression_failed"] = True

        # Try to detect if content is JSON regardless of content type
        if raw_content and (raw_content.startswith(b'{') or raw_content.startswith(b'[')):
            entry["is_json"] = True
            entry["is_text"] = True

        # Determine content type from headers
        content_type = response_headers.get("content-type", "").lower()

        # Set flags for special content types
        if not entry.get("is_json", False):  # Don't override if we already detected JSON
            entry["is_json"] = "application/json" in content_type
        entry["is_xml"] = "application/xml" in content_type or "text/xml" in content_type
        entry["is_html"] = "text/html" in content_type
        entry["is_text"] = "text/" in content_type or entry.get("is_json", False) or entry.get("is_xml", False)

        # Extract charset if specified
        charset = "utf-8"  # Default
        if "charset=" in content_type:
            charset_part = content_type.split("charset=")[1].split(";")[0].strip()
            if charset_part:
                charset = charset_part

        # Process content if available
        if raw_content:
            # First try specified charset if it's likely text content
            if entry.get("is_text", False):
                try:
                    content = raw_content.decode(charset)
                    detected_encoding = charset
                except (UnicodeDecodeError, LookupError):
                    # If specified charset fails, auto-detect
                    detection = chardet.detect(raw_content)
                    detected_encoding = detection['encoding'] if detection and detection['encoding'] and detection['confidence'] > 0.7 else 'utf-8'
                    try:
                        content = raw_content.decode(detected_encoding)
                    except (UnicodeDecodeError, TypeError):
                        # Last resort - use latin-1 which can decode any byte sequence
                        detected_encoding = 'latin-1'
                        content = raw_content.decode('latin-1')
            else:
                # Binary content
                content = "[Binary content - view in Hex or Base64 mode]"
                detected_encoding = 'utf-8'
        else:
            content = "[No response body]"
            detected_encoding = 'utf-8'

        # Update entry with processed content
        entry["content"] = content
        entry["detected_encoding"] = detected_encoding
        entry["content_loaded"] = True

    def refresh_content_view(self):
        if not hasattr(self, 'current_content_idx'):
            return

        idx = self.current_content_idx
        if 0 <= idx < len(self.captured_requests):
            entry = self.captured_requests[idx]

            # Check if content is loaded
            if not entry["content_loaded"]:
                self.content_text.delete("1.0", tk.END)
                self.content_text.insert("1.0", "Loading content...")
                return

            raw_content = entry.get("raw_content", b"")
            self.content_text.delete("1.0", tk.END)

            view_mode = self.view_mode.get()
            encoding = self.encoding_var.get()

            if not raw_content:
                self.content_text.insert("1.0", entry.get("content", "[No content available]"))
                return

            if view_mode == "hex":
                # Display as hex
                hex_view = ' '.join(f'{b:02x}' for b in raw_content)
                self.content_text.insert("1.0", hex_view)
            elif view_mode == "base64":
                # Display as base64
                b64_content = base64.b64encode(raw_content).decode('ascii')
                self.content_text.insert("1.0", b64_content)
            else:
                # Display as text with selected encoding
                try:
                    if encoding == "auto":
                        encoding = entry.get("detected_encoding", "utf-8")

                    text_content = entry.get("content", "")

                    # Format JSON if requested and content is JSON
                    if self.format_json.get() and entry.get("is_json", False):
                        try:
                            parsed_json = json.loads(text_content)
                            text_content = json.dumps(parsed_json, indent=4, ensure_ascii=False)
                        except json.JSONDecodeError:
                            # If JSON parsing fails, just use the original content
                            pass

                    # For binary content that we're trying to show as text
                    if text_content == "[Binary content - view in Hex or Base64 mode]":
                        try:
                            # Try to decode with selected encoding anyway
                            text_content = raw_content.decode(encoding, errors='replace')
                        except:
                            pass

                    self.content_text.insert("1.0", text_content)
                except Exception as e:
                    self.content_text.insert("1.0", f"[Error displaying content: {str(e)}]")

    def save_content(self):
        if not self.content_text.get("1.0", tk.END).strip():
            return

        # Determine file extension based on content type
        default_ext = ".txt"
        filetypes = [("All files", "*.*"), ("Text files", "*.txt")]

        if hasattr(self, 'current_content_idx'):
            idx = self.current_content_idx
            if 0 <= idx < len(self.captured_requests):
                entry = self.captured_requests[idx]
                content_type = entry.get("type", "").lower()

                # Add appropriate file types based on content
                if entry.get("is_json", False):
                    default_ext = ".json"
                    filetypes.insert(1, ("JSON files", "*.json"))
                elif entry.get("is_xml", False):
                    default_ext = ".xml"
                    filetypes.insert(1, ("XML files", "*.xml"))
                elif entry.get("is_html", False):
                    default_ext = ".html"
                    filetypes.insert(1, ("HTML files", "*.html"))
                elif "vtt" in content_type:
                    default_ext = ".vtt"
                    filetypes.insert(1, ("VTT files", "*.vtt"))
                elif "srt" in content_type:
                    default_ext = ".srt"
                    filetypes.insert(1, ("SRT files", "*.srt"))

                # Try to extract extension from URL if content type doesn't help
                if default_ext == ".txt":
                    url = entry.get("url", "")
                    file_part = url.split("?")[0].split("/")[-1]
                    if "." in file_part:
                        ext = "." + file_part.split(".")[-1]
                        if len(ext) < 6:  # Reasonable extension length
                            default_ext = ext
                            filetypes.insert(1, (f"{ext.upper()} files", f"*{ext}"))

        file_path = filedialog.asksaveasfilename(
            defaultextension=default_ext,
            filetypes=filetypes
        )

        if file_path:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(self.content_text.get("1.0", tk.END))
            self.status_var.set(f"Content saved to {file_path}")

    def save_raw_content(self):
        if not hasattr(self, 'current_content_idx'):
            messagebox.showinfo("Info", "No content selected")
            return

        idx = self.current_content_idx
        if 0 <= idx < len(self.captured_requests):
            entry = self.captured_requests[idx]

            if not entry["content_loaded"]:
                messagebox.showinfo("Info", "Content not loaded yet")
                return

            raw_content = entry.get("raw_content", b"")

            if not raw_content:
                messagebox.showinfo("Info", "No raw content available")
                return

            # Try to get appropriate extension
            default_ext = ".bin"
            filetypes = [("Binary files", "*.bin"), ("All files", "*.*")]

            url = entry.get("url", "")
            content_type = entry.get("type", "").lower()

            # Try to use URL file extension if available
            file_part = url.split("?")[0].split("/")[-1]
            if "." in file_part:
                ext = "." + file_part.split(".")[-1]
                if len(ext) < 6:  # Reasonable extension length
                    default_ext = ext
                    filetypes.insert(1, (f"{ext.upper()} files", f"*{ext}"))

            # Or use MIME type
            elif content_type and content_type != "Unknown":
                ext = mimetypes.guess_extension(content_type)
                if ext:
                    default_ext = ext
                    filetypes.insert(1, (f"{ext.upper()} files", f"*{ext}"))

            file_path = filedialog.asksaveasfilename(
                defaultextension=default_ext,
                filetypes=filetypes
            )

            if file_path:
                with open(file_path, "wb") as f:
                    f.write(raw_content)
                self.status_var.set(f"Raw content saved to {file_path}")

    def stop_monitoring(self):
        self.monitoring = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_var.set("Monitoring stopped")
        self.close_driver()

    def close_driver(self):
        if self.driver:
            try:
                self.driver.quit()
            except:
                pass
            finally:
                self.driver = None

    def clear_all(self):
        self.tree.delete(*self.tree.get_children())
        self.content_text.delete("1.0", tk.END)
        self.headers_text.delete("1.0", tk.END)
        self.captured_requests = []
        self.status_var.set("All data cleared")
        if hasattr(self, 'current_content_idx'):
            delattr(self, 'current_content_idx')

def main():
    root = tk.Tk()
    app = RequestInterceptorApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()