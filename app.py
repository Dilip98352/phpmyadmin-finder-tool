import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import requests
from urllib.parse import urlparse, urlunparse, urljoin
import threading
import queue
import hashlib
import re
import time

# --- Configuration ---
# More comprehensive list including common misspellings or versioned paths
EXTENDED_PMA_PATHS = [
    "phpmyadmin", "phpMyAdmin", "PMA", "pma", "mysqladmin", "admin/phpmyadmin", "dbadmin",
    "mysql", "phpmyadmin2", "phpmyadmin3", "phpmyadmin4", "phpmyadmin5",
    "phpMyAdmin-5.2.1-all-languages", "phpMyAdmin-5.1.3-all-languages",
    "phpMyAdmin-5.0.4-all-languages", "phpMyAdmin-4.9.10-all-languages",
    "tools/phpmyadmin", "web/phpmyadmin", "manage/phpmyadmin", "adminpma", "myadmin",
    "phpadmin", "sql", "admin/mysql", "admin/pma", "phpmyAdmin", "phpMyadmin",
    "phpmyadminer", "adminer", "db", "database", "sqladmin", "webadmin/phpmyadmin",
    "php/phpmyadmin", "pmaold", "PMAOLD", "oldphpmyadmin", "PMA2023", "PMA2024",
    "phpmyadmin/index.php", "phpMyAdmin/index.php", "pma/index.php"
]

COMMON_SUBDOMAINS = [
    "", # For the base domain itself
    "db", "mysql", "phpmyadmin", "pma", "sql", "database", "admin", "my",
    "devsql", "testsql", "control", "cpanel", "directadmin" # Common hosting panel subdomains
]

# Common ports, including those for cPanel/WHM etc.
TARGET_PORTS = [None, 80, 443, 8080, 8000, 8888, 8008, 2082, 2083, 2086, 2087, 2095, 2096, 10000] # Added Webmin

# Keywords to identify a phpMyAdmin page (more specific)
PMA_TITLE_REGEX = r"<title>phpmyadmin\s*[^<]*</title>" # Case insensitive
PMA_BODY_KEYWORDS = [
    "pma_token", "pma_username", "phpmyadmin.net", "Welcome to phpMyAdmin",
    " PMA_VERSION ", "phpMyAdmin setup", "pma_config.inc.php",
    'name="pma_servername"', 'name="pma_username"', 'id="input_username"',
    'src="themes/pmahomme/img/logo_right.png"', # Common theme image
    'PMA_sprintf("SELECT %s FROM %s.%s")', # Code snippet often in comments
]

# Known phpMyAdmin favicon.ico MD5 hash (This can vary slightly, best to have a few)
# You can get this by downloading favicon.ico from a known PMA instance and hashing it
# Example: open a PMA instance, go to /favicon.ico, save it, then:
# python -c "import hashlib; print(hashlib.md5(open('favicon.ico', 'rb').read()).hexdigest())"
KNOWN_PMA_FAVICON_HASHES = [
    "c7e4731730979f99c85943838860059c", # A common one
    "376c6354f9583812e26cb99639584801", # Another possibility
    "7cdee2cb03589f19a349928989356741"  # PMA 5.x
]

REQUEST_TIMEOUT = 7  # seconds
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.84 Safari/537.36 PMAScanner/1.1"

# --- Helper Functions ---
def is_likely_phpmyadmin_page(response_text, response_url):
    text_lower = response_text.lower()
    if re.search(PMA_TITLE_REGEX, text_lower, re.IGNORECASE):
        return True
    for keyword in PMA_BODY_KEYWORDS:
        if keyword.lower() in text_lower:
            return True
    # Check if the final URL path itself is a strong indicator
    parsed_final_url = urlparse(response_url)
    if any(p.lower() in parsed_final_url.path.lower() for p in ["phpmyadmin", "/pma/"]):
        return True
    return False

def get_favicon_hash(session, base_url_for_favicon):
    try:
        favicon_url = urljoin(base_url_for_favicon, "favicon.ico")
        # Try common link rel in head if direct favicon.ico fails
        # This part can be extended to parse HTML for <link rel="icon" ...>
        response = session.get(favicon_url, timeout=REQUEST_TIMEOUT-2, allow_redirects=True, verify=False)
        if response.status_code == 200 and response.content:
            return hashlib.md5(response.content).hexdigest()
    except requests.RequestException:
        pass
    return None

def check_robots_txt(session, base_url_for_robots):
    found_paths = []
    try:
        robots_url = urljoin(base_url_for_robots, "robots.txt")
        response = session.get(robots_url, timeout=REQUEST_TIMEOUT-2, allow_redirects=True, verify=False)
        if response.status_code == 200:
            lines = response.text.splitlines()
            for line in lines:
                line_lower = line.lower().strip()
                if line_lower.startswith("disallow:"):
                    path = line_lower.split(":", 1)[1].strip()
                    # Check if this disallowed path looks like a PMA path
                    if any(pma_path_segment in path for pma_path_segment in ["phpmyadmin", "pma", "mysqladmin"]):
                        # Construct full URL from this path
                        full_potential_url = urljoin(robots_url, path)
                        found_paths.append(full_potential_url)
    except requests.RequestException:
        pass
    return found_paths


# --- GUI Application ---
class PmaFinderAppEnhanced:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced phpMyAdmin Finder v1.1")
        self.root.geometry("750x600")

        self.thread_stop_event = threading.Event()
        self.message_queue = queue.Queue()
        self.current_scan_thread = None

        style = ttk.Style()
        style.theme_use('clam')

        # --- Top Frame: URL and Options ---
        top_frame = ttk.Frame(root, padding=10)
        top_frame.pack(fill="x")

        # URL Input
        ttk.Label(top_frame, text="Base URL (e.g., example.com or https://example.com):").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        self.url_entry = ttk.Entry(top_frame, width=50)
        self.url_entry.grid(row=0, column=1, columnspan=2, sticky="ew", padx=5, pady=2)
        self.url_entry.insert(0, "localhost") # Default

        # User Agent
        ttk.Label(top_frame, text="User-Agent:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.user_agent_entry = ttk.Entry(top_frame, width=50)
        self.user_agent_entry.grid(row=1, column=1, columnspan=2, sticky="ew", padx=5, pady=2)
        self.user_agent_entry.insert(0, DEFAULT_USER_AGENT)

        # Scan Options
        options_frame = ttk.LabelFrame(top_frame, text="Scan Options", padding=5)
        options_frame.grid(row=2, column=0, columnspan=3, sticky="ew", padx=5, pady=5)

        self.scan_subdomains_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Scan Common Subdomains", variable=self.scan_subdomains_var).pack(side=tk.LEFT, padx=5)

        self.check_favicon_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Check Favicon Hash", variable=self.check_favicon_var).pack(side=tk.LEFT, padx=5)

        self.check_robots_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Check robots.txt", variable=self.check_robots_var).pack(side=tk.LEFT, padx=5)

        # --- Control Frame: Buttons ---
        control_frame = ttk.Frame(root, padding=(10,0,10,5))
        control_frame.pack(fill="x")

        self.find_button = ttk.Button(control_frame, text="Start Scan", command=self.start_search)
        self.find_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = ttk.Button(control_frame, text="Stop Scan", command=self.stop_search, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        # --- Output Frame ---
        output_frame = ttk.LabelFrame(root, text="Scan Log & Results", padding=10)
        output_frame.pack(padx=10, pady=5, fill="both", expand=True)

        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, height=15, state='disabled', font=("Consolas", 9))
        self.output_text.pack(fill="both", expand=True, padx=5, pady=5)
        self.configure_tags()

        # --- Progress Bar & Status ---
        progress_status_frame = ttk.Frame(root, padding=(10,0,10,10))
        progress_status_frame.pack(fill="x", side=tk.BOTTOM)

        self.progress_var = tk.DoubleVar()
        self.progressbar = ttk.Progressbar(progress_status_frame, orient="horizontal", length=300, mode="determinate", variable=self.progress_var)
        self.progressbar.pack(side=tk.LEFT, fill="x", expand=True, padx=(0,10))

        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(progress_status_frame, textvariable=self.status_var, relief=tk.FLAT, anchor=tk.E) #SUNKEN
        status_bar.pack(side=tk.RIGHT)


        self.root.after(100, self.process_queue)
        # Suppress InsecureRequestWarning
        requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

    def configure_tags(self):
        self.output_text.tag_configure("INFO", foreground="#007bff") # Blue
        self.output_text.tag_configure("SUCCESS", foreground="#28a745", font=('TkDefaultFont', 9, 'bold')) # Green
        self.output_text.tag_configure("ERROR", foreground="#dc3545") # Red
        self.output_text.tag_configure("TRYING", foreground="#6c757d") # Gray
        self.output_text.tag_configure("WARNING", foreground="#ffc107") # Yellow
        self.output_text.tag_configure("IMPORTANT", font=('TkDefaultFont', 9, 'bold'))

    def log_message(self, message, tag="INFO"): # Default tag changed
        self.output_text.configure(state='normal')
        self.output_text.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {message}\n", tag)
        self.output_text.configure(state='disabled')
        self.output_text.see(tk.END)

    def start_search(self):
        base_url_input = self.url_entry.get().strip()
        if not base_url_input:
            messagebox.showerror("Error", "Please enter a base URL or domain name.")
            return

        if not base_url_input.startswith("https://") and not base_url_input.startswith("https://"):
            base_url_input = "https://" + base_url_input # Default to http, worker will try https too

        try:
            parsed_url = urlparse(base_url_input)
            if not parsed_url.netloc:
                messagebox.showerror("Error", "Invalid URL. Please include a domain name (e.g., example.com or https://example.com).")
                return
        except ValueError:
            messagebox.showerror("Error", "Invalid URL format.")
            return

        self.output_text.configure(state='normal')
        self.output_text.delete(1.0, tk.END)
        self.output_text.configure(state='disabled')

        self.find_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.status_var.set("Initializing scan...")
        self.progress_var.set(0)
        self.thread_stop_event.clear()

        scan_params = {
            "base_input": base_url_input,
            "scan_subdomains": self.scan_subdomains_var.get(),
            "check_favicon": self.check_favicon_var.get(),
            "check_robots": self.check_robots_var.get(),
            "user_agent": self.user_agent_entry.get() or DEFAULT_USER_AGENT
        }

        self.current_scan_thread = threading.Thread(target=self.search_worker_enhanced, args=(scan_params,), daemon=True)
        self.current_scan_thread.start()

    def stop_search(self):
        if self.current_scan_thread and self.current_scan_thread.is_alive():
            self.log_message("Stop signal sent. Waiting for current checks to finish...", "WARNING")
            self.thread_stop_event.set()
            self.stop_button.config(state=tk.DISABLED) # Disable until thread confirms stop
            # No need to join here, process_queue will handle UI updates on thread exit.
        else:
            self.log_message("No active scan to stop.", "INFO")
            self.find_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.status_var.set("Scan manually stopped.")


    def process_queue(self):
        try:
            while True: # Process all messages in queue
                msg_type, data = self.message_queue.get_nowait()

                if msg_type == "LOG":
                    self.log_message(data['text'], data.get('tag', "INFO"))
                elif msg_type == "STATUS":
                    self.status_var.set(data)
                elif msg_type == "PROGRESS_MAX":
                    self.progressbar.config(maximum=data)
                elif msg_type == "PROGRESS_UPDATE":
                    self.progress_var.set(data)
                elif msg_type == "FOUND_PMA":
                    self.log_message(f"phpMyAdmin FOUND!: {data['url']}", "SUCCESS")
                    self.log_message(f"Method: {data['method']}", "SUCCESS")
                    self.status_var.set("phpMyAdmin Found! Scan stopped.")
                    self.thread_stop_event.set() # Signal thread to stop fully
                    self.find_button.config(state=tk.NORMAL)
                    self.stop_button.config(state=tk.DISABLED)
                    messagebox.showinfo("Success!", f"phpMyAdmin panel found at:\n{data['url']}")
                elif msg_type == "SCAN_COMPLETE":
                    self.status_var.set(data)
                    self.find_button.config(state=tk.NORMAL)
                    self.stop_button.config(state=tk.DISABLED)
                    if "not found" in data.lower():
                         messagebox.showinfo("Scan Complete", "phpMyAdmin not found with the current configuration.")
                elif msg_type == "THREAD_STOPPED": # Worker confirms it has stopped
                    self.log_message("Scan worker has stopped.", "INFO")
                    self.find_button.config(state=tk.NORMAL)
                    self.stop_button.config(state=tk.DISABLED)
                    if not self.status_var.get().startswith("phpMyAdmin Found!"):
                        self.status_var.set("Scan stopped by user or completed.")


        except queue.Empty:
            pass
        finally:
            self.root.after(100, self.process_queue)

    def _send_to_queue(self, msg_type, data):
        """Helper to put messages in the queue."""
        self.message_queue.put((msg_type, data))

    def search_worker_enhanced(self, params):
        base_input_url = params["base_input"]
        parsed_base = urlparse(base_input_url)
        # Ensure scheme for base domain if user only types 'example.com'
        base_domain_for_subdomains = parsed_base.netloc or parsed_base.path # Handles 'example.com'

        session = requests.Session()
        session.headers.update({'User-Agent': params["user_agent"]})

        targets_to_check = [] # List of (target_base_url_with_scheme_and_port, original_domain_for_display)

        # 1. Prepare main domain targets (with and without common ports, http/https)
        schemes = ['https', 'http']
        for scheme in schemes:
            for port in TARGET_PORTS:
                netloc = base_domain_for_subdomains
                if port:
                    # Ensure port is not duplicated if already in netloc
                    domain_part = netloc.split(':')[0]
                    netloc = f"{domain_part}:{port}"
                targets_to_check.append( (urlunparse((scheme, netloc, '', '', '', '')), base_domain_for_subdomains) )

        # 2. Prepare subdomain targets
        if params["scan_subdomains"]:
            for sub in COMMON_SUBDOMAINS:
                if not sub: continue # Skip empty, already handled by base domain
                sub_domain = f"{sub}.{base_domain_for_subdomains.split(':')[0]}" # ensure no port on subdomain part
                for scheme in schemes:
                    for port in TARGET_PORTS:
                        netloc = sub_domain
                        if port:
                            netloc = f"{sub_domain}:{port}"
                        targets_to_check.append( (urlunparse((scheme, netloc, '', '', '', '')), sub_domain) )

        # Remove duplicates that might arise from None port vs 80/443
        targets_to_check = sorted(list(set(targets_to_check)))

        # Estimate total checks for progress bar
        # Each target_to_check will be subject to:
        # - robots.txt (1 check)
        # - favicon (1 check)
        # - N paths
        num_path_checks = len(EXTENDED_PMA_PATHS)
        num_base_checks = 0
        if params["check_robots"]: num_base_checks += 1
        if params["check_favicon"]: num_base_checks += 1

        total_checks = len(targets_to_check) * (num_base_checks + num_path_checks)
        self._send_to_queue("PROGRESS_MAX", total_checks)
        self._send_to_queue("LOG", {'text': f"Estimated total checks: {total_checks}", 'tag': "INFO"})
        checks_done = 0

        found_pma_details = None

        unique_domains_processed_for_robots_favicon = set()

        for base_url_to_probe, display_domain in targets_to_check:
            if self.thread_stop_event.is_set(): break

            # Robots.txt and Favicon check (once per unique scheme+host+port combination)
            # Use the base_url_to_probe as it includes scheme and port for these checks.
            # We use display_domain to avoid re-checking robots/favicon for example.com:80 and example.com if they resolve to same.
            # A better key might be scheme+hostname.
            probe_key_for_aux_checks = urlparse(base_url_to_probe)._replace(path='', params='', query='', fragment='').geturl()

            if probe_key_for_aux_checks not in unique_domains_processed_for_robots_favicon:
                if self.thread_stop_event.is_set(): break
                if params["check_robots"]:
                    self._send_to_queue("LOG", {'text': f"Checking robots.txt for {base_url_to_probe}", 'tag': "TRYING"})
                    checks_done +=1
                    self._send_to_queue("PROGRESS_UPDATE", checks_done)
                    try:
                        potential_urls_from_robots = check_robots_txt(session, base_url_to_probe)
                        for p_url in potential_urls_from_robots:
                            if self.thread_stop_event.is_set(): break
                            self._send_to_queue("LOG", {'text': f"Potentially from robots.txt: {p_url}", 'tag': "INFO"})
                            # Now try to access this p_url
                            try:
                                r_resp = session.get(p_url, timeout=REQUEST_TIMEOUT, allow_redirects=True, verify=False)
                                if r_resp.status_code == 200 and is_likely_phpmyadmin_page(r_resp.text, r_resp.url):
                                    found_pma_details = {'url': r_resp.url, 'method': f'Found via robots.txt entry from {base_url_to_probe}'}
                                    self._send_to_queue("FOUND_PMA", found_pma_details)
                                    break # Found!
                            except requests.RequestException:
                                pass # Silently fail individual robot path checks
                    except Exception as e_robots:
                        self._send_to_queue("LOG", {'text': f"Error checking robots.txt for {base_url_to_probe}: {e_robots}", 'tag': "ERROR"})
                    if found_pma_details: break

                if self.thread_stop_event.is_set(): break
                if params["check_favicon"]:
                    self._send_to_queue("LOG", {'text': f"Checking favicon for {base_url_to_probe}", 'tag': "TRYING"})
                    checks_done +=1
                    self._send_to_queue("PROGRESS_UPDATE", checks_done)
                    try:
                        f_hash = get_favicon_hash(session, base_url_to_probe)
                        if f_hash and f_hash in KNOWN_PMA_FAVICON_HASHES:
                            # If favicon matches, the base_url_to_probe MIGHT be PMA, or a common path
                            # We should still try common paths on this base_url_to_probe
                            self._send_to_queue("LOG", {'text': f"Known PMA favicon hash ({f_hash}) found at {base_url_to_probe}/favicon.ico. Checking standard paths...", 'tag': "INFO"})
                            # Try accessing the base URL itself directly, as it might be the PMA page
                            try:
                                r_fav_base = session.get(base_url_to_probe, timeout=REQUEST_TIMEOUT, allow_redirects=True, verify=False)
                                if r_fav_base.status_code == 200 and is_likely_phpmyadmin_page(r_fav_base.text, r_fav_base.url):
                                    found_pma_details = {'url': r_fav_base.url, 'method': f'PMA favicon match and base URL ({base_url_to_probe}) is PMA page'}
                                    self._send_to_queue("FOUND_PMA", found_pma_details)
                                    break # Found!
                            except requests.RequestException:
                                pass
                    except Exception as e_favicon:
                         self._send_to_queue("LOG", {'text': f"Error checking favicon for {base_url_to_probe}: {e_favicon}", 'tag': "ERROR"})
                    if found_pma_details: break
                unique_domains_processed_for_robots_favicon.add(probe_key_for_aux_checks)
            if found_pma_details: break # From favicon or robots check

            # 3. Path checks for the current base_url_to_probe
            for path_segment in EXTENDED_PMA_PATHS:
                if self.thread_stop_event.is_set(): break
                
                # Construct test URL using urljoin to handle base paths correctly
                # e.g., if base_url_to_probe is http://host/somepath/ and path_segment is pma
                # urljoin will correctly form http://host/somepath/pma
                current_test_url = urljoin(base_url_to_probe + ('/' if not base_url_to_probe.endswith('/') else ''), path_segment.lstrip('/'))

                self._send_to_queue("LOG", {'text': f"Trying: {current_test_url}", 'tag': "TRYING"})
                checks_done += 1
                self._send_to_queue("PROGRESS_UPDATE", checks_done)

                try:
                    response = session.get(current_test_url, timeout=REQUEST_TIMEOUT, allow_redirects=True, verify=False)
                    if response.status_code == 200:
                        if is_likely_phpmyadmin_page(response.text, response.url):
                            found_pma_details = {'url': response.url, 'method': 'Direct path scan'}
                            self._send_to_queue("FOUND_PMA", found_pma_details)
                            break # Found, break from paths loop
                        # else:
                        #    self._send_to_queue("LOG", {'text': f"{current_test_url} - Status 200, but not recognized as PMA content.", 'tag': "INFO"})
                    # else:
                    #    self._send_to_queue("LOG", {'text': f"{current_test_url} - Status: {response.status_code}", 'tag': "INFO"})
                except requests.exceptions.Timeout:
                    self._send_to_queue("LOG", {'text': f"{current_test_url} - Timed out.", 'tag': "WARNING"})
                except requests.exceptions.ConnectionError:
                    # This is common, so maybe don't log every single one if list is huge
                    # self._send_to_queue("LOG", {'text': f"{current_test_url} - Connection error.", 'tag': "ERROR"})
                    pass # Often expected for non-existent ports/hosts
                except requests.exceptions.RequestException as e:
                    self._send_to_queue("LOG", {'text': f"{current_test_url} - Error: {type(e).__name__}", 'tag': "ERROR"})

            if found_pma_details: break # Break from main target loop

        # After all loops
        self.progress_var.set(total_checks) # Ensure progress bar is full
        if not found_pma_details and not self.thread_stop_event.is_set():
            self._send_to_queue("SCAN_COMPLETE", "Scan complete. phpMyAdmin not found.")
        elif self.thread_stop_event.is_set() and not found_pma_details:
             self._send_to_queue("SCAN_COMPLETE", "Scan stopped by user.")
        # If found_pma_details is True, FOUND_PMA message already sent and scan stopped.

        self._send_to_queue("THREAD_STOPPED", None) # Signal that worker is done

if __name__ == "__main__":
    app_root = tk.Tk()
    app = PmaFinderAppEnhanced(app_root)
    app_root.mainloop()
