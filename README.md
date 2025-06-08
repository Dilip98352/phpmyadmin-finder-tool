# Advanced phpMyAdmin (PMA) Finder

![Python Version](https://img.shields.io/badge/python-3.6%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

A graphical, multi-threaded scanner written in Python and Tkinter to discover hidden or non-standard phpMyAdmin login panels on a web server. This tool uses a combination of techniques for a comprehensive and efficient search.

## Features

- Graphical User Interface: Easy-to-use interface built with Tkinter.
- Multi-Threaded Scanning: The UI remains responsive while the scan runs in the background.
- Comprehensive Path List: Uses an extensive list of over 40 common and obscure paths for phpMyAdmin.
- Subdomain Scanning: Option to scan a list of common subdomains (e.g., `db.example.com`, `mysql.example.com`).
- Port Scanning: Checks multiple common web ports (e.g., 80, 443, 8080, 2083, 10000).
- Smart Detection:
  - Content Analysis: Scans page content and titles for keywords specific to phpMyAdmin.
  - Favicon Hash Check: Verifies the `favicon.ico` MD5 hash against known phpMyAdmin hashes.
  - Robots.txt Analysis: Checks `robots.txt` for `Disallow` entries that might reveal the panel's location.
- Real-time Logging: See what the scanner is doing in real-time with colored log output.
- Cancellable Scans: Stop the scan at any time.
- Custom User-Agent: Set a custom User-Agent for requests.

## Screenshot

(The GUI allows you to input a target URL, select scan options, and view live results in the log area.)

## Requirements

- Python 3.6 or higher
- `requests` library

## Installation & Usage

Follow these steps to get the scanner running:

1. Clone the Repository

```bash
git clone https://github.com/Dilip98352/phpmyadmin-finder-tool.git
cd pma-finder
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Markdown
IGNORE_WHEN_COPYING_END

(Replace your-username/pma-finder with the actual repository URL)

2. Create and Activate a Virtual Environment (Recommended)

On macOS/Linux:

python3 -m venv venv
source venv/bin/activate
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Bash
IGNORE_WHEN_COPYING_END

On Windows:

python -m venv venv
.\venv\Scripts\activate
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Bash
IGNORE_WHEN_COPYING_END

3. Install Dependencies

Create a file named requirements.txt in the project directory and add the following line:

requests
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
IGNORE_WHEN_COPYING_END

Then, run the following command to install the required library:

pip install -r requirements.txt
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Bash
IGNORE_WHEN_COPYING_END

4. Run the Application

python pma_finder_app.py
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Bash
IGNORE_WHEN_COPYING_END

(Replace pma_finder_app.py with the actual name of your Python script file.)

5. How to Use the Scanner

Launch the application.

Enter the base target URL or domain name (e.g., example.com).

Select your desired scan options (Scan Subdomains, Check Favicon, etc.).

Click the "Start Scan" button.

Monitor the "Scan Log & Results" area for real-time updates.

If a phpMyAdmin panel is found, a success message will appear in the log and a pop-up will notify you.

You can stop the scan at any time by clicking the "Stop Scan" button.

Disclaimer

This tool is intended for educational purposes and for use in authorized security testing or penetration testing engagements only. Unauthorized scanning of web applications is illegal. The author is not responsible for any misuse or damage caused by this program. Always obtain permission from the website owner before scanning.

License

This project is licensed under the MIT License. See the LICENSE file for details.
```
