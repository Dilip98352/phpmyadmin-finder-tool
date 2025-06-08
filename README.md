# Advanced phpMyAdmin Finder

<p align="center">
  A powerful, multi-threaded GUI scanner for discovering phpMyAdmin login panels on web servers.
  <br><br>
  <a href="https://github.com/Dilip98352/phpmyadmin-finder-tool/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/Python-3.6+-blue.svg" alt="Python Version"></a>
  <a href="https://github.com/Dilip98352/phpmyadmin-finder-tool/issues"><img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg" alt="PRs Welcome"></a>
</p>

<p align="center">
  <img src="./screenshot/screenshot1.png" alt="Screenshot of the phpMyAdmin Finder GUI" width="750">
</p>

## Table of Contents

- [✨ Features](#-features)
- [🚀 Getting Started](#-getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [📋 How to Use](#-how-to-use)
- [⚠️ Disclaimer](#️-disclaimer)
- [🤝 Contributing](#-contributing)
- [📜 License](#-license)
- [❤️ Support](#️-support)

## ✨ Features

- Intuitive GUI: A clean and user-friendly interface built with Tkinter.
- Multi-Threaded Scanning: Ensures the UI remains responsive and never freezes, even during intensive scans.
- Comprehensive Path List: Checks over 40 common and obscure paths where phpMyAdmin might be hosted.
- Subdomain Scanning: Optionally scans a list of common subdomains (e.g., `db`, `mysql`, `phpmyadmin`) to find hidden panels.
- Flexible Port Scanning: Scans popular web ports, including `80`, `443`, `8080`, `2083`, and `10000`.
- Smart Detection Engine:
  - Keyword Matching: Analyzes page titles and content for phpMyAdmin-specific keywords.
  - Favicon Hash Matching: Identifies panels by comparing favicon hashes against known phpMyAdmin icons.
  - `robots.txt` Analysis: Parses `robots.txt` for `Disallow` entries that may reveal panel locations.
- Live-Updating Log Panel: Provides real-time, color-coded feedback on the scanning process.
- Easy Scan Cancellation: Stop any ongoing scan instantly with a single click.
- Custom User-Agent: Set a custom User-Agent string for all HTTP requests.

## 🚀 Getting Started

# Prerequisites

- Python 3.6 or higher
- The `requests` library

# Installation

1.  Clone the repository:

    ```bash
    git clone https://github.com/Dilip98352/phpmyadmin-finder-tool.git
    cd phpmyadmin-finder-tool
    ```

2.  Create and activate a virtual environment (Recommended):
    This keeps your project dependencies isolated.

    - macOS / Linux:
      ```bash
      python3 -m venv venv
      source venv/bin/activate
      ```
    - Windows (PowerShell):
      ```powershell
      python -m venv venv
      .\venv\Scripts\Activate.ps1
      ```

3.  Install the required dependencies:

    ```bash
    pip install -r requirements.txt
    ```

4.  Run the application:
    ```bash
    python3 app.py
    ```

## 📋 How to Use

1.  Launch the application by running `python3 app.py`.
2.  Enter the target domain (e.g., `example.com`) in the URL input field.
3.  Select your desired scan options (Subdomains, Favicon Check, Ports, etc.).
4.  Click the Start Scan button to begin.
5.  Monitor the Scan Log & Results panel for real-time updates.
6.  Found instances will be highlighted in green with a success notification.
7.  Click the Stop Scan button at any time to abort the process.

## ⚠️ Disclaimer

> [!WARNING]
> This tool is intended for educational and authorized security testing purposes only. Unauthorized scanning of web applications is illegal and unethical. The author is not responsible for any misuse or damage caused by this program. Always obtain explicit, written permission from the website owner before conducting any form of testing.

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Feel free to check the [issues page](https://github.com/Dilip98352/phpmyadmin-finder-tool/issues) or submit a [pull request](https://github.com/Dilip98352/phpmyadmin-finder-tool/pulls).

## 📜 License

This project is distributed under the MIT License. See `LICENSE` for more information.

## ❤️ Support

If you find this tool helpful, please consider supporting its development.

<a href="https://coff.ee/user03863g">
  <img src="https://img.shields.io/badge/Buy_Me_A_Coffee-FF813F?style=for-the-badge&logo=buy-me-a-coffee&logoColor=white" alt="Buy Me A Coffee">
</a>
