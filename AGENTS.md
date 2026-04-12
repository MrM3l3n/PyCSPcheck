## Cursor Cloud specific instructions

**PYCSPCHECKER** is a single-file Python CLI tool that analyzes Content Security Policy (CSP) headers for websites. See `README.md` for full documentation.

### Running the application

The script is interactive and prompts for input (URLs, output format, file save option, timeout, retries). To run non-interactively, pipe input:

```
echo -e "google.com\ntext\nno\n3\n3" | python3 PYCSPCheck.py
```

The prompts in order are:
1. Comma-separated URLs
2. Output format (`text` or `json`)
3. Save to file (`yes` / `no`)
4. Timeout in seconds
5. Max retries

### Key notes

- No lint, build, or automated test commands exist in this repository — it is a single Python script with no test suite or linter configuration.
- The script requires outbound internet access to fetch CSP headers from URLs.
- Dependencies are listed in `requirements.txt` and installed via `pip3 install -r requirements.txt`.
