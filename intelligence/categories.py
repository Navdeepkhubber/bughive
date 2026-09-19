"""CWE -> category classifier for skill generation."""
CATEGORY_MAP = {
    "CWE-79":  "xss",
    "CWE-89":  "sqli",
    "CWE-94":  "rce",
    "CWE-918": "ssrf",
    "CWE-639": "idor",
    "CWE-22":  "lfi",
    "CWE-352": "csrf",
    "CWE-287": "authn",
    "CWE-269": "privesc",
    "CWE-200": "info_disclosure",
    "CWE-787": "memory",
    "CWE-400": "dos",
    "CWE-840": "business_logic",
    "CWE-798": "secrets",
    "CWE-601": "open_redirect",
    "CWE-74":  "http_injection",
    "CWE-502": "deserialization",
    "CWE-77":  "injection",
    "CWE-611": "xxe",
    "CWE-327": "crypto",
    "CWE-295": "tls",
    "CWE-362": "race_condition",
    "CWE-1021":"clickjacking",
    "CWE-942": "cors",
    "CWE-434": "file_upload",
    "CWE-1426":"llm",
    "CWE-1357":"supply_chain",
}

def get_category(cwe):
    if not cwe:
        return "misc"
    for prefix, cat in CATEGORY_MAP.items():
        if cwe.startswith(prefix):
            return cat
    return "misc"
