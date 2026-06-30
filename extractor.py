import re
from typing import Dict, List, Set

class IOCExtractor:
    """
    Extracts and defangs Indicators of Compromise (IOCs) from unstructured security reports or logs.
    """
    PATTERNS = {
        "ipv4": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
        "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "url": r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w\.-]*",
        "md5": r"\b[a-fA-F0-9]{32}\b",
        "sha1": r"\b[a-fA-F0-9]{40}\b",
        "sha256": r"\b[a-fA-F0-9]{64}\b"
    }

    def __init__(self, text: str):
        self.text = text

    def extract(self, defang: bool = True) -> Dict[str, List[str]]:
        results = {}
        for ioc_type, pattern in self.PATTERNS.items():
            matches: Set[str] = set(re.findall(pattern, self.text))
            
            if defang:
                if ioc_type == "ipv4":
                    matches = {ip.replace(".", "[.]") for ip in matches}
                elif ioc_type == "url":
                    matches = {url.replace("http://", "http[:]//").replace("https://", "https[:]//").replace(".", "[.]") for url in matches}
                elif ioc_type == "email":
                    matches = {email.replace("@", "[@]").replace(".", "[.]") for email in matches}
                    
            results[ioc_type] = sorted(list(matches))
        return results
