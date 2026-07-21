# -*- coding: utf-8 -*-
from typing import List, Tuple
from .base_parser import BaseParser
from .finding_schema import Finding

class TrivyParser(BaseParser):
    def can_parse(self, filename: str, content: str) -> bool:
        fn_lower = filename.lower()
        return "trivy" in fn_lower or "dependency-check" in fn_lower or "vulnerabilities" in content[:1000].lower()

    def parse(self, filename: str, content: str) -> Tuple[List[Finding], None]:
        # Stub implementation for Trivy / Dependency-Check JSON exports
        return [], None
