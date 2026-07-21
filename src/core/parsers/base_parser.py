# -*- coding: utf-8 -*-
from abc import ABC, abstractmethod
from typing import List, Tuple, Any
from .finding_schema import Finding

class BaseParser(ABC):
    @abstractmethod
    def can_parse(self, filename: str, content: str) -> bool:
        """
        Determines whether this parser can process the given file based on filename/content.
        """
        pass

    @abstractmethod
    def parse(self, filename: str, content: str) -> Tuple[List[Finding], Any]:
        """
        Parses raw file content into a tuple of:
        - List[Finding]: Actionable & Informational vulnerability findings.
        - Any: Supplemental data (e.g. AssetInventory for open ports/services).
        """
        pass
