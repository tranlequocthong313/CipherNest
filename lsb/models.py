from typing import List, Dict, Any, Tuple

class ExtractedPayload:
    def __init__(self, metadata: Dict[str, Any], extracted_files: List[Tuple[str, bytes]]):
        self.metadata = metadata  
        self.extracted_files = extracted_files  

    def is_encrypted(self) -> bool:
        ef_block = self.metadata.get("EF")
        return ef_block == "1"

    def is_compressed(self) -> bool:
        cf_block = self.metadata.get("CF")
        return cf_block == "1"

    def get_version(self) -> str:
        version_block = self.metadata.get("VERSION")
        return version_block if version_block else None

    def get_filenames(self) -> List[str]:
        filenames_block = self.metadata.get("FILENAMES")
        return filenames_block if filenames_block else []

    def get_embedded_sizes(self) -> List[int]:
        sizes_block = self.metadata.get("EMBEDDED_SIZES")
        return sizes_block if sizes_block else []

    def get_hmac(self) -> str:
        hmac_block = self.metadata.get("HMAC")
        return hmac_block if hmac_block else None
