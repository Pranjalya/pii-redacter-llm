import uuid
from typing import Dict, List, Optional
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
import diskcache
from faker import Faker
import logging

logger = logging.getLogger(__name__)

class PIIVault:
    """
    A secure vault for anonymizing and deanonymizing Personally Identifiable Information (PII).
    Uses Microsoft Presidio for detection and replacement.
    Features:
    - Disk-based persistence with TTL (via diskcache).
    - Smarter anonymization using Faker for realistic placeholders.
    - Session-scoped storage to prevent cross-talk and improve performance.
    """

    def __init__(self, cache_dir: str = "./pii_cache", ttl_seconds: int = 1800):
        """
        Initialize the PII Vault with Presidio Analyzer and Anonymizer.
        
        Args:
            cache_dir: Directory to store the disk cache.
            ttl_seconds: Time-to-live for cached mappings in seconds (default: 30 mins).
        """
        self.analyzer = AnalyzerEngine()
        self.anonymizer = AnonymizerEngine()
        # Use 'en_IN' for Indian names
        self.fake = Faker(['en_IN', 'en_US'])
        
        # Initialize DiskCache
        self.vault_storage = diskcache.Cache(cache_dir, size_limit=1024 * 1024 * 100) # 100MB limit
        self.ttl_seconds = ttl_seconds
        logger.info(f"PII Vault initialized with DiskCache at {cache_dir}, TTL: {ttl_seconds}s")

    def _generate_fake_data(self, entity_type: str) -> str:
        """
        Generate realistic fake data based on entity type.
        """
        if entity_type == "PERSON":
            return self.fake.name()
        elif entity_type == "EMAIL_ADDRESS":
            return self.fake.email()
        elif entity_type == "PHONE_NUMBER":
            return self.fake.phone_number()
        elif entity_type == "CREDIT_CARD":
            return self.fake.credit_card_number()
        else:
            return f"<{entity_type}_{str(uuid.uuid4())[:8]}>"

    def anonymize(self, text: str, session_id: str) -> str:
        """
        Analyze the text for PII and replace detected entities with realistic placeholders.
        Stores the mapping in the vault, scoped to the session.

        Args:
            text: The input text containing potential PII.
            session_id: Unique identifier for the user session.

        Returns:
            The anonymized text with placeholders.
        """
        entities = ["PHONE_NUMBER", "EMAIL_ADDRESS", "PERSON", "CREDIT_CARD"]
        results = self.analyzer.analyze(text=text, entities=entities, language='en')
        results.sort(key=lambda x: x.start, reverse=True)
        
        anonymized_text_list = list(text)
        
        # Track new mappings for this request
        new_mappings = {}

        for result in results:
            entity_type = result.entity_type
            start = result.start
            end = result.end
            original_value = text[start:end]
            
            # Generate a realistic placeholder
            placeholder = self._generate_fake_data(entity_type)
            
            # Store mapping: Placeholder -> Original
            # Key: session:{session_id}:{placeholder}
            key = f"session:{session_id}:{placeholder}"
            self.vault_storage.set(key, original_value, expire=self.ttl_seconds)
            
            new_mappings[placeholder] = original_value
            
            # Replace in text
            anonymized_text_list[start:end] = list(placeholder)
            
        # Update the list of keys for this session
        # Key: session:{session_id}:keys
        # We need to lock or handle concurrency if multiple requests come for same session?
        # For MVP, simple read-modify-write is okay (DiskCache is process-safe but race conditions possible).
        session_keys_key = f"session:{session_id}:keys"
        current_keys = self.vault_storage.get(session_keys_key, default=[])
        current_keys.extend(new_mappings.keys())
        self.vault_storage.set(session_keys_key, current_keys, expire=self.ttl_seconds)

        return "".join(anonymized_text_list)

    def deanonymize(self, text: str, session_id: str) -> str:
        """
        Restore the original PII in the text using the stored mapping for the specific session.

        Args:
            text: The anonymized text containing placeholders.
            session_id: Unique identifier for the user session.

        Returns:
            The text with original PII restored.
        """
        deanonymized_text = text
        
        # Get all placeholders for this session
        session_keys_key = f"session:{session_id}:keys"
        session_placeholders = self.vault_storage.get(session_keys_key, default=[])
        
        # Iterate only over the placeholders relevant to this session
        for placeholder in session_placeholders:
            if placeholder in deanonymized_text:
                key = f"session:{session_id}:{placeholder}"
                original_value = self.vault_storage.get(key)
                if original_value:
                    deanonymized_text = deanonymized_text.replace(placeholder, original_value)
                
        return deanonymized_text

    def clear_storage(self):
        """
        Clear the storage.
        """
        self.vault_storage.clear()
