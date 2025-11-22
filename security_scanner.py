import re
import torch
from transformers import DistilBertTokenizer, DistilBertForSequenceClassification
from transformers import pipeline
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SecurityScanner:
    """
    A multi-layered security scanner for LLM prompts.
    Layer 1: Regex-based Prompt Injection Detection.
    Layer 2: ML-based Toxicity/Malicious Intent Detection (CPU optimized).
    """

    def __init__(self):
        """
        Initialize the Security Scanner.
        Loads the ML model for toxicity detection.
        """
        self.device = torch.device("cpu")
        logger.info(f"Initializing SecurityScanner on device: {self.device}")

        # Layer 1: Regex Patterns for Prompt Injection
        # These are common patterns used to bypass LLM instructions.
        self.injection_patterns = [
            r"ignore previous instructions",
            r"ignore all previous instructions",
            r"system override",
            r"you are now",
            r"jailbreak",
            r"developer mode",
            r"do anything now",
            r"always answer",
            r"unfiltered",
            r"dan mode"
        ]
        self.compiled_patterns = [re.compile(p, re.IGNORECASE) for p in self.injection_patterns]

        # Layer 2: ML Model for Toxicity/Malicious Intent
        model_name = "distilbert-base-uncased-finetuned-sst-2-english"
        logger.info(f"Loading ML model: {model_name}")
        
        try:
            self.tokenizer = DistilBertTokenizer.from_pretrained(model_name)
            self.model = DistilBertForSequenceClassification.from_pretrained(model_name)
            self.model.to(self.device)
            self.model.eval()
            logger.info("ML model loaded successfully.")
        except Exception as e:
            logger.error(f"Failed to load ML model: {e}")
            raise e

    def scan(self, text: str) -> bool:
        """
        Scan the text for security threats.

        Args:
            text: The input prompt to scan.

        Returns:
            True if the text is SAFE, False if MALICIOUS.
        """
        # Layer 1: Regex Check
        for pattern in self.compiled_patterns:
            if pattern.search(text):
                logger.warning(f"Prompt Injection detected via regex: {pattern.pattern}")
                return False

        # Layer 2: ML Check
        # We interpret "Negative" sentiment with high confidence as potentially malicious for this MVP demo.
        # In a real system, we would use a dedicated Prompt Injection classifier.
        is_safe_ml = self._check_ml(text)
        if not is_safe_ml:
             logger.warning("Malicious intent detected via ML model.")
             return False

        return True

    def _check_ml(self, text: str) -> bool:
        """
        Internal method to check text using the loaded ML model.
        """
        try:
            inputs = self.tokenizer(text, return_tensors="pt", truncation=True, padding=True, max_length=512)
            inputs = {k: v.to(self.device) for k, v in inputs.items()}
            
            with torch.no_grad():
                outputs = self.model(**inputs)
            
            logits = outputs.logits
            probabilities = torch.softmax(logits, dim=1)
            
            # In SST-2: Label 0 is NEGATIVE, Label 1 is POSITIVE.
            # We'll assume highly negative prompts might be aggressive/malicious.
            negative_score = probabilities[0][0].item()
            
            logger.info(f"ML Scan - Text: '{text[:30]}...' | Negative Score: {negative_score:.4f}")
            
            # Threshold: If > 99% negative, flag it.
            # Increased from 0.95 to 0.99 to reduce false positives on neutral text.
            if negative_score > 0.99:
                return False
            
            return True

        except Exception as e:
            logger.error(f"Error during ML scan: {e}")
            return True
