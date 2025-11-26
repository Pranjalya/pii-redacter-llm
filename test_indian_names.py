from pii_vault import PIIVault
import uuid

def test_indian_names():
    vault = PIIVault()
    session_id = str(uuid.uuid4())
    
    # List of test sentences with Indian names
    test_cases = [
        "My name is Rahul Sharma.",
        "Contact Priya Patel at 555-0123.",
        "Amitabh Bachchan is a famous actor.",
        "Suresh Raina played cricket.",
        "My email is anjali.gupta@example.com"
    ]
    
    print(f"--- Testing Indian Name Detection (Session: {session_id}) ---")
    
    for text in test_cases:
        anonymized = vault.anonymize(text, session_id)
        print(f"\nOriginal:   {text}")
        print(f"Anonymized: {anonymized}")
        
        # Simple check: if the original text is different from anonymized, something was redacted.
        if text != anonymized:
            print("✅ Detection: YES")
        else:
            print("❌ Detection: NO")

if __name__ == "__main__":
    test_indian_names()
