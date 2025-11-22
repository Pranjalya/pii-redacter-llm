import uuid
from typing import Dict, Any, List, Union
from langchain_core.runnables import RunnableLambda, RunnableSerializable
from langchain_core.messages import BaseMessage, HumanMessage, AIMessage, SystemMessage
from langchain_core.language_models import BaseChatModel
import logging

from pii_vault import PIIVault
from security_scanner import SecurityScanner

# Configure logging
logger = logging.getLogger("secure_chain")
logging.basicConfig(level=logging.INFO)

class SecureChainFactory:
    """
    Factory to create a secure LangChain Runnable.
    Wraps an LLM with:
    1. Security Scanning (Input Guard)
    2. PII Anonymization (Input Transform)
    3. PII Deanonymization (Output Transform)
    """
    
    def __init__(self):
        self.pii_vault = PIIVault()
        self.security_scanner = SecurityScanner()

    def create_secure_chain(self, llm: BaseChatModel) -> RunnableSerializable:
        """
        Creates a secure chain that wraps the provided LLM.
        
        Args:
            llm: The base ChatModel (e.g., ChatOpenAI) to wrap.
            
        Returns:
            A Runnable that accepts input (str or List[BaseMessage]), 
            scans/anonymizes it, calls the LLM, and deanonymizes the response.
        """
        
        def input_guard(input_data: Union[str, List[BaseMessage], Dict[str, Any]]) -> Dict[str, Any]:
            """
            Step 1: Scan and Anonymize Input
            """
            # Extract text content and session ID
            # We assume input might be a simple string, a list of messages, or a dict with 'input' and 'session_id'
            
            text_to_scan = ""
            session_id = str(uuid.uuid4()) # Default if not provided
            messages = []
            
            if isinstance(input_data, str):
                text_to_scan = input_data
                messages = [HumanMessage(content=text_to_scan)]
            elif isinstance(input_data, list):
                # Assume list of messages. We scan the last user message.
                messages = input_data
                for msg in reversed(messages):
                    if isinstance(msg, HumanMessage):
                        text_to_scan = msg.content
                        break
            elif isinstance(input_data, dict):
                # Expecting {"input": ..., "session_id": ...}
                raw_input = input_data.get("input")
                session_id = input_data.get("session_id", session_id)
                
                if isinstance(raw_input, str):
                    text_to_scan = raw_input
                    messages = [HumanMessage(content=text_to_scan)]
                elif isinstance(raw_input, list):
                    messages = raw_input
                    for msg in reversed(messages):
                        if isinstance(msg, HumanMessage):
                            text_to_scan = msg.content
                            break
            
            # 1. Security Scan
            if text_to_scan:
                logger.info(f"Scanning input for session {session_id}...")
                if not self.security_scanner.scan(text_to_scan):
                    raise ValueError("Security Alert: Malicious prompt detected.")
            
            # 2. Anonymize PII
            # We need to reconstruct the messages with anonymized content
            anonymized_messages = []
            for msg in messages:
                if isinstance(msg, HumanMessage) and isinstance(msg.content, str):
                    anonymized_content = self.pii_vault.anonymize(msg.content, session_id)
                    anonymized_messages.append(HumanMessage(content=anonymized_content))
                else:
                    anonymized_messages.append(msg)
            
            return {
                "messages": anonymized_messages,
                "session_id": session_id
            }

        def call_llm(data: Dict[str, Any]) -> Dict[str, Any]:
            """
            Step 2: Call the LLM
            """
            messages = data["messages"]
            session_id = data["session_id"]
            
            logger.info(f"Forwarding to LLM (Session {session_id})...")
            response = llm.invoke(messages)
            
            return {
                "response": response,
                "session_id": session_id
            }

        def output_guard(data: Dict[str, Any]) -> AIMessage:
            """
            Step 3: Deanonymize Output
            """
            response = data["response"]
            session_id = data["session_id"]
            
            if isinstance(response, AIMessage) and isinstance(response.content, str):
                logger.info(f"Deanonymizing response (Session {session_id})...")
                deanonymized_content = self.pii_vault.deanonymize(response.content, session_id)
                return AIMessage(content=deanonymized_content)
            
            return response

        # Compose the chain
        chain = (
            RunnableLambda(input_guard) 
            | RunnableLambda(call_llm) 
            | RunnableLambda(output_guard)
        )
        
        return chain
