import json
from copy import deepcopy
import tiktoken

from openai import OpenAI
from dotenv import load_dotenv
import os

import constants
from GPT.gpt_constants import LS_RESPONSE_TEXT_FORMAT, LS_PROMPT_MESSAGES_SYSTEM, \
    LS_PROMPT_MESSAGES_USER, SYSTEM, USER
from instructions import SYSTEM_TEXT_INSTRUCTION
from logger.logger import Logger

load_dotenv()

organization = os.getenv("ORGANIZATION")
project_id = os.getenv("PROJECT_ID")

# Initialize tokenizer once (critical for performance)
enc = tiktoken.get_encoding("o200k_base")

# Adjusted token limits to stay within model's context window
MAX_FULLTEXT_TOKENS = 100000  # Reduced from 250000
MAX_INTROTEXT_TOKENS = 20000  # Reduced from 50000
RESERVE_TOKENS = 1000  # Reserve tokens for system messages and response

class GPT(Logger):
    """
    GPT class to handle interactions with OpenAI's chat models.
    Inherits from Logger for logging capabilities.
    """
    def __init__(self, logger=__file__, quiet=False):
        """
        Initializes the GPT class with OpenAI client configuration.

        Args:
            logger (str): The name of the logger (default is the file name).
            quiet (bool): Whether to print log in console. If `True`, the function will not print log in console.
        """
        super().__init__(logger, quiet)
        self.client = OpenAI(
            organization=organization,
            project=project_id,
        )

    def count_total_tokens(self, system_instruction: str, prompt: str) -> int:
        """
        Count total tokens in system instruction and prompt combined.
        """
        return len(enc.encode(system_instruction)) + len(enc.encode(prompt)) + RESERVE_TOKENS

    def truncate_by_tokens(self, text: str, max_tokens: int) -> str:
        """
        Truncates text to fit within max_tokens limit, cutting from the start.
        
        Args:
            text (str): The text to truncate
            max_tokens (int): Maximum number of tokens allowed
            
        Returns:
            str: Truncated text that fits within token limit
        """
        tokens = enc.encode(text)
        if len(tokens) <= max_tokens:
            return text
        return enc.decode(tokens[-max_tokens:])

    def generate_structured_response_by_single_prompt(self, prompt, system_instruction=SYSTEM_TEXT_INSTRUCTION,
                                                    model=constants.DEFAULT_GPT_MODEL,
                                                    response_format=LS_RESPONSE_TEXT_FORMAT):
        """
        Generates a structured response for a single user prompt.

        This function creates system and user messages and sends them
        to OpenAI's API. It is useful when only a single user message is required in a chat.

        Args:
            prompt (str): The user input message.
            system_instruction (str, optional): System instructions for the model. Defaults to SYSTEM_TEXT_INSTRUCTION.
            model (str, optional): The GPT model to use. Defaults to constants.DEFAULT_GPT_MODEL.
            response_format (str, optional): The format of the response. Defaults to LS_RESPONSE_TEXT_FORMAT.

        Returns:
            str: The model's response.
        """
        try:
            prompt_list = json.loads(prompt)
            if "fulltext" in prompt_list[0]:
                if prompt_list[0]["fulltext"] is None:
                    prompt_list[0]["fulltext"] = ""
                prompt_list[0]["fulltext"] = self.truncate_by_tokens(prompt_list[0]["fulltext"], MAX_FULLTEXT_TOKENS)
            if "introtext" in prompt_list[0]:
                if prompt_list[0]["introtext"] is None:
                    prompt_list[0]["introtext"] = ""
                prompt_list[0]["introtext"] = self.truncate_by_tokens(prompt_list[0]["introtext"], MAX_INTROTEXT_TOKENS)
            prompt = json.dumps(prompt_list, indent=4)
        except (json.JSONDecodeError, IndexError, KeyError):
            # If not JSON or doesn't have expected structure, treat as plain text
            max_allowed = 120000 - self.count_total_tokens(system_instruction, "")  # Leave room for system message
            prompt = self.truncate_by_tokens(prompt, max_allowed)

        # Create system and user messages
        system_message = self.create_chat_message(system_instruction, SYSTEM)
        user_message = self.create_chat_message(prompt, USER)

        # Verify total tokens before making the API call
        total_tokens = self.count_total_tokens(system_instruction, prompt)
        if total_tokens > 120000:  # Safe limit below 128000
            self.logger.warning(f"Total tokens ({total_tokens}) approaching limit, truncating prompt further")
            max_allowed = 120000 - self.count_total_tokens(system_instruction, "")
            prompt = self.truncate_by_tokens(prompt, max_allowed)
            user_message = self.create_chat_message(prompt, USER)

        # Send request to OpenAI's API
        response = self.client.chat.completions.create(
            model=model,
            max_tokens=constants.MAX_TOKENS,
            response_format=response_format,
            messages=[
                system_message,
                user_message
            ]
        )
        result = response.choices[0].message.content
        return result

    def create_chat_message(self, prompt, message_type=SYSTEM):
        """
        Creates a formatted chat message for OpenAI API.

        Args:
            prompt (str): The message text.
            message_type (str, optional): The type of message (SYSTEM or USER). Defaults to SYSTEM.

        Returns:
            dict: A structured message dictionary compatible with OpenAI API.
        """
        # Select the appropriate message schema based on type
        message_schema = (
            deepcopy(LS_PROMPT_MESSAGES_SYSTEM)
            if message_type == SYSTEM
            else deepcopy(LS_PROMPT_MESSAGES_USER)
            if message_type == USER
            else None
        )

        # Update the schema with the prompt content
        if message_schema:
            message_schema["content"][0]["text"] = prompt
        return message_schema

