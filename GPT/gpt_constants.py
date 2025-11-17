import instructions

SYSTEM = "system"
USER = "user"


LS_GPT_TEXT_SCHEMA = {
    "type": "object",
    "properties": {
        "tags": {"type": "array", "items": {"type": "string"}},
        "metadesc": {"type": "string"},
        "meta_keywords": {"type": "string"},
        "title_tag": {"type": "string"},
        "h1_tag": {"type": "string"},
        "description": {"type": "string"},
        "alt_tags_introtext": {"type": "array", "items": {"type": "string"}},
        "alt_tags_fulltext": {"type": "array", "items": {"type": "string"}},
        "extra_alt_tags": {"type": "array", "items": {"type": "string"}},
        "alt_tag_title_image": {"type": "string"},
        "severity": {"type": "string"},
        "application": {"type": "string"}
    },
    "required": ["tags", "metadesc", "meta_keywords", "title_tag", "h1_tag", "description", "alt_tags_introtext", "alt_tags_fulltext", "alt_tag_title_image", "extra_alt_tags", "severity", "application"],
    "additionalProperties": False
}

LS_ONE_MESSAGE_STRING_SCHEMA = {
    "type": "object",
    "properties": {
        "string": {"type": "string"},
    },
    "required": ["string"],
    "additionalProperties": False
}

LS_GPT_IMAGE_SCHEMA = {
    "type": "object",
    "properties": {
        "description": {"type": "string"},
    },
    "required": ["description"],
    "additionalProperties": False
}

LS_RESPONSE_TEXT_FORMAT = {
    "type": "json_schema",
    "json_schema": {
        "name": "blog_format",
        "schema": LS_GPT_TEXT_SCHEMA,
        "strict": True
    }
}


LS_RESPONSE_SINGLE_STRING_FORMAT = {
    "type": "json_schema",
    "json_schema": {
        "name": "one_string_format",
        "schema": LS_ONE_MESSAGE_STRING_SCHEMA,
        "strict": True
    }
}

LS_RESPONSE_IMAGE_FORMAT = {
    "type": "json_schema",
    "json_schema": {
        "name": "blog_image_format",
        "schema": LS_GPT_IMAGE_SCHEMA,
        "strict": True
    }
}

LS_PROMPT_MESSAGES_SYSTEM = {
    "role": "system",
    "content": [
        {
            "type": "text",
            "text": None
        }
    ]
}

LS_PROMPT_MESSAGES_USER = {
    "role": "user",
    "content": [
        {
            "type": "text",
            "text": None
        }
    ]
}
