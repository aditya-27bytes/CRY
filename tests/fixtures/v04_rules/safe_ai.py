# Tests fixture: safe AI application patterns for v0.4 rules

import json

from flask import request


def prompt_injection_safe():
    user_input = request.args.get("query")
    # Safe: separated roles with message dictionary arrays
    messages = [
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": user_input},
    ]
    return messages


def excessive_agency_tool_safe():
    # Safe: scoped read-only tool
    class ReadOnlyCalculator:
        def add(self, a: int, b: int) -> int:
            return a + b

    return ReadOnlyCalculator()


def unvalidated_exec_sink_safe(response):
    # Safe: parse structured JSON instead of evaluating code
    data = json.loads(response.choices[0].message.content)
    return data


def rag_unfiltered_safe(url, vectorstore):
    # Safe: sanitized document ingestion with filtering
    import requests

    raw_text = requests.get(url).text
    clean_text = raw_text.replace("ignore previous instructions", "")
    vectorstore.add_documents([clean_text])
