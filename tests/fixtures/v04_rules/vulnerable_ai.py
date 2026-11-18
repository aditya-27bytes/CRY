# Tests fixture: vulnerable AI application patterns for v0.4 rules

from flask import request


def prompt_injection_vulnerable():
    user_input = request.args.get("query")
    # Vulnerable: direct f-string prompt concatenation
    prompt = f"You are a helpful assistant. User question: {user_input}"
    return prompt


def excessive_agency_tool_vulnerable():
    # Vulnerable: arbitrary code execution tool
    from langchain.tools import PythonREPLTool

    tool = PythonREPLTool()
    return tool


def unvalidated_exec_sink_vulnerable(response):
    # Vulnerable: passing LLM response directly to eval()
    result = eval(response.choices[0].message.content)
    return result


def rag_unfiltered_vulnerable(url, vectorstore):
    import requests

    # Vulnerable: direct ingestion of external URL into vectorstore
    vectorstore.add_texts(requests.get(url).text)
