# Tests fixture: safe secret management using environment variables

import os

OPENROUTER_KEY = os.environ.get("OPENROUTER_API_KEY", "")
ANTHROPIC_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
PINECONE_KEY = os.environ.get("PINECONE_API_KEY", "")
LANGSMITH_KEY = os.environ.get("LANGSMITH_API_KEY", "")
REPLICATE_KEY = os.environ.get("REPLICATE_API_TOKEN", "")
COHERE_KEY = os.environ.get("COHERE_API_KEY", "")
TOGETHER_KEY = os.environ.get("TOGETHER_API_KEY", "")
