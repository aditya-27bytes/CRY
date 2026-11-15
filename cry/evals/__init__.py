"""CRY BYOM (Bring Your Own Model) evaluation and benchmarking engine."""

from cry.evals.benchmark import (
    export_benchmark_markdown,
    run_model_benchmark,
    run_multi_model_benchmark,
)

__all__ = ["export_benchmark_markdown", "run_model_benchmark", "run_multi_model_benchmark"]
