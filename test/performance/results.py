import json
import os
import platform
import tempfile
from datetime import datetime, timezone
from pathlib import Path


SCENARIOS = ("baseline", "with_mac")
PLOT_DIRECTORY = Path(__file__).resolve().parents[1] / "perf_plot"
OUTPUT_FILES = {
    "function": "function/test_results.json",
    "qps": "qps/test_results.json",
    "syscall": "syscall/test_results.json",
}


def get_architecture():
    machine = platform.machine().lower()
    if machine in ("amd64", "x86_64"):
        return "amd64"
    if machine in ("arm64", "aarch64"):
        return "arm64"
    raise RuntimeError(f"Unsupported benchmark architecture: {machine}")


def save_results(suite, scenario, iterations, results):
    if scenario not in SCENARIOS:
        raise ValueError(f"scenario must be one of: {', '.join(SCENARIOS)}")
    if suite not in OUTPUT_FILES:
        raise ValueError(f"unsupported benchmark suite: {suite}")

    output_path = PLOT_DIRECTORY / OUTPUT_FILES[suite]
    output_path.parent.mkdir(parents=True, exist_ok=True)

    data = {"schema_version": 1, "runs": {}}
    if output_path.exists():
        with output_path.open("r", encoding="utf-8") as result_file:
            data = json.load(result_file)
        if data.get("schema_version") != 1:
            raise ValueError(
                f"Unsupported results format in {output_path}; "
                "existing data was left unchanged."
            )
        if not isinstance(data.get("runs"), dict):
            raise ValueError(
                f"Invalid results structure in {output_path}; "
                "existing data was left unchanged."
            )

    architecture = get_architecture()
    runs = data.setdefault("runs", {}).setdefault(architecture, {})
    run = runs.setdefault(scenario, {"results": {}})
    stored_results = run.setdefault("results", {})
    for key, value in results.items():
        if isinstance(value, dict) and isinstance(stored_results.get(key), dict):
            stored_results[key].update(value)
        else:
            stored_results[key] = value
    run["iterations"] = iterations
    run["updated_at"] = datetime.now(timezone.utc).isoformat()

    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=output_path.parent,
            delete=False,
        ) as result_file:
            json.dump(data, result_file, indent=2, allow_nan=False)
            result_file.write("\n")
            temporary_path = result_file.name
        os.replace(temporary_path, output_path)
    finally:
        if temporary_path and os.path.exists(temporary_path):
            os.unlink(temporary_path)

    print(f"[INFO] Results saved to {output_path}")
