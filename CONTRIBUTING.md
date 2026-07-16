# Contributing to LinuxMD

Bug reports, feature requests, and pull requests are welcome. Please include enough diagnostic
context to reproduce a problem, but remove credentials and sensitive host information before
sharing reports.

Keep changes focused and follow the existing Python style and type annotations. Add or update tests
for behavior changes.

Run the project checks before submitting a pull request:

```console
uv run ruff check .
uv run ruff format --check .
uv run pytest
```
