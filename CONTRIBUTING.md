# Contributing to LinuxMD

LinuxMD is currently in an early alpha stage. Direct issue creation is temporarily restricted while
the initial architecture and interfaces are evolving.

Focused pull requests are welcome. For questions, bug reports, or proposed enhancements, please
contact the project author through the LinkedIn link in the main README before preparing a large
change.

Run the project checks before submitting a pull request:

```console
uv run ruff check .
uv run ruff format --check .
uv run pytest
```
