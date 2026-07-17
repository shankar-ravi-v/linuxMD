# Contributing to LinuxMD

LinuxMD is currently in an early alpha stage. Public issue creation is temporarily restricted while
the initial architecture and interfaces continue to evolve.

Focused pull requests are welcome. Before preparing a substantial change, please contact the
project author through the LinkedIn link in the main README.

Remove credentials, hostnames, IP addresses, and other sensitive operational information from any
diagnostic evidence shared with the project.

Run the following checks before submitting a pull request:

```console
uv run ruff check .
uv run ruff format --check .
uv run pytest
```
