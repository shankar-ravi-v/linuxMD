# Release Checklist

## Quality checks

- [ ] `uv run pytest` passes
- [ ] `uv run ruff check .` passes
- [ ] `uv run ruff format --check .` passes
- [ ] Sample collection and analysis output has been verified
- [ ] Provider tests have been completed without exposing credentials

## Documentation and metadata

- [ ] README status, usage, and compatibility notes have been reviewed
- [ ] CHANGELOG has been updated for the release
- [ ] Version metadata is consistent
- [ ] LICENSE is present and accurate

## Publishing

- [ ] Distribution artifacts have been built and inspected
- [ ] GitHub release notes have been prepared
- [ ] Release tag matches the documented release version
