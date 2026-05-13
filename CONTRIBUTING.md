# Contributing

## Project Structure

```text
napalm_netgear/
├── napalm_netgear/
│   ├── netgear.py        # Main driver — all getters and connection logic
│   └── parser.py         # Shared parsing utilities (fixed-width tables, key-value lists)
├── test/
│   └── unit/
│       ├── conftest.py               # pytest fixtures, PatchedNetgearDriver, FakeNetgearDevice
│       ├── test_getters.py           # M-series getter tests (delegates to NAPALM BaseTestGetters)
│       ├── test_getters_gs.py        # GS-series getter tests (standalone, separate mock driver)
│       ├── test_compare_config.py    # compare_config unit tests
│       ├── mocked_data/              # M-series mock fixtures (M4250, M4350, M4500)
│       └── gs_mocked_data/           # GS-series mock fixtures (gs108tv3)
├── scripts/              # Dev-only helper scripts (gitignored)
├── real_output/          # Raw device output for fixture generation (gitignored)
├── pyproject.toml
└── tox.ini
```

## Driver Architecture

### Platform Detection

On `open()`, `_detect_platform()` sends `show sysinfo`. If the device responds with "Unknown command" it is a GS-series switch; otherwise it is M-series. The result is stored in `self._platform_type` (`"m_series"` or `"gs_series"`).

All getters branch on `self._platform_type` at the top:

```python
def get_facts(self):
    if self._platform_type == "gs_series":
        return self._get_facts_gs()
    ...  # M-series logic
```

### M-Series (M4250 / M4350 / M4500)

- Uses `send_command_timing` via Netmiko for all commands.
- `_send_command(command)` is the internal wrapper — handles list of fallback commands, pagination stripping, and `ConnectionClosedException`.
- Port naming: `1/0/1` style (M4350/M4500) or `0/1` style (M4250).

### GS-Series (GS108Tv3)

- `no pager` does not work — `_send_command` handles `--More--` prompts automatically.
- Uses `show tech-support` as the primary data source, cached in `self._gs_tech_support_cache`.
- Sections are delimited by `---------- Section Name ----------` lines and accessed via `_get_gs_section(name)`.

## Configuration Files

| File | Purpose |
| ---- | ------- |
| `pyproject.toml` | Package metadata, runtime dependencies (`napalm`, `netmiko`), and `[dev]` extras for testing |
| `requirements.txt` | Pinned runtime deps — used by `tox` via `-rrequirements.txt` |
| `requirements-dev.txt` | Test/lint deps (`pytest`, `pytest-cov`, `pylama`, `mock`, `tox`) — used by `tox` |
| `setup.cfg` | Tool config: pylama linter rules (pep8, pyflakes, mccabe), pytest `addopts`, and coverage include/exclude paths |
| `tox.ini` | Multi-Python test matrix (3.10–3.13); installs both requirements files and runs `pytest` |

**For local development** the recommended install is:

```bash
pip install -e ".[dev]"
```

This installs the package in editable mode with all dev dependencies declared in `pyproject.toml`. The `requirements*.txt` files are used by `tox` and CI only.

## Testing

### Running Tests

```bash
pip install -e ".[dev]"
pytest test/unit/
```

### Mock Data Structure

Each getter test has a directory under `test/unit/mocked_data/<test_name>/` with one subdirectory per device variant:

```text
test/unit/mocked_data/test_get_facts/
├── m4250/
│   ├── show_sysinfo.txt          # Raw CLI output (filename = sanitized command)
│   ├── show_version.txt
│   └── expected_result.json      # Expected getter return value
├── m4350/
└── m4500/
```

GS fixtures follow the same pattern under `test/unit/gs_mocked_data/` with a single `gs108tv3/` variant.

**Filename convention**: the mock filename is the CLI command with spaces and special characters replaced by underscores (via `BaseTestDouble.sanitize_text`). For example `show interfaces status all` → `show_interfaces_status_all.txt`.

### Adding a New Getter

1. Implement the getter in `napalm_netgear/netgear.py` (branch on `_platform_type` if needed).
2. Create mock fixture directories for each variant:

   ```text
   test/unit/mocked_data/test_get_<name>/m4250/
   test/unit/mocked_data/test_get_<name>/m4350/
   test/unit/mocked_data/test_get_<name>/m4500/
   ```

3. Add the sanitized CLI output `.txt` files.
4. Add `expected_result.json` matching the getter's return value.
5. If NAPALM's `BaseTestGetters` includes a `test_get_<name>` method it will be picked up automatically by `TestGetter` in `test_getters.py`. Otherwise add a test to `test_compare_config.py` or a new file.
