# Third-Party Licenses (P1 Foundation)

Recorded for Python 3.15.2 local test environment (`C:\Users\kenta\.gemini\antigravity\scratch\.ctf-vdp-harness-venv`) in accordance with `docs/10-implementation-plan(.ja).md` and `docs/11-contracts-and-acceptance(.ja).md`.

## Pinned Primary & Dev Dependencies (`pyproject.toml`)

| Package | Version | License | Notes |
|---|---|---|---|
| `fastmcp` | `4.1.8` | `Apache-2.0` | Requires `PYYAML_FORCE_LIBYAML=0` when building transitive `PyYAML==6.0.3` on Windows Python 3.15 without MSVC Build Tools |
| `mcp` | `2.3.0` | `MIT` | Official MCP SDK |
| `pydantic` | `2.14.3` | `MIT` | Strict contract validation |
| `jsonschema[format-nongpl]` | `4.26.0` | `MIT` | **Must use `format-nongpl`** instead of `format` to exclude GPLv3+ `rfc3987` |
| `pytest` | `9.2.0` | `MIT` | Dev/test extra |

## Environment Build Note (`PyYAML`)

On Windows with Python 3.15.2 and no MSVC Build Tools (`cl.exe`), `PyYAML==6.0.3` has no prebuilt `cp315-win_amd64` wheel on PyPI. Setting `PYYAML_FORCE_LIBYAML=0` disables the optional C extension (`yaml._yaml`) and builds a pure-Python `py3-none-any` wheel cleanly.

## Full Resolved Dependency Inventory (80 Project + Dev Distributions; 0 Copyleft / 0 Unknown)

Inspected via `importlib.metadata` from installed distributions (tool installer `pip==26.3` [`MIT`] excluded from runtime list; `pip` is also `MIT`):

| Package | Version | License (Metadata / Classifier) |
|---|---|---|
| `aiofile` | `3.12.3` | `Apache-2.0` |
| `annotated-types` | `0.8.0` | `MIT` |
| `anyio` | `4.16.0` | `MIT` |
| `arrow` | `1.4.0` | `Apache Software License` |
| `attrs` | `26.1.0` | `MIT` |
| `Authlib` | `1.9.5` | `BSD-3-Clause` |
| `beartype` | `0.23.1` | `MIT` |
| `cachetools` | `8.0.0` | `MIT` |
| `caio` | `0.12.10` | `Apache-2.0` |
| `certifi` | `2026.10.23` | `MPL-2.0` |
| `cffi` | `2.1.1` | `MIT-0` |
| `click` | `8.5.1` | `BSD-3-Clause` |
| `colorama` | `0.4.6` | `BSD License` |
| `cryptography` | `50.0.2` | `Apache-2.0 OR BSD-3-Clause` |
| `cyclopts` | `5.4.2` | `Apache-2.0` |
| `dnspython` | `2.9.2` | `ISC` |
| `docstring_parser` | `0.18.0` | `MIT` |
| `email-validator` | `2.3.0` | `Unlicense` |
| `exceptiongroup` | `1.3.1` | `MIT License` |
| `fastmcp` | `4.1.8` | `Apache-2.0` |
| `fastmcp-slim` | `4.1.8` | `Apache-2.0` |
| `fqdn` | `1.6.0` | `MPL-2.0` |
| `griffelib` | `2.4.1` | `ISC` |
| `h11` | `0.16.0` | `MIT` |
| `httpcore2` | `2.16.0` | `BSD-3-Clause` |
| `httpx2` | `2.16.0` | `BSD-3-Clause` |
| `idna` | `3.20` | `BSD-3-Clause` |
| `iniconfig` | `2.3.1` | `MIT` |
| `isoduration` | `20.11.0` | `ISC License (ISCL)` |
| `joserfc` | `1.8.0` | `BSD-3-Clause` |
| `jsonpointer` | `3.12` | `BSD-3-Clause` |
| `jsonref` | `1.1.0` | `MIT` |
| `jsonschema` | `4.26.0` | `MIT` |
| `jsonschema-path` | `0.5.0` | `Apache-2.0` |
| `jsonschema-specifications` | `2025.9.1` | `MIT` |
| `lark` | `1.3.1` | `MIT` |
| `markdown-it-py` | `4.3.0` | `MIT License` |
| `mcp` | `2.3.0` | `MIT` |
| `mcp-types` | `2.3.0` | `MIT` |
| `mdurl` | `0.1.2` | `MIT License` |
| `openapi-pydantic` | `0.6.0` | `MIT` |
| `opentelemetry-api` | `1.45.2` | `Apache-2.0` |
| `packaging` | `26.3` | `Apache-2.0 OR BSD-2-Clause` |
| `pathable` | `0.6.0` | `Apache-2.0` |
| `platformdirs` | `4.14.5` | `MIT` |
| `pluggy` | `1.7.0` | `MIT` |
| `py-key-value-aio` | `0.4.6` | `Apache-2.0` |
| `pycparser` | `3.12` | `BSD-3-Clause` |
| `pydantic` | `2.14.3` | `MIT` |
| `pydantic-settings` | `2.16.2` | `MIT` |
| `pydantic_core` | `2.50.4` | `MIT` |
| `Pygments` | `2.21.0` | `BSD-2-Clause` |
| `PyJWT` | `2.15.1` | `MIT` |
| `pyperclip` | `1.11.0` | `BSD` |
| `pytest` | `9.2.0` | `MIT` |
| `python-dateutil` | `4.0.0` | `BSD-3-Clause` |
| `python-dotenv` | `1.2.4` | `BSD-3-Clause` |
| `python-multipart` | `0.0.33` | `Apache-2.0` |
| `pywin32` | `312` | `PSF` |
| `PyYAML` | `6.0.3` | `MIT` |
| `referencing` | `0.37.0` | `MIT` |
| `rfc3339-validator` | `0.1.4` | `MIT license` |
| `rfc3986-validator` | `0.1.1` | `MIT license` |
| `rfc3987-syntax` | `1.1.0` | `MIT` |
| `rich` | `15.0.0` | `MIT` |
| `rich-rst` | `2.2.0` | `MIT` |
| `rpds-py` | `2026.9.1` | `MIT` |
| `six` | `1.17.0` | `MIT` |
| `sse-starlette` | `3.7.0` | `BSD-3-Clause` |
| `starlette` | `1.10.0` | `BSD-3-Clause` |
| `truststore` | `0.10.5` | `MIT` |
| `typing-inspection` | `0.4.5` | `MIT` |
| `typing_extensions` | `4.16.0` | `PSF-2.0` |
| `tzdata` | `2026.6` | `Apache-2.0` |
| `uncalled-for` | `0.6.1` | `MIT` |
| `uri-template` | `1.3.0` | `MIT License` |
| `uvicorn` | `0.54.0` | `BSD-3-Clause` |
| `watchfiles` | `1.3.0` | `MIT` |
| `webcolors` | `25.10.0` | `BSD-3-Clause` |
| `websockets` | `17.4` | `BSD-3-Clause` |
