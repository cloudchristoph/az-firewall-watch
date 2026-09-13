# Development

## Running from source

```bash
git clone https://github.com/cloudchristoph/az-firewall-watch.git
cd az-firewall-watch
./start.sh          # Windows: start.bat
```

The start scripts create a virtual environment, install `requirements.txt` and
launch `main.py`. Python 3.10 or newer is required.

## Project layout

| Path                | What lives there                                                                  |
| ------------------- | --------------------------------------------------------------------------------- |
| `main.py`           | Entry point: loads `.env`, runs the wizard when needed, starts the app             |
| `fw_parser.py`      | Log parsing for the structured and legacy formats                                  |
| `dialogs.py`        | Shared modal dialogs (connecting, error, update, policy-context notice) and the status bar |
| `viewer/`           | The TUI: `app.py`, `streaming.py` (Event Hub worker), `config.py`, `updates.py`    |
| `viewer/views/`     | Tab and screen widgets: `firewall.py`, `policy.py`, `ip_groups.py`, the row detail dialog and the trace panel |
| `viewer/arm.py`     | ARM client (`DefaultAzureCredential` with Azure CLI token fallback)                |
| `viewer/azure_resources.py` | Typed fetchers for firewall, policy chain, IP groups and subnets           |
| `viewer/management.py` | Orchestrates cache lookup → ARM fetch → cache write                            |
| `viewer/enrichment.py` | Ties log rows to the metadata: IP-group membership, the logged rule's definition, `AzFw.<octet>` rendering |
| `viewer/trace.py`   | Policy evaluation trace, the logic behind the detail dialog's tree              |
| `viewer/cache.py`   | On-disk metadata cache                                                             |
| `setup/`            | The setup wizard: `screens.py`, `operations.py` (Azure CLI), `services.py`         |
| `tests/`            | pytest suite; `tests/live/` holds the optional live integration tests              |

## Building the binary

```bash
pip install -r requirements.txt -r requirements-build.txt

pyinstaller \
  --onefile \
  --name az-firewall-watch \
  --collect-all textual \
  --hidden-import azure.eventhub \
  --hidden-import azure.eventhub.aio \
  --hidden-import azure.eventhub._transport._pyamqp_transport \
  --add-data "fw_parser.py:." \
  --add-data "version.txt:." \
  main.py

# Binary is at dist/az-firewall-watch  (or dist/az-firewall-watch.exe on Windows)
```

Releases are built by `.github/workflows/release.yml` when a `v*` tag is pushed;
the workflow refuses to build if `CHANGELOG.md` has no section for that version.

## Linting and types

```bash
ruff check .        # --fix applies what can be fixed automatically
mypy
```

Both are configured in `pyproject.toml`, so neither takes arguments. `ruff` runs
the `E`, `F`, `W`, `I`, `B` and `UP` rule sets at line length 120, with `E501`
and `E701` off because long TUI strings and one-line guards are deliberate here.
`mypy` checks the entry point, the shared modules and the `viewer` and `setup`
packages against Python 3.10.

A `lint` job in CI runs both on every push, in parallel with the test matrix, so
a failure here is as blocking as a failing test.

## 🧪 Running tests

```bash
pip install -r requirements.txt -r requirements-dev.txt
pytest
```

The suite covers the log parser (structured and legacy formats), the filter logic,
rendering helpers, the Event Hub streaming worker (against a fake client), the
GitHub update check, the ARM client and policy context (against canned ARM
payloads), and headless runs of both the viewer and the whole setup wizard via
Textual's test pilot with the Azure CLI mocked out.

**No Azure connection is required.** The same suite runs in CI on every push and
pull request: Linux on Python 3.10, 3.12 and 3.13, plus Windows and macOS on 3.12.

Before committing, the full local round is `ruff check .`, `mypy`, `pytest`.

While working on one area, run just that part:

```bash
pytest tests/test_trace.py        # one file
pytest -k "trace and not live"    # by name
pytest tests/test_views.py -x     # stop at the first failure
```

### Live integration tests

Optional, never run in CI: these exercise the real ARM round trip and a real Event
Hub. They are skipped unless you point them at your environment. Only read
operations are made, and the metadata cache is redirected to a temporary
directory:

```bash
AZFW_LIVE_FIREWALL_ID=/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Network/azureFirewalls/<fw> \
AZFW_LIVE_EVENTHUB_NAMESPACE=<ns>.servicebus.windows.net \
AZFW_LIVE_EVENTHUB_NAME=firewall-logs \
pytest tests/live -m live
```

Add `AZFW_LIVE_CONSUMER_GROUP=<name>` when `$Default` is already taken by another
reader; without it the tests use `$Default`.

Your identity needs **Reader** on the firewall, its policy and IP groups, and the
**Azure Event Hubs Data Receiver** role on the hub.

### Live wizard runs

`tests/live/test_live_wizard.py` drives every path of the setup wizard through
the real screens with the real Azure CLI behind them, and after each path starts
the viewer headless on the `.env` the wizard wrote until it reports the hub as
connected. The paste, enter and discover paths only read; they need the two
`AZFW_LIVE_EVENTHUB_*` variables above and, for discovery, the name of the
subscription the hub lives in:

```bash
AZFW_LIVE_EVENTHUB_NAMESPACE=<ns>.servicebus.windows.net \
AZFW_LIVE_EVENTHUB_NAME=firewall-logs \
AZFW_LIVE_WIZARD_SUBSCRIPTION="<subscription name>" \
pytest tests/live/test_live_wizard.py -m live
```

The deploy path is opted into separately, because it creates things: a resource
group `rg-azfw-watch-e2e`, a Basic namespace with a fresh name, a hub, the auth
rules, a diagnostic setting named `azfw-e2e-diag` on the firewall and, for the
Entra ID variant, a role assignment. It waits for the first record to reach the
new hub, then runs discovery with SAS against it so the *create a Listen rule*
prompt is exercised for real, and removes everything again in a `finally`. Add
`AZFW_LIVE_WIZARD_DEPLOY=1` and `AZFW_LIVE_WIZARD_FIREWALL=<firewall name>`;
the firewall needs a free diagnostic-setting slot (Azure allows five) and your
identity needs to be able to create these resources and assign roles. The
firewall must be carrying traffic, or no record can arrive. Budget about ten
minutes for the SAS variant and up to forty for the Entra ID one: a new
diagnostic setting delivers its first batch anywhere between five and twenty
minutes after it was created, and the test waits for that.

## Releasing

Version lives in `version.txt`, and every release needs a matching
`## [x.y.z]` section in `CHANGELOG.md` (the format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/)). Tagging `vx.y.z`
triggers the release workflow, which validates the changelog, builds the three
binaries and attaches them to the GitHub release.
