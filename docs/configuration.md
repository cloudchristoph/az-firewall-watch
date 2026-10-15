# Configuration

The [setup wizard](getting-started.md#-the-setup-wizard) writes all of this for
you, so reach for this page when you would rather configure the viewer by hand:
your Event Hub already exists or comes out of Terraform or Bicep, or the machine
has no Azure CLI, which the wizard needs for discovery and deployment.

## Writing `.env` yourself

Create a `.env` file next to the binary (or in the repo root when running from
source).

**SAS connection string:**

```ini
EVENT_HUB_CONNECTION_STRING=Endpoint=sb://your-ns.servicebus.windows.net/;SharedAccessKeyName=...;EntityPath=your-hub-name
EVENT_HUB_CONSUMER_GROUP=$Default
EVENT_HUB_START_POSITION=latest   # or: earliest
```

**Entra ID (passwordless)**, which is required when SAS keys are disabled on the
namespace:

```ini
EVENT_HUB_NAMESPACE=your-ns.servicebus.windows.net
EVENT_HUB_NAME=your-hub-name
EVENT_HUB_CONSUMER_GROUP=$Default
EVENT_HUB_START_POSITION=latest
```

Entra ID auth uses `DefaultAzureCredential`, which picks up your Azure CLI login,
a managed identity, environment variables and so on.

> [!CAUTION]
> Never commit `.env` to source control. A SAS connection string grants access to
> your Event Hub, so protect the file and rotate keys regularly.

## Without a `.env` file

`.env` is optional. The viewer reads plain environment variables too, and values
already present in the environment win over the file. Useful when you would rather
not keep a SAS connection string on disk, or when a wrapper script pulls the
values from a secret store before starting the viewer:

```bash
export EVENT_HUB_NAMESPACE=your-ns.servicebus.windows.net
export EVENT_HUB_NAME=your-hub-name
export POLICY_CONTEXT=on
./az-firewall-watch
```

As soon as either `EVENT_HUB_CONNECTION_STRING` or
`EVENT_HUB_NAMESPACE` + `EVENT_HUB_NAME` is set, the wizard stays out of the way.

> [!NOTE]
> Decide [policy context](policy-context.md) explicitly when you run without a
> `.env` file, either with `POLICY_CONTEXT` as above or with the
> `--policy-context` / `--no-policy-context` flag. Without an explicit answer the
> viewer shows its one-time notice at start-up, and it can only save your reply to
> an existing `.env` file, so the notice would come back on every launch.

## Environment variables

<!-- markdownlint-disable MD060 -->
| Variable                      | Description                                                                               | Default    |
| ----------------------------- | ----------------------------------------------------------------------------------------- | ---------- |
| `EVENT_HUB_CONNECTION_STRING` | Primary connection string incl. `EntityPath=<your-hub-name>`                              | n/a        |
| `EVENT_HUB_NAMESPACE`         | Fully qualified namespace (e.g. `mynamespace.servicebus.windows.net`), for Entra ID auth | n/a        |
| `EVENT_HUB_NAME`              | Event Hub name, for Entra ID auth                                                         | n/a        |
| `EVENT_HUB_CONSUMER_GROUP`    | Consumer group                                                                            | `$Default` |
| `EVENT_HUB_START_POSITION`    | `latest` (only new events) or `earliest` (replay the hub's full retention first), case-insensitive and also accepted as the SDK spellings `@latest` / `@earliest`, with `-1` as a synonym for earliest. Anything else is passed to the SDK unchanged, so a raw offset or sequence number works | `latest`   |
| `POLICY_CONTEXT`              | `on` / `off`: [policy context](policy-context.md) via Azure Resource Manager (tabs, trace, cache). If the key is missing, the viewer asks once at start-up and saves your answer | `on`       |
<!-- markdownlint-enable MD060 -->

> [!NOTE]
> When both `EVENT_HUB_NAMESPACE`/`EVENT_HUB_NAME` and
> `EVENT_HUB_CONNECTION_STRING` are set, Entra ID is preferred.

## MCP server

The [MCP server](mcp-server.md) reads the same `.env` as the viewer, so the
variables above apply to it too. The variables below are its own. Each one can
also be given on the command line, and the command line wins (see
[the MCP server's options](mcp-server.md#command-line-options)).

<!-- markdownlint-disable MD060 -->
| Variable               | Description                                                                                                  | Default     |
| ---------------------- | ------------------------------------------------------------------------------------------------------------ | ----------- |
| `AZFW_FIREWALL_ID`     | Azure Firewall resource id (`/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Network/azureFirewalls/<name>`). Loads the policy context at start instead of waiting for the first log record | n/a         |
| `AZFW_MCP_BUFFER_SIZE` | Log rows kept in memory, between 100 and 1000000                                                              | `20000`     |
| `AZFW_MCP_TRANSPORT`   | `stdio` (the client starts the server and talks to it over standard input and output) or `http` (streamable HTTP on `AZFW_MCP_HOST` and `AZFW_MCP_PORT`, path `/mcp`, no authentication) | `stdio`     |
| `AZFW_MCP_HOST`        | Address the HTTP transport listens on                                                                         | `127.0.0.1` |
| `AZFW_MCP_PORT`        | Port the HTTP transport listens on, 1 to 65535                                                                | `8765`      |
| `AZFW_MCP_LOG_LEVEL`   | Log level on standard error: `DEBUG`, `INFO`, `WARNING`, `ERROR` or `CRITICAL`                                | `INFO`      |
<!-- markdownlint-enable MD060 -->

The server and the viewer can run side by side only with separate consumer
groups. Give the server its own `EVENT_HUB_CONSUMER_GROUP`, as described in
[Use your own consumer group](mcp-server.md#use-your-own-consumer-group).

## Command-line options

| Option                | Effect                                                                        |
| --------------------- | ----------------------------------------------------------------------------- |
| `--reconfigure`       | Re-run the setup wizard even though `.env` is already configured               |
| `--policy-context`    | Force policy context **on** for this run, ignoring `POLICY_CONTEXT` in `.env`  |
| `--no-policy-context` | Force it **off** for this run: no ARM requests, no cache, Logs tab only       |
| `--mcp`               | Start the [MCP server](mcp-server.md) instead of the viewer. Every other option is passed to the server |

Command-line flags win over `.env` and are never written back, so they affect a
single run. Either policy-context flag also counts as an explicit answer, so the
one-time notice stays away even when `.env` has no `POLICY_CONTEXT` key.

## Required Azure permissions

Two questions decide what you need: what the **viewer** reads while it runs, and
which **wizard** paths you use once during setup. Most of the list below belongs
to the second question, and you can skip it entirely by writing `.env` yourself.

### For running the viewer

| Scope                               | Role                               | When                                                                 |
| ----------------------------------- | ---------------------------------- | -------------------------------------------------------------------- |
| Event Hub namespace or hub          | **Azure Event Hubs Data Receiver** | Entra ID auth. Not needed with a SAS connection string                |
| Firewall, its policy, its IP groups, its subnets and public IPs | **Reader**     | [Policy context](policy-context.md), which is on by default. Not needed with `POLICY_CONTEXT=off` |
| A NAT gateway on the firewall subnet, a maintenance configuration assigned to the firewall | **Reader**, optional | Only for the corresponding lines on the Firewall tab. Without it the line says the resource is not readable |

That is the complete list for day-to-day use. The viewer only ever reads, and
without these roles it degrades instead of failing: no Data Receiver means the
connection is refused with a hint, no Reader means `○ Context unavailable` with
the exact error on the Firewall tab and the Logs tab otherwise. Nothing the viewer does is an ARM action: the learned SNAT
prefixes of an auto-learn firewall, for example, are only available through a
POST and therefore stay off screen by design.

### For the setup wizard

Only for the path you actually pick, and only during setup. All of these also
need the Azure CLI installed and logged in.

| Wizard path                                       | Scope                        | Role                                              |
| ------------------------------------------------- | ---------------------------- | ------------------------------------------------- |
| *Discover Event Hub automatically*                | Subscriptions, namespaces, hubs | **Reader**                                     |
| *SAS auth rule*, reading its keys or creating one  | Event Hub namespace or hub   | List keys and manage auth rules (e.g. **Contributor**) |
| *Deploy new Event Hub*, the namespace and hub     | Target resource group        | **Contributor**                                   |
| *Deploy new Event Hub*, the Diagnostic Settings   | The Azure Firewall           | **Contributor** or **Monitoring Contributor**     |
| *Entra ID*, assigning Data Receiver for you       | Event Hub namespace or hub   | **Owner** or **User Access Administrator**        |

The last row is optional: if the assignment fails, the wizard prints the exact
role assignment so somebody with the rights can run it for you.

*Enter existing Event Hub data* and *Paste SAS connection string* need no Azure
permissions at all, since the wizard only writes `.env` in those paths.

> [!NOTE]
> The wizard changes something in Azure in exactly two places, the *deploy* path
> and creating a SAS auth rule, and both ask for confirmation first. Everything
> else it does is reading and writing your local `.env`.
