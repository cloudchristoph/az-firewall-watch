# Azure Firewall Watch documentation

Live Azure Firewall log monitoring in your terminal. Start at the
[project README](../README.md) for the short version.

## Set it up

- **[Getting started](getting-started.md)**: download and run on Windows, macOS
  or Linux, run from source, and walk through the first-run setup wizard.
- **[Event Hub](event-hub.md)**: how firewall logs reach the hub, which
  diagnostic categories to enable, retention and what it costs.
- **[Configuration](configuration.md)**: write `.env` yourself, all environment
  variables, command-line options and the Azure roles you need.

## Use it

- **[Using the viewer](using-the-viewer.md)**: the log table, filters and
  category presets, row details, key bindings and the status bar.
- **[Policy context](policy-context.md)**: the Firewall, Policy and IP Groups
  tabs, the evaluation trace, caching, and how to turn all of it off.
- **[Log categories](log-categories.md)**: which Azure log categories are
  parsed and how to enable flow trace and fat flow on the firewall.

## Work on it

- **[Development](development.md)**: build the binary, run the test suite
  (including the optional live tests), and find your way around the packages.
