# Code signing policy

The Windows binary of Azure Firewall Watch is signed with a certificate issued to the
SignPath Foundation, which provides free code signing for open source projects. Signing
starts with the first release after the project is approved; until then the binary is
unsigned (see [Blocked by your organisation's security policy?](getting-started.md#blocked-by-your-organisations-security-policy)).

> Free code signing provided by [SignPath.io](https://signpath.io), certificate by
> [SignPath Foundation](https://signpath.org).

## What is signed

Only `az-firewall-watch.exe` from a GitHub release. The binary is built from this
repository by the `Release binaries` workflow on GitHub-hosted runners, and nothing else
is signed. winget installs exactly this file. The macOS and Linux archives, which the
Homebrew cask installs, are not signed. Every release also carries
[build provenance attestations](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations)
for all binaries, so you can check that a file was built by this repository's workflow:

```bash
gh attestation verify az-firewall-watch.exe --repo cloudchristoph/az-firewall-watch
```

## Roles

| Role      | Who                                                      | Does                                      |
| --------- | -------------------------------------------------------- | ----------------------------------------- |
| Author    | [cloudchristoph](https://github.com/cloudchristoph)      | changes the code                          |
| Reviewer  | [cloudchristoph](https://github.com/cloudchristoph)      | reviews pull requests                     |
| Approver  | [cloudchristoph](https://github.com/cloudchristoph)      | approves every signing request by hand    |

Everyone with a role uses multi-factor authentication on GitHub and SignPath.

## Privacy

Azure Firewall Watch reads logs from your own Event Hub and, for the policy context, from
Azure Resource Manager, with the credentials you sign in with. It talks to these hosts only:

- your Event Hub namespace and the Microsoft Entra sign-in endpoints, to stream logs;
- `management.azure.com`, to read firewall, policy and IP group definitions;
- `api.github.com`, to check whether a newer release exists (no data about you is sent).

The update check is the only request to a host you did not configure. It asks for the
latest release and sends only a `User-Agent` with the app version; GitHub sees your IP
address, as with any web request. The setup wizard
says so on its first screen, and `UPDATE_CHECK=off` in `.env` or `--no-update-check`
turns it off (see [Configuration](configuration.md)).

It sends nothing to the author or to any other third party. Logs and resource definitions
stay on your machine. The app writes two things:

- the `.env` with your connection settings: next to the binary, or in the user config
  directory when winget or Homebrew installed it (`%LOCALAPPDATA%\az-firewall-watch\`,
  `~/Library/Application Support/az-firewall-watch/`, `~/.config/az-firewall-watch/`);
- a cache of ARM responses in the operating system's per-user cache directory (on Windows
  `%LOCALAPPDATA%\az-firewall-watch\Cache`).

Delete either at any time. The binary makes no other system changes and needs no
installer: delete the file, or run `winget uninstall cloudchristoph.az-firewall-watch` or
`brew uninstall --cask --zap az-firewall-watch`.
