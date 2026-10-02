# Code signing policy

The Windows binary of Azure Firewall Watch is signed with a certificate issued to the
SignPath Foundation, which provides free code signing for open source projects.

> Free code signing provided by [SignPath.io](https://signpath.io), certificate by
> [SignPath Foundation](https://signpath.org).

## What is signed

Only `az-firewall-watch.exe` from a GitHub release. The binary is built from this
repository by the `Release binaries` workflow on GitHub-hosted runners, and nothing else
is signed. The macOS and Linux archives are not signed.

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

It sends nothing to the author or to any other third party. Logs and resource definitions
stay on your machine. The app writes two things: the `.env` with your connection settings
next to the binary, and a cache of ARM responses in the operating system's per-user cache
directory (on Windows `%LOCALAPPDATA%\az-firewall-watch\Cache`). Delete either at any time.
The binary makes no other system changes and needs no installer.
