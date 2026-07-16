# Remote Collection

Remote collection currently applies to bounded performance diagnostics. LinuxMD invokes the system
OpenSSH client in batch mode and relies on SSH configuration, an agent, or a readable identity file.
It never accepts or stores a plaintext password.

```console
uv run linuxmd performance --host 192.168.1.100 --user diagnostics
```

Specify additional connection and sampling options when needed:

```console
uv run linuxmd performance \
  --host app-01.example.net \
  --user diagnostics \
  --port 2222 \
  --identity-file ~/.ssh/diagnostics_ed25519 \
  --duration 10 \
  --timeout 90
```

Confirm non-interactive access first:

```console
ssh diagnostics@192.168.1.100 true
```

Commands are read-only and have finite sample counts. The remote account must be able to run the
standard diagnostic tools. Restricted `dmesg`, absent sysstat commands, and distribution-specific
output are recorded as limitations rather than guessed. LinuxMD does not request sudo or elevate
privileges.

Remote host identifiers, process names, kernel messages, and command output may be sensitive. Store
and share the resulting `performance.json` accordingly.
