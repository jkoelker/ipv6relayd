# Repository Guidelines

## Project Structure & Module Organization

- `cmd/ipv6relayd`: CLI entrypoint using `urfave/cli/v3`.
- `pkg/`: Core logic organized by domain:
  - `config`: YAML/JSON configuration loading and validation.
  - `ra`: Router Advertisement relay service.
  - `dhcpv6`: DHCPv6 relay with upstream autodiscovery.
  - `ndp`: Neighbor Discovery proxy with learned + static bindings.
  - `iface`: Interface management abstractions.
  - `ifmon`: Interface event monitoring via netlink.
  - `netstate`: Link-local address and interface state caching.
  - `cache`: Generic TTL cache utilities.
  - `netutil`, `serviceutil`, `testutil`: Shared helpers.
- `integration/`: Network-namespace tests using `gont` framework.
- `docs/design.md`: Architecture notes; `info/`: captured packet samples.
- Tooling: `Makefile` + `Containerfile.devkit` wrap the devkit container.

## Build, Test, and Development Commands

All commands run inside the devkit container (requires Podman or Docker).

```bash
# Lint (golangci-lint with all linters enabled)
make lint

# Unit tests (all packages except integration/)
make test

# Run a single test
make run WHAT="go test -v -run TestLoadConfig ./pkg/config/..."

# Run tests in a specific package
make run WHAT="go test -v ./pkg/ra/..."

# Run any arbitrary command in devkit
make run WHAT="go build ./cmd/ipv6relayd"

# Integration tests (requires privileged container with network namespaces)
make integration

# Interactive shell in devkit container
make shell
```

## Code Style & Formatting

### Imports
Imports are organized into three groups separated by blank lines:
1. Standard library
2. Third-party packages
3. Local packages (`github.com/jkoelker/ipv6relayd/...`)

```go
import (
    "context"
    "errors"
    "fmt"

    "github.com/mdlayher/ndp"
    "golang.org/x/net/ipv6"

    "github.com/jkoelker/ipv6relayd/pkg/config"
    "github.com/jkoelker/ipv6relayd/pkg/iface"
)
```

Formatting is enforced by `gofmt`, `goimports`, and `gci` (all run by `make lint`).

### Naming Conventions
- **Packages/files**: lowercase nouns (e.g., `config`, `netstate`).
- **JSON/YAML tags**: `snake_case` (enforced by `tagliatelle` linter).
- **Variables**: descriptive names; short names (`ok`, `ip`) allowed for common patterns.
- **Errors**: package-level `var Err...` for sentinel errors with descriptive names.

### Function Guidelines
- Keep functions tight: ~100 lines max, ~50 statements max (enforced by `funlen`).
- Prefer exhaustive switch statements with explicit default cases.
- Do NOT alias function signatures (e.g., `type Handler func(...)`)—keep signatures explicit.

### Error Handling
- Use `fmt.Errorf("context: %w", err)` for wrapping errors.
- Define sentinel errors at package level for expected failure modes.
- Never use empty catch blocks or ignore errors silently.

### Logging
- Use structured logging with `log/slog`, not `fmt.Printf`.
- Include relevant context fields: `s.log.Debug("message", "key", value)`.

## Testing Guidelines

- Unit tests live next to code in `_test.go` files.
- Name tests as `TestThing` or `TestThing_Subcase`.
- Always use `t.Parallel()` for test isolation.
- Use `github.com/stretchr/testify/require` for setup invariants (fails immediately).
- Use `github.com/stretchr/testify/assert` for assertions (continues on failure).

```go
func TestLoadConfig(t *testing.T) {
    t.Parallel()

    cfg, err := config.Load("testdata/good.yaml")
    require.NoError(t, err)
    require.NotNil(t, cfg)

    assert.Equal(t, "br0", cfg.Interface)
    assert.True(t, cfg.RouterAdvertisements.Enabled)
}
```

Integration tests use `gont` for network namespace isolation and require privileged execution.

## Commit & Pull Request Guidelines

Follow Linux kernel commit message style:

### Subject line
- **50 characters or less** (hard limit: 72)
- Imperative mood ("Add feature" not "Added feature" or "Adds feature")
- Use conventional commit format: `type(scope): description`
  - Types: `fix`, `feat`, `chore`, `refactor`, `test`, `perf`
  - Scopes: `ci`, `docs`, `config`, `ra`, `dhcpv6`, `ndp`, `deps`, etc.
- No period at end
- Examples:
  - `fix(ra): prevent hop-limit underflow on reload`
  - `feat(ci): add AI agent workflow for automation`
  - `chore(docs): update AGENTS.md with commit guidelines`
  - `chore(deps): update module golang.org/x/net to v0.48.0`

### Body
- Separate from subject with a blank line
- **Wrap at 72 characters**
- Explain *what* and *why*, not *how* (the code shows how)
- Use prose, not bullet points: describe the problem, the fix, and why it helps
- Reference issues/PRs at the bottom if applicable

### Example
```
feat(ci): add AI agent workflow for issue/PR automation

Development commands previously required a local Go installation, which
creates friction for contributors and AI agents operating in constrained
environments.

Add GitHub Actions workflow that triggers an AI agent (dobbyphus) in
response to issue comments, PR review requests, and PR review comments.
The agent can assist with code review, issue triage, and development
tasks when mentioned by repository collaborators.

Closes #42
```

### Pull Requests
- Describe what/why in the PR body
- List commands run (`make lint`, `make test`, `make integration` if applicable)
- Link related issues/TODOs

## Linter Configuration Highlights

The `.golangci.yaml` enables nearly all linters. Key settings:
- `funlen`: 100 lines, 50 statements max per function.
- `tagliatelle`: enforces `snake_case` for JSON/YAML struct tags.
- `exhaustive`: `default-signifies-exhaustive: true` for switch statements.
- `ireturn`: allows returning `error`, `context.Context`, `net.Addr`, and select interfaces.
- Tests are exempt from `dupl`, `err113`, `funlen`, and `maintidx`.

## Security & Runtime Notes

- Keep `ipv6relayd.yaml` free of environment-specific secrets.
- Do not commit real packet captures to the repository.
- The daemon requires `CAP_NET_ADMIN` and `CAP_NET_RAW` capabilities.

## Notes

- Go 1.24+ is used; there is no "loop variable captured by reference" issue in range loops.
- The project uses Go modules; run `go mod tidy` after dependency changes.
