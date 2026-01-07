# Repository Guidelines

## Project Structure & Module Organization
- `cmd/ipv6relayd`: CLI entrypoint.
- `pkg/`: Core logic (config, ra, dhcpv6, ndp, iface/ifmon/netstate helpers).
- `integration/`: Network-namespace tests and shared fixtures.
- `docs/design.md`: Architecture notes; `info/`: captured samples.
 - Tooling: `Makefile` + `Containerfile.devkit` wrap the devkit image.

## Build, Test, and Development Commands
- `make lint` — golangci-lint with repo config (runs inside devkit).
- `make test` — unit tests for all packages except integration (runs inside devkit).
- `make integration` — integration tests to confirm RFC-compliance (runs inside devkit).
- Quick build/run: `go build ./cmd/ipv6relayd` then `sudo ./ipv6relayd run -config ipv6relayd.yaml`.

## Coding Style & Naming Conventions
- Auto-format via `gofmt`, `goimports`, `gci` (all run by `make lint`).
- Package/files: lowercase nouns; JSON/YAML tags `snake_case`.
- Keep functions tight (lint budgets ~100 lines/50 statements); prefer exhaustive switch defaults.
- Use structured logging (`slog`), not printf.
- Do not alias function signatures (e.g., `type Handler func(...)`)—keep signatures explicit so readers see required params/returns at call sites.

## Testing Guidelines
- Unit tests live next to code in `_test.go`; name as `TestThing`.
- Integration smoke example: `make integration`.
- Add focused tests when touching packet parsing, option rewrites, or interface state handling.
- Prefer `github.com/stretchr/testify/require` for setup invariants and `github.com/stretchr/testify/assert` for the rest so failures stay readable. Example:

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

## Commit & Pull Request Guidelines

Follow Linux kernel commit message style:

### Subject line
- **50 characters or less** (hard limit: 72)
- Imperative mood ("Add feature" not "Added feature" or "Adds feature")
- Use conventional commit prefix when appropriate: `fix:`, `feat:`, `ci:`, `docs:`, `refactor:`, `test:`, `chore:`
- No period at end
- Example: `fix: prevent RA hop-limit underflow on reload`

### Body
- Separate from subject with a blank line
- **Wrap at 72 characters**
- Explain *what* and *why*, not *how* (the code shows how)
- Use bullet points for multiple discrete changes
- Reference issues/PRs at the bottom if applicable

### Example
```
ci: add AI agent workflow for issue/PR automation

Add GitHub Actions workflow that triggers an AI agent (dobbyphus) in
response to issue comments, PR review requests, and PR review comments.
The agent can assist with code review, issue triage, and development
tasks when mentioned by repository collaborators.

The workflow:
- Triggers on @dobbyphus mentions in issues/PRs by authorized users
- Supports manual dispatch with custom prompts
- Uses a GitHub App token for elevated permissions

Closes #42
```

### Pull Requests
- Describe what/why in the PR body
- List commands run (`make lint`, `make test`, `make integration` if applicable)
- Link related issues/TODOs

## Security & Runtime Notes
- Keep `ipv6relayd.yaml` free of environment-specific secrets; avoid committing real packet captures.

## NOTE
- There is no issue with "loop variable captured by reference" in range loops when used with golang > 1.24
