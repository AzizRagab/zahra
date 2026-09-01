# Contributing to ZAHRA

Thank you for your interest in contributing! ZAHRA is an open-source,
AI-powered penetration-testing platform, and contributions from the community
make it better.

> **Important:** ZAHRA is an offensive-security tool. Contribute only features
> that support **authorized** security testing, research, education, CTF, and
> bug-bounty work. See [SECURITY.md](SECURITY.md) and the README's
> *Responsible Use* section.

## Table of Contents

- [Getting Started](#getting-started)
- [Repository Layout](#repository-layout)
- [Development Workflow](#development-workflow)
- [Code Style](#code-style)
- [Commit Messages](#commit-messages)
- [Opening Issues](#opening-issues)
- [Submitting Pull Requests](#submitting-pull-requests)
- [License](#license)

## Getting Started

1. **Fork and clone** the repository.
2. **Install dependencies** with the one-shot installer for your OS:

   ```powershell
   # Windows (PowerShell 7+)
   .\install.ps1
   ```

   ```bash
   # Kali / Ubuntu
   ./install.sh
   ```

   The installer creates a `.venv`, installs Python dependencies, and (optionally)
   installs Ollama and builds the local `zahra` model.

3. **Run the platform**:

   ```bash
   python main.py status        # smoke-test the CLI
   python main.py serve --port 8090   # dashboard + API
   ```

## Repository Layout

```
zahra/
├── main.py                  # Python entry point
├── core/                    # orchestrator, blackboard, RAG, router
├── agents/                  # swarm agents + skills
├── ai_engine/               # LLM wrapper, prompts
├── interfaces/              # CLI, FastAPI, web dashboard
├── services/
│   ├── pentest-swarm/       # Go reference implementation (AGPL-3.0)
│   └── omniroute/           # Node LLM gateway (MIT)
└── docs/                    # feature & integration docs
```

## Development Workflow

- Create a branch off `main` for each change: `git checkout -b feat/my-change`.
- Keep changes focused. If a change spans the Python core and a service, split it
  into separate PRs.
- Run the relevant checks **before** opening a PR (see below).
- Update the README or `docs/` when user-facing behavior changes.

## Code Style

| Language | Tooling |
|---|---|
| Python | [`black`](https://black.readthedocs.io/) (line-length 100, see `pyproject.toml`) + [`mypy`](https://mypy.readthedocs.io/) |
| Go | `gofmt` + [`golangci-lint`](https://golangci-lint.run/) (see `services/pentest-swarm/.golangci.yml`) |
| TypeScript / Node | ESLint + Prettier (see `services/omniroute/`) |

Quick checks:

```bash
python -m black --check . && python -m mypy interfaces core agents ai_engine
cd services/pentest-swarm && go build ./... && go vet ./...
```

## Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(cli): add --json output to memory command
fix(dashboard): correct severity badge contrast on light mode
docs: document OmniRoute gateway wiring
```

## Opening Issues

- Search existing issues first.
- For **bugs**: include OS, Python/Go/Node versions, steps to reproduce, and
  expected vs. actual behavior.
- For **security vulnerabilities**: do **not** open a public issue — follow
  [SECURITY.md](SECURITY.md).

## Submitting Pull Requests

1. Reference the issue your PR fixes (`Closes #123`).
2. Describe what changed and why, and how you verified it.
3. Keep PRs reviewable — small, single-purpose diffs are preferred.
4. Ensure CI checks pass (build, lint, tests).

## License

By contributing, you agree that your contributions are licensed under the same
terms as the component you touch:

- **ZAHRA core (Python)** — [MIT](LICENSE)
- **Pentest-Swarm-AI (Go)** — AGPL-3.0 (`services/pentest-swarm/LICENSE`)
- **OmniRoute (Node)** — MIT (`services/omniroute/LICENSE`)
