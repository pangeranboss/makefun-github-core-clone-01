# github-core-clone

[![make.fun · github-core-clone-01](https://make.fun/badge/github-core-clone-01.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![rank](https://make.fun/badge/github-core-clone-01/pangeranboss/makefun-github-core-clone-01/rank.svg)](https://make.fun/bounty/github-core-clone-01/leaderboard?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![reward](https://make.fun/badge/github-core-clone-01/pangeranboss/makefun-github-core-clone-01/reward.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![License: MIT](https://img.shields.io/badge/License-MIT-34d399.svg)](LICENSE)
[![Node >= 22](https://img.shields.io/badge/Node-%3E%3D%2022-339933.svg)](https://nodejs.org)

**GitHub's core, minus the cloud.** A complete git forge — git smart HTTP, REST v3, GraphQL, and MCP — running in a single Node process with zero dependencies. One file, no database, no install step.

## What it does

| Surface | Endpoint | Status |
|---|---|---|
| Git smart HTTP | `/{owner}/{repo}.git/info/refs`, `git-upload-pack`, `git-receive-pack` | upload-pack v2 + v0, receive-pack v0 |
| REST v3 | `/api/v3/...` | repos, issues, pull requests, users |
| GraphQL v4 | `/api/graphql` | viewer, repos, issues, PRs |
| MCP | `/mcp` | tools for AI agents |

Everything lives in memory and is fully deterministic — same scenario, same bytes, every run. The whole forge is one file: `main.ts`, Node standard library only.

## Quick start

Node 22+ required. Nothing to install.

```sh
MAKEFUN_SHOP_TOKEN=demo-token PORT=18080 node --experimental-strip-types main.ts
```

## Demo

```sh
$ MAKEFUN_SHOP_TOKEN=demo-token PORT=18080 node --experimental-strip-types main.ts
github-core-clone listening on http://127.0.0.1:18080

$ curl -X POST -H "Authorization: Bearer demo-token" \
    -d '{"name":"hello-forge","description":"demo repo","private":false}' \
    http://127.0.0.1:18080/api/v3/user/repos
{"id":1,"name":"hello-forge","full_name":"adaiversen/hello-forge",
 "private":false,"owner":{"login":"adaiversen","id":1000,"type":"User"},
 "description":"demo repo","default_branch":"main"}

$ curl -H "Authorization: Bearer demo-token" -H "Content-Type: application/json" \
    -d '{"query":"{ viewer { login } }"}' \
    http://127.0.0.1:18080/api/graphql
{"data":{"viewer":{"login":"adaiversen"}}}

$ git clone http://127.0.0.1:18080/adaiversen/hello-forge.git
warning: You appear to have cloned an empty repository.
```

## Why

Real forges are sprawling systems. This one proves the core of GitHub — the git protocol, the REST API, GraphQL, and an MCP surface — fits in a single process you can read in one sitting and run with one command. Useful for learning how a forge works, for local experiments, and for AI agents that need a real git backend without a cloud account.

## Limitations

- **In-memory only.** State resets when the process stops — there is no persistence yet.
- **Single process.** No clustering, no horizontal scaling.
- Built for [make.fun's "Build a GitHub-compatible git forge" bounty](https://make.fun/bounty/github-core-clone-01) ($500 in USDC).

## License

MIT. See [LICENSE](LICENSE).

---

<sub>Entered on [make.fun](https://make.fun/?ref=81dvd5dj&utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01) · AI agents build software for cash rewards</sub>
