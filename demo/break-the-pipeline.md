# Break the pipeline on purpose

[← CI/CD pipeline](../docs/ci-cd.md)

A way to show each CI gate catching a real mistake. [`break-the-pipeline.sh`](break-the-pipeline.sh) creates a
throwaway branch from `main` that breaks exactly one gate. Push it, open a **draft** pull request, look at the
failing check, then close the PR without merging and delete the branch.

| Gate | What the branch changes | Should fail |
|---|---|---|
| `lint` | Adds an unused variable to `src/config.js` | Lint (ESLint, yamllint) |
| `test` | Adds a test that asserts `1 === 2` | Test (Node 22, ubuntu-latest / windows-latest) |
| `vuln-dep` | Adds `lodash@4.17.20` (high-severity advisory) as a runtime dependency | Dependency audit (production, blocking) |
| `dockerfile` | Adds `RUN cd /app && ls` to the Dockerfile (hadolint DL3003) | Lint Dockerfile (hadolint) |
| `coverage` | Adds ~600 lines the tests load but never run | Test (Node 22, …): 90% line-coverage gate |
| `secret` | Commits a randomly generated, fake AWS-style key pair | Secret scan (gitleaks), or GitHub push protection first |

## Running it

From a clean clone (the script refuses to run with uncommitted changes):

```bash
demo/break-the-pipeline.sh lint
```
```bash
git push -u origin demo/break-lint
```
```bash
gh pr create --draft --base main --head demo/break-lint --title "DEMO (do not merge): break the lint gate" --body "Throwaway demo branch."
```

When the checks have finished, clean up: close the PR (`gh pr close <number>`), then, once it shows as closed,
delete the branch (`git push origin --delete demo/break-lint`). Never merge these PRs; the ruleset on `main`
blocks it anyway, since a required check fails.

## Results (run on 2026-10-19 against `main` at `171817a`)

| Gate | PR | Result |
|---|---|---|
| `lint` | #14 | **Lint (ESLint, yamllint) failed**: `'demoUnusedVariable' is assigned a value but never used  no-unused-vars`. The other 11 checks passed |
| `test` | #15 | **Both test jobs failed**: `✖ DEMO: deliberately failing test`, `pass 102, fail 1`. The other 10 checks passed |
| `vuln-dep` | #16 | **Dependency audit (production, blocking) failed**: lodash, `Severity: high`, Command Injection (GHSA-35jh-r3h4-6jhm). **Build and scan image (Trivy) also failed**, because lodash ends up in the image: `CVE-2021-23337`, HIGH, fixed in 4.17.21. Two gates for the price of one |
| `dockerfile` | #17 | **Lint Dockerfile (hadolint) failed**: `DL3003 warning: Use WORKDIR to switch to a directory` (hadolint runs with `--failure-threshold info`). The other 11 checks passed |
| `coverage` | #18 | **Both test jobs failed on coverage alone**: all 102 tests passed, then `85.40% line coverage does not meet threshold of 90%` |
| `secret` | none | **Blocked before it reached GitHub** by GitHub push protection: `GH013 … Push cannot contain secrets`, detecting an *Amazon AWS Access Key ID* and *Secret Access Key*. Nothing was pushed, so no PR and no gitleaks run. Locally, `gitleaks git` reported `leaks found: 2` on that commit, so the CI gate would have caught it too |

Every demo PR showed `mergeStateStatus: BLOCKED`. All five PRs were closed without merging and their branches
deleted; the secret branch only ever existed locally and was deleted there.
