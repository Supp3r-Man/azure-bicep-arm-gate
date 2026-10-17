# azure-bicep-arm-gate

![ci](https://github.com/Supp3r-Man/azure-bicep-arm-gate/actions/workflows/ci.yml/badge.svg)

**A policy gate for Azure Bicep that runs before anything is deployed, and a what-if gate for after Azure has resolved the values.** Bicep is compiled by the **real Bicep compiler**, the resulting ARM template is read into resolved resources, and 18 rules check storage, Key Vault, network security groups, App Service and tags. The part most policy repos skip: values the gate cannot resolve are reported as **cannot verify and fail the gate**, never as "fine".

> **What is verified, and what is not.** 300 tests pass locally on Python 3.13 with **Bicep 0.48.1**: unit tests for the reader and every rule, **72 Bicep fixtures** (18 compliant, 54 not) each compiled by the real compiler and required to produce *exactly* the expected rule ids, 16 what-if documents, and the command line's exit codes. I broke the code on purpose (port-range edges, the `/1` network, the firewall route, the retention boundary, absent-means-fine, unknown-means-fine, the pre-existing-violation ratchet, an unprotected vault delete, module scoping, the crash exit code) and tests failed each time; the fixture matrix catches the port-edge mutations on its own. **No Azure subscription is involved.** The what-if documents are **hand-written** to the structure I understand `az deployment group what-if --no-pretty-print` to emit; no real what-if produced them, and `whatif.yml` was never run. GitHub Actions on Linux, with the pinned Bicep 0.48.1, passed the tests, all 72 fixtures, the gate and `bicep lint` on the shipped templates, the check that generated fixtures are in sync, and `actionlint` (2026-10-17), after a first failed run caused by my own CI step (`curl -o bicep` collided with the `bicep/` directory).

## Two gates, one rule set

```
Bicep ──real compiler──▶ ARM JSON ──resolve parameters/variables──▶ resources ──rules──▶ findings   (python -m bicepgate check)
                                                     │ anything else (a function call) = Unknown
az deployment group what-if ──▶ changes[] ──resolved `after` of each Create/Modify──▶ the SAME rules   (python -m bicepgate whatif)
```

Before deployment, `[parameters('x')]` and `[variables('tags')]` are lookups the gate can follow (through nested module deployments, with the module's own defaults). `[resourceGroup().location]`, `[if(...)]` and the like are not, so they become `Unknown`. **What-if has already evaluated every expression**, so the same rules see concrete values with nothing unknown; that is why the second gate exists.

## The rules (`bicepgate/rules.py`)

| ID | What it flags |
|---|---|
| `STG-001/002/003` | storage account without HTTPS-only, with TLS below 1.2, or allowing anonymous blob access |
| `STG-004` | storage reachable from the internet (`publicNetworkAccess` not `Disabled` **and** firewall default not `Deny`) |
| `STG-005` | shared-key access enabled (warning) |
| `KV-001/002/003/004` | no purge protection; access policies instead of RBAC; soft delete off or retention under 30 days; reachable from the internet |
| `NSG-001` | an inbound Allow from any source (`*`, `Any`, `Internet`, `0.0.0.0/0`, `::/0`) covering SSH 22 or RDP 3389, **including ranges and lists** |
| `NSG-002` | an inbound Allow from any source to every port |
| `WEB-001/002/003/005` | App Service without HTTPS-only, TLS below 1.2, FTP allowed, remote debugging on; `WEB-004` no managed identity (warning) |
| `TAG-001` | missing or empty `owner` / `env` tag |
| `SEC-001` | a parameter named like a secret (`password`, `secret`, `token`, `apiKey`, ...) that is not `securestring` |
| `COV-001` / `COV-002` | a deployment whose template is not inline (cannot be read: error); a resource type with no rules (warning, so coverage gaps are visible) |
| what-if: `WI-001/002/003` | a delete of a vault or data store (error); any other delete (warning); a resource what-if did not evaluate (warning) |

**Design decisions on purpose:** a security property must be set **explicitly** (service defaults change between API versions and a reviewer cannot see a default in a diff); an unresolvable value **fails**; and in the what-if gate a change to a resource that was *already* non-compliant only **warns** (it must not block an unrelated edit), while a change that *introduces* a violation fails.

## Exit codes

`0` nothing to fix, `1` at least one error (a warning never fails), `2` **could not judge** (compile error, unreadable input, a what-if that is not `Succeeded`, an internal error). Python's default exit code for an uncaught exception is 1, which here would look like "findings", so the command line catches every exception and exits 2.

## What the checks found while building it

- **The real compiler caught a bug in my own template.** `take(...)` was missing from the storage account name; with the longest `prefix` and environment it could be 34 characters against a limit of 24 (Bicep warning `BCP335`). The shipped templates now compile with no warnings under a strict `bicepconfig.json`, and a test pins it.
- **My reader crashed on a shape I had not seen.** Bicep can emit a module parameter as an *expression string* (`"tlsVersion": "[if(equals(...), createObject('value', ...), ...)]"`) instead of `{"value": ...}`. The fixture matrix found it, the entry becomes `Unknown`, and any unexpected exception now exits 2.
- **Edges of port ranges are where firewall rules are wrong.** The fixtures include `21-22`, `22-23`, `3388-3389`, `3389-3390` (flagged) beside `23-3388`, `1-21`, `3390-4000` (not). Exclusive-upper and exclusive-lower mutations each turn 11 fixtures wrong.
- One mutation of mine "survived" because I swapped the handler for the very exception the test injects. A mutation has to remove the behaviour, not mirror the test.

## Honest limits

- **Not Azure.** The rules encode what I believe each property means; nothing here was checked against a deployment, and an API version can change a default or reject a combination (a vault with `enableSoftDelete: false`, for instance, is flagged here even if the service would reject it).
- **The reader is not an ARM engine.** Only parameter and variable lookups are resolved. Resources with `copy` loops are read once (the index is unknown), nested child `resources` arrays are not walked (Bicep does not emit them), and `templateLink` modules are reported unreadable.
- **No dependency or priority modelling.** An NSG Deny with a lower priority number shadows an Allow in Azure; the rule still flags the Allow. Rules that sit in separate `sites/config` resources are not read.
- **The what-if structure is from my reading of the documentation.** Delta details (`delta[]` paths) are not used; the gate compares full `before` and `after` objects. A real result may differ in ways these fixtures do not show, and what-if itself is known to be approximate for some resource types.
- 18 rules over five resource types are a sample, not a benchmark (no Azure Policy, Defender or CIS coverage), and the gate complements, not replaces, Azure Policy at the subscription level.
- A secret-looking parameter is a name heuristic: `passwordPolicy` would be flagged, a secret named `x` would not.
- `whatif.yml` is a reference workflow, never run.

## Run it

```
# needs the Bicep CLI (https://github.com/Azure/bicep/releases) on PATH, or set BICEP to its path
python -m pip install pytest pyyaml
python -m pytest
python tools/run_matrix.py                                                      # 72 fixtures, exact rule ids
python -m bicepgate check bicep/main.bicep --params bicep/dev.parameters.json   # passes
python -m bicepgate check bicep/main.bicep                                      # fails: the SSH source cannot be verified
python -m bicepgate check fixtures/bad/nsg_range_22_23.bicep                    # fails with NSG-001
python -m bicepgate whatif whatif/modify_weakens.json                           # fails; try the others in whatif/
```

`tools/make_fixtures.py` and `tools/make_whatif.py` regenerate the fixtures (each bad one is a good one with a single text replacement); CI checks they are in sync.
