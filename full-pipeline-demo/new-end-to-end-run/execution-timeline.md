# Execution timeline — Run X40Ks

| Stage | Status | Evidence |
|---|---|---|
| Readiness | SUCCEEDED | Doctor JSON returned `ready: true` |
| Target preparation | SUCCEEDED | `victim-X40Ks`, IP `172.18.0.4`, image ID recorded in state |
| Trivy BEFORE | SUCCEEDED | Canonical state/artifact under `output` |
| Top-N prioritization | SUCCEEDED | `top_n_returned: 30` |
| Resolver | RUNNING / BLOCKED | Process did not return within the observation window |
| Attack Form onward | NOT STARTED | Mandatory resolver/form gate not reached |

Run was not cancelled and no exploit or patch command was executed.
