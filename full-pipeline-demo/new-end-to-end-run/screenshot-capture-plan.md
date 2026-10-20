# Screenshot capture plan

## Real capture options

The current execution environment does not expose an approved automated
terminal screenshot API to the repository process. Windows terminal UI
automation is intentionally not used to run commands. Therefore the supplied
viewer is the practical capture mechanism.

## Evidence Viewer workflow

From the repository root, run:

```powershell
.\.venv\Scripts\python.exe tools\viper_evidence_viewer.py --run-id X40Ks --output-root output
```

Open `http://127.0.0.1:8765/?run=X40Ks` in a normal browser. Capture the page
with the browser's native screenshot command. Save those as
`screenshots/viewer-01-...png` and label them **EVIDENCE_VIEWER_SCREENSHOT**.
They represent actual canonical artifacts, not live terminal screenshots.

For a live terminal screenshot, the user should capture the visible terminal
manually immediately after each stage command returns and label it
**LIVE_EXECUTION_SCREENSHOT**, with the Run ID and timestamp in the filename.
Never reconstruct a terminal image from text.
