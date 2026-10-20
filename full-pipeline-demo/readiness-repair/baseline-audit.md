# Baseline audit — 2026-10-14

Repository: `C:\Users\distortion\Documents\new-idea-kalama`, branch `main`,
HEAD `5699dc10bc772e1dc72478e55f3c9b3ac8ef7905`.

The working tree was already dirty before this task; unrelated changes were
preserved. Python 3.12.14, PyYAML 6.0.3, and `pip check` passed. The CLI loads
in `.venv`. Docker CLI 29.7.2 and Compose 5.5.0 are installed, but Docker's
Linux daemon is unreachable. `kalama doctor` therefore reports
`DOCKER_DAEMON_UNREACHABLE`, and network/workbench/Trivy/Metasploit checks are
unchecked. Overall baseline: **NOT_READY**.

The focused suite reproduced 24 passed and 4 failed in the narrower run; the
failures were blocked during fixture setup by Windows sandbox temp-directory
permission errors. The broader earlier run showed the same environmental
failure pattern. No live Docker operation was attempted.
