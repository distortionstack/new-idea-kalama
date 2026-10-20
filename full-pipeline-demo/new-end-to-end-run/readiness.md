# Readiness

Validated with host Docker access on 2026-10-14.

- Docker Engine 29.7.2: READY
- `kalama-net`: present and attached to Workbench and Metasploit resolver
- Workbench `kalama-workbench-modern`: running, managed, socket usable
- Trivy: 0.74.0
- Metasploit resolver container: running and attached
- VIPER/Kalama Doctor: `Overall READY`
- Lab scope: Docker Desktop isolated network `kalama-net`; target is the authorized local lab image

The regular sandbox session lacked access to the Docker named pipe, so Docker
commands requiring host access were executed read-only or through the approved
host-access path. No historical run was modified.
