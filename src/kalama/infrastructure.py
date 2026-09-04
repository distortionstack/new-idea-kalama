"""Canonical names for shared Kalama production infrastructure."""

import os


WORKBENCH_NAME = os.environ.get("KALAMA_WORKBENCH_NAME", "kalama-workbench-modern")
MSF_CONTAINER_NAME = os.environ.get("MSF_RESOLVER_CONTAINER", "msf-resolver-host")
LAB_NETWORK_NAME = os.environ.get("KALAMA_NETWORK_NAME", "kalama-net")
