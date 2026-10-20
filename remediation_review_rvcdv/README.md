# RVcdV isolated source-build review

This context builds only a new candidate image. It uses the exact Apache 2.3.20.1
REST Showcase source lineage identified in the deployed S2-045 WAR, then resolves
the application against a coherent Struts 2.3.32 dependency closure. It does not
touch `victim-RVcdV`.
