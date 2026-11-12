# Security and privacy

HASHLENS is **not** a password cracker. It recognizes *formats*, not secrets.

- The website contains no server endpoints, external JS/CSS, analytics, localStorage, IndexedDB, or cookies.
- Signature input is evaluated in the active browser tab without transmission.
- Clipboard/JSON exports remove raw user-supplied input strings, though metadata may still be sensitive.
- The Python CLI reads values provided explicitly through arguments or batch input files; it never sends data over the network.
- Avoid pasting real tokens, session cookies, production credentials, or sensitive content without authorization.
- Hash recognition is heuristic. Prefix-only matches can identify even malformed/synthetic strings; raw hex lengths can map to multiple algorithms.

To report a security issue in your own fork, use GitHub's private vulnerability reporting feature if enabled, or your project maintainer's published security contact. Do not post confidential test data in public issues.
