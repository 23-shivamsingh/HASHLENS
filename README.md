# HASHLENS

<img src="web/assets/icon-192.png" alt="HASHLENS icon" width="72" height="72">

**Hash-format identification for the browser and terminal.**

Maintained by **Shivam Singh**.

HASHLENS suggests possible hash formats by inspecting prefixes, character sets, lengths and record layouts. It includes a static browser dashboard and a Python command-line tool, with matching detection rules in JavaScript and Python.

> HASHLENS identifies likely formats. It does not crack hashes, recover passwords, verify a password or prove which algorithm produced a value. Confidence labels describe recognition heuristics, not probabilities.

## Features

- **Single-signature analysis:** View possible algorithms, confidence labels and the reason for each match.
- **Batch analysis:** Inspect newline-separated signatures in the browser or through the CLI.
- **Input characteristics:** Inspect character count, UTF-8 byte count, character set, recognized prefix and structural shape.
- **Signature library:** Search and filter supported signature patterns, then load synthetic examples into the analyzer.
- **Sample inputs:** Try built-in examples without supplying real credentials.
- **Result exports:** Copy results or download JSON without the original submitted input strings.
- **Local detection:** The supplied browser and CLI analysis code does not call a remote identification service.
- **Automated checks:** Python unit tests, JavaScript engine tests and a cross-language parity test are included.

## Supported patterns

| Family | Examples recognized by the engines |
| --- | --- |
| Password-hash prefixes | Argon2id/i/d, bcrypt variants, SHA-512 crypt, SHA-256 crypt, MD5 crypt, Apache MD5-crypt, yescrypt, phpass, Drupal 7 and scrypt |
| Django formats | PBKDF2-SHA256, PBKDF2-SHA1, bcrypt-SHA256 and Argon2 |
| LDAP wrappers | `{SSHA}`, `{SHA}`, `{SMD5}`, `{MD5}` and `{CRYPT}` |
| Structured records | NetNTLMv1, NetNTLMv2, MySQL5 and traditional DES crypt |
| Hexadecimal digests | Candidate families for lengths from 16 to 128 hexadecimal characters, including MD5, SHA families, RIPEMD families, BLAKE2 and Whirlpool |
| Other clues | Generic PHC-style strings, JWT-like text and possible Base64 data |

These checks are structural. Prefix matching can accept an incomplete or malformed value. Many algorithms share the same digest length, and JWT-like or Base64-like data is not necessarily a hash. Unsupported input may produce no candidates.

## How analysis works

The browser loads `index.html`, `styles.css` and `app.js`. The UI passes input to `identify()`, `characterize()` or `identifyBatch()` in `engine.mjs`, then renders the results in the page. Export controls build a separate report that excludes submitted strings.

The Python CLI implements the same candidate rules independently in `hash_identifier.py`. It reads one argument, a local file or standard input and prints text or JSON. The browser does not invoke the Python CLI, and neither engine calculates or reverses a cryptographic hash.

## Requirements

- **Python 3.10 or later** for the CLI and Python tests.
- **A modern browser** with JavaScript modules enabled for the dashboard.
- **Node.js** for JavaScript tests only. The included CI workflow uses Node.js 22 and Python 3.13.

Running the CLI directly requires only the Python standard library. The website has no package-install or build step. There is no `requirements.txt` or `package.json` in this archive.

## Run the browser dashboard

Extract the project, open a terminal inside `HASHLENS/` and run:

```bash
python3 -m http.server 8000 --directory web
```

Open <http://localhost:8000>.

1. Choose single-signature or batch mode.
2. Load a sample or paste an authorized test value.
3. Select **Analyze signature** or **Analyze batch**. `Ctrl + Enter` / `Cmd + Enter` also runs analysis.
4. Review the candidate list and format clues.
5. Use the copy or download controls to export results.

Use the local server instead of opening `web/index.html` through `file://`, where browser restrictions can block module imports.

### Browser limits

- The input field allows up to **30,000 characters**.
- Batch mode analyzes the first **100 non-empty lines** and displays a notice if additional lines are skipped.
- Batch results display submitted values on screen, even though result exports omit them.
- Clipboard copying depends on browser permissions and context. If it is unavailable, use the JSON download control.

## Run the Python CLI

From the project root:

```bash
# Analyze one signature
python3 hash_identifier.py '5f4dcc3b5aa765d61d8327deb882cf99'

# Return JSON without the original input string
python3 hash_identifier.py --json '5f4dcc3b5aa765d61d8327deb882cf99'

# Limit the displayed candidates in single-signature text output
python3 hash_identifier.py --top 2 '5f4dcc3b5aa765d61d8327deb882cf99'

# Show available arguments
python3 hash_identifier.py --help
```

A 32-character hexadecimal value can match MD5, NTLM, MD4 and RIPEMD-128. A first-ranked candidate is not proof of the original algorithm.

### Batch input

Create a UTF-8 file named `hashes.txt` with one signature per line:

```text
5f4dcc3b5aa765d61d8327deb882cf99
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

Then run:

```bash
python3 hash_identifier.py --batch hashes.txt
python3 hash_identifier.py --batch hashes.txt --json

# Read from standard input on a Unix-like shell
cat hashes.txt | python3 hash_identifier.py --batch -
```

The CLI rejects input exceeding **30,000 characters** or **100 non-empty batch lines**, rather than silently truncating it. `--top` affects single-signature text output; it does not filter JSON or batch reports.

Quote signatures containing `$` so the shell does not expand their contents. The examples above use Unix-like shell syntax. If your system provides Python as `python`, use that command instead of `python3` after confirming it is Python 3.10 or later.

## Project structure

```text
HASHLENS/
├── .github/
│   └── workflows/
│       ├── pages.yml              # Publish web/ to GitHub Pages
│       └── test.yml               # Run tests and syntax checks
├── docs/
│   └── VALIDATION.md              # Existing validation notes
├── tests/
│   ├── parity.mjs                 # Compare Python and JS candidates
│   └── test_hash_identifier.py    # Python unit tests
├── web/
│   ├── assets/                    # Icons, SVG marks and social image
│   ├── tests/
│   │   └── engine.test.mjs        # JavaScript engine tests
│   ├── app.js                     # UI, library and sanitized exports
│   ├── engine.mjs                 # JavaScript detection rules
│   ├── index.html                 # Dashboard markup
│   ├── site.webmanifest           # Web app metadata
│   └── styles.css                 # Dashboard styles
├── .gitignore
├── hash_identifier.py             # Python detection engine and CLI
├── pyproject.toml                # Python package metadata
├── README.md
└── SECURITY.md                   # Security and privacy notes
```

The tree lists project content, not the archive's macOS `__MACOSX/` metadata. Generated files such as `__pycache__/` are not part of the source layout.

## Tests and syntax checks

Run from the project root:

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
node --test web/tests/*.test.mjs tests/parity.mjs
python3 -m py_compile hash_identifier.py
node --check web/engine.mjs
node --check web/app.js
```

The parity test launches `python3` by default. If that command is unavailable, set the `PYTHON` environment variable to your Python executable before running the Node.js tests.

The GitHub Actions test workflow runs on pushes, pull requests and manual dispatch. On the supplied archive, all **14 Python tests** and **43 Node.js tests** (42 engine tests plus one cross-language parity test) passed, along with the syntax checks above. Local tests do not establish deployment status or full browser compatibility.

## Deployment

The browser application is the static contents of **`web/`**. It does not need a Python backend. For a static host, publish this directory without an application build step.

### Included GitHub Pages workflow

The archive contains `.github/workflows/pages.yml`. It uploads `web/` as the Pages artifact and runs on pushes to `main` or manual dispatch.

Put the project files at the repository root and configure GitHub Pages to use GitHub Actions before using this workflow. A successful deployment produces its own site URL; this README does not assume an existing live deployment.

## Privacy and responsible use

- The supplied browser code analyzes input in the active tab. It contains no remote analysis API calls, third-party JavaScript/CSS, analytics or persistent input-storage code.
- The CLI performs local analysis and does not make network requests.
- Clipboard and JSON result exports omit raw submitted strings. Length, prefix and other metadata may still disclose information.
- Input remains visible in the page while you use it. CLI arguments can also remain in shell history or be visible to local process-inspection tools; files, screenshots and downloaded reports need their own care.
- Serving the site still creates ordinary requests to the host for its files. Local detection is not a guarantee against browser extensions, a compromised device or changes made by a hosting provider.

Use synthetic samples or data you are authorized to inspect. Avoid live passwords, session tokens, production credentials and other secrets. Read [SECURITY.md](SECURITY.md) for the project's security notes.

