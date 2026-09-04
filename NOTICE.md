# Third-party notices

This project is MIT-licensed. Bundled and invoked third-party software keeps
its own licenses. You must comply with those licenses if you distribute
binaries or run the scanners.

| Component | Used for | License |
|-----------|----------|---------|
| [Nuclei](https://github.com/projectdiscovery/nuclei) | Website vulnerability templates | MIT |
| [Semgrep](https://github.com/semgrep/semgrep) | SAST for source code | LGPL-2.1 |
| [Trivy](https://github.com/aquasecurity/trivy) | FS / container CVE scanning | Apache-2.0 |
| [ClamAV](https://www.clamav.net/) | Local malware scan | GPL-2.0 |
| [Bandit](https://github.com/PyCQA/bandit) | Python security linter | Apache-2.0 |
| [aiogram](https://github.com/aiogram/aiogram) | Telegram Bot API | MIT |
| [Celery](https://github.com/celery/celery) | Task queue | BSD-3-Clause |
| [DejaVu Sans](https://dejavu-fonts.github.io/) (`app/assets/DejaVuSans.ttf`) | Cyrillic in PDF reports | Bitstream Vera / public-domain changes |

Optional **hosted** services (not shipped in this repo):

- [VirusTotal](https://www.virustotal.com/) — file hash lookup. Files are **not** uploaded by default.
- [OpenRouter](https://openrouter.ai/) — optional LLM summaries. Findings are masked before send.

Scanner rule packs (Nuclei templates, Semgrep `p/ci`, Trivy vulnerability DB) are downloaded at runtime by those tools and are subject to their upstream terms.
