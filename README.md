# Emulator Testing Research

Research report and slides on research paper :
Tickling x86_64: Detecting Emulator Inaccuracies Through CPU Instruction Forensics

## Build

```bash
# Report
cd report/report && make all

# Slides  
cd report/slides && make all
```

## Releases

GitHub Actions automatically builds PDFs and creates releases on push to main. Use [Conventional Commits](https://www.conventionalcommits.org/):
- `feat:` → minor version (1.0.0 → 1.1.0)
- `fix:` → patch version (1.0.0 → 1.0.1)
- `BREAKING CHANGE:` → major version (1.0.0 → 2.0.0)
