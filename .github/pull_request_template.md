## Description
<!-- Briefly describe the changes introduced in this PR -->

## Type of Change
- [ ] 🔌 New Tool Harness (e.g., Inspect AI, DeepEval, CyberSecEval)
- [ ] 🎯 New Adversarial Input / Attack Dataset (e.g., new probe, jailbreak seed)
- [ ] 🔄 Output Converter or Parser (e.g., SARIF, CycloneDX)
- [ ] 🐳 Mock Environment Enhancement
- [ ] 📚 Documentation & Guides
- [ ] 🐛 Bug fix / Refactoring

## Verification Checklist
- [ ] I have tested that the harness runs completely offline against the local Docker mocks (`docker compose up -d`).
- [ ] Checked-in input/output fixtures contain no real API keys, credentials, or proprietary data.
- [ ] `python3 scripts/validate_fixtures.py` passes without errors.
- [ ] Relevant documentation in `README.md` and/or `docs/TOOL_IO_SPECIFICATION.md` has been updated.
