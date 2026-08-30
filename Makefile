.PHONY: install test scan report ci serve clean
install: ; pip install -r requirements.txt
test:    ; python -m pytest -q
scan:    ; python app/engine/cli.py scan $(P)
report:  ; python app/engine/cli.py report $(P)
ci:      ; python app/engine/cli.py ci $(P) --fail-on critical
serve:   ; ECDAT_LOCAL=1 uvicorn app.server:app --port 8000
clean:   ; rm -rf .pytest_cache **/__pycache__ ecdat-cbom.json ecdat.sarif ecdat-report.md
