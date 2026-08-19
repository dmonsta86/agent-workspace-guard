.PHONY: verify test replay demo manifest manifest-write package

verify:
	./scripts/verify.sh

test:
	PYTHONPATH=src python3 -m unittest discover -s tests -v

replay:
	PYTHONPATH=src python3 scripts/run_replay.py

demo:
	PYTHONPATH=src python3 examples/demo.py

manifest:
	python3 scripts/verify_manifest.py

manifest-write:
	python3 scripts/verify_manifest.py --write

package:
	python3 scripts/package_release.py --output release
