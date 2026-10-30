.PHONY: setup test eval demo
PYTHON ?= python

setup:
	python -m pip install --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt

test:
	$(PYTHON) -m unittest discover -s tests -p "test_*.py" -v

eval:
	python -m privacylens.eval

demo:
	python -m privacylens
