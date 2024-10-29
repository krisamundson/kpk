default:
	sudo cp kpk/__init__.py /usr/local/bin/kpk
	sudo chmod 755 /usr/local/bin/kpk
	sudo sed -i '' 's@#!/usr/bin/env python@#!/Users/krisamundson/c/kpk/venv/bin/python@g' /usr/local/bin/kpk
