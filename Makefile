default:
	pip3 install -r requirements.txt
	sudo cp kpk/__init__.py /usr/local/bin/kpk
	sudo chmod 755 /usr/local/bin/kpk
	#sudo sed -i '' 's/\#\!\/usr\/bin\/env python3/\#\!\/usr\/local\/bin\/python3/g' /usr/local/bin/kpk
