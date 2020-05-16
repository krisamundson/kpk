import setuptools

with open("README.md", "r") as ld:
    long_description = ld.read()

with open("requirements.txt") as r:
    requirements = r.readlines()

setuptools.setup(
    name="kpk",
    version="2.0.1",
    author="Kris Amundson",
    author_email="krisa@subtend.net",
    description="Simple on-disk key/value store secured by GPG.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/krisamundson/kpk",
    packages=setuptools.find_packages(),
    entry_points={
        'console_scripts': [
            'kpk = kpk.kpk:main'
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
    keywords="kv key value kvstore",
    install_requires=requirements,
    zip_safe=False
)
