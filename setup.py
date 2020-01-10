import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

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
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)
