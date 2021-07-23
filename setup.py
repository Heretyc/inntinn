import os.path
from setuptools import setup

HERE = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(HERE, "README.md"), encoding="utf8") as fid:
    README = fid.read()

setup(
    name="inntinn",
    version="1.0.1",
    description="OSINT composite vulnerability database",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/BlackburnHax/inntinn",
    author="Brandon Blackburn",
    author_email="contact@bhax.net",
    license="Apache License, Version 2.0",
    classifiers=[
        "Topic :: Security",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3 :: Only",
        "Natural Language :: English",
    ],
    packages=["inntinn"],
    include_package_data=True,
    install_requires=["requests", "mongoblack"],
)
