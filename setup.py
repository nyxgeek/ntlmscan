from setuptools import setup

setup(
    name="ntlmscan",
    version="1.0",
    install_requires=[ "requests" ],
    entry_points={ "console_scripts": [ "ntlmscan=ntlmscan:main" ] }
)
