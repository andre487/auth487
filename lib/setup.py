import setuptools

requirements = ['attrs==20.3.0', 'Authlib==0.15.2', 'cachetools==4.2.0', 'certifi==2020.12.5', 'cffi==1.14.4', 'chardet==4.0.0', 'click==7.1.2', 'cryptography==3.3.1', 'flake8==3.8.4', 'Flask==1.1.2', 'google-api-core==1.24.1', 'google-api-python-client==1.12.8', 'google-auth==1.24.0', 'google-auth-httplib2==0.0.4', 'google-auth-oauthlib==0.4.2', 'googleapis-common-protos==1.52.0', 'httplib2==0.18.1', 'idna==2.10', 'iniconfig==1.1.1', 'invoke==1.4.1', 'itsdangerous==1.1.0', 'Jinja2==2.11.2', 'MarkupSafe==1.1.1', 'mccabe==0.6.1', 'oauthlib==3.1.0', 'packaging==20.8', 'pluggy==0.13.1', 'protobuf==3.14.0', 'py==1.10.0', 'pyasn1==0.4.8', 'pyasn1-modules==0.2.8', 'pycodestyle==2.6.0', 'pycparser==2.20', 'pyflakes==2.2.0', 'pymongo==3.11.2', 'pyotp==2.4.1', 'pyparsing==2.4.7', 'pytest==6.2.1', 'pytz==2020.4', 'PyYAML==5.3.1', 'requests==2.25.1', 'requests-oauthlib==1.3.0', 'rsa==4.6', 'six==1.15.0', 'toml==0.10.2', 'ua-parser==0.10.0', 'uritemplate==3.0.1', 'urllib3==1.26.3', 'user-agents==2.2.0', 'uWSGI==2.0.19.1', 'Werkzeug==1.0.1']  # noqa: E501

setuptools.setup(
    name='auth487',
    version='1.0.0',
    author='andre487',
    author_email='andrey.prokopyuk@gmail.com',
    description='Auth 487 library',
    long_description='Auth 487 library',
    long_description_content_type='text/plain',
    url='https://github.com/andre487/auth487',
    packages=setuptools.find_packages(),
    install_requires=requirements,
    classifiers=(
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ),
)
