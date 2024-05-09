import setuptools

requirements = [
    'Authlib>=1.3.0,<2',
    'pymongo>=4.7.2,<5',
    'pyotp>=2.9.0,<3',
    'pytz>=2024.1',
]

setuptools.setup(
    name='auth487',
    version='2.0.0',
    author='andre487',
    author_email='andrey.prokopyuk@gmail.com',
    description='Auth 487 library',
    long_description='Auth 487 library',
    long_description_content_type='text/plain',
    url='https://github.com/andre487/auth487',
    packages=setuptools.find_packages(),
    install_requires=requirements,
    classifiers=(
        'Programming Language :: Python :: 3.10',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ),
    python_requires='>=3.10',
)
