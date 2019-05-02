import setuptools

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
    install_requires=(
        'Authlib==0.10',
    ),
    classifiers=(
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ),
)
