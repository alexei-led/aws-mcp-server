# Version Management with setuptools_scm

This project uses [setuptools_scm](https://setuptools-scm.readthedocs.io/) to automatically determine version numbers from Git tags.

## How it works

1. The version is automatically determined from your git tags
2. In development environments, the version is dynamically determined
3. For Docker builds and CI, the version is passed as a build argument

## Version Format

- Release: When on a tag (e.g., `1.2.3`), the version is exactly that tag
- Development: When between tags, the version is `<last-tag>.dev<n>+g<commit-hash>.d<date>`
  - Example: `1.2.3.dev10+gb697684.d20250101`

## Local Development

The version is automatically determined whenever you:

```bash
# Install the package
pip install -e .

# Run the version-file generator
make version-file

# Check the current version
python -m setuptools_scm
```

## Importing Version in Code

```python
# Preferred method - via Python metadata
from importlib.metadata import version
__version__ = version("aws-mcp")

# Alternative - if using version file
from aws_mcp_server._version import version, __version__
```

## Docker and CI

For Docker builds, the version is:

1. Determined by setuptools_scm
2. Passed to Docker as a build argument
3. Used in the image's labels and metadata

## Creating Releases

To create a new release:

1. Create and push a tag that follows semantic versioning:

   ```bash
   git tag -a 1.2.3 -m "Release 1.2.3"
   git push origin 1.2.3
   ```

2. The CI pipeline will:
   - Use setuptools_scm to get the version
   - Build the Docker image with proper tags
   - Push the release to registries

## Usage Notes

- The `_version.py` file is automatically generated and ignored by git
- Always include the patch version in tags (e.g., use `1.2.3` instead of `1.2`)
- For the Docker image, the `+` in versions is replaced with `-` for compatibility
