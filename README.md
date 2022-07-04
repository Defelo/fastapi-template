<p>

  [![CI](https://github.com/Defelo/fastapi-template/actions/workflows/ci.yml/badge.svg)](https://github.com/Defelo/fastapi-template/actions/workflows/ci.yml)
  [![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
  [![Maintainability](https://api.codeclimate.com/v1/badges/72080273c78701c4f0eb/maintainability)](https://codeclimate.com/github/Defelo/fastapi-template/maintainability)
  [![Test Coverage](https://api.codeclimate.com/v1/badges/72080273c78701c4f0eb/test_coverage)](https://codeclimate.com/github/Defelo/fastapi-template/test_coverage)

</p>

# fastapi-template

A template for projects that use the [FastAPI framework](https://fastapi.tiangolo.com/).

## How to use this template

### Choose a template branch

Currently these two branches are available:

- `develop`: Contains a basic FastAPI template using SQLAlchemy and aioredis, including basic logging, optional token authentication, utilities to simplify documentation creation and some demo endpoints, as well as a `Dockerfile` to create a Docker image and a GitHub Actions workflow to automatically build and push the Docker image to GitHub Container Registry.
- `users`: Contains everything included in the `develop` branch and implements basic user management functionality. This includes endpoints for user creation, session management and administration as well as features such as 2FA via TOTP, generic OAuth2 and reCAPTCHA on account creation and/or too many failed login attempts.

Replace `TEMPLATE_BRANCH` in the next section with the branch you would like to use.

### Setup repository

1. Click the [Use this template](https://github.com/Defelo/fastapi-template/generate) button to generate a new repository
2. `git clone` your new repository
3. Add this repository as a `template` remote: `git remote add template https://github.com/Defelo/fastapi-template.git && git fetch template`
4. Reset your branch to the template branch you would like to use: `git reset --hard template/TEMPLATE_BRANCH`
5. Force push your branch to GitHub: `git push -f`

To later update your repository you can just merge the template into your own branch: `git fetch template && git merge template/TEMPLATE_BRANCH`

### Customize template files

1. Adjust `name`, `description`, `authors`, `homepage` and `repository` in [pyproject.toml](https://github.com/Defelo/fastapi-template/blob/develop/pyproject.toml#L2-L9)
2. Adjust repository url in [Dockerfile](https://github.com/Defelo/fastapi-template/blob/develop/Dockerfile#L24)
3. Adjust docker image tag in [docker-compose.yml](https://github.com/Defelo/fastapi-template/blob/develop/docker-compose.yml#L5) and [.github/workflows/ci.yml](https://github.com/Defelo/fastapi-template/blob/develop/.github/workflows/ci.yml#L9)
4. (optional) Enable additional platforms for docker buildx in [.github/workflows/ci.yml](https://github.com/Defelo/fastapi-template/blob/develop/.github/workflows/ci.yml#L165-L168)
5. Enable docker push in [.github/workflows/ci.yml](https://github.com/Defelo/fastapi-template/blob/develop/.github/workflows/ci.yml#L232) by removing the `"false" #`
6. (optional) Adjust [.github/workflows/ci.yml](https://github.com/Defelo/fastapi-template/blob/develop/.github/workflows/ci.yml#L292-L304) to enable automatic deployment by sending an HTTP request to a specific url
7. (optional) If you *don't* want your dependabot pull requests to be merged automatically, remove the [.github/workflows/merge-me.yml](https://github.com/Defelo/fastapi-template/blob/develop/.github/workflows/merge-me.yml) workflow
8. (optional) If you want to automatically delete unused docker tags from GHCR:
    1. Adjust repository owner and name in [.github/workflows/docker_clean.yml](https://github.com/Defelo/fastapi-template/blob/develop/.github/workflows/docker_clean.yml#L10-L11)
    2. Uncomment the workflow triggers in [.github/workflows/docker_clean.yml](https://github.com/Defelo/fastapi-template/blob/develop/.github/workflows/docker_clean.yml#L4-L6)
    3. Create a [personal access token](https://github.com/settings/tokens/new) with `delete:packages` permissions
    4. Create a new `docker-clean` environment, allow only `develop` as deployment branch and create a `CR_PAT` secret that contains the personal access token

## Development

### Prerequisites
- [Python 3.10](https://python.org/)
- [Poetry](https://python-poetry.org/) + [poethepoet](https://pypi.org/project/poethepoet/)
- [Git](https://git-scm.com/)
- [Docker](https://www.docker.com/) + [docker-compose](https://docs.docker.com/compose/) (recommended)
- [PyCharm Community/Professional](https://www.jetbrains.com/pycharm/) (recommended)

### Clone the repository

#### SSH (recommended)
```bash
git clone --recursive git@github.com:Defelo/fastapi-template.git
```

#### HTTPS
```bash
git clone --recursive https://github.com/Defelo/fastapi-template.git
```

### Setup development environment

After cloning the repository, you can setup the development environment by running the following command:

```bash
poe setup
```

This will create a virtual environment, install the dependencies, create a `.env` file and install the pre-commit hook.

### PyCharm configuration

Configure the Python interpreter:

- Open PyCharm and go to `Settings` ➔ `Project` ➔ `Python Interpreter`
- Open the menu `Python Interpreter` and click on `Show All...`
- Click on the plus symbol
- Click on `Poetry Environment`
- Select `Existing environment` (setup the environment first by running `poe setup`)
- Confirm with `OK`

Setup the run configuration:

- Click on `Add Configuration...` ➔ `Add new...` ➔ `Python`
- Change target from `Script path` to `Module name` and choose the `api` module
- Change the working directory to root path  ➔ `Edit Configurations`  ➔ `Working directory`
- In the `EnvFile` tab add your `.env` file
- Confirm with `OK`

### Run the API

To run the api for development you can use the `api` task:

```bash
poe api
```
