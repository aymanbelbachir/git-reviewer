# Sandbox image for `git-reviewer review --run-tests` (docs/ARCHITECTURE.md §8.2).
#
# git-reviewer never builds or pulls images: that would need the network. Build it yourself, once,
# from the repository root:
#   docker build -t git-reviewer-sandbox:0.1 sandbox/
#
# The base image is pinned by digest (python:3.12-slim, multi-platform index) and every package is
# pinned by hash, so a rebuild cannot silently change what runs the tests (SECURITY.md T-29).
FROM python:3.12-slim@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704

COPY requirements.txt /tmp/requirements.txt
# The reviewed code (/work/src, then /work) is importable, but only after the standard library and
# the installed packages: a pytest.py, pluggy.py or json.py in the reviewed repository cannot
# replace them. git-reviewer runs `python -P`, so /work is not put first either.
RUN pip install --no-cache-dir --no-deps --require-hashes --only-binary=:all: \
        --root-user-action=ignore --disable-pip-version-check -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt \
    && printf '/work/src\n/work\n' \
        > "$(python -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')/git-reviewer-work.pth" \
    && useradd --uid 10001 --user-group --no-create-home --home-dir /tmp \
        --shell /usr/sbin/nologin sandbox

# git-reviewer also passes --user=10001:10001 and checks it; this is the default if run by hand.
USER 10001:10001
WORKDIR /work
