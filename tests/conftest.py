import asyncio
import os

import pytest

from src.python_x509_pkcs11.pkcs11_handle import PKCS11Session

ON_GITHUB = bool(os.getenv("GITHUB_ACTIONS", False))


async def delete_keys():
    "We delete keys in a loop"

    # No need to delete keys in github actions.
    if ON_GITHUB:
        return
    session = PKCS11Session()
    keys = await session.key_labels()
    for key_label, key_type in keys.items():
        if key_label == "test_pkcs11_device_do_not_use":
            continue
        if key_label.startswith("testpkcs"):
            await session.delete_keypair(key_label, key_type)


def pytest_sessionfinish(session: pytest.Session) -> None:
    # Delete all test keys
    asyncio.run(delete_keys())


def pytest_sessionstart(session: pytest.Session) -> None:
    # Delete all test keys
    asyncio.run(delete_keys())
