"""Best-effort scan caching for a frozen, validated Grype database."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import subprocess
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class ScanCache:
    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self._prepared = False
        self._context: str | None = None

    def path_for(self, target: str, env: dict[str, str]) -> Path | None:
        # An auto-updating scanner could use a different DB after the lookup.
        # Without a frozen DB we must let Grype update and scan normally.
        if env.get("GRYPE_DB_AUTO_UPDATE", "").lower() != "false":
            logger.debug("Scan cache bypassed: GRYPE_DB_AUTO_UPDATE is not false")
            return None
        if not self._prepared:
            self._prepared = True
            try:
                self._context = self._fingerprint(env)
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                logger.warning("Scan cache unavailable; scanning normally: %s", error)
        if self._context is None:
            return None
        key = hashlib.sha256(target.encode()).hexdigest()
        return self.directory / self._context / f"{key}.json"

    def _fingerprint(self, env: dict[str, str]) -> str:
        def output(*args: str) -> str:
            return subprocess.run(
                ["grype", *args], check=True, capture_output=True, text=True, env=env
            ).stdout

        logger.debug(
            "Preparing scan cache fingerprint from Grype configuration and database"
        )
        version = output("version", "-o", "json")
        config = output("config", "--load")
        status = json.loads(output("db", "status", "-o", "json"))
        if not isinstance(status, dict) or status.get("valid") is not True:
            raise ValueError("Grype database is not valid")
        db_path = status.get("path")
        if not isinstance(db_path, str) or not db_path:
            raise ValueError("Grype database path is missing")
        with Path(db_path).open("rb") as database:
            database_hash = hashlib.file_digest(database, "sha256").hexdigest()
        scanner_env = {
            key: value
            for key, value in env.items()
            if key.startswith(("GRYPE_", "SYFT_"))
        }
        # Only the hash is persisted: loaded configuration may contain secrets.
        context = json.dumps(
            ["v1", version, config, database_hash, scanner_env], sort_keys=True
        )
        return hashlib.sha256(context.encode()).hexdigest()

    @staticmethod
    def load(path: Path) -> dict[str, Any] | None:
        try:
            document = json.loads(path.read_text())
        except OSError, ValueError:
            return None
        if not isinstance(document, dict) or not isinstance(
            document.get("matches"), list
        ):
            return None
        for match in document["matches"]:
            if not isinstance(match, dict) or not all(
                isinstance(match.get(key), dict)
                for key in ("vulnerability", "artifact")
            ):
                return None
        return document

    @staticmethod
    def save(path: Path, document: dict[str, Any]) -> bool:
        if not isinstance(document.get("matches"), list):
            return False
        temporary = path.with_suffix(f".{os.getpid()}.tmp")
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            # Do not persist Grype's descriptor/configuration (registry credentials).
            temporary.write_text(json.dumps({"matches": document["matches"]}))
            temporary.replace(path)
            return True
        except OSError as error:
            logger.warning("Could not save scan cache: %s", error)
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
            return False
