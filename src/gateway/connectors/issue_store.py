"""Issue filing backends for ``codehost.issue_open`` (Pillar 2 §3.5).

``IssueOpener`` is the interface; the MVP ships ``LocalIssueStore``
(the safe file-backed fallback) and defines-but-does-not-implement
``GitHubIssueOpener`` (selecting it is a fail-closed startup config
error until the GitHub OAuth app decision lands).

The pre-file redaction gate runs BEFORE the store write, identically
for both backends. A write failure → the tool call errors, the
finding stays ``draft_blocked``, the run log records it — the store
never fails open and never leaks.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class IssueRef:
    id: str            # "local-000123" or GitHub issue number
    url: str           # file path (local) or https URL
    dedupe_key: str    # "RT-04|inspection.injected_output_blocked"
    state: str         # "open" | "closed"


class IssueOpener(Protocol):
    def open_issue(self, *, repo: str, title: str, body: str, labels: list[str]) -> IssueRef: ...
    def find_open_issues(self, *, repo: str, labels: list[str]) -> list[IssueRef]: ...
    def comment(self, *, issue_id: str, body: str) -> None: ...
    def count_opened_since(self, *, repo: str, since_utc: dt.datetime) -> int: ...


_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def _check_repo(repo: str) -> None:
    if not _REPO_RE.match(repo or ""):
        raise ValueError(f"invalid repo {repo!r}; want 'owner/name'")


class LocalIssueStore:
    """File-backed issue store (MVP).

    One JSON file per issue under
    ``GATEWAY_CODEHOST_ISSUES_DIR/<owner>/<repo>/``, plus an
    ``index.json`` for dedupe-key lookup and daily counts. The index
    is rewritten atomically (write + rename).
    """

    def __init__(self, root_dir: str) -> None:
        self.root_dir = root_dir

    # -- paths --------------------------------------------------------

    def _repo_dir(self, repo: str) -> str:
        _check_repo(repo)
        owner, name = repo.split("/", 1)
        # owner/name are constrained by _REPO_RE (no path separators
        # beyond the one split) — no traversal possible.
        path = os.path.join(self.root_dir, owner, name)
        os.makedirs(path, exist_ok=True)
        return path

    def _index_path(self, repo: str) -> str:
        return os.path.join(self._repo_dir(repo), "index.json")

    def _load_index(self, repo: str) -> list[dict[str, Any]]:
        path = self._index_path(repo)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            return list(data) if isinstance(data, list) else []
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    def _save_index(self, repo: str, index: list[dict[str, Any]]) -> None:
        path = self._index_path(repo)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(index, fh, indent=2, sort_keys=True)
        os.replace(tmp, path)

    # -- IssueOpener ----------------------------------------------------

    def open_issue(self, *, repo: str, title: str, body: str, labels: list[str]) -> IssueRef:
        _check_repo(repo)
        if not title or not title.strip():
            raise ValueError("issue title is required")
        index = self._load_index(repo)
        number = len(index) + 1
        issue_id = f"local-{number:06d}"
        created_at = dt.datetime.now(dt.timezone.utc).isoformat()
        dedupe_key = _dedupe_key_from_labels(labels)
        record = {
            "id": issue_id,
            "number": number,
            "repo": repo,
            "title": title,
            "body": body,
            "labels": sorted(set(labels or [])),
            "state": "open",
            "dedupe_key": dedupe_key,
            "created_at": created_at,
            "comments": [],
        }
        issue_path = os.path.join(self._repo_dir(repo), f"{issue_id}.json")
        tmp = issue_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(record, fh, indent=2, sort_keys=True)
        os.replace(tmp, issue_path)
        index.append(
            {
                "id": issue_id, "number": number, "state": "open",
                "dedupe_key": dedupe_key, "labels": sorted(set(labels or [])),
                "created_at": created_at, "title": title,
            }
        )
        self._save_index(repo, index)
        return IssueRef(
            id=issue_id, url=issue_path, dedupe_key=dedupe_key, state="open"
        )

    def find_open_issues(self, *, repo: str, labels: list[str]) -> list[IssueRef]:
        index = self._load_index(repo)
        wanted = set(labels or [])
        out: list[IssueRef] = []
        for entry in index:
            if entry.get("state") != "open":
                continue
            if wanted and not wanted.issubset(set(entry.get("labels") or [])):
                continue
            out.append(
                IssueRef(
                    id=entry["id"],
                    url=os.path.join(self._repo_dir(repo), f"{entry['id']}.json"),
                    dedupe_key=entry.get("dedupe_key", ""),
                    state="open",
                )
            )
        return out

    def comment(self, *, issue_id: str, body: str) -> None:
        # The issue id is constrained to the local-###### shape; the
        # repo dir is resolved by scanning the store (no path from the
        # caller reaches the filesystem).
        if not re.fullmatch(r"local-\d{6}", issue_id or ""):
            raise ValueError(f"invalid local issue id {issue_id!r}")
        for owner in os.listdir(self.root_dir):
            owner_dir = os.path.join(self.root_dir, owner)
            if not os.path.isdir(owner_dir):
                continue
            for repo_name in os.listdir(owner_dir):
                candidate = os.path.join(owner_dir, repo_name, f"{issue_id}.json")
                if os.path.isfile(candidate):
                    with open(candidate, "r", encoding="utf-8") as fh:
                        record = json.load(fh)
                    record.setdefault("comments", []).append(
                        {
                            "body": body,
                            "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                        }
                    )
                    tmp = candidate + ".tmp"
                    with open(tmp, "w", encoding="utf-8") as fh:
                        json.dump(record, fh, indent=2, sort_keys=True)
                    os.replace(tmp, candidate)
                    return
        raise ValueError(f"local issue {issue_id!r} not found")

    def count_opened_since(self, *, repo: str, since_utc: dt.datetime) -> int:
        count = 0
        for entry in self._load_index(repo):
            try:
                created = dt.datetime.fromisoformat(entry["created_at"])
            except (KeyError, ValueError):
                continue
            if created.tzinfo is None:
                created = created.replace(tzinfo=dt.timezone.utc)
            if created >= since_utc:
                count += 1
        return count

    # -- operator affordances -------------------------------------------

    def close_issue(self, repo: str, issue_id: str) -> None:
        """Close an issue (operator action; closed issues do not
        suppress duplicates — a regression re-opens the conversation
        as a new issue referencing the old one)."""
        index = self._load_index(repo)
        for entry in index:
            if entry["id"] == issue_id:
                entry["state"] = "closed"
        self._save_index(repo, index)
        path = os.path.join(self._repo_dir(repo), f"{issue_id}.json")
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as fh:
                record = json.load(fh)
            record["state"] = "closed"
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(record, fh, indent=2, sort_keys=True)
            os.replace(tmp, path)


def _dedupe_key_from_labels(labels: list[str]) -> str:
    """Dedupe key from the issue labels: scenario + control point.

    Labels carry ``rt-<nn>`` (scenario) and ``redteam-finding``; the
    control point rides in the label ``cp:<control_point>`` when the
    caller provides it.
    """
    scenario = next(
        (l for l in labels if l.startswith("rt-")), "rt-unknown"
    )
    control = next(
        (l[3:] for l in labels if l.startswith("cp:")), "unknown"
    )
    return f"{scenario.upper()}|{control}"


class GitHubIssueOpener:
    """DEFINED BUT NOT IMPLEMENTED in the MVP slice.

    Instantiating raises a clear config error — selecting the github
    backend never silently degrades. When implemented, it uses the
    vault-held GitHub credential via the derived-token path (FR-012b).
    """

    def __init__(self, *_: Any, **__: Any) -> None:
        raise RuntimeError(
            "GitHub issue backend not implemented; use `file` "
            "(GATEWAY_CODEHOST_ISSUES_BACKEND=file). The GitHub backend "
            "needs the GitHub OAuth app decision before real filing exists."
        )


def opener_from_settings(settings: Any) -> IssueOpener:
    """Build the configured issue opener (fail-closed on github)."""
    backend = str(getattr(settings, "codehost_issues_backend", "file") or "file").lower()
    if backend == "file":
        return LocalIssueStore(str(getattr(settings, "codehost_issues_dir", "data/issues")))
    if backend == "github":
        return GitHubIssueOpener()  # raises RuntimeError — fail-closed
    raise ValueError(f"unknown issues backend {backend!r}")
