from __future__ import annotations

import os
import secrets
import subprocess

from dataclasses import dataclass
from datetime import (
    datetime,
    timedelta,
    timezone,
)
from pathlib import Path
from threading import Lock
from uuid import uuid4


# -----------------------------------------------------------------------------
# Native collector configuration
# -----------------------------------------------------------------------------

SELECTION_TTL = timedelta(
    minutes=15
)


# A random token is generated whenever the FastAPI process starts.
#
# The browser receives this token from the local application and must send it
# back before it can request native collector operations.
#
# This prevents ordinary unauthenticated requests from invoking the collector.
_SESSION_TOKEN = (
    secrets.token_urlsafe(
        32
    )
)


# Source file selections are stored only in memory.
#
# The browser never receives the real path as something it can later submit
# back to the acquisition endpoint. Instead, it receives an opaque selection ID.
_SELECTIONS: dict[
    str,
    "SelectionRecord",
] = {}


_SELECTIONS_LOCK = Lock()


# -----------------------------------------------------------------------------
# Selection record
# -----------------------------------------------------------------------------

@dataclass(
    frozen=True
)
class SelectionRecord:

    selection_id: str

    path: Path

    selected_at_utc: datetime


# -----------------------------------------------------------------------------
# Collector session token
# -----------------------------------------------------------------------------

def collector_session_token() -> str:
    """
    Return the temporary collector token for the current application process.
    """

    return _SESSION_TOKEN


def token_matches(
    candidate: str | None,
) -> bool:
    """
    Compare a supplied collector token against the current process token.
    """

    if not candidate:

        return False


    return secrets.compare_digest(
        candidate,
        _SESSION_TOKEN,
    )


# -----------------------------------------------------------------------------
# Native source selection
# -----------------------------------------------------------------------------

def choose_source_file() -> Path | None:
    """
    Open a native operating-system file picker.

    The path comes from the locally executed collector process rather than from
    arbitrary browser input.

    Windows uses the native Windows Forms OpenFileDialog.

    Other platforms fall back to tkinter when available.
    """

    if os.name == "nt":

        return (
            _choose_source_file_windows()
        )


    return (
        _choose_source_file_tk()
    )


# -----------------------------------------------------------------------------
# Register a source selection
# -----------------------------------------------------------------------------

def register_selection(
    path: Path,
) -> SelectionRecord:
    """
    Register the selected source file and return an opaque selection record.
    """

    record = SelectionRecord(
        selection_id=str(
            uuid4()
        ),

        path=path.resolve(),

        selected_at_utc=(
            datetime.now(
                timezone.utc
            )
        ),
    )


    with _SELECTIONS_LOCK:

        _purge_expired_locked()


        _SELECTIONS[
            record.selection_id
        ] = record


    return record


# -----------------------------------------------------------------------------
# Read a selection without removing it
# -----------------------------------------------------------------------------

def get_selection(
    selection_id: str,
) -> SelectionRecord | None:
    """
    Retrieve a source selection if it still exists and has not expired.
    """

    with _SELECTIONS_LOCK:

        _purge_expired_locked()


        return _SELECTIONS.get(
            selection_id
        )


# -----------------------------------------------------------------------------
# Consume a selection
# -----------------------------------------------------------------------------

def consume_selection(
    selection_id: str,
) -> SelectionRecord | None:
    """
    Retrieve and remove a source selection.

    A selection is therefore single-use for an acquisition.
    """

    with _SELECTIONS_LOCK:

        _purge_expired_locked()


        return _SELECTIONS.pop(
            selection_id,
            None,
        )


# -----------------------------------------------------------------------------
# Remove expired selections
# -----------------------------------------------------------------------------

def _purge_expired_locked() -> None:
    """
    Remove source selections older than the configured TTL.

    Must be called while _SELECTIONS_LOCK is held.
    """

    cutoff = (
        datetime.now(
            timezone.utc
        )
        - SELECTION_TTL
    )


    expired = [

        selection_id

        for (
            selection_id,
            record,
        )
        in _SELECTIONS.items()

        if (
            record.selected_at_utc
            < cutoff
        )
    ]


    for selection_id in expired:

        _SELECTIONS.pop(
            selection_id,
            None,
        )


# -----------------------------------------------------------------------------
# Windows native file picker
# -----------------------------------------------------------------------------

def _choose_source_file_windows() -> Path | None:
    """
    Open the Windows native Open File dialog using Windows Forms.

    The selected path is returned directly to Python and does not originate
    from browser-controlled input.
    """

    script = r"""
Add-Type -AssemblyName System.Windows.Forms

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$dialog = New-Object System.Windows.Forms.OpenFileDialog

$dialog.Title = 'Select source evidence'

$dialog.Multiselect = $false

$dialog.CheckFileExists = $true

$dialog.CheckPathExists = $true

$dialog.RestoreDirectory = $true

$result = $dialog.ShowDialog()

if (
    $result -eq
    [System.Windows.Forms.DialogResult]::OK
) {
    Write-Output $dialog.FileName
}
"""


    creation_flags = getattr(
        subprocess,
        "CREATE_NO_WINDOW",
        0,
    )


    completed = subprocess.run(
        [
            "powershell.exe",

            "-NoProfile",

            "-NonInteractive",

            "-STA",

            "-Command",

            script,
        ],

        capture_output=True,

        text=True,

        encoding="utf-8",

        errors="replace",

        creationflags=(
            creation_flags
        ),

        check=False,
    )


    if (
        completed.returncode
        != 0
    ):

        message = (
            completed.stderr.strip()
            or (
                "Native Windows "
                "file picker failed."
            )
        )


        raise RuntimeError(
            message
        )


    selected = (
        completed.stdout.strip()
    )


    if not selected:

        # User cancelled the dialog.
        return None


    selected_path = Path(
        selected
    ).resolve()


    if (
        not selected_path.exists()
        or not selected_path.is_file()
    ):

        raise RuntimeError(
            (
                "The selected source "
                "file is unavailable."
            )
        )


    return selected_path


# -----------------------------------------------------------------------------
# Cross-platform fallback
# -----------------------------------------------------------------------------

def _choose_source_file_tk() -> Path | None:
    """
    Cross-platform development fallback using tkinter.

    Windows normally uses the native Windows Forms picker above.
    """

    try:

        import tkinter as tk

        from tkinter import (
            filedialog,
        )


    except ImportError as error:

        raise RuntimeError(
            (
                "No native file picker "
                "is available on this "
                "platform."
            )
        ) from error


    root = tk.Tk()


    root.withdraw()


    root.attributes(
        "-topmost",
        True,
    )


    try:

        selected = (
            filedialog.askopenfilename(
                title=(
                    "Select source evidence"
                )
            )
        )


    finally:

        root.destroy()


    if not selected:

        return None


    selected_path = Path(
        selected
    ).resolve()


    if (
        not selected_path.exists()
        or not selected_path.is_file()
    ):

        raise RuntimeError(
            (
                "The selected source "
                "file is unavailable."
            )
        )


    return selected_path