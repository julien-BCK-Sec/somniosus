import subprocess
from typing import List, Optional, Tuple


def run(cmd: List[str], timeout: Optional[int] = None) -> str:
    """
    Backwards-compatible helper:
    - Returns stdout as a string
    - Raises RuntimeError on non-zero exit
    """
    rc, stdout, stderr = run_capture(cmd, timeout=timeout)
    if rc != 0:
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\n{stderr}")
    return stdout


def run_capture(cmd: List[str], timeout: Optional[int] = None) -> Tuple[int, str, str]:
    """
    Returns (rc, stdout, stderr) without raising.
    """
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout or "", p.stderr or ""


def run_with_stdin(cmd: List[str], stdin_text: str, timeout: Optional[int] = None) -> str:
    """
    Backwards-compatible helper:
    - Returns stdout as a string
    - Raises RuntimeError on non-zero exit
    """
    rc, stdout, stderr = run_with_stdin_capture(cmd, stdin_text, timeout=timeout)
    if rc != 0:
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\n{stderr}")
    return stdout


def run_with_stdin_capture(
    cmd: List[str], stdin_text: str, timeout: Optional[int] = None
) -> Tuple[int, str, str]:
    """
    Returns (rc, stdout, stderr) without raising.
    """
    p = subprocess.run(cmd, input=stdin_text, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout or "", p.stderr or ""
