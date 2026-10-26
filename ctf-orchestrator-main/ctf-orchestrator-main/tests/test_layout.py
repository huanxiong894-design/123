from __future__ import annotations

import os

import pytest

from tests.helpers import make_challenge
from ycb.models import Attachment
from ycb.workspace.layout import (
    challenge_dirname,
    challenge_path,
    prepare_challenge_dir,
    safe_component,
    safe_filename,
    slugify,
    write_target_info,
)
from ycb.models import Target


def test_safe_component_blocks_traversal_and_hidden_names():
    assert safe_component("../../etc/passwd") == "etc_passwd"
    assert safe_component("../evil") == "evil"
    assert safe_component(".hidden") == "hidden"
    assert safe_component("..") == "challenge"
    assert safe_component("") == "challenge"
    assert safe_component("羊城杯") == "challenge"
    assert safe_component("A" * 80, max_len=10) == "A" * 10
    assert "/" not in safe_component("a/b/c")
    assert "\x00" not in safe_component("a\x00b")


def test_safe_filename_keeps_only_basename():
    assert safe_filename("../../x.zip") == "x.zip"
    assert safe_filename("C:\\Temp\\evil.zip") == "evil.zip"
    assert safe_filename(".bashrc") == "bashrc"
    assert safe_filename("..") == "attachment.bin"
    assert safe_filename("") == "attachment.bin"
    chinese = safe_filename("名字.zip")  # 非 ASCII 用短哈希，保留扩展名
    assert chinese.startswith("attachment-") and chinese.endswith(".zip")
    assert safe_filename("名字.zip") == chinese  # 确定性
    assert safe_filename("附件.zip") != chinese  # 不同原名不互相覆盖
    assert len(safe_filename("a" * 200 + ".bin")) <= 120


def test_challenge_dirname_is_ascii_and_stable():
    name = challenge_dirname(3, "Crypto", "Warmup RSA 羊城杯!", "mock:1749:crypto-warmup-rsa")
    assert name.startswith("03_crypto_warmup_rsa_")
    assert all(ord(ch) < 128 for ch in name)
    assert name == challenge_dirname(3, "Crypto", "Warmup RSA 羊城杯!", "mock:1749:crypto-warmup-rsa")


def test_challenge_path_stays_inside_root(tmp_path):
    root = tmp_path / "challenges"
    path = challenge_path(root, 1, "Misc", "../../evil", "uid")
    assert path.resolve().is_relative_to(root.resolve())
    assert "evil" not in path.name.split("_")[:1]


def test_prepare_is_idempotent_and_preserves_agent_work(tmp_path):
    challenge = make_challenge(
        "c1",
        title="Warmup RSA",
        attachments=[Attachment(name="warmup_rsa.zip", size=10, sha256="a" * 64)],
    )
    workspace = prepare_challenge_dir(
        tmp_path / "challenges", challenge, seq_no=1, flag_regex=r"^DASCTF\{.*\}$"
    )

    assert (workspace / "attachments").is_dir()
    assert (workspace / "files").is_dir()
    assert not (workspace / "CLAUDE.md").exists()
    assert not (workspace / ".claude").exists()
    description = (workspace / "description.md").read_text(encoding="utf-8")
    assert "不可信数据" in description
    assert "flag.txt" in description
    assert "DASCTF" in description
    assert "warmup_rsa.zip" in description

    notes = workspace / "notes.md"
    notes.write_text("agent notes", encoding="utf-8")
    again = prepare_challenge_dir(
        tmp_path / "challenges", challenge, seq_no=1, flag_regex=r"^DASCTF\{.*\}$"
    )
    assert again == workspace
    assert notes.read_text(encoding="utf-8") == "agent notes"
    assert (workspace / "metadata.json").is_file()
    if os.name == "posix":
        assert (workspace.stat().st_mode & 0o777) == 0o700


def test_write_target_info(tmp_path):
    workspace = tmp_path / "ws"
    workspace.mkdir()
    (workspace / "description.md").write_text(
        "# t\n\n- 靶机地址：`未启动`\n", encoding="utf-8"
    )
    write_target_info(workspace, Target(kind="tcp", host="127.0.0.1", port=31337))
    text = (workspace / "target.txt").read_text(encoding="utf-8")
    assert "127.0.0.1" in text and "31337" in text
    desc = (workspace / "description.md").read_text(encoding="utf-8")
    assert "127.0.0.1:31337" in desc
    assert "bound method" not in desc
    if os.name == "posix":
        assert ((workspace / "target.txt").stat().st_mode & 0o777) == 0o600


def test_slugify_lowercases():
    assert slugify("Hello World") == "hello_world"
