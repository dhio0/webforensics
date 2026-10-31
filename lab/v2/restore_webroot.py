"""Rebuild a complete scenario webroot from its pinned app image and safe overlay."""

from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
import time
from pathlib import Path

from collect import read_manifest

ROOT = Path(__file__).resolve().parents[2]


def digest(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            sha.update(chunk)
    return sha.hexdigest()


def is_inside(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def restore(scenario: str, destination: Path) -> int:
    scenario_dir = ROOT / "benchmark" / "v2" / scenario
    metadata = scenario_dir / "replay" / "restore.json"
    if not metadata.is_file():
        raise FileNotFoundError(f"missing pinned image metadata: {metadata}")
    import json

    config = json.loads(metadata.read_text(encoding="utf-8"))
    image = config["image"]
    app_type = config.get("app_type", "wordpress")
    image_webroot = config.get("webroot", "/var/www/html")
    dest = destination.resolve()
    repo = ROOT.resolve()
    if is_inside(dest, repo):
        raise ValueError("destination must be outside the repository")
    if dest.exists() and any(dest.iterdir()):
        raise ValueError(f"destination must be empty: {dest}")
    dest.mkdir(parents=True, exist_ok=True)
    manifest = read_manifest(scenario_dir / "evidence" / "manifest.tsv")
    baseline = read_manifest(scenario_dir / "evidence" / "baseline.tsv")
    overlay = scenario_dir / "evidence" / "webroot"
    defanged_path = scenario_dir / "evidence" / "defanged.tsv"
    allowed_stub = set()
    with defanged_path.open(encoding="utf-8") as table:
        next(table, None)
        for row in table:
            allowed_stub.add(row.split("\t", 1)[0])

    env_file = ROOT / "lab" / "v2" / ".env"
    local_env = {}
    if env_file.is_file():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                key, value = line.split("=", 1)
                local_env[key.strip()] = value.strip()
    word_env = {
        "WORDPRESS_DB_HOST": "db:3306",
        "WORDPRESS_DB_NAME": local_env.get("MYSQL_DATABASE", "wordpress"),
        "WORDPRESS_DB_USER": local_env.get("MYSQL_USER", "wordpress"),
        "WORDPRESS_DB_PASSWORD": local_env.get("MYSQL_PASSWORD", "wordpress"),
        "WORDPRESS_CONFIG_EXTRA": "define('WP_HOME', 'http://edge');\ndefine('WP_SITEURL', 'http://edge');\n",
    }
    defaults = {
        "WORDPRESS_AUTH_KEY": "m8v2-round5-auth-key-test-only",
        "WORDPRESS_SECURE_AUTH_KEY": "m8v2-round5-secure-auth-key-test-only",
        "WORDPRESS_LOGGED_IN_KEY": "m8v2-round5-logged-in-key-test-only",
        "WORDPRESS_NONCE_KEY": "m8v2-round5-nonce-key-test-only",
        "WORDPRESS_AUTH_SALT": "m8v2-round5-auth-salt-test-only",
        "WORDPRESS_SECURE_AUTH_SALT": "m8v2-round5-secure-auth-salt-test-only",
        "WORDPRESS_LOGGED_IN_SALT": "m8v2-round5-logged-in-salt-test-only",
        "WORDPRESS_NONCE_SALT": "m8v2-round5-nonce-salt-test-only",
    }
    word_env.update({key: local_env.get(key, value) for key, value in defaults.items()})
    args = ["docker", "create", "--network", "none"]
    for key, value in word_env.items():
        args.extend(("--env", f"{key}={value}"))
    args.append(image)
    container = subprocess.check_output(args, text=True).strip()
    try:
        subprocess.run(["docker", "start", container], check=True, stdout=subprocess.DEVNULL)
        for _ in range(60):
            probe = subprocess.run(
                [
                    "docker",
                    "exec",
                    container,
                    "sh",
                    "-c",
                    (
                        "test -f /var/www/html/wp-config.php -a -f /var/www/html/.htaccess"
                        if app_type == "wordpress"
                        else "test -f /var/www/html/index.php"
                    ),
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if probe.returncode == 0:
                break
            time.sleep(1)
        else:
            raise TimeoutError("pinned app image did not initialize its webroot")
        subprocess.run(
            ["docker", "cp", f"{container}:{image_webroot}/.", str(dest)],
            check=True,
            stdout=subprocess.DEVNULL,
        )
    finally:
        subprocess.run(["docker", "rm", "-f", container], check=False, stdout=subprocess.DEVNULL)

    overlay_value = config.get("setup_overlay")
    if overlay_value:
        setup_overlay = (scenario_dir / overlay_value).resolve()
        if not is_inside(setup_overlay, scenario_dir.resolve()):
            raise ValueError("setup overlay must stay inside the scenario directory")
        if setup_overlay.is_dir():
            for source in setup_overlay.rglob("*"):
                if not source.is_file() or source.is_symlink():
                    continue
                rel = source.relative_to(setup_overlay)
                target = dest / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)

    if app_type == "phpmyfaq":
        def php_quote(value: str) -> str:
            return value.replace("\\", "\\\\").replace("'", "\\'")

        values = {
            "server": "pgdb",
            "port": "5432",
            "user": local_env.get("MYSQL_USER", "benchv2"),
            "password": local_env.get("MYSQL_PASSWORD", "benchv2"),
            "db": local_env.get("MYSQL_DATABASE", "benchv2"),
            "prefix": "",
            "type": "pgsql",
        }
        config_dir = dest / "config"
        config_dir.mkdir(exist_ok=True)
        config_path = config_dir / "database.php"
        if not config_path.exists():
            config_path.write_text(
                ("<?php\n" + "".join(
                    f"$DB['{key}'] = '{php_quote(value)}';\n"
                    for key, value in values.items()
                )).rstrip("\n"),
                encoding="utf-8",
                newline="\n",
            )

    checked = 0
    for rel, row in manifest.items():
        target = dest / Path(rel)
        base_row = baseline.get(rel)
        changed = base_row is None or any(
            row.fields[index] != base_row.fields[index] for index in (1, 2, 3, 4, 5, 7, 8, 9, 10)
        )
        if changed and (overlay / rel).is_file():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(overlay / rel, target)
        if not target.exists():
            raise ValueError(f"manifest path missing from restored image: {rel}")
        if row.kind == "f":
            actual = digest(target)
            if actual != row.sha256:
                if rel not in allowed_stub:
                    raise ValueError(f"manifest hash mismatch for {rel}: {actual} != {row.sha256}")
                stub = target.read_text(encoding="ascii", errors="strict")
                if not stub.startswith(f"DEFANGED {row.sha256} {row.fields[2]}\n"):
                    raise ValueError(f"defanged stub is invalid for {rel}")
        checked += 1
    extras = {
        p.relative_to(dest).as_posix()
        for p in dest.rglob("*")
        if p.is_file() and p.relative_to(dest).as_posix() not in manifest
    }
    if extras:
        raise ValueError(f"restored image has files outside manifest: {sorted(extras)[:5]}")
    return checked


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario")
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    if args.scenario not in {f"s{i:02}" for i in range(1, 13)}:
        parser.error("unknown scenario")
    try:
        count = restore(args.scenario, args.destination)
    except (OSError, KeyError, ValueError, subprocess.CalledProcessError) as exc:
        parser.error(str(exc))
    print(f"restored {count} manifest entries to {args.destination.resolve()}")


if __name__ == "__main__":
    main()
