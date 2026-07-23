"""Wi-Fi visibility and saved-profile audit helper for Windows.

This script lists Wi-Fi networks currently visible to your adapter and can show
security details for profiles already saved on this computer. Windows does not
expose passwords for arbitrary nearby networks; displaying keys only works for
profiles that were previously saved by the current Windows installation and
that the current user is authorized to view.
"""

from __future__ import annotations

import re
import subprocess
import sys
from dataclasses import dataclass


@dataclass
class VisibleNetwork:
    ssid: str
    auth: str = "Unknown"
    encryption: str = "Unknown"
    signal: str = "Unknown"


def run_netsh(command: list[str]) -> str:
    """Run a netsh command and return decoded output."""
    try:
        return subprocess.check_output(
            command,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError:
        sys.exit("This script must be run on Windows where netsh is available.")
    except subprocess.CalledProcessError as exc:
        sys.exit(f"Command failed: {' '.join(command)}\n\n{exc.output}")


def get_visible_networks() -> list[VisibleNetwork]:
    """Return nearby Wi-Fi networks visible to the adapter."""
    output = run_netsh(["netsh", "wlan", "show", "networks", "mode=bssid"])
    networks: list[VisibleNetwork] = []
    current: VisibleNetwork | None = None

    for raw_line in output.splitlines():
        line = raw_line.strip()
        ssid_match = re.match(r"SSID\s+\d+\s*:\s*(.*)", line)
        if ssid_match:
            current = VisibleNetwork(ssid=ssid_match.group(1).strip() or "<hidden>")
            networks.append(current)
            continue

        if current is None or ":" not in line:
            continue

        key, value = [part.strip() for part in line.split(":", 1)]
        if key == "Authentication":
            current.auth = value
        elif key == "Encryption":
            current.encryption = value
        elif key == "Signal" and current.signal == "Unknown":
            current.signal = value

    return networks


def get_saved_profile_names() -> list[str]:
    """Return Wi-Fi profile names saved on this computer."""
    output = run_netsh(["netsh", "wlan", "show", "profiles"])
    names: list[str] = []
    for line in output.splitlines():
        if "All User Profile" in line and ":" in line:
            names.append(line.split(":", 1)[1].strip())
    return names


def get_saved_profile_details(profile_name: str) -> str:
    """Return details for a saved Wi-Fi profile, including its key if Windows allows it."""
    return run_netsh(
        ["netsh", "wlan", "show", "profile", f"name={profile_name}", "key=clear"]
    )


def choose(options: list[str], prompt: str) -> str | None:
    """Prompt for a numbered option and return the selected value."""
    if not options:
        return None

    while True:
        choice = input(prompt).strip()
        if choice.lower() in {"q", "quit", "exit"}:
            return None
        if choice.isdigit() and 1 <= int(choice) <= len(options):
            return options[int(choice) - 1]
        print(f"Enter a number from 1 to {len(options)}, or q to quit.")


def main() -> None:
    visible = get_visible_networks()
    saved_profiles = get_saved_profile_names()
    saved_lookup = {name.casefold(): name for name in saved_profiles}

    print("Nearby Wi-Fi networks:")
    if not visible:
        print("  No networks found.")
    for index, network in enumerate(visible, 1):
        saved_marker = (
            "saved profile"
            if network.ssid.casefold() in saved_lookup
            else "not saved"
        )
        print(
            f"[{index}] {network.ssid} | {network.auth} | "
            f"{network.encryption} | Signal: {network.signal} | {saved_marker}"
        )

    print(
        "\nNote: You cannot reveal passwords for arbitrary scannable networks. "
        "Windows can only show keys for profiles already saved on this computer "
        "when your account has permission."
    )

    matching_saved = [
        saved_lookup[network.ssid.casefold()]
        for network in visible
        if network.ssid.casefold() in saved_lookup
    ]
    matching_saved_set = set(matching_saved)
    remaining_saved = [
        name for name in saved_profiles if name not in matching_saved_set
    ]
    display_profiles = matching_saved + remaining_saved

    if not display_profiles:
        print("\nNo saved Wi-Fi profiles were found on this computer.")
        return

    print("\nSaved profiles available for authorized audit:")
    for index, profile in enumerate(display_profiles, 1):
        in_range = (
            "in range" if profile in matching_saved else "not currently visible"
        )
        print(f"[{index}] {profile} ({in_range})")

    selected = choose(
        display_profiles, "\nChoose a saved profile to inspect, or q to quit: "
    )
    if selected is None:
        return

    print("\n" + get_saved_profile_details(selected))


if __name__ == "__main__":
    main()
