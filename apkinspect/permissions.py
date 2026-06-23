"""Catalogue of Android permissions worth flagging, with a severity and a short
reason.  Keys are the permission suffix (after the final ``.``)."""
from __future__ import annotations

# severity, human description
PERMISSIONS: dict[str, tuple[str, str]] = {
    # --- runtime "dangerous" permissions (privacy-sensitive) --------------
    "READ_CALENDAR": ("LOW", "Read the user's calendar"),
    "WRITE_CALENDAR": ("LOW", "Modify the user's calendar"),
    "CAMERA": ("LOW", "Access the camera"),
    "READ_CONTACTS": ("LOW", "Read contacts"),
    "WRITE_CONTACTS": ("LOW", "Modify contacts"),
    "GET_ACCOUNTS": ("LOW", "List device accounts"),
    "ACCESS_FINE_LOCATION": ("LOW", "Precise location"),
    "ACCESS_COARSE_LOCATION": ("LOW", "Approximate location"),
    "ACCESS_BACKGROUND_LOCATION": ("MEDIUM", "Location in the background"),
    "RECORD_AUDIO": ("LOW", "Record audio from the microphone"),
    "READ_PHONE_STATE": ("LOW", "Read phone state / identifiers"),
    "READ_PHONE_NUMBERS": ("LOW", "Read phone numbers"),
    "CALL_PHONE": ("LOW", "Place calls without user confirmation"),
    "ANSWER_PHONE_CALLS": ("LOW", "Answer incoming calls"),
    "READ_CALL_LOG": ("MEDIUM", "Read the call log"),
    "WRITE_CALL_LOG": ("MEDIUM", "Modify the call log"),
    "ADD_VOICEMAIL": ("LOW", "Add voicemails"),
    "USE_SIP": ("LOW", "Use SIP calling"),
    "PROCESS_OUTGOING_CALLS": ("MEDIUM", "Intercept outgoing calls"),
    "BODY_SENSORS": ("LOW", "Access body sensors"),
    "ACTIVITY_RECOGNITION": ("LOW", "Detect physical activity"),
    "SEND_SMS": ("MEDIUM", "Send SMS (can incur cost / exfiltrate)"),
    "RECEIVE_SMS": ("MEDIUM", "Intercept incoming SMS (2FA risk)"),
    "READ_SMS": ("MEDIUM", "Read SMS messages (2FA risk)"),
    "RECEIVE_MMS": ("LOW", "Receive MMS"),
    "RECEIVE_WAP_PUSH": ("LOW", "Receive WAP push"),
    "READ_EXTERNAL_STORAGE": ("LOW", "Read shared storage"),
    "WRITE_EXTERNAL_STORAGE": ("LOW", "Write shared storage"),
    "ACCESS_MEDIA_LOCATION": ("LOW", "Read location metadata from media"),
    "READ_MEDIA_IMAGES": ("LOW", "Read image media"),
    "READ_MEDIA_VIDEO": ("LOW", "Read video media"),
    "READ_MEDIA_AUDIO": ("LOW", "Read audio media"),
    # --- powerful / abusable permissions ----------------------------------
    "SYSTEM_ALERT_WINDOW": ("HIGH", "Draw overlays over other apps (tapjacking / phishing)"),
    "REQUEST_INSTALL_PACKAGES": ("HIGH", "Prompt to install other APKs (malware vector)"),
    "MANAGE_EXTERNAL_STORAGE": ("HIGH", "Full read/write to all shared storage"),
    "BIND_ACCESSIBILITY_SERVICE": ("HIGH", "Accessibility access (can read screen / inject input)"),
    "WRITE_SECURE_SETTINGS": ("HIGH", "Modify secure system settings"),
    "READ_LOGS": ("HIGH", "Read system logs (may contain other apps' data)"),
    "MANAGE_ACCOUNTS": ("MEDIUM", "Manage device accounts"),
    "QUERY_ALL_PACKAGES": ("MEDIUM", "Enumerate all installed apps (privacy)"),
    "WRITE_SETTINGS": ("MEDIUM", "Modify system settings"),
    "PACKAGE_USAGE_STATS": ("MEDIUM", "Read app usage statistics"),
    "BIND_DEVICE_ADMIN": ("HIGH", "Device administration"),
    "DELETE_PACKAGES": ("HIGH", "Uninstall packages"),
    "INSTALL_PACKAGES": ("HIGH", "Silently install packages (privileged)"),
    "MOUNT_UNMOUNT_FILESYSTEMS": ("MEDIUM", "Mount/unmount filesystems"),
    "RECEIVE_BOOT_COMPLETED": ("LOW", "Start on boot (persistence)"),
    "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS": ("LOW", "Run unrestricted in background"),
    "DUMP": ("HIGH", "Dump system service state"),
    "CAPTURE_AUDIO_OUTPUT": ("HIGH", "Capture system audio output"),
    "ACCESS_SUPERUSER": ("HIGH", "Requests root/superuser access"),
}


def lookup(permission: str) -> tuple[str, str] | None:
    """Return (severity, description) for a full permission name, or None."""
    suffix = permission.rsplit(".", 1)[-1]
    return PERMISSIONS.get(suffix)
