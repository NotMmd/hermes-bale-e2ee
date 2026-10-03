"""
Bale platform plugin entry point for Hermes Agent.
"""

from .adapter import (
    BaleAdapter,
    check_requirements,
    validate_config,
    is_connected,
    _env_enablement,
    _standalone_send,
    interactive_setup,
    MAX_MESSAGE_LENGTH,
)


def register(ctx):
    """Plugin entry point: registers Bale as a messaging platform."""
    ctx.register_platform(
        name="bale",
        label="Bale",
        adapter_factory=lambda cfg: BaleAdapter(cfg),
        check_fn=check_requirements,
        validate_config=validate_config,
        is_connected=is_connected,
        required_env=["BALE_BOT_TOKEN"],
        install_hint="pip install aiohttp cryptography",
        setup_fn=interactive_setup,
        env_enablement_fn=_env_enablement,
        cron_deliver_env_var="BALE_HOME_CHANNEL",
        standalone_sender_fn=_standalone_send,
        allowed_users_env="BALE_ALLOWED_USERS",
        allow_all_env="BALE_ALLOW_ALL_USERS",
        max_message_length=MAX_MESSAGE_LENGTH,
        emoji="🟦",
        pii_safe=True,
        allow_update_command=True,
        platform_hint=(
            "You are communicating via Bale (بله), an Iranian messenger. "
            "All messages and media between you and the user are end-to-end encrypted (E2EE) "
            "with AES-256-GCM. Markdown formatting is supported by the E2EE client after decryption. Keep responses helpful and natural in Persian."
        ),
    )
