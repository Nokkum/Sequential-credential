import requests
import logging
from typing import Tuple

logger = logging.getLogger('sequential.validators')

try:
    from rust_core import (
        validate_discord_token as rust_validate_discord,
        validate_github_token as rust_validate_github,
        validate_openai_token as rust_validate_openai,
        validate_slack_token as rust_validate_slack,
        validate_stripe_token as rust_validate_stripe,
    )
    RUST_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Rust validators not available, using Python fallback: {e}")
    RUST_AVAILABLE = False


def validate_discord_token(token: str, timeout: int = 5) -> Tuple[bool, str]:
    """Validate a Discord bot token by attempting a gateway bot connection or using the /users/@me endpoint.

    Note: Discord may rate-limit; this function does a minimal check.
    Returns (is_valid, message)
    """
    if RUST_AVAILABLE:
        try:
            return rust_validate_discord(token, timeout)
        except Exception as e:
            logger.warning(f"Rust validate_discord_token failed, using Python fallback: {e}")
    headers = {
        'Authorization': f'Bot {token}'
    }
    try:
        r = requests.get('https://discord.com/api/v10/users/@me', headers=headers, timeout=timeout)
        if r.status_code == 200:
            return True, 'Valid token'
        elif r.status_code == 401:
            return False, 'Unauthorized (invalid token)'
        else:
            return False, f'Unexpected status: {r.status_code}'
    except requests.RequestException as e:
        return False, f'Network error: {e}'


def validate_github_token(token: str, timeout: int = 5) -> Tuple[bool, str]:
    if RUST_AVAILABLE:
        try:
            return rust_validate_github(token, timeout)
        except Exception as e:
            logger.warning(f"Rust validate_github_token failed, using Python fallback: {e}")
    headers = {'Authorization': f'token {token}', 'User-Agent': 'Sequential-Credential-Manager'}
    try:
        r = requests.get('https://api.github.com/user', headers=headers, timeout=timeout)
        if r.status_code == 200:
            return True, 'Valid token'
        elif r.status_code == 401:
            return False, 'Unauthorized (invalid token)'
        else:
            return False, f'Unexpected status: {r.status_code}'
    except requests.RequestException as e:
        return False, f'Network error: {e}'


def validate_openai_token(token: str, timeout: int = 5) -> Tuple[bool, str]:
    """Validate an OpenAI API key."""
    if RUST_AVAILABLE:
        try:
            return rust_validate_openai(token, timeout)
        except Exception as e:
            logger.warning(f"Rust validate_openai_token failed, using Python fallback: {e}")
    headers = {'Authorization': f'Bearer {token}'}
    try:
        r = requests.get('https://api.openai.com/v1/models', headers=headers, timeout=timeout)
        if r.status_code == 200:
            return True, 'Valid token'
        elif r.status_code == 401:
            return False, 'Unauthorized (invalid token)'
        else:
            return False, f'Unexpected status: {r.status_code}'
    except requests.RequestException as e:
        return False, f'Network error: {e}'


def validate_slack_token(token: str, timeout: int = 5) -> Tuple[bool, str]:
    """Validate a Slack API token."""
    if RUST_AVAILABLE:
        try:
            return rust_validate_slack(token, timeout)
        except Exception as e:
            logger.warning(f"Rust validate_slack_token failed, using Python fallback: {e}")
    headers = {'Authorization': f'Bearer {token}'}
    try:
        r = requests.get('https://slack.com/api/auth.test', headers=headers, timeout=timeout)
        if r.status_code == 200:
            data = r.json()
            if data.get('ok'):
                return True, 'Valid token'
            return False, data.get('error', 'Invalid token')
        else:
            return False, f'Unexpected status: {r.status_code}'
    except requests.RequestException as e:
        return False, f'Network error: {e}'


def validate_stripe_token(token: str, timeout: int = 5) -> Tuple[bool, str]:
    """Validate a Stripe API key."""
    if RUST_AVAILABLE:
        try:
            return rust_validate_stripe(token, timeout)
        except Exception as e:
            logger.warning(f"Rust validate_stripe_token failed, using Python fallback: {e}")
    try:
        r = requests.get('https://api.stripe.com/v1/balance', 
                         auth=(token, ''), timeout=timeout)
        if r.status_code == 200:
            return True, 'Valid token'
        elif r.status_code == 401:
            return False, 'Unauthorized (invalid token)'
        else:
            return False, f'Unexpected status: {r.status_code}'
    except requests.RequestException as e:
        return False, f'Network error: {e}'
