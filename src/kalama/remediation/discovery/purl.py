"""PURL parsing and exact-version normalization for discovery requests."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from urllib.parse import parse_qsl, unquote, urlsplit

from packageurl import PackageURL

from .contracts import PackageIdentity


class NormalizationErrorCode(str, Enum):
    PURL_MISSING = "PURL_MISSING"
    PURL_INVALID = "PURL_INVALID"
    PURL_CREDENTIALS_NOT_ALLOWED = "PURL_CREDENTIALS_NOT_ALLOWED"
    FIXED_VERSION_INVALID = "FIXED_VERSION_INVALID"


@dataclass(frozen=True)
class NormalizationError:
    code: NormalizationErrorCode
    safe_message: str

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code.value, "safe_message": self.safe_message}


@dataclass(frozen=True)
class PurlNormalizationResult:
    original_purl: str | None
    normalized_input_purl: str | None
    fixed_version_purl: str | None
    package: PackageIdentity | None
    scanner_requested_version: str | None
    registry_normalized_version: str | None = None
    provider_resolved_version: str | None = None
    error: NormalizationError | None = None

    @property
    def ok(self) -> bool:
        return self.error is None

    def to_dict(self) -> dict[str, object]:
        return {
            "original_purl": self.original_purl,
            "normalized_input_purl": self.normalized_input_purl,
            "fixed_version_purl": self.fixed_version_purl,
            "package": self.package.to_dict() if self.package else None,
            "scanner_requested_version": self.scanner_requested_version,
            "registry_normalized_version": self.registry_normalized_version,
            "provider_resolved_version": self.provider_resolved_version,
            "error": self.error.to_dict() if self.error else None,
        }


_SENSITIVE_QUALIFIERS = {
    "authorization", "cookie", "token", "access_token", "api_key", "apikey",
    "password", "passwd", "secret", "client_secret",
}
_MAX_ADDITIONAL_URL_DECODES = 1


def _is_url_qualifier(key: str) -> bool:
    normalized = key.casefold().replace("-", "_")
    return normalized == "url" or normalized.endswith("_url")


def _has_credentials(purl: PackageURL) -> bool:
    for key, value in purl.qualifiers.items():
        if key.casefold().replace("-", "_") in _SENSITIVE_QUALIFIERS:
            return True
        candidate = value
        for depth in range(_MAX_ADDITIONAL_URL_DECODES + 1):
            try:
                parts = urlsplit(candidate)
            except ValueError:
                return _is_url_qualifier(key)
            if parts.scheme and parts.netloc:
                if parts.username is not None or parts.password is not None:
                    return True
                if any(
                        query_key.casefold().replace("-", "_")
                        in _SENSITIVE_QUALIFIERS
                        for query_key, _ in parse_qsl(
                            parts.query, keep_blank_values=True)):
                    return True
            decoded = unquote(candidate)
            if decoded == candidate:
                break
            if depth == _MAX_ADDITIONAL_URL_DECODES:
                return _is_url_qualifier(key)
            candidate = decoded
    return False


def normalize_purl(original_purl: str | None,
                   requested_fixed_version: str | None) -> PurlNormalizationResult:
    """Parse and rebuild a fixed-version PURL using packageurl-python only."""
    if not isinstance(original_purl, str) or not original_purl:
        return PurlNormalizationResult(
            None, None, None, None, requested_fixed_version,
            error=NormalizationError(
                NormalizationErrorCode.PURL_MISSING, "package PURL is missing"),
        )
    try:
        parsed = PackageURL.from_string(original_purl)
    except (TypeError, ValueError) as exc:
        return PurlNormalizationResult(
            None, None, None, None, requested_fixed_version,
            error=NormalizationError(
                NormalizationErrorCode.PURL_INVALID,
                f"package PURL is invalid: {type(exc).__name__}"),
        )
    if _has_credentials(parsed):
        return PurlNormalizationResult(
            None, None, None, None, requested_fixed_version,
            error=NormalizationError(
                NormalizationErrorCode.PURL_CREDENTIALS_NOT_ALLOWED,
                "package PURL contains credential-bearing qualifiers"),
        )
    package = PackageIdentity(
        parsed.type, parsed.namespace, parsed.name,
        tuple(sorted(parsed.qualifiers.items())), parsed.subpath,
    )
    normalized_input = parsed.to_string()
    if requested_fixed_version is None:
        return PurlNormalizationResult(
            original_purl, normalized_input, normalized_input, package, None)
    if not isinstance(requested_fixed_version, str) or not requested_fixed_version:
        return PurlNormalizationResult(
            original_purl, normalized_input, None, package, None,
            error=NormalizationError(
                NormalizationErrorCode.FIXED_VERSION_INVALID,
                "scanner requested version must be a non-empty string"),
        )
    try:
        fixed = PackageURL(
            type=parsed.type, namespace=parsed.namespace, name=parsed.name,
            version=requested_fixed_version, qualifiers=dict(parsed.qualifiers),
            subpath=parsed.subpath,
        )
        fixed_purl = fixed.to_string()
    except (TypeError, ValueError) as exc:
        return PurlNormalizationResult(
            original_purl, normalized_input, None, package, requested_fixed_version,
            error=NormalizationError(
                NormalizationErrorCode.FIXED_VERSION_INVALID,
                f"scanner requested version is invalid: {type(exc).__name__}"),
        )
    return PurlNormalizationResult(
        original_purl, normalized_input, fixed_purl, package,
        requested_fixed_version,
    )


def _debian_part(version: str) -> tuple[int, str, str]:
    epoch_text, separator, rest = version.partition(":")
    if separator:
        if not epoch_text.isdigit():
            raise ValueError("invalid Debian epoch")
        epoch = int(epoch_text)
    else:
        epoch, rest = 0, version
    if "-" in rest:
        upstream, revision = rest.rsplit("-", 1)
    else:
        upstream, revision = rest, "0"
    return epoch, upstream, revision


def _debian_char_order(character: str) -> int:
    if character == "~":
        return -1
    if character == "":
        return 0
    if character.isalpha():
        return ord(character)
    return ord(character) + 256


def _compare_debian_segment(left: str, right: str) -> int:
    left_index = right_index = 0
    while left_index < len(left) or right_index < len(right):
        while ((left_index < len(left) and not left[left_index].isdigit())
               or (right_index < len(right) and not right[right_index].isdigit())):
            left_char = left[left_index] if left_index < len(left) else ""
            right_char = right[right_index] if right_index < len(right) else ""
            difference = _debian_char_order(left_char) - _debian_char_order(right_char)
            if difference:
                return -1 if difference < 0 else 1
            if left_index < len(left):
                left_index += 1
            if right_index < len(right):
                right_index += 1
        left_start, right_start = left_index, right_index
        while left_index < len(left) and left[left_index].isdigit():
            left_index += 1
        while right_index < len(right) and right[right_index].isdigit():
            right_index += 1
        left_digits = left[left_start:left_index].lstrip("0")
        right_digits = right[right_start:right_index].lstrip("0")
        if len(left_digits) != len(right_digits):
            return -1 if len(left_digits) < len(right_digits) else 1
        if left_digits != right_digits:
            return -1 if left_digits < right_digits else 1
    return 0


def compare_debian_versions(left: str, right: str) -> int:
    """Compare Debian versions, including epoch and Debian/Ubuntu revision."""
    left_epoch, left_upstream, left_revision = _debian_part(left)
    right_epoch, right_upstream, right_revision = _debian_part(right)
    if left_epoch != right_epoch:
        return -1 if left_epoch < right_epoch else 1
    upstream = _compare_debian_segment(left_upstream, right_upstream)
    return upstream or _compare_debian_segment(left_revision, right_revision)


def versions_equal(package_type: str | None, left: str, right: str) -> bool:
    """Apply only ecosystem-specific equality; never strip prefixes globally."""
    normalized = (package_type or "").casefold()
    if normalized in {"deb", "debian", "ubuntu"}:
        try:
            return compare_debian_versions(left, right) == 0
        except ValueError:
            return False
    # Alpine revisions, Go's v prefix, Composer aliases, and all unknown types
    # remain opaque exact strings until their provider supplies normalization.
    return left == right
