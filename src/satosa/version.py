try:
    from importlib.metadata import version as _resolve_package_version
except ImportError:
    from importlib_metadata import version as _resolve_package_version  # type: ignore[no-redef]


def _parse_version():
    value = _resolve_package_version("satosa")
    return value


version = _parse_version()
