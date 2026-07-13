"""Simple broker discovery over an injected trustful store."""

import config


def discover(action, input_type, output_type, store=None, provider_sids=None):
    store = store or config.get_store()
    matches = []
    for provider_sid in provider_sids or []:
        index = store.resolve_metadata(provider_sid) or {}
        services = index.get("services", [])
        if isinstance(services, str):
            services = [sid.strip() for sid in services.split(",") if sid.strip()]
        for sid in services:
            meta = store.resolve_metadata(sid)
            if not meta:
                continue
            if (
                meta.get("action") == action
                and meta.get("in") == input_type
                and meta.get("out") == output_type
            ):
                matches.append(sid)
    return matches
