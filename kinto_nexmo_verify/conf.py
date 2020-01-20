from functools import partial


def get_conf(prefix, request, name):
    key = f"{prefix}.{name}"
    return request.registry.settings.get(key)


nexmo_conf = partial(get_conf, "nexmo")
