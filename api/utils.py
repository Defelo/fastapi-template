def get_example(arg: type) -> dict:
    # noinspection PyUnresolvedReferences
    return arg.Config.schema_extra["example"]


def example(*args, **kwargs) -> type:
    ex = dict(e for arg in args for e in get_example(arg).items())
    return type("Config", (), {"schema_extra": {"example": ex | kwargs}})
