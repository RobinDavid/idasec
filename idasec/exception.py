class IDARequired(Exception):
    pass


def assert_ida_available():
    try:
        import idc
    except ImportError:
        raise IDARequired()