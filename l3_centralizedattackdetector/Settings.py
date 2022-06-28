import os

def get_setting(name, **kwargs):
    value = os.environ.get(name)
    if 'settings' in kwargs:
        value = kwargs['settings'].pop(name, value)
    if value is not None: return value
    if 'default' in kwargs: return kwargs['default']
    raise Exception('Setting({}) not specified in environment or configuration'.format(name))
