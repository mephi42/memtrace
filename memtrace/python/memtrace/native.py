from inspect import signature
import os


def wrap_err(func):
    sig = signature(func)
    func_name = func.__name__

    def wrapped(self, *args, **kwargs):
        native_obj = self.native
        native_func = getattr(native_obj, func_name)
        bound_args = sig.bind(self, *args, **kwargs)
        bound_args.apply_defaults()
        native_args = list(bound_args.arguments.values())
        assert native_args[0] is self
        err = native_func(*native_args[1:])
        if err < 0:
            native_type_name = type(native_obj).__name__
            error_str = os.strerror(-err)
            raise Exception(
                f'{native_type_name}.{func_name}() failed: {error_str}')

    return wrapped
