#!/usr/bin/python3


from typing import Mapping, Sequence


class Namespace(dict):
    """
	A dict subclass that exposes its items as attributes.

    Warning: Namespace instances do not have direct access to the
    dict methods.
    """

    def __init__(self, obj={}):
        super().__init__(obj)

    def __dir__(self):
        return tuple(self)

    def __repr__(self):
        return f"{type(self).__name__}({super().__repr__()})"

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(
                f"'{type(self).__name__}' object has no attribute '{name}'")

    def __setattr__(self, name, value):
        self[name] = value

    def __delattr__(self, name):
        del self[name]

    @classmethod
    def from_object(cls, obj, names=None):
        if names is None:
            names = dir(obj)
        ns = {name:getattr(obj, name) for name in names}
        return cls(ns)

    @classmethod
    def from_mapping(cls, ns, names=None):
        if names:
            ns = {name:ns[name] for name in names}
        return cls(ns)

    @classmethod
    def from_sequence(cls, seq, names=None):
        if names:
            seq = {name:val for name, val in seq if name in names}
        return cls(seq)

    def hasattr(self, name):
        try:
            self.__getattr__(name)
        except AttributeError:
            return False
        else:
            return True

    def getattr(self, name):
        return self.__getattr__(name)

    def setattr(self, name, value):
        return self.__setattr__(name, value)

    def delattr(self, name):
        return self.__delattr__(name)


def as_namespace(obj, names=None):
    if isinstance(obj, type(as_namespace)):
        obj = obj()
    if isinstance(obj, type):
        CLASS_ATTRS = [
            '__class__',
            '__delattr__',
            '__dict__',
            '__dir__',
            '__doc__',
            '__eq__',
            '__format__',
            '__ge__',
            '__getattribute__',
            '__gt__',
            '__hash__',
            '__init__',
            '__init_subclass__',
            '__le__',
            '__lt__',
            '__module__',
            '__ne__',
            '__new__',
            '__reduce__',
            '__reduce_ex__',
            '__repr__',
            '__setattr__',
            '__sizeof__',
            '__str__',
            '__subclasshook__',
            '__weakref__'
        ]
        names = (name for name in dir(obj) if name not in CLASS_ATTRS)
        return Namespace.from_object(obj, names)
    if isinstance(obj, Mapping):
        return Namespace.from_mapping(obj, names)
    if isinstance(obj, Sequence):
        return Namespace.from_sequence(obj, names)

    return Namespace.from_object(obj, names)
