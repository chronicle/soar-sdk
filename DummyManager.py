import logging

class DmManager(object):

    def __init__(self):
        self._log = logging.getLogger("siemplify_default_logger")

    def foo(self):
        self._log.warn("Foo Foo Foo")
        print "Foo Foo Foo"