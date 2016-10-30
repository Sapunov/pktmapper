#!/usr/bin/env python

import sys

di = {}

for i in sys.stdin.readlines():
    spl = i.split(",")
    app = spl[-1].strip()

    if app not in di:
        di[app] = 1
    else:
        di[app] += 1

d = sorted([(value, key) for key, value in di.items()], reverse=True)
del di

for p, i in d:
    print i.ljust(20), p
