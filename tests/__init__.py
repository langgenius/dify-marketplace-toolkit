"""Offline regression tests for :mod:`toolkit`.

Run with ``python3 -m unittest discover -t . -s tests``.

Every test here pins down a rule chosen from measurement over the whole plugin
corpus, and each one fails loudly if that rule regresses into wrong Marketplace
data. Nothing here touches the network.
"""
