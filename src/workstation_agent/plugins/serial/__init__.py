"""Serial plugin for PersonaCore-Agent (contract §5.5, §6, §6.1).

Owns the ``pyserial`` dependency (declared in the repo's ``pyproject.toml``,
BSD-3, reasoned there) for both this family's device I/O and B7's
``serial.tools.list_ports`` use in ``devices_list``.
"""
