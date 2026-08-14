"""Reference bridge packages for robot middleware.

These are non-normative software references: they map KineGrant concepts onto
transport-shaped interfaces without claiming ROS 2 / SROS2 / Matter / OPC UA
certification or a production integration.
"""

from .ros2 import Ros2GoalGate, Sros2PolicyMapping

__all__ = ["Ros2GoalGate", "Sros2PolicyMapping"]
