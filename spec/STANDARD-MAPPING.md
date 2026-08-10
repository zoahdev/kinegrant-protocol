# Standards integration map

KineGrant treats existing standards as authorities within their domains instead of
forking them.

| Source | Reused concept | KineGrant boundary | Deliberately not claimed |
| --- | --- | --- | --- |
| W3C ODRL 2.2 | Permission, prohibition, duty, party, asset, constraint | Converts a conservative profile into `PolicyRule` objects | Full ODRL semantics or profile certification |
| IEEE 7012-2025 | Individual-proffered machine-readable privacy terms | Experimental privacy-term bridge for `observe`, `record`, `retain`, and `train_on_data` | Legal agreement or IEEE conformance |
| W3C WoT TD | Thing identity and action affordances | Discovers targets/actions and forms `ActionRequest` | Replacing WoT security or bindings |
| ROS 2/SROS2 | Robot identity, namespaces, actions, middleware ACLs | Maps a ROS action to a physical request; gate belongs before actuator execution | Replacing DDS Security |
| OPC UA | Server/node identity, methods, role permissions | Maps method calls to physical targets; OPC UA remains local authorization | Full information-model translation |
| Matter | Fabric/node/endpoint/cluster/command identity | Maps commands into physical requests; Matter ACL remains device access control | Matter certification or cluster implementation |
| Public/consortium ledger | Timestamped policy/revocation/receipt hashes | Optional asynchronous anchoring | Real-time consensus in the actuator path |

## Integration rule

External authorization and KineGrant authorization are cumulative. KineGrant cannot widen
permissions granted by SROS2, OPC UA, Matter, or a device's native safety system.
The final physical action occurs only when every required layer allows it.

```text
native platform allow
AND KineGrant capability valid
AND local safety controller allow
= actuator may execute
```

Any layer can veto. No layer can force another layer to permit.

## Primary references

- W3C ODRL 2.2: <https://www.w3.org/TR/odrl-model/>
- W3C Web of Things Thing Description 1.1: <https://www.w3.org/TR/wot-thing-description11/>
- IEEE 7012-2025 overview: <https://standards.ieee.org/ieee/7012/7192/>
- ROS 2 access controls: <https://docs.ros.org/en/humble/Tutorials/Advanced/Security/Access-Controls.html>
- OPC UA role-based security: <https://reference.opcfoundation.org/specs/OPC-10000-18/4/>
- Matter specifications: <https://csa-iot.org/developer-resource/specifications-download-request/>
