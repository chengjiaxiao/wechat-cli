# Third-party notices

The Windows WCDB `Config.Cipher` object layout and XOR decoding in
`wechat_cli/keys/config_cipher.py` are adapted from
[fanyuantaier/wechatauto-replica, wechatauto/db.py](https://github.com/fanyuantaier/wechatauto-replica/blob/main/wechatauto/db.py).
That project is licensed under Apache License 2.0, the same license as this
repository. Its license is available at
[upstream LICENSE](https://github.com/fanyuantaier/wechatauto-replica/blob/main/LICENSE).

This adaptation implements only read-only process memory access and local
database verification. It does not incorporate upstream UI automation,
message sending, or process memory modification features.
