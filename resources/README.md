`geoip-cn.mmdb` is the unmodified `Country-only-cn-private.mmdb` from
[Loyalsoldier/geoip](https://github.com/Loyalsoldier/geoip), distributed under
[CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) (see `geoip-LICENSE`).
It is embedded in the core for `geoip-db = builtin:cn`; other database paths
continue to use the configured file. It contains CN and PRIVATE classifications.

Source: https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country-only-cn-private.mmdb
Git blob: `99b9e382ab649c7afef44cf2059d70f131588953`
SHA-256: `81f981310fb3e44459c6bc7822b63d619af9a55c61108b201086fb792a1fb50f`
Retrieved: 2026-10-30. No changes were made to the database.

To update, replace the file from that source, verify its upstream SHA-256,
and update the blob/hash/date here. Run the offline routing tests before shipping.
