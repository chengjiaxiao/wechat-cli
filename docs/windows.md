# Windows setup and maintenance

Windows WeChat 4.1 can store database keys inside XOR-encoded WCDB
`com.Tencent.WCDB.Config.Cipher` objects. Searching process memory only for
plaintext `x'…'` strings can therefore produce zero candidates despite successful
process reads. The Windows scanner now reads those objects, decodes candidates,
and accepts each key only after a database page HMAC-SHA512 check. Plaintext key
scanning remains a fallback for earlier clients.

## Install from the maintained fork

Use Python 3.10 or newer, with a 64-bit interpreter. Keep the source checkout,
virtual environment, build output, and private state outside OneDrive.

```powershell
$wechatRoot = Join-Path $env:LOCALAPPDATA 'wechat-cli'
git clone --branch fix/windows-config-cipher https://github.com/chengjiaxiao/wechat-cli.git "$wechatRoot\source"
python -m venv "$wechatRoot\venv"
& "$wechatRoot\venv\Scripts\python.exe" -m pip install -e "$wechatRoot\source"
```

Keep Windows WeChat running and logged in, then initialize:

```powershell
& "$wechatRoot\venv\Scripts\wechat-cli.exe" init
& "$wechatRoot\venv\Scripts\wechat-cli.exe" sessions --limit 5
& "$wechatRoot\venv\Scripts\wechat-cli.exe" history 'filehelper' --limit 5
```

If directory detection fails, pass `init --db-dir '<account>\db_storage'`.
Multiple accounts need the directory for the currently logged-in account. A
cached history query alone does not prove WeChat is currently logged in. A live
scan with keys verified against that account's database does provide evidence.

`init` stores configuration and keys in `%USERPROFILE%\.wechat-cli`. Those files,
decrypted database caches, exports, and chat logs must remain local and must not
be committed. Windows scan logs omit usable key values. Process access is
read-only; this scanner does not send messages or modify WeChat memory.

## Verified on 2026-10-08

Windows WeChat **4.1.13.65**, Python **3.13.11 x64**, CLI **0.2.4**:

- Before this change: 21 databases found, zero keys extracted; query commands
  stopped because initialization had not completed.
- After this change: all 21 database keys passed HMAC checks. Native `init`
  completed without a separate extraction script, and emitted no key values.
- Sessions, contacts, history, file-message history, group members, favorites,
  unread, statistics, and export succeeded. A positive search found a known
  history message.
- Attachment checks matched the local originals against message-declared size
  and MD5. Attachment availability is separate from message-query success;
  missing originals still need downloading through WeChat.

This verifies the listed client version. Future updates can change object
offsets, the XOR mask, or database formats and require another live test.
Full signature verification and media/image decoding are separate tasks.

## Update and check

```powershell
git -C "$wechatRoot\source" pull --ff-only
& "$wechatRoot\venv\Scripts\python.exe" -m pip install -e "$wechatRoot\source"
& "$wechatRoot\venv\Scripts\python.exe" -m unittest discover -s "$wechatRoot\source\tests" -v
```

If a key cache becomes invalid, rerun `init --force` against the correct account.
Compare process read failures with candidate and verified-key counts before
assuming elevation is needed. In the verified environment, process reads worked
without administrator privileges and the failure was the old key scan method.

CI runs synthetic fixtures on Windows and Linux, Python 3.10 and 3.13. Live
client compatibility still requires the tests above after WeChat updates.
The object-layout source and license are recorded in `THIRD_PARTY_NOTICES.md`.
