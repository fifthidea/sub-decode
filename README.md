# V2ray subscriptions generator from encrypted config files

Workflow runs, channels scanned and files get downloaded, files get decoded and get written into `decoded.txt` and `parsed.txt`

## Decoded files

**`decoded.txt`**: Converted raw v2ray configs + v2ray urls

**`parsed.txt`**: only Converted JSON raw v2ray configs.

> `stats.json` contains

## Configuration

Channels and their message scan limits are configured in `update.py`

## Supported files

File format to download and decode is configure in `update.py`

Pantegnos does the decoding. so whatever Pantegnos supprts can be included.

Decoding will work as long as the decoded configs have the same encryption pattern that Pantegnos can detect.

if App devs update their encryption, decoding will most probably fail.

## Credits

**FrontierTM** for **Pantegnos** decoding tool.
