# V2ray subscriptions generator from encrypted config files (NPVT, NM, etc)

Workflow runs, Telegram channels scanned and files get downloaded using Telethon, files get decoded using Pantegnos and v2ray configs get written into `decoded.txt` and `parsed.txt`

## Decoded files

**`decoded.txt`**:     Converted raw JSON configs + v2ray URLs

**`parsed.txt`**: only Converted raw JSON configs.

also both files get deduplicated before commit to avoid multiple same configs.

> `stats.json` contains statistics.

## Configuration

Channels and their message scan limits are configured in `update.py`. (`CHANNELS = {}` at line 64)  (required)

## Supported files

File format to download and decode is configure in `update.py`. (`SUPPORTED_EXTENSIONS = {}` at line 74)

Pantegnos does the decoding. so whatever Pantegnos supprts can be included (.npvt, .netmod, .hat, .ehi, .dark, .hat). Slipnet and Happ is also supported but these are not files, they are links. So if you need decoding for Slipnet and Happ, you need to implement them yourself.

Decoding will work as long as the config files have the same encryption pattern that Pantegnos can detect and decode.

If App devs update their encryption, decoding will most probably fail.

## Required Workflow Secrets

`TG_SESSION`

`TG_API_HASH`

`TG_API_ID`

If not exist, Telethon will fail. 

How to get those secret values? ask AI :/

## Want your own?

1. Fork repo

2. Configure `update.py`

3. Set required Secrets

4. Run workflow

5. update pantegnos binary once in a while if FrontierTM pushes updates. (optional but preferred)

> Note: You can use cron trigger to for triggering workflow automatically every x minutes. but i'm not gonna explain it here. ask AI. :/

## Credits

**FrontierTM** for their awesome **Pantegnos** decoding tool. [here](https://github.com/FrontierTM/Pantegnos)
