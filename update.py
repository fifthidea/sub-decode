import os
import asyncio
import shutil
import time
import json
import subprocess
import re
import jdatetime
from pathlib import Path
from urllib.parse import urlencode, quote
from datetime import datetime, timedelta

import pytz

from telethon import TelegramClient
from telethon.sessions import StringSession
from telethon.errors import (
    ChannelPrivateError,
    ChannelInvalidError,
    UsernameInvalidError,
    UsernameNotOccupiedError,
    FloodWaitError,
)


API_ID = int(os.environ["TG_API_ID"])
API_HASH = os.environ["TG_API_HASH"]
SESSION = os.environ["TG_SESSION"]


client = TelegramClient(
    StringSession(SESSION),
    API_ID,
    API_HASH
)


# ==========================
# CONFIG
# ==========================

#SUPPORTED_URL_SCHEMES = (
#    "vmess://",
#    "vless://",
#    "trojan://",
#    "ss://",
#    "ssr://",
#    "hy2://",
#    "hysteria://",
#    "hysteria2://",
#    "tuic://",
#)

URL_PATTERN = re.compile(
    r"(?:(?:vmess|vless|trojan|ss|ssr|hy2|hysteria2?|tuic)://[^\s\"'<>]+)",
    re.IGNORECASE
)

JSON_START_PATTERN = re.compile(
    r"[\{\[]"
)

CHANNELS = {

    # public username
    # "example_channel": 500,

    # numeric ID
    -1001235816045: 300,    # t.me/ConfigsHub
    -1003613216743: 300,    # t.me/iranconnecting
}

SUPPORTED_EXTENSIONS = {
    ".npvt",
    ".nm"
}

CONFIG_DIR = Path("configs")
OUTPUT_DIR = Path("output")

CHANNEL_ACTIVITY_DAYS = 3
CHANNEL_WORKERS = 5

PANTEGNOS_WINDOWS = "pantegnos.exe"
PANTEGNOS_LINUX = "./pantegnos"

# ==========================

def sanitize_filename(name):

    if not name:
        return "unknown"


    bad = [
        "/",
        "\\",
        ":",
        "*",
        "?",
        "\"",
        "<",
        ">",
        "|"
    ]


    for char in bad:
        name = name.replace(char, "_")


    return name
    
def format_jalali_tehran(dt):

    tehran = pytz.timezone(
        "Asia/Tehran"
    )

    dt_tehran = dt.astimezone(
        tehran
    )

    jalali = jdatetime.datetime.fromgregorian(
        datetime=dt_tehran
    )

    return (
        f"{jalali.year:04d}-"
        f"{jalali.month:02d}-"
        f"{jalali.day:02d} "
        f"{dt_tehran.strftime('%H:%M:%S')}"
    )
    
def get_extension(message):

    try:

        if not message.file:
            return None


        if not message.file.name:
            return None


        return Path(
            message.file.name
        ).suffix.lower()


    except Exception:

        return None
        
def clean_temp_dirs():

    for folder in [CONFIG_DIR, OUTPUT_DIR]:

        if folder.exists():
            shutil.rmtree(folder)

        folder.mkdir(parents=True, exist_ok=True)
        
def get_value(data, *keys, default=None):

    for key in keys:

        value = data.get(key)

        if value is not None and value != "":
            return value

    return default


def normalize_security(value):

    if not value:
        return None

    value = str(value).lower()


    if "reality" in value:
        return "reality"


    if "tls" in value:
        return "tls"


    if "xtls" in value:
        return "xtls"


    if value in (
        "none",
        "false",
        "0"
    ):
        return "none"

    return value

def normalize_network(value):

    if not value:
        return None

    value = str(value).lower()

    mapping = {
        "ws": "ws",
        "websocket": "ws",
        "grpc": "grpc",
        "tcp": "tcp",
        "http": "http"
    }

    return mapping.get(
        value,
        value
    )


def build_query(profile):

    query = {}

    query["encryption"] = "none"


    network = normalize_network(
        get_value(
            profile,
            "network",
            "net",
            "type"
        )
    )

    if network:
        query["type"] = network


    security = normalize_security(
        get_value(
            profile,
            "security",
            "tls"
        )
    )

    if security:
        query["security"] = security


    field_aliases = {

        "host": [
            "host",
            "hostName"
        ],

        "path": [
            "path",
            "wsPath"
        ],

        "sni": [
            "sni",
            "serverName"
        ],

        "fp": [
            "fp",
            "fingerprint",
            "clientFingerprint"
        ],

        "alpn": [
            "alpn"
        ],

        "flow": [
            "flow"
        ],

        "serviceName": [
            "serviceName",
            "grpcServiceName"
        ],

        "authority": [
            "authority"
        ],

        "headerType": [
            "headerType"
        ],

        "pbk": [
            "pbk",
            "publicKey",
            "realityPublicKey"
        ],

        "sid": [
            "sid",
            "shortId",
            "shortID"
        ],

        "spx": [
            "spx",
            "spiderX",
            "spider"
        ]

    }


    for output_name, aliases in field_aliases.items():

        value = get_value(
            profile,
            *aliases
        )

        if value:

            query[output_name] = value


    if "insecure" in profile:

        query["allowInsecure"] = (
            "1"
            if profile["insecure"]
            else "0"
        )


    return query

def detect_protocol(profile):

    value = get_value(
        profile,
        "protocol",
        "type",
        "app",
        "name"
    )


    if value:

        value = str(value).lower()

        if "vless" in value:
            return "vless"

        if "trojan" in value:
            return "trojan"

        if "vmess" in value:
            return "vmess"

        if value in ("ss", "shadowsocks"):
            return "ss"

        if "tuic" in value:
            return "tuic"

        if "hysteria" in value or value.startswith("hy"):
            return "hysteria2"

    # fallback detection

    if get_value(
        profile,
        "uuid",
        "id"
    ) and get_value(
        profile,
        "security",
        "reality",
        "realityPublicKey"
    ):
        return "vless"


    if get_value(
        profile,
        "password"
    ) and not get_value(
        profile,
        "uuid"
    ):
        return "trojan"


    return "vless"

def profile_to_vless(profile):

    server = get_value(
        profile,
        "server",
        "address",
        "host"
    )

    port = get_value(
        profile,
        "serverPort",
        "port"
    )

    uuid = get_value(
        profile,
        "password",
        "uuid",
        "id"
    )


    if not server or not port or not uuid:
        return None


    query = build_query(profile)


    remark = get_value(
        profile,
        "remarks",
        "name",
        "ps",
        default=""
    )


    return (
        f"vless://{uuid}@{server}:{port}"
        f"?{urlencode(query)}"
        f"#{quote(str(remark))}"
    )
        
def extract_json_objects(text):

    objects = []

    decoder = json.JSONDecoder()

    tried = set()


    def try_parse(value):

        value = value.strip()

        if not value:
            return

        if value in tried:
            return

        tried.add(value)

        try:
            objects.append(
                json.loads(value)
            )

        except Exception:
            pass


    raw = text.lstrip("\ufeff")


    try_parse(raw)


    first = re.search(
        r"[\{\[]",
        raw
    )


    if first:
        try_parse(
            raw[first.start():]
        )


    start = -1
    depth = 0
    in_string = False
    escape = False


    for i, ch in enumerate(raw):

        if in_string:

            if escape:
                escape = False

            elif ch == "\\":
                escape = True

            elif ch == '"':
                in_string = False

            continue


        if ch == '"':
            in_string = True

        elif ch in "[{":

            if depth == 0:
                start = i

            depth += 1


        elif ch in "]}":

            if depth > 0:

                depth -= 1

                if depth == 0 and start >= 0:

                    try_parse(
                        raw[start:i+1]
                    )

                    start = -1


    return objects
    
def extract_json_profiles(text):

    configs = []

    print(
        "Testing JSON extraction. Length:",
        len(text)
    )

    json_objects = extract_json_objects(text)
    
    print(
        "JSON objects found:",
        len(json_objects)
    )

    for data in json_objects:

        print("DEBUG JSON TYPE:", type(data))

        if isinstance(data, dict):
            print("DEBUG KEYS:", list(data.keys())[:20])


        if isinstance(data, list):

            items = data


        elif isinstance(data, dict):

            items = [data]


        else:

            continue


        for item in items:


            if not isinstance(item, dict):
                continue


            if item.get("type") != "V2RAY":

                print(
                    "DEBUG SKIPPED TYPE:",
                    item.get("type")
                )

                continue


            profile = item.get(
                "v2rayProfile"
            )


            if not isinstance(profile, dict):
                continue
                
            if profile.get("configType") != 5:

                print(
                    "Skipping configType:",
                    profile.get("configType")
                )

                continue

            protocol = detect_protocol(profile)


            if protocol == "vless":

                config = profile_to_vless(profile)

            else:
                
                print(
                    "Unsupported protocol:",
                    protocol
                )

                config = None


            if config:

                configs.append(config)


    return configs
        
def run_pantegnos():

    if os.name == "nt":
        command = [
            PANTEGNOS_WINDOWS,
            "-input",
            str(CONFIG_DIR),
            "-output",
            str(OUTPUT_DIR)
        ]

    else:
        command = [
            PANTEGNOS_LINUX,
            "-input",
            str(CONFIG_DIR),
            "-output",
            str(OUTPUT_DIR)
        ]


    print("Running Pantegnos...")

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )


    if result.returncode != 0:
        print(result.stdout)

        if result.stderr:
            print(result.stderr)

        raise RuntimeError(
            f"Pantegnos failed ({result.returncode})"
        )

    print("Pantegnos finished successfully.")
        
def get_output_files():

    if not OUTPUT_DIR.exists():
        return []

    return sorted(
        OUTPUT_DIR.glob("*.txt")
    )
    
def extract_v2ray_urls(active_channels):

    configs = []

    channel_counts = {}

    for txt in get_output_files():
        
        channel_id = txt.name.split("_", 1)[0]
        
        if channel_id not in active_channels:
            continue

        stats = channel_counts.setdefault(
            channel_id,
            {
                "url_configs": 0,
                "json_configs": 0
            }
        )

        try:

            text = txt.read_text(
                encoding="utf-8",
                errors="ignore"
            )

        except Exception:

            continue

        urls = URL_PATTERN.findall(text)

        json_configs = extract_json_profiles(text)
        
        if "{" in text or "[" in text:
            print("JSON-like content detected in:", txt.name)

        stats["url_configs"] += len(urls)
        stats["json_configs"] += len(json_configs)

        configs.extend(urls)

        configs.extend(json_configs)

    return configs, channel_counts

def deduplicate_configs(configs):

    seen = set()
    unique = []

    for config in configs:

        if config not in seen:

            seen.add(config)
            unique.append(config)

    return unique

async def scan_channel(
    channel_ref,
    limit
):


    stats = {

        "files_found": 0,

        "files_downloaded": 0,

        "url_configs": 0,

        "json_configs": 0,

        "configs_found": 0,

        "last_file_date": None,

        "active": False

    }


    downloaded = []
    file_messages = []


    try:

        entity = await client.get_entity(
            channel_ref
        )


        async for msg in client.iter_messages(
            entity,
            limit=limit
        ):


            extension = get_extension(msg)


            if extension not in SUPPORTED_EXTENSIONS:

                continue

            stats["files_found"] += 1


            if stats["last_file_date"] is None:

                stats["last_file_date"] = (
                    msg.date
                )

            file_messages.append(msg)

        if not stats["last_file_date"]:

            print(
                f"No config files found in {channel_ref}"
            )

            return {
                "channel": str(channel_ref),
                "files": [],
                "stats": stats
            }

        age = (
            datetime.now(
                pytz.UTC
            )
            -
            stats["last_file_date"]
        )


        if age <= timedelta(days=CHANNEL_ACTIVITY_DAYS):

            stats["active"] = True
                
        if not stats["active"]:

            print(
                f"Skipping inactive channel {channel_ref}"
            )

            return {
                "channel": str(channel_ref),
                "files": [],
                "stats": stats
            }
            
        for msg in file_messages:

            filename = sanitize_filename(
                msg.file.name
            )

            save_path = (
                CONFIG_DIR /
                f"{entity.id}_{msg.id}_{filename}"
            )

            await msg.download_media(
                file=str(save_path)
            )

            downloaded.append(
                str(save_path)
            )

            stats["files_downloaded"] += 1

        return {

            "channel": str(channel_ref),

            "files": downloaded,

            "stats": stats

        }



    except (
        ChannelPrivateError,
        ChannelInvalidError,
        UsernameInvalidError,
        UsernameNotOccupiedError,
        FloodWaitError

    ) as e:


        print(
            f"Skipping {channel_ref}: {e}"
        )


        return None



    except Exception as e:
        print(
            f"Error {channel_ref}: {e}"
        )
        return None
        
async def collect_files():
    sem = asyncio.Semaphore(
        CHANNEL_WORKERS
    )

    async def worker(
        channel,
        limit
    ):

        async with sem:
            return await scan_channel(
                channel,
                limit
            )

    tasks = []

    for channel, limit in CHANNELS.items():
        tasks.append(
            worker(
                channel,
                limit
            )
        )

    results = await asyncio.gather(
        *tasks
    )

    return [
        r for r in results
        if r
    ]

async def main():
    start = time.time()

    # clean old files
    clean_temp_dirs()
    results = await collect_files()

    if any(
        result["files"]
        for result in results
    ):
        run_pantegnos()
    else:
        print("No files to decode")
    
    active_channels = set()

    for result in results:

        if result["stats"]["active"]:

            channel_id = (
                str(result["channel"])
                .replace("-100", "")
            )

            active_channels.add(channel_id)
    
    decoded_files = get_output_files()

    print(f"Decoded text files: {len(decoded_files)}")

    for file in decoded_files:
        print(file.name)

    v2ray_configs, channel_counts = extract_v2ray_urls(
        active_channels
    )

    raw_count = len(v2ray_configs)

    v2ray_configs = deduplicate_configs(
        v2ray_configs
    )

    duplicates_removed = (
        raw_count - len(v2ray_configs)
    )

    after_dedup = len(v2ray_configs)

    print(
        "Removed duplicates:",
        raw_count - after_dedup
    )

    with open(
        "decoded.txt",
        "w",
        encoding="utf-8"
    ) as f:

        f.write(
            "\n".join(v2ray_configs)
        )

    print(
        "Extracted V2Ray URLs:",
        len(v2ray_configs)
    )

    for config in v2ray_configs[:10]:
        print(config)

    stats = {}
    total = 0
    
    for result in results:
    
        channel = result["channel"]
    
        prefix = str(channel).replace("-100", "")

        counts = channel_counts.get(
            prefix,
            {
                "url_configs": 0,
                "json_configs": 0
            }
        )

        result["stats"]["url_configs"] = counts["url_configs"]
        result["stats"]["json_configs"] = counts["json_configs"]
        result["stats"]["configs_found"] = (
            counts["url_configs"] +
            counts["json_configs"]
        )
    
        if result["stats"]["last_file_date"]:

            result["stats"]["last_file_date"] = (
                format_jalali_tehran(
                    result["stats"]["last_file_date"]
                )
            )

        stats[channel] = result["stats"]
    
        total += len(result["files"])
    
        print(
            channel,
            result["stats"]
        )
    
    total_urls = sum(
        x["url_configs"]
        for x in channel_counts.values()
    )

    total_json = sum(
        x["json_configs"]
        for x in channel_counts.values()
    )
    
    stats = {
        "summary": {
            "channels": len(results),
            "files_downloaded": total,
            "url_configs": total_urls,
            "json_configs": total_json,
            "raw_configs_found": raw_count,
            "duplicates_removed": duplicates_removed,
            "configs_found": len(v2ray_configs),
            "runtime_seconds": round(
                time.time() - start,
                2
            )
        },
        **stats
    }

    print(
        "Downloaded files:",
        total
    )

    with open(
        "stats.json",
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            stats,
            f,
            indent=4,
            default=str
        )

    print(
        "Runtime:",
        time.time()-start
    )

with client:

    client.loop.run_until_complete(main())