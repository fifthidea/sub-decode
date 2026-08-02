import os
import asyncio
import shutil
import time
import json
import subprocess
import tempfile
import re
import base64
from pathlib import Path
from datetime import datetime, timedelta

import pytz
import jdatetime

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

SUPPORTED_URL_SCHEMES = (
    "vmess://",
    "vless://",
    "trojan://",
    "ss://",
    "ssr://",
    "hy2://",
    "hysteria://",
    "hysteria2://",
    "tuic://",
)

URL_PATTERN = re.compile(
    r"(?:(?:vmess|vless|trojan|ss|ssr|hy2|hysteria2?|tuic)://[^\s\"'<>]+)",
    re.IGNORECASE
)

CHANNELS = {

    # public username
    # "example_channel": 500,

    # numeric ID
    -1001235816045: 100,  #t.me/ConfigsHub

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


    print(result.stdout)

    if result.stderr:
        print(result.stderr)


    if result.returncode != 0:
        raise RuntimeError(
            f"Pantegnos failed with code {result.returncode}"
        )
        
def get_output_files():

    if not OUTPUT_DIR.exists():
        return []

    return sorted(
        OUTPUT_DIR.glob("*.txt")
    )
    
def extract_v2ray_urls():

    configs = []

    for txt in get_output_files():

        try:

            text = txt.read_text(
                encoding="utf-8",
                errors="ignore"
            )

        except Exception:

            continue

        matches = URL_PATTERN.findall(text)

        configs.extend(matches)

    return configs

async def scan_channel(
    channel_ref,
    limit
):


    stats = {

        "files_found": 0,

        "files_downloaded": 0,

        "last_file_date": None,

        "active": False

    }


    downloaded = []


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



        if stats["last_file_date"]:

            age = (
                datetime.now(
                    pytz.UTC
                )
                -
                stats["last_file_date"]
            )


            if age.days <= CHANNEL_ACTIVITY_DAYS:

                stats["active"] = True



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
    run_pantegnos()
    
    decoded_files = get_output_files()

    print(f"Decoded text files: {len(decoded_files)}")

    for file in decoded_files:
        print(file.name)

    v2ray_configs = extract_v2ray_urls()

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

        stats[channel] = result["stats"]

        total += len(
            result["files"]
        )

        print(
            channel,
            result["stats"]
        )

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