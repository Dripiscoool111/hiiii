import os
import aiohttp
import discord
from discord import app_commands
from dotenv import load_dotenv

load_dotenv()

DISCORD_TOKEN = os.getenv("DISCORD_TOKEN")
API_URL       = os.getenv("API_URL", "http://localhost:5000")
API_MASTER    = os.getenv("API_MASTER_KEY", "William@2013")

intents = discord.Intents.default()
client  = discord.Client(intents=intents)
tree    = app_commands.CommandTree(client)

HEADERS     = {"Authorization": f"Bearer {API_MASTER}", "Content-Type": "application/json"}
ALLOWED_IDS = [1054348699293196308]


def is_allowed(interaction: discord.Interaction) -> bool:
    return interaction.user.id in ALLOWED_IDS


async def api_post(endpoint: str, body: dict) -> dict:
    async with aiohttp.ClientSession() as s:
        async with s.post(f"{API_URL}{endpoint}", json=body, headers=HEADERS) as r:
            return await r.json()


async def api_get(endpoint: str, params: dict = {}) -> dict:
    async with aiohttp.ClientSession() as s:
        async with s.get(f"{API_URL}{endpoint}", params=params, headers=HEADERS) as r:
            return await r.json()


async def api_delete(endpoint: str, body: dict) -> dict:
    async with aiohttp.ClientSession() as s:
        async with s.delete(f"{API_URL}{endpoint}", json=body, headers=HEADERS) as r:
            return await r.json()


def ok(title: str, desc: str) -> discord.Embed:
    return discord.Embed(title=f"✅ {title}", description=desc, color=0x57F287)

def err(desc: str) -> discord.Embed:
    return discord.Embed(title="❌ Error", description=desc, color=0xED4245)

def info(title: str, desc: str) -> discord.Embed:
    return discord.Embed(title=f"ℹ️ {title}", description=desc, color=0x5865F2)


@tree.command(name="genkey", description="Generate a new key.")
@app_commands.describe(
    days="Expiry in days (leave blank for never)",
    max_uses="Max number of uses before the key expires (leave blank for unlimited)",
    note="Optional note for this key"
)
async def genkey(interaction: discord.Interaction, days: int = None, max_uses: int = None, note: str = ""):
    await interaction.response.defer(ephemeral=True)
    if not is_allowed(interaction):
        return await interaction.followup.send(embed=err("You are not allowed to use this command."), ephemeral=True)

    body = {"note": note}
    if days:
        body["expires_in_days"] = days
    if max_uses:
        body["max_uses"] = max_uses

    data = await api_post("/keys/generate", body)
    if not data.get("success"):
        return await interaction.followup.send(embed=err(data.get("message", "API error.")), ephemeral=True)

    exp  = f"<t:{int(__import__('datetime').datetime.fromisoformat(data['expires_at']).timestamp())}:R>" if data.get("expires_at") else "Never"
    uses = str(max_uses) if max_uses else "Unlimited"

    embed = ok("Key Generated", f"```\n{data['key']}\n```")
    embed.add_field(name="Expires",  value=exp,        inline=True)
    embed.add_field(name="Max Uses", value=uses,       inline=True)
    embed.add_field(name="Note",     value=note or "—", inline=True)
    await interaction.followup.send(embed=embed, ephemeral=True)


@tree.command(name="keyinfo", description="Look up info on a key.")
@app_commands.describe(key="The key to look up")
async def keyinfo(interaction: discord.Interaction, key: str):
    await interaction.response.defer(ephemeral=True)
    if not is_allowed(interaction):
        return await interaction.followup.send(embed=err("You are not allowed to use this command."), ephemeral=True)

    data = await api_get("/keys/info", {"key": key})
    if not data.get("success"):
        return await interaction.followup.send(embed=err(data.get("message")), ephemeral=True)

    d      = data
    exp    = f"<t:{int(__import__('datetime').datetime.fromisoformat(d['expires_at']).timestamp())}:R>" if d.get("expires_at") else "Never"
    status = "🔴 Revoked" if d["revoked"] else "🟢 Active"
    uses   = f"{d['use_count']} / {d['max_uses']}" if d.get("max_uses") is not None else f"{d['use_count']} / Unlimited"

    embed = info("Key Info", f"```\n{d['key']}\n```")
    embed.add_field(name="Status",  value=status,               inline=True)
    embed.add_field(name="Expires", value=exp,                  inline=True)
    embed.add_field(name="Uses",    value=uses,                 inline=True)
    embed.add_field(name="HWID",    value=d["hwid"] or "None",  inline=True)
    embed.add_field(name="Note",    value=d["note"] or "—",     inline=True)
    embed.add_field(name="Created", value=d["created_at"][:10], inline=True)
    await interaction.followup.send(embed=embed, ephemeral=True)


@tree.command(name="revokekey", description="Revoke a key so it can no longer be used.")
@app_commands.describe(key="The key to revoke")
async def revokekey(interaction: discord.Interaction, key: str):
    await interaction.response.defer(ephemeral=True)
    if not is_allowed(interaction):
        return await interaction.followup.send(embed=err("You are not allowed to use this command."), ephemeral=True)

    data = await api_post("/keys/revoke", {"key": key})
    if not data.get("success"):
        return await interaction.followup.send(embed=err(data.get("message")), ephemeral=True)
    await interaction.followup.send(embed=ok("Key Revoked", f"`{key.upper()}` has been revoked."), ephemeral=True)


@tree.command(name="deletekey", description="Permanently delete a key from the database.")
@app_commands.describe(key="The key to delete")
async def deletekey(interaction: discord.Interaction, key: str):
    await interaction.response.defer(ephemeral=True)
    if not is_allowed(interaction):
        return await interaction.followup.send(embed=err("You are not allowed to use this command."), ephemeral=True)

    data = await api_delete("/keys/delete", {"key": key})
    if not data.get("success"):
        return await interaction.followup.send(embed=err(data.get("message")), ephemeral=True)
    await interaction.followup.send(embed=ok("Key Deleted", f"`{key.upper()}` has been permanently deleted."), ephemeral=True)


@tree.command(name="resethwid", description="Reset the HWID lock on a key.")
@app_commands.describe(key="The key to reset HWID for")
async def resethwid(interaction: discord.Interaction, key: str):
    await interaction.response.defer(ephemeral=True)
    if not is_allowed(interaction):
        return await interaction.followup.send(embed=err("You are not allowed to use this command."), ephemeral=True)

    data = await api_post("/keys/reset-hwid", {"key": key})
    if not data.get("success"):
        return await interaction.followup.send(embed=err(data.get("message")), ephemeral=True)
    await interaction.followup.send(embed=ok("HWID Reset", f"HWID for `{key.upper()}` has been cleared."), ephemeral=True)


@tree.command(name="listkeys", description="List all keys in the database.")
async def listkeys(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    if not is_allowed(interaction):
        return await interaction.followup.send(embed=err("You are not allowed to use this command."), ephemeral=True)

    data = await api_get("/keys/list")
    if not data.get("success"):
        return await interaction.followup.send(embed=err(data.get("message")), ephemeral=True)

    keys = data["keys"]
    if not keys:
        return await interaction.followup.send(embed=info("All Keys", "No keys found."), ephemeral=True)

    pages, chunk = [], []
    for k in keys:
        exp    = k["expires_at"][:10] if k.get("expires_at") else "Never"
        status = "🔴" if k["revoked"] else "🟢"
        uses   = f"{k['use_count']}/{k['max_uses']}" if k.get("max_uses") is not None else f"{k['use_count']}/∞"
        chunk.append(f"{status} `{k['key']}` · Uses: {uses} · Exp: {exp} · Note: {k['note'] or '—'}")
        if len(chunk) == 10:
            pages.append(chunk)
            chunk = []
    if chunk:
        pages.append(chunk)

    for i, page in enumerate(pages):
        embed = info(f"All Keys (Page {i+1}/{len(pages)})", "\n".join(page))
        await interaction.followup.send(embed=embed, ephemeral=True)


@client.event
async def on_ready():
    await tree.sync()
    print(f"✅ {client.user} online | Commands synced")


client.run(DISCORD_TOKEN)
