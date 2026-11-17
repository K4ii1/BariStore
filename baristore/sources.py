#!/usr/bin/env python3
# =============================================================================
#  BariStore — AltSource Manager, Multi-Source Aggregator & Downloader (MIT)
# =============================================================================

import concurrent.futures
import hashlib
import http.client
import json
import os
import re
import time
import urllib.parse

from . import apple, storage

RELEASES_URL = "https://api.github.com/repos/%s/releases?per_page=30"
USER_AGENT = "BariStore/1.0 (+https://github.com/barismd/BariStore)"
CHUNK = 262144
BAD_TAG = re.compile(r"(alpha|beta|rc)", re.IGNORECASE)


class DownloadError(Exception):
    pass


# Fallback catalogue: the Featured tab must never come up empty, even if
# sources.json did not survive an install. Keep this in sync with sources.json.
BUILTIN_CONFIG = {
    "store_variants": [
        {
            "id": "sidestore-stable",
            "name": "SideStore",
            "subtitle": "Stable Release · Untethered App Store",
            "channel": "stable",
            "repo": "SideStore/SideStore",
            "asset_pattern": "SideStore.ipa",
            "bundle_id": "com.SideStore.SideStore",
            "icon_url": "https://apps.sidestore.io/apps/sidestore/v0.1.1/icon.png",
            "tint_color": "#A405FA",
            "description": "Untethered community fork of AltStore that refreshes apps on-device over LocalDevVPN. BariStore automatically configures and injects its pairing file during installation.",
        },
        {
            "id": "sidestore-nightly",
            "name": "SideStore Nightly",
            "subtitle": "Nightly Build · Latest Features",
            "channel": "nightly",
            "repo": "SideStore/SideStore",
            "asset_pattern": "SideStore.ipa",
            "bundle_id": "com.SideStore.SideStore",
            "icon_url": "https://apps.sidestore.io/apps/sidestore/v0.1.1/icon.png",
            "tint_color": "#7B2CBF",
            "warning": "Nightly pre-release build; may contain experimental changes.",
            "description": "Rolling nightly build from SideStore's official pipeline. BariStore writes both ALTPairingFile.mobiledevicepairing and PairingFile_RemoteRP.plist plus preferences.",
        },
        {
            "id": "livecontainer-sidestore-stable",
            "name": "LiveContainer + SideStore",
            "subtitle": "Stable Combined Build · Unlimited Apps in 1 Slot",
            "channel": "stable",
            "repo": "LiveContainer/LiveContainer",
            "asset_pattern": "LiveContainer+SideStore.ipa",
            "bundle_id": "com.kdt.livecontainer",
            "icon_url": "https://raw.githubusercontent.com/LiveContainer/LiveContainer/main/LiveContainerSwiftUI/Images.xcassets/AppIcon.appiconset/AppIcon.png",
            "tint_color": "#0A84FF",
            "description": "Combined LiveContainer + built-in SideStore in a single app slot. Run multiple iOS apps inside LiveContainer without using extra free-account app slots.",
        },
        {
            "id": "livecontainer-sidestore-nightly",
            "name": "LiveContainer + SideStore Nightly",
            "subtitle": "Nightly Combined Build · iOS 27 Ready",
            "channel": "nightly",
            "repo": "LiveContainer/LiveContainer",
            "asset_pattern": "LiveContainer+SideStore.ipa",
            "bundle_id": "com.kdt.livecontainer",
            "icon_url": "https://raw.githubusercontent.com/LiveContainer/LiveContainer/main/LiveContainerSwiftUI/Images.xcassets/AppIcon.appiconset/AppIcon.png",
            "tint_color": "#0066CC",
            "warning": "Nightly pre-release build; recommended for latest iOS compatibility.",
            "description": "Latest nightly build of LiveContainer with built-in SideStore and automatic pairing file placement.",
        },
        {
            "id": "livecontainer-stable",
            "name": "LiveContainer",
            "subtitle": "Standalone Stable · App Container",
            "channel": "stable",
            "repo": "LiveContainer/LiveContainer",
            "asset_pattern": "LiveContainer.ipa",
            "bundle_id": "com.kdt.livecontainer",
            "icon_url": "https://raw.githubusercontent.com/LiveContainer/LiveContainer/main/LiveContainerSwiftUI/Images.xcassets/AppIcon.appiconset/AppIcon.png",
            "tint_color": "#30B0C7",
            "description": "Standalone LiveContainer app launcher that runs iOS apps inside a single container without installing them individually.",
        },
        {
            "id": "livecontainer-nightly",
            "name": "LiveContainer Nightly",
            "subtitle": "Standalone Nightly · Latest Container Engine",
            "channel": "nightly",
            "repo": "LiveContainer/LiveContainer",
            "asset_pattern": "LiveContainer.ipa",
            "bundle_id": "com.kdt.livecontainer",
            "icon_url": "https://raw.githubusercontent.com/LiveContainer/LiveContainer/main/LiveContainerSwiftUI/Images.xcassets/AppIcon.appiconset/AppIcon.png",
            "tint_color": "#1E88E5",
            "warning": "Nightly pre-release build.",
            "description": "Rolling nightly standalone LiveContainer build from the official GitHub Actions pipeline.",
        },
        {
            "id": "altstore-classic-stable",
            "name": "AltStore Classic",
            "subtitle": "Stable Release · Official AltStore",
            "channel": "stable",
            "repo": "altstoreio/AltStore",
            "asset_pattern": ".ipa",
            "bundle_id": "com.rileytestut.AltStore",
            "icon_url": "https://user-images.githubusercontent.com/705880/65270980-1eb96f80-dad1-11e9-9367-78ccd25ceb02.png",
            "tint_color": "#018084",
            "description": "Official AltStore Classic with Remote AltServer support and automatic ALTPairingFile.plist injection.",
        },
    ],
    "default_sources": [
        {"name": "AltStore Official", "url": "https://cdn.altstore.io/file/altstore/apps.json"},
        {
            "name": "SideStore Community Picks",
            "url": "https://community-apps.sidestore.io/sidecommunity.json",
        },
        {"name": "SideStore Official", "url": "https://apps.sidestore.io"},
        {"name": "StikDebug Official", "url": "https://stikdebug.xyz/index.json"},
        {"name": "Provenance Emulator", "url": "https://provenance-emu.com/apps.json"},
        {"name": "UTM Repository", "url": "https://alt.getutm.app"},
        {"name": "OatmealDome (DolphiniOS)", "url": "https://altstore.oatmealdome.me"},
        {
            "name": "Flycast Official",
            "url": "https://flyinghead.github.io/flycast-builds/altstore.json",
        },
        {"name": "PojavLauncher", "url": "https://alt.crystall1ne.dev"},
        {"name": "Yattee", "url": "https://repos.yattee.stream/alt/apps.json"},
    ],
}


def load_sources_config():
    try:
        with open(storage.SOURCES_CONFIG_FILE, "r", encoding="utf-8") as handle:
            config = json.load(handle)
    except Exception:
        config = {}
    if not isinstance(config, dict):
        config = {}
    variants = config.get("store_variants")
    if not isinstance(variants, list) or not variants:
        variants = BUILTIN_CONFIG["store_variants"]
    sources = config.get("default_sources")
    if not isinstance(sources, list) or not sources:
        sources = BUILTIN_CONFIG["default_sources"]
    return {"store_variants": variants, "default_sources": sources}


def get_store_variants():
    return load_sources_config().get("store_variants") or []


def get_configured_sources():
    """Return the active list of AltSource entries [{name, url, custom}]."""
    state = storage.load_state()
    saved = state.get("alt_sources")
    if isinstance(saved, list) and saved:
        return saved
    defaults = [
        {"name": item["name"], "url": item["url"], "custom": False}
        for item in (load_sources_config().get("default_sources") or [])
        if item.get("url")
    ]
    storage.update_state(alt_sources=defaults)
    return defaults


def add_alt_source(url, name=""):
    url = (url or "").strip()
    if not url:
        raise DownloadError("Please enter a valid AltSource URL.")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    # Fetch and validate the source JSON first
    raw = _fetch_source_json(url, timeout=15)
    source_name = (raw.get("name") or name or urllib.parse.urlsplit(url).hostname or "Custom Source").strip()
    sources = get_configured_sources()
    norm = url.rstrip("/").lower()
    for entry in sources:
        if (entry.get("url") or "").rstrip("/").lower() == norm:
            entry["name"] = source_name
            storage.update_state(alt_sources=sources)
            _update_cached_source(url, raw)
            return entry
    new_entry = {"name": source_name, "url": url, "custom": True}
    sources.insert(0, new_entry)
    storage.update_state(alt_sources=sources)
    _update_cached_source(url, raw)
    return new_entry


def remove_alt_source(url):
    norm = (url or "").strip().rstrip("/").lower()
    sources = [
        s for s in get_configured_sources()
        if (s.get("url") or "").rstrip("/").lower() != norm
    ]
    storage.update_state(alt_sources=sources)
    return sources


def reset_default_sources():
    defaults = [
        {"name": item["name"], "url": item["url"], "custom": False}
        for item in (load_sources_config().get("default_sources") or [])
        if item.get("url")
    ]
    storage.update_state(alt_sources=defaults)
    return defaults


def _load_sources_cache():
    try:
        with open(storage.SOURCES_CACHE_FILE, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_sources_cache(cache):
    storage.ensure_dirs()
    tmp = storage.SOURCES_CACHE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(cache, handle)
    os.replace(tmp, storage.SOURCES_CACHE_FILE)


def _update_cached_source(url, payload):
    cache = _load_sources_cache()
    raw_map = cache.get("raw_sources") or {}
    raw_map[url] = {"fetched_at": int(time.time()), "data": payload}
    cache["raw_sources"] = raw_map
    _save_sources_cache(cache)


def _fetch_source_json(url, timeout=12):
    status, _headers, body = apple.http_request(
        "GET",
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/json, text/plain, */*",
        },
        timeout=timeout,
    )
    if status != 200:
        raise DownloadError("Source %s returned HTTP %d" % (url, status))
    try:
        data = json.loads((body or b"").decode("utf-8", "replace"))
    except ValueError:
        raise DownloadError("Source %s did not return valid JSON." % url)
    if not isinstance(data, dict) or not isinstance(data.get("apps"), list):
        raise DownloadError("Source %s is not a valid AltSource (missing 'apps' list)." % url)
    return data


def _normalise_icon_url(icon_url):
    icon = (icon_url or "").strip()
    if not icon:
        return ""
    if icon.startswith(("http://", "https://", "data:")):
        return icon
    return "https://" + icon.lstrip("/")


def _extract_latest_version(app_dict):
    """Extract latest version details from an AltSource app object."""
    versions = app_dict.get("versions")
    latest = {}
    if isinstance(versions, list) and versions:
        for item in versions:
            if isinstance(item, dict) and item.get("downloadURL"):
                latest = item
                break
    version = (
        latest.get("version")
        or app_dict.get("version")
        or latest.get("buildVersion")
        or "1.0"
    )
    download_url = latest.get("downloadURL") or app_dict.get("downloadURL") or ""
    size = int(latest.get("size") or app_dict.get("size") or 0)
    sha256 = latest.get("sha256") or app_dict.get("sha256") or ""
    date = latest.get("date") or app_dict.get("versionDate") or ""
    version_desc = (
        latest.get("localizedDescription")
        or app_dict.get("versionDescription")
        or ""
    )
    return {
        "version": str(version),
        "download_url": str(download_url),
        "size": size,
        "sha256": str(sha256).lower(),
        "date": str(date),
        "version_description": str(version_desc),
    }


def fetch_all_sources(force_refresh=False):
    """Return aggregated catalog from all configured AltSources (using cache when offline)."""
    configured = get_configured_sources()
    cache = _load_sources_cache()
    raw_map = cache.get("raw_sources") or {}
    now = int(time.time())

    to_fetch = []
    for entry in configured:
        url = entry.get("url") or ""
        if not url:
            continue
        cached = raw_map.get(url)
        if force_refresh or not cached or (now - int(cached.get("fetched_at") or 0) > 1800):
            to_fetch.append(url)

    if to_fetch:
        def _worker(u):
            return u, _fetch_source_json(u, timeout=10)

        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            futures = [pool.submit(_worker, u) for u in to_fetch]
            for fut in concurrent.futures.as_completed(futures):
                try:
                    u, data = fut.result()
                    raw_map[u] = {"fetched_at": now, "data": data}
                except Exception:
                    pass
        cache["raw_sources"] = raw_map
        _save_sources_cache(cache)

    return build_catalog_from_cache(configured, raw_map)


def build_catalog_from_cache(configured=None, raw_map=None):
    """Build deduplicated app catalog and source status list without blocking on network."""
    configured = configured if configured is not None else get_configured_sources()
    if raw_map is None:
        raw_map = (_load_sources_cache().get("raw_sources")) or {}

    sources_meta = []
    apps_by_bundle = {}

    for entry in configured:
        url = entry.get("url") or ""
        cached = raw_map.get(url) or {}
        data = cached.get("data") if isinstance(cached.get("data"), dict) else {}
        source_name = data.get("name") or entry.get("name") or url
        app_list = data.get("apps") if isinstance(data.get("apps"), list) else []

        sources_meta.append(
            {
                "name": source_name,
                "url": url,
                "custom": bool(entry.get("custom")),
                "app_count": len(app_list),
                "fetched_at": cached.get("fetched_at") or 0,
                "subtitle": data.get("subtitle") or data.get("description") or "",
                "icon_url": _normalise_icon_url(data.get("iconURL") or ""),
            }
        )

        for app in app_list:
            if not isinstance(app, dict):
                continue
            bundle_id = (app.get("bundleIdentifier") or app.get("appID") or "").strip()
            if not bundle_id:
                continue
            ver_info = _extract_latest_version(app)
            if not ver_info["download_url"] or not ver_info["download_url"].startswith("http"):
                continue

            offer = {
                "source_name": source_name,
                "source_url": url,
                "version": ver_info["version"],
                "download_url": ver_info["download_url"],
                "size": ver_info["size"],
                "sha256": ver_info["sha256"],
                "date": ver_info["date"],
                "version_description": ver_info["version_description"],
            }

            if bundle_id not in apps_by_bundle:
                apps_by_bundle[bundle_id] = {
                    "bundle_id": bundle_id,
                    "name": app.get("name") or bundle_id,
                    "developer": app.get("developerName") or source_name,
                    "subtitle": app.get("subtitle") or "",
                    "description": app.get("localizedDescription") or app.get("subtitle") or "",
                    "icon_url": _normalise_icon_url(app.get("iconURL") or ""),
                    "tint_color": app.get("tintColor") or "#0A84FF",
                    "category": app.get("category") or "utilities",
                    "screenshots": (
                        app.get("screenshotURLs") or app.get("screenshots") or []
                    )[:6],
                    "version": ver_info["version"],
                    "download_url": ver_info["download_url"],
                    "size": ver_info["size"],
                    "sha256": ver_info["sha256"],
                    "source_name": source_name,
                    "source_url": url,
                    "offers": [offer],
                }
            else:
                existing = apps_by_bundle[bundle_id]
                if not any(o["source_url"] == url for o in existing["offers"]):
                    existing["offers"].append(offer)
                if not existing["icon_url"] and app.get("iconURL"):
                    existing["icon_url"] = _normalise_icon_url(app.get("iconURL"))

    apps = list(apps_by_bundle.values())
    for item in apps:
        item["multi_source"] = len(item["offers"]) > 1
        item["source_count"] = len(item["offers"])

    return {
        "sources": sources_meta,
        "apps": apps,
        "store_variants": get_store_variants(),
    }


# --- GitHub Release Resolver & IPA Downloader -------------------------------

def _github_api(url, timeout=30):
    status, _headers, body = apple.http_request(
        "GET",
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": USER_AGENT,
        },
        timeout=timeout,
    )
    text = (body or b"").decode("utf-8", "replace")
    if status == 403 and "rate limit" in text.lower():
        raise DownloadError("GitHub API rate limit reached. Try again later or use an AltSource/Custom IPA.")
    if status != 200:
        raise DownloadError("GitHub API returned HTTP %d" % status)
    return json.loads(text)


def _asset_for(release, pattern):
    exact = pattern and pattern.lower() != ".ipa"
    for asset in release.get("assets") or []:
        name = asset.get("name") or ""
        if not name.lower().endswith(".ipa"):
            continue
        if exact:
            if name == pattern:
                return asset
        else:
            return asset
    return None


def resolve_store_variant(variant):
    """Resolve a built-in Store/Container variant from GitHub Releases at runtime."""
    repo = variant.get("repo")
    if not repo:
        raise DownloadError("Variant %s has no GitHub repository." % variant.get("name"))
    releases = _github_api(RELEASES_URL % repo)
    if not isinstance(releases, list):
        raise DownloadError("Unexpected release list from GitHub.")

    channel = variant.get("channel") or "stable"
    eligible = []
    for release in releases:
        if release.get("draft"):
            continue
        tag = release.get("tag_name") or ""
        if channel == "nightly":
            if tag != "nightly":
                continue
        else:
            if release.get("prerelease") or BAD_TAG.search(tag):
                continue
        eligible.append(release)
    eligible.sort(key=lambda r: r.get("published_at") or "", reverse=True)

    for release in eligible:
        asset = _asset_for(release, variant.get("asset_pattern"))
        if asset is None:
            continue
        digest = asset.get("digest") or ""
        sha256 = digest.split(":", 1)[1].lower() if digest.startswith("sha256:") else ""
        if channel == "nightly":
            stamp = (asset.get("updated_at") or "")[:10]
            version = "nightly-%s" % (stamp or "latest")
        else:
            version = release.get("tag_name") or "stable"
        return {
            "id": variant.get("id") or "",
            "name": variant.get("name") or repo,
            "bundle_id": variant.get("bundle_id") or "",
            "channel": channel,
            "version": version,
            "url": asset.get("browser_download_url") or "",
            "size": int(asset.get("size") or 0),
            "sha256": sha256,
            "icon_url": variant.get("icon_url") or "",
        }
    raise DownloadError("No .ipa asset found for %s (%s)." % (variant.get("name"), channel))


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            block = handle.read(CHUNK)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest().lower()


def _open_stream(url, timeout=90, redirects=8):
    while True:
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("https", "http"):
            raise DownloadError("Unsupported URL scheme: %s" % url[:80])
        host = parts.hostname
        if not host:
            raise DownloadError("Download URL has no hostname.")
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        if parts.scheme == "https":
            conn = http.client.HTTPSConnection(
                host,
                parts.port or 443,
                timeout=timeout,
                context=apple.ssl_context_for(host),
            )
        else:
            conn = http.client.HTTPConnection(host, parts.port or 80, timeout=timeout)
        try:
            conn.request(
                "GET",
                path,
                headers={"User-Agent": USER_AGENT, "Accept-Encoding": "identity"},
            )
            response = conn.getresponse()
        except Exception as exc:
            conn.close()
            raise DownloadError("Download connection failed: %s" % str(exc)[:100])
        if response.status in (301, 302, 303, 307, 308) and redirects > 0:
            location = response.getheader("location")
            response.read()
            conn.close()
            if not location:
                raise DownloadError("Redirect missing Location header.")
            url = urllib.parse.urljoin(url, location)
            redirects -= 1
            continue
        if response.status != 200:
            conn.close()
            raise DownloadError("Download failed with HTTP %d" % response.status)
        return conn, response


def download_ipa(url, dest_name, expected_size=0, expected_sha256="", progress=None):
    """Download an IPA to `storage.UNSIGNED_DIR`, reusing cached copy when valid."""
    storage.ensure_dirs()
    safe_name = re.sub(r"[^A-Za-z0-9._+-]", "_", dest_name)
    if not safe_name.lower().endswith(".ipa"):
        safe_name += ".ipa"
    destination = os.path.join(storage.UNSIGNED_DIR, safe_name)

    if os.path.isfile(destination) and os.path.getsize(destination) > 0:
        actual_size = os.path.getsize(destination)
        size_ok = (not expected_size) or (actual_size == expected_size)
        sha_ok = (not expected_sha256) or (_sha256_file(destination) == expected_sha256.lower())
        if size_ok and sha_ok and (expected_size or expected_sha256):
            if progress:
                progress(actual_size, actual_size)
            return destination

    partial = destination + ".part"
    digest = hashlib.sha256()
    received = 0
    conn, response = _open_stream(url)
    total = int(expected_size or response.getheader("Content-Length") or 0)
    try:
        with open(partial, "wb") as handle:
            while True:
                block = response.read(CHUNK)
                if not block:
                    break
                handle.write(block)
                digest.update(block)
                received += len(block)
                if progress:
                    progress(received, total)
    except Exception as exc:
        try:
            os.remove(partial)
        except OSError:
            pass
        raise DownloadError("Download interrupted: %s" % exc)
    finally:
        conn.close()

    if expected_size and received != expected_size:
        try:
            os.remove(partial)
        except OSError:
            pass
        raise DownloadError(
            "Downloaded size (%d bytes) did not match expected size (%d bytes)."
            % (received, expected_size)
        )
    if expected_sha256 and digest.hexdigest().lower() != expected_sha256.lower():
        try:
            os.remove(partial)
        except OSError:
            pass
        raise DownloadError("Downloaded IPA failed SHA-256 integrity verification.")

    os.replace(partial, destination)
    return destination
