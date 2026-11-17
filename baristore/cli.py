#!/usr/bin/env python3
# =============================================================================
#  BariStore — Command Line Launcher (MIT)
#
#  Usage in a-Shell:
#      baristore          Opens the BariStore Web UI in a-Shell's internal browser
#      baristore update   Updates BariStore in place
# =============================================================================

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from baristore import VERSION, webui  # noqa: E402


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in ("update", "--update"):
        print("BariStore %s — checking for updates…" % VERSION)
        try:
            msg = webui.run_self_update()
            print("  " + msg)
            return 0
        except Exception as exc:
            print("  ! Update failed: %s" % exc)
            return 1
    if argv and argv[0] in ("--version", "-v", "version"):
        print("BariStore %s" % VERSION)
        return 0
    if argv and argv[0] in ("--check", "check"):
        return 0
    if argv and argv[0] in ("--help", "-h", "help"):
        print("BariStore %s" % VERSION)
        print()
        print("  baristore          open BariStore UI")
        print("  baristore update   update BariStore in place")
        return 0
    return webui.run(open_browser=True)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        sys.exit(130)
    except Exception:
        import traceback

        report = traceback.format_exc()
        try:
            from baristore import storage

            storage.ensure_dirs()
            with open(os.path.join(storage.STATE_DIR, "launch.log"), "a") as handle:
                handle.write("FATAL\n" + report + "\n")
        except Exception:
            pass
        sys.stderr.write("BariStore failed to start:\n" + report)
        sys.exit(1)
