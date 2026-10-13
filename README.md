# SSH Workbench

SSH Workbench is a standalone desktop terminal and remote file explorer. It
connects directly to a machine over SSH, using SFTP where the host offers it and
falling back to a shell and `scp` where it does not; the remote machine does not
need a web UI, agent, daemon, or any software beyond its normal SSH service.

The interface combines:

- Tabbed sessions in as many windows as you want: up to eight connections per
  window, each with its own terminal, remote folder, selection, and search.
- An xterm.js terminal backed by a real SSH pseudo-terminal, with Windows-console
  copy and paste: Shift+drag copies, right-click copies or pastes, `Enter`
  finishes a mouse selection.
- An SFTP file explorer with name, path, and wildcard search across the tree,
  which falls back to `scp` and `ls` on hosts with no SFTP subsystem.
- Multi-file and recursive folder upload/download.
- Native drag-and-drop uploads from the desktop and real-file drags back out.
- Paste a screenshot or copied files straight into the remote folder.
- Text editing, image preview, rename, mkdir, and recursive deletion.
- Remembered split position and search scope.
- The build number in the window title and on the connection screen, so which copy
  is running is never in question.
- Password, private-key, and SSH-agent authentication, with password the default
  for a new connection.
- Named saved connections with optional OS-encrypted passwords and key
  passphrases, and an optional master password over them with a re-prompt
  interval you choose.
- Native jump-host connections with separate authentication and host-key
  verification for the bastion and destination.
- First-use host fingerprint confirmation and changed-key warnings.

Connecting leaves no trace of where: the host, username, and key path you type are
not recorded anywhere unless you deliberately save the connection. Local storage
holds only the pane divider position, the search scope, and the id of the saved
connection last used. Passwords and private-key passphrases are never stored in
browser local storage or plaintext profile data. When credential saving is enabled, Electron encrypts
them using Windows Data Protection, macOS Keychain, or a real Linux keyring.
If secure OS storage is unavailable, Workbench saves only non-secret connection
details. Remembered profiles and host fingerprints live in Electron's per-user
application data directory with owner-only permissions where supported.

## Remote requirements

The remote machine needs:

- An SSH server reachable from the computer running SSH Workbench.
- Either the SFTP subsystem — enabled by default in standard OpenSSH
  installations — or `scp` and a POSIX shell. See **File transfer: SFTP and SCP**
  below.
- A valid user account and one of the supported authentication methods.

Nothing listens on a local HTTP port, and nothing is installed on the remote
machine.

## File transfer: SFTP and SCP

Some hosts have the SFTP subsystem switched off — a hardened `sshd_config`, an
appliance, a router, or an old system with `scp` and nothing else. **File
transfer** on the connection form decides what such a host means:

| Setting | What it does |
| --- | --- |
| **SFTP, fall back to SCP** (default) | Tries SFTP. If the subsystem is refused, the session continues over a shell and `scp` and says so. |
| **SFTP only** | Tries SFTP and nothing else. A host without it does not connect. |
| **SCP only (shell)** | Goes straight to the shell and `scp`, without trying SFTP first. |

A session using the fallback is marked `· SCP` next to its name in the tab bar,
and the file pane says whether that was asked for or was the only thing available.
Both are per connection, so a saved profile remembers which one it needs.

SCP mode is a genuine fallback, not a second first-class protocol. In it:

- Folder listings are parsed from `ls -lAn` output, so a name containing a
  newline, or a name containing ` -> ` on a symbolic link, cannot be told apart
  from the listing syntax. SFTP has no such ambiguity.
- Every operation is its own `exec` channel and its own round trip, so folders
  open more slowly, and recursive search runs four folders at a time rather than
  twelve, because a host allows only so many channels at once.
- Timestamps are exact where `ls` understands `--time-style`; on a host whose
  `ls` does not, they are read from the abbreviated date and can be a year out
  either side of the present.
- A POSIX shell and `scp` are required. Where `scp` is missing, the connection
  says so at once rather than failing at the first transfer.
- Every path is single-quoted before it reaches the shell, so a filename
  containing quotes, spaces, `$(...)`, or a leading `-` is a filename and not
  syntax.

SCP mode is tested against a real OpenSSH server with no `Subsystem sftp` line, in
addition to the project's own test double: `test/scp-real-sshd.test.js` starts an
unprivileged `sshd` on a high port with its own host key and throwaway directory,
then drives the same code the interface uses through listings, byte-exact transfers
in both directions, recursive upload and download, search, editing, rename, and
recursive deletion. It skips where `sshd` or `ssh-keygen` is unavailable, so it is a
no-op on a Windows or macOS build host.

## Sessions and tabs

Each tab is a separate SSH connection with its own SFTP session and shell. The
tab strip sits in the title bar; a green dot means the session is live and a red
dot means the far end went away. Switching tabs restores that session's folder,
selection, search text, and terminal scrollback exactly as you left it.

| Action | Shortcut |
| --- | --- |
| New session | `Ctrl+Shift+T` or the `＋` button |
| New window | `Ctrl+Shift+N` or the `⧉` button |
| Close the current session | `Ctrl+Shift+W`, the tab's `×`, or **Disconnect** |
| Previous / next session | `Ctrl+PageUp` / `Ctrl+PageDown` |
| Jump to a session | `Alt+1` … `Alt+9` |
| Focus remote-name search | `Ctrl+F` |
| Connect, or reconnect | `Enter`, from anywhere on the connection form |
| Refresh the listing | `F5` or the `⟳` button, which turns once as it reloads |
| Lock saved credentials | `Ctrl+Shift+L`, or **Lock now** (only with a master password set) |
| See which build this is | The version beside the title on the connection screen, and in the `? Help` dialog |

These combinations are handled by the application and are not forwarded to the
remote shell. Everything else, including `Ctrl+C`, goes to the shell as usual.

If a connection drops, its tab stays in place, remote actions are disabled, and
**Reconnect** reopens the same tab with the connection details already filled in.
A tab opened from a saved connection reconnects with that connection's saved
password and passphrases (after the master password, if they are locked), so
nothing has to be retyped; anything typed into the form is used instead. Saved
secrets only ever go to the server they were saved for.
Sessions are independent: a failure, disconnection, or busy transfer in one tab
does not affect the others. Host fingerprints you trust are shared by every tab.

Eight sessions in one window is the maximum; the `＋` button is disabled at that
point, and another window takes eight more.

## Terminal copy and paste

The terminal follows Windows console habits, so muscle memory from `ssh` in
PowerShell carries over. **? Help** in the terminal toolbar lists every shortcut
and mouse action, including the file pane and drag-and-drop ones.

| Action | Result |
| --- | --- |
| Drag | Select text; the clipboard is left alone |
| `Shift`+drag | Select **and copy**, including while a remote program holds the mouse |
| Double-click / triple-click | Select a word / a line |
| `Enter` after a mouse selection | Copy and clear it, instead of reaching the shell |
| Right-click | Copy the selection; paste when nothing is selected |
| `Ctrl+C` | Copy the selection, or send SIGINT when there is none |
| `Ctrl+Insert` | Copy the selection |
| `Ctrl+Shift+C` | Copy the selection exactly as it is on screen |
| `Ctrl+V`, `Ctrl+Shift+V`, `Shift+Insert` | Paste text into the shell |

Remote programs that ask for the mouse — `vim`, `tmux`, `less`, `htop` — receive
clicks, drags, and wheel movement in both the classic `ESC [ M` and the SGR
encodings. While such a program has the mouse, dragging belongs to it rather than
to local selection; holding `Shift` takes the drag back so text can still be
selected and copied, which is otherwise impossible.

### Indentation is not part of the copy

A selection is a rectangle of screen, so a block copied out of indented output
carries the depth it happened to be printed at. Every way of copying therefore
removes the indentation that **all** the selected lines share — `Shift`+drag,
right-click, `Enter`, `Ctrl+C`, `Ctrl+Insert` — and the file pane says so when it
has happened.

Only the shared part goes, so the structure inside the block survives, which is
the whole of what a pasted YAML fragment depends on. Copying this out of a tool's
output:

```
    hooks:
      PreToolUse:
        - matcher: Bash
```

puts `hooks:` at the left margin with its children still two and four spaces in.
A margin of spaces and a margin of tabs are compared as text rather than counted,
so lines that do not genuinely share a margin are left alone rather than sliced.

`Ctrl+Shift+C` is the one that copies byte for byte, for when the leading
whitespace is the point. Copy and paste both go through the application rather
than the browser clipboard API, so no clipboard permission is involved.

Before 0.11.5 only `Ctrl+C` did this, which is why the same selection came out
indented or not depending on how it had been copied.

### `Shift`+drag with nothing selected

Also fixed in 0.11.5: a terminal reads `Shift`+click as *extend the selection*, and
with nothing selected there was nothing to extend, so the first `Shift`+drag after
connecting selected — and copied — nothing at all. It appeared to work from the
second attempt onwards, and inside `vim`, `tmux` or `less`, where holding `Shift`
means something different because the program has taken the mouse.

`Shift`+drag now starts a selection wherever it lands, every time. The same drag
used to copy different text depending on what had been selected before it — and a
selection stretched back to a line at the left margin shares no indentation to
remove, which is the other half of why the indentation came off only sometimes.

The trade is xterm's `Shift`+click-to-extend, which is gone while the mouse is
local: drag to select, and `Enter`, right-click or `Ctrl+C` to copy. Inside a
program that has taken the mouse — `vim`, `tmux`, `less` — nothing changes, because
there `Shift` is what takes the drag back and already starts a selection.

## Searching remote names and paths

The search box matches names by default. A query that contains a slash matches the
path below the folder being searched, and one that starts with a slash matches the
whole remote path, so folder names can be part of the query. `*` and `?` turn a
query into a wildcard pattern.

| Query | Matches |
| --- | --- |
| `report` | any name containing `report` |
| `logs/report` | `logs/report-mid.txt`, `srv/logs/report.gz` |
| `/var/log/rep` | anything whose full remote path contains it |
| `*.log` | any name ending in `.log`, and nothing else |
| `report-?.txt` | `report-1.txt` but not `report-12.txt` |
| `alice/*.txt` | any `.txt` inside a folder named `alice`, at any depth |

A wildcard pattern must match the whole name or path rather than part of it, and
`*` spans `/`. Matching always ignores case. **Subfolders** searches the tree
below the current folder; **Current folder** searches only that folder.

### What the search does and does not cover

Searching is a client-side walk over SFTP: there is no remote agent, so Workbench
reads one directory listing per folder. It reads the folders nearest the current
one first, several at a time, and stops at whichever of these comes first:

- 500 matches,
- about four seconds,
- the end of the tree.

Up to twelve listings are kept in flight at once, refilled as each one returns
rather than in fixed batches, so one slow folder cannot leave the other slots idle.
On a link with a 25 ms round trip that searches sixty folders in about half a
second, against roughly three seconds one folder at a time.

Because the nearest folders are read first, a search that stops early has covered
the folders around you rather than one deep branch. The status line reports what
actually happened — how many folders were searched, how many could not be read,
how many were never reached, and which folders were skipped — so an empty result
is never mistaken for a definite answer. Hovering it shows the full text.

`.git`, `.cache`, `.venv`, `venv`, `node_modules`, and `__pycache__` are never
entered, and links to folders are not followed. Names are matched, not file
contents. On a high-latency link the round trip per folder, not the server, sets
the pace; narrowing the starting folder helps far more than narrowing the text.

## Saved connections

Enter the destination, authentication, optional jump host, and starting folder.
Give it a name in **Saved connections**, choose whether to save passwords and
passphrases, then select **Save connection**. Selecting that name later restores
the complete connection with one click.

`Enter` connects from anywhere on the connection form — including from a dropdown,
which a browser form would not submit from on its own. With a saved connection
chosen in the list, `Enter` opens that one, loading its credentials first; otherwise
it submits whatever the form holds. Pressing it twice starts one connection, not
two. **Connect** beside the list and double-clicking the entry do the same thing.

A new connection starts on **Password** authentication with the password field
already shown; **Private key** and **SSH agent** are the other two choices. The
whole form — saved connections, destination, authentication, transfer setting, and
starting folder — fits on screen without scrolling at the default window size, with
the jump-host section open and private-key fields shown.

Private-key paths are part of the normal profile. Passwords and passphrases are
stored only when **Save passwords and key passphrases using OS encryption** is
enabled. SSH-agent profiles need no saved credential because the agent performs
authentication. Deleting a profile removes its encrypted credential blob too.

### Master password

**Master password…** in **Saved connections** puts a password of your own over
the saved credentials. It is asked for when a saved credential is actually
used — when **Connect** is pressed on a saved connection, or when one is saved with
its password — and never at startup, never merely for choosing a connection in the
list, never for a connection typed in by hand, and never for a profile that
authenticates through the SSH agent. Choosing a saved connection fills in the form
and says the master password will be wanted on connecting; nothing secret is read
until it is.

Choose when it is needed again:

- **Every time saved credentials are used.** The key is discarded as soon as it
  has been used once.
- **Once, then again after N minutes** (1 to 1440; 15 by default). Each use moves
  the window along, so a working session is not interrupted.

**Lock now**, or `Ctrl+Shift+L`, locks immediately. One process holds the vault,
so unlocking in one window unlocks the saved credentials for all of them, and
locking does the same in reverse.

The password itself is stored nowhere. It needs at least six characters. A random
16-byte salt and scrypt (N = 65536, r = 8, p = 1) turn it into a 32-byte key, which
encrypts each stored credential with AES-256-GCM; a verifier token proves a typed
password was right without the password being kept.

Wrong attempts are rate limited, mildly: four cost nothing beyond the derivation
itself — mistyping happens — and after that each one buys a pause of 15 seconds
more than the last, up to a minute, reported as the seconds left to wait. A correct
password clears the counter, and so does restarting the application; the limit is
there to make a script pointed at the dialog unrewarding, not to lock you out of
your own connections. The real cost to an attacker is scrypt, which no amount of
restarting avoids. Where the operating system keyring is available,
it wraps the result, so both have to be defeated. Where there is no keyring — a
Linux machine with no real Secret Service, for one — the master password is what
makes saving credentials possible at all, and removing it means the saved
credentials are forgotten rather than written somewhere weaker; the button says
so before you confirm.

Changing the master password re-encrypts every saved credential in memory and
writes the file once, so an interruption cannot leave some connections readable
with the old password and some with the new. A forgotten master password cannot
be recovered: remove it, and enter the connection passwords again as you use
them.

## The path bar

The path above the listing is a text field, and it is a text field all the time --
there is nothing to click first. Select it and copy, or type or paste a path over it
and press Enter to go there. `Ctrl+L` focuses it and selects the whole path, ready to
copy or to type over; inside the terminal `Ctrl+L` still clears the screen, as a
shell expects. Escape puts the folder actually being shown back in the box, and so
does moving on to something else in the window -- a path typed but never entered is
not left standing there claiming a folder you are not in. Switching to another
application is the exception, since fetching a path from somewhere else is half the
reason to type in here. `↑ Up` walks back up the tree.

What arrives on a clipboard is rarely clean, so a pasted path is read the way it was
meant. Explorer's "Copy as path" wraps its result in quotes, and a path copied out of
a chat message or a log carries a trailing newline; both are stripped, and only the
first line that has anything on it is used. `~` is your home folder on the host, and a
path with no leading slash is read from the folder on screen. A path naming a file
rather than a folder opens the folder holding it and selects the file, which is what
pasting a path out of an error message is usually for. A Windows path -- `C:\...` or a
`\\server\share` -- is refused by name rather than sent to the host to fail there.

## Copy as path

Right-click a row for **Copy as path**: the full remote path of that item, on the
clipboard. Right-clicking one of several selected rows copies the whole selection
instead, one path per line, the same rule dragging a row out to the desktop follows.

A path is quoted only when leaving it bare would change what it means. Explorer
always quotes; a remote path is usually going into a shell, a ticket or a message, so
`/var/log/syslog` is copied as itself and `/tmp/my report.txt` comes out as
`'/tmp/my report.txt'`. The quoting is POSIX single quotes, which is what the far end
speaks, and the path box strips them again if the path comes back this way.

## Paste into a remote folder

`Ctrl+V` anywhere in the window puts the clipboard into the folder shown in the
active tab:

- A screenshot — from Snipping Tool, `Win+Shift+S`, or any capture tool — is
  saved as `pasted-<date>-<time>.png` in that folder. The image exists only as
  bytes on the clipboard, so it is written directly over SFTP; nothing touches
  your local disk on the way.
- Files copied in Explorer are uploaded by path, exactly as if dropped.

Focus does not matter, because the clipboard decides. Only *text* is ambiguous —
the shell has a use for it — so text pasted while the terminal has focus goes to
the shell as always. An image or a file has one possible destination, and it goes
there whether the terminal or the file pane has focus.

Names are generated from the local clock and checked against the folder, so a
second paste in the same second never overwrites the first. Pasted images are
capped at 20 MB.

## Drag and drop

Drop local files or folders anywhere on the file pane to upload them into the
folder shown in the active tab. Folder contents are uploaded recursively, links
to folders are uploaded as real folders, and a link that points back up its own
tree is followed once instead of endlessly. Dropping again while an upload is
still running queues the new items rather than discarding them.

### When a name is already taken

An upload that would land on a name already in the destination stops and asks
before a single byte is sent. Each name is listed with what is on the host beside
what is being uploaded — size, timestamp, and whether either is a folder or a
shortcut — and each gets its own answer:

- **Overwrite** replaces it. For a folder this reads **Merge, replacing files
  that clash**: the folder is merged into, and files inside it are replaced where
  the names meet. That is the one place a file is replaced without being listed
  by name, and it follows from the answer given for the folder.
- **Keep both** uploads beside it, counting up the way a download does when a
  local name is taken: `report.txt`, then `report_2.txt`.
- **Skip** leaves it alone and uploads nothing under that name.

With more than one collision, **Apply to all** sets every row that can take the
answer. Closing the dialog — Cancel, Escape, or the close button — is a refusal:
nothing is uploaded at all, rather than falling back to replacing what is there.
A file cannot replace a folder or a folder a file, so those rows offer only
*Keep both* and *Skip*, and say why.

Two dropped items can also clash with each other rather than with the host --
dragging out of a search results window gathers files from several folders, and two
of them can share a name. Nothing is in the way when the first one is written, so
checking the destination alone would never see it and the second would quietly
replace the first. Such a name is listed too, once, and the answer covers every copy
of it: *Keep both, numbered* -- the default here, since both files were chosen
deliberately -- *Keep the last one*, or *Keep the first one*.

The question is asked once per dropped name, not once per file inside a dropped
tree, so a deep folder does not turn into a queue of dialogs. The same dialog
covers **Upload files**, **Upload folder**, and files pasted with `Ctrl+V`. The
names are checked by probing the destination, so a name that appears in the gap
between the check and the write is a race this cannot close.

Dropped items are turned into local paths inside the preload script's isolated
world, at the moment of the drop, and only those path strings are sent onward.
Native file objects lose their local path when they cross the context bridge, so
extracting the paths anywhere else yields nothing at all.

Drag a remote row to the desktop or a local folder to download it as a real
file or folder. If multiple selected rows include the row being dragged, the
whole selection is included. Workbench must stage remote data locally before
Windows can receive it, so keep holding the first drag while it prepares. If a
large transfer does not land on the first attempt, drag it again; the prepared
copy is cached for two minutes and the second drag starts immediately.

Staged drag data is kept in the per-user application data directory and removed
after two minutes or when Workbench closes. Chromium link dragging is disabled,
so dragging a remote name does not create an Internet Shortcut (`.url`).

## Jump hosts

Enable **Connect through a jump host (ProxyJump)** on the connection screen.
Fill the main fields with the final destination and the expanded section with
the bastion. For this OpenSSH command:

```bash
ssh -J jump-user@bastion.example.com remote-user@server.internal
```

use:

| Section | Host | Port | Username |
| --- | --- | --- | --- |
| Destination | `server.internal` | `22` | `remote-user` |
| Jump host | `bastion.example.com` | `22` | `jump-user` |

Choose authentication independently for each host. Workbench first verifies
and authenticates the jump host, opens a forwarded TCP channel, then verifies
and authenticates the destination through that channel. No external `ssh -L`
process is needed.

## Run from source

Install Node.js 22.12 or newer, then:

```bash
npm install
npm start
```

On Electron releases that defer their platform download, run this once if
`npm start` says the Electron binary is missing:

```bash
npx --no-install install-electron --no
```

## Build a standalone application

Build on the target operating system for the simplest packaging experience:

```bash
# Windows portable executable
npm run dist:win

# Linux AppImage
npm run dist
```

For an unpacked Windows directory that can be zipped and copied without an
installer:

```bash
npm run pack:win
```

SSH2's optional native CPU-detection and crypto-acceleration addons are excluded
from packages so the same source can be cross-packaged. SSH2 automatically uses
its portable implementation when those optimizations are absent.

The application icon is `build/icon.ico` (Windows) and `build/icon.png` (Linux and
the window itself). Both are rendered from the drawings in `build/icon/`:
`icon.svg` for 48 px and up, and `icon-32.svg`, `icon-24.svg` and `icon-16.svg`
drawn separately on their own pixel grids so the small sizes stay sharp. Edit the
drawings and re-render all of them together if the icon changes.

Build output is written to `release/`. Code signing is not configured; public
distribution should add an appropriate Windows or macOS signing identity.

## Security design

- The renderer loads only packaged local files.
- Node integration is disabled.
- Context isolation and Chromium renderer sandboxing are enabled.
- Only narrow, argument-specific operations cross the preload bridge.
- Local filesystem paths from a drop never pass through the renderer world, and
  the main process independently checks that each one is absolute and exists.
- Navigation, new-window creation, and webview attachment are blocked.
- Every browser permission request and check is denied; clipboard access goes
  through an explicit, length-limited channel instead.
- A corrupt saved-connection or host-fingerprint file is set aside rather than
  trusted or silently overwritten, and the application reports that it happened.
- Hostnames, usernames, and key paths are written to disk only through **Save
  connection**. Nothing about a connection is retained implicitly, and any record
  left by a version before 0.9.1 is cleared on first run.
- Remote names and file data are rendered as text or isolated image blobs,
  never inserted as HTML.
- Names in a remote listing are treated as data, not as path structure. An entry
  whose name holds a path separator, a `..`, or a null byte cannot exist on a real
  filesystem, so it is refused at the point the folder is read: browsing hides such
  entries and says how many, while a recursive download or deletion stops outright
  rather than following one. Without that, a hostile or compromised server could
  answer a directory listing with `../../file` and have a download written outside
  the folder chosen for it, or a deletion reach a sibling of the folder selected.
- A recursive download additionally checks that every file it is about to write
  stays under the folder it was sent to, and refuses to write through a symbolic
  link that is already sitting at the target name.
- Host keys are verified before authentication. A changed key requires an
  explicit replacement confirmation.
- Saved passwords and passphrases cross the isolated bridge only for profile
  operations and connection requests, and are encrypted at rest by Electron's
  OS-backed safe storage.
- A master password, where one is set, encrypts each saved credential with
  AES-256-GCM under an scrypt-derived key before the keyring sees it. The typed
  password goes straight to the main process; the renderer is told only whether
  the vault is set and whether it is currently unlocked, never the password, the
  key, or anything derived from either. The key is held in memory only for as
  long as the chosen interval allows and is zeroed when it is dropped.
- In SCP mode every remote path is single-quoted before it reaches the shell, and
  each command is given `--` so a path can never be read as an option.
- The Linux `basic_text` safe-storage fallback is rejected for credential
  persistence because it does not provide meaningful secret protection.
- Repeated wrong master passwords are rate limited in memory after four attempts,
  and every path that checks the password — unlocking, changing it, removing it,
  changing how often it is asked for — goes through that one check.
- Remote items dragged to the desktop are temporarily materialized in an
  app-owned cache, then automatically removed.

## Current scope

Version 0.11 supports multiple windows, named connection profiles with one-click
connect, a master password over saved credentials, SFTP with an SCP fallback for
hosts without the subsystem, native file drag and drop, clipboard paste into
remote folders, tabbed sessions, Windows-console copy and paste, mouse-aware
remote programs, path and wildcard search, and one optional jump host per
session. SSH config import, multi-hop chains, general port forwarding, split
panes within a tab, and automatic updates are natural follow-up features.

## Two copies at once

The application allows one instance, and a second launch asks the running one for
another window — which is what makes a new window open in 0.03 s instead of four
seconds. That lock belongs to the application, not to the folder it was extracted
into, so launching a freshly downloaded copy while an older one is still running
would otherwise hand you a window drawn by the **older** build: the update appears
to have changed nothing.

From 0.11.5 the build you launch is the build you get. A launch from a different
folder finds the copy that is running, reads its version out of the folder it runs
from, and offers to close it and take its place — naming both builds and both
paths, and saying that closing the other copy ends its sessions and any transfer
in progress. Decline and nothing is touched.

This works against **any** older copy, including one from before this behaviour
existed, because closing a process needs no cooperation from it. What the older
copy cannot do is the reverse: launch a 0.11.3 while 0.11.5 is running and 0.11.3
still quits without a word, since the offer is made by the copy being launched.

Two flags answer the question in advance, for a shortcut that should never stop to
ask:

| Flag | Effect |
| --- | --- |
| `--take-over` | Close a copy from another folder without asking, and start |
| `--no-take-over` | Never close another copy; exit quietly instead |

A copy that is identified as this application by the `package.json` beside it is
the only one closed automatically. An unpackaged development run has nothing
beside it to read, and is identified by its executable name alone — so
`--take-over` from a source checkout on a machine running other Electron
applications is the one case where the name is all there is to go on.

The window title is the other half of this: it reads `SSH Workbench 0.11.5`, so the
build that drew the window is on screen whatever the window is showing — a session
connected for days included. The connection screen carries it beside the title as
well, with the Electron version and platform on hover.

## If the application is slow to start

The application's own startup work is about a millisecond: it sets aside the drag
cache, reads two small JSON files, and opens the window. Everything else is
Electron starting and Chromium loading the page. To find out where the time
actually goes, set one variable before launching:

```powershell
$env:SSH_WORKBENCH_TIMING = "1"
.\"SSH Workbench.exe"
```

A report is written to `%APPDATA%\SSH Workbench\startup-timing.txt`:

```
milliseconds since the process started
   332 ms  electron ready, application code starts
   332 ms  drag cache set aside
   333 ms  saved connections and known hosts read
   960 ms  window created and page loaded
```

Read the first line first. If **electron ready** is already several seconds, the
delay happened before any of this code ran, and it is the operating system rather
than the application. On Windows the usual causes, in order of likelihood:

- **The folder is synchronised or on a network drive.** Running a 145 MB
  application out of a OneDrive-backed or mapped home directory means every library
  it loads is fetched through that layer. Extract somewhere local, such as
  `C:\Tools\SSH-Workbench`.
- **The download is still marked as coming from the internet.** That mark
  propagates to every extracted file and makes Defender and SmartScreen inspect
  each one. Clear it on the archive before extracting:
  `Unblock-File .\SSH-Workbench-Windows-x64-0.9.2.zip`
- **Real-time scanning of an unsigned application.** The build is not code-signed,
  so the first launch of each new version is examined more closely than later ones.
  A folder exclusion removes the repeated cost if policy allows one.
- **A cold profile.** The first run of a version builds Chromium's code and shader
  caches; later runs reuse them. Measured here: 960 ms cold, 550 ms warm.

If **electron ready** is fast but the last line is far behind it, the problem is in
the page rather than the environment — send the file and it can be traced from
there.

## Development checks

```bash
npm run check   # build the renderer bundle and run the unit and SFTP tests
npm audit
```

The SFTP tests run a real in-process SSH server (`test/helpers/ssh-test-server.js`)
and exercise listing, search, upload, download, editing, deletion, and the shell
against it. The SCP tests do the same through a shell and scp emulator, and
`test/scp-real-sshd.test.js` repeats the important parts against a genuine
unprivileged `sshd` with no SFTP subsystem where the machine has one — it skips
otherwise. No external machine or credential is involved in any of them.

There is also an end-to-end check that launches the actual application, drives it
over the Chrome DevTools Protocol, and verifies tab isolation, inbound drops of
real local files, outbound drag staging, and reconnection — including reconnecting a dropped tab with
its own saved credentials, locked and unlocked, while another saved connection is
showing in the form:

```bash
npm run e2e              # needs a display
xvfb-run -a npm run e2e  # headless machines
```
