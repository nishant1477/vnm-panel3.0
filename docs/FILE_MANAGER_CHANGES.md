# Live VPS File Manager — what was added

This update adds a production File Manager to each VPS's management page,
without touching the existing VNM UI, layout, theming, or features.

## New files
- `filemanager.js` — self-contained backend module: SFTP session manager
  (reuses each VM's own stored SSH credentials, same as the existing SSH
  Terminal feature), strict path/name validation, REST endpoints, and the
  WebSocket live-update broadcaster. Fully commented.
- `views/users/vm-files.ejs`, `views/admin/vm-files.ejs` — the File Manager
  page, built with the panel's existing CSS classes/tokens (cards, modals,
  toasts, dropdowns, progress bars) so it looks native to VNM. Includes a
  breadcrumb file browser, drag-and-drop upload with progress, a built-in
  CodeMirror code/text editor with syntax highlighting, right-click context
  menu, multi-select + bulk actions, and compress/extract.

## Changed files
- `app.js` — mounts the file manager's API router at
  `/api/vms/:vm_id/files`, adds the `/vm/:id/files` and `/admin/vm/:id/files`
  page routes, and adds a `/file-manager/:vmId` branch to the existing
  WebSocket connection handler for live updates. No existing route,
  middleware, or behavior was removed or altered.
- `views/users/vm-detail.ejs`, `views/admin/vm-detail.ejs` — added a
  "Files" button next to the existing Console/SSH buttons, and a folder
  icon to the shared SVG sprite. Nothing else changed.
- `package.json` / `package-lock.json` / `node_modules` — added `busboy`
  (streamed multipart uploads, so large files are never buffered fully in
  memory).

## How it works
- Every operation goes over SFTP/SSH to the **selected VPS's own**
  filesystem — never the host, the panel's own files, the database, or
  QEMU disk images. The panel already had SSH credentials stored per VM
  (used by the SSH Terminal); the File Manager reuses those to connect
  automatically, no extra login step.
- All `/api/vms/:vm_id/files/*` routes sit behind the existing `checkAuth`
  middleware, the existing VM-ownership check (or admin bypass), and the
  existing global CSRF protection (`/api/*`) — nothing new was introduced
  for auth.
- Paths are normalized and validated server-side (traversal-safe); names
  for new files/folders/archive members can't contain `/`; compress/extract
  shell out to `tar`/`zip`/`unzip` with every argument single-quoted and
  never built from unescaped input. If a VM's guest doesn't have `zip`,
  `unzip`, or `tar` installed, compress/extract fail gracefully with a
  clear "not installed on this VPS" message instead of a raw error.
- If the VPS isn't running, every endpoint fails fast with a clean
  "VPS is offline" response instead of hanging on a dead SSH connection.
- Live updates: the File Manager opens a small WebSocket channel
  (`/file-manager/:vmId`) and the server pushes a message after every
  successful upload/rename/delete/etc. so open tabs refresh automatically
  — no polling loop.

## Configuration (optional, all have sensible defaults)
Add any of these to `.env` to override:
- `FM_MAX_UPLOAD_MB` (default `4096`) — max upload size per file
- `FM_MAX_EDIT_MB` (default `8`) — max size of a file the built-in editor
  will open (larger files still list/download/delete fine, just not edit)
- `FM_IDLE_MS` (default `600000`, 10 min) — how long an idle SFTP session
  to a VM is kept open before the panel closes it
- `FM_CONNECT_TIMEOUT_MS` (default `15000`) — SSH connect timeout

## Tested
Ran the full flow end-to-end against a real local SSH server (not
mocked): directory listing, path-traversal rejection, upload, edit/save,
download, live storage stats, tar.gz compress, extract, rename, recursive
delete, CSRF rejection, offline-VPS handling, and the WebSocket
live-update broadcast. Both `views/users/vm-files.ejs` and
`views/admin/vm-files.ejs` were confirmed to render without errors and
the existing VM detail pages were confirmed to still render correctly
with the new "Files" button in place.

## Note on `node_modules`
The runtime `data/` folder (your live database) was intentionally left
out of this package — drop this into your existing panel install and
your data isn't touched, or run it fresh and the panel will bootstrap a
new database and default admin account exactly like it does today.
