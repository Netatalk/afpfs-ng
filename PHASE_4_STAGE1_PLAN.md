# Phase 4 Stage 1: Refactor afpcmd to Use Stateless Library

## Goal

Demonstrate that the stateless library works end-to-end by refactoring afpcmd's **existing operations** to use `afp_sl_*` functions instead of `ml_*` functions.

## Current Architecture

### Connection Flow
```
com_connect() [cmdline_afp.c:371]
  └─> server_subconnect() [line 293]
      └─> afp_server_full_connect() → creates struct afp_server *server
  └─> connect_volume() [line 263]
      └─> find_volume_by_name()
      └─> afp_connect_volume() → creates struct afp_volume *vol
```

### Disconnection Flow
```
com_disconnect() [cmdline_afp.c:354]
  └─> afp_unmount_volume(vol)
  └─> vol = NULL, server = NULL
```

### Global State
```c
static struct afp_server *server = NULL;  // line 61
struct afp_volume *vol = NULL;           // line 62
```

## New Stateless Architecture

### Connection Flow
```
com_connect()
  └─> afp_sl_connect(&url, uam_mask, &server_id, mesg, &error)
  └─> afp_sl_attach(&url, volume_options, &vol_id)
```

### Disconnection Flow
```
com_disconnect()
  └─> afp_sl_detach(&vol_id, &url)
```

### New Global State
```c
static volumeid_t vol_id = NULL;  // Opaque handle for stateless API
static int connected = 0;         // Track connection state
```

## Implementation Changes

### 1. Header Changes

**Remove:**
```c
#include "midlevel.h"
```

**Add:**
```c
#include "afpsl.h"
```

### 2. Global Variable Changes

**Replace:**
```c
static struct afp_server *server = NULL;
struct afp_volume *vol = NULL;
```

**With:**
```c
static volumeid_t vol_id = NULL;
static int connected = 0;
```

### 3. Connection Management

#### com_connect() - Refactor to use stateless library

**Current code (line 371):**
```c
int com_connect(char * arg)
{
    // ... parse URL ...

    if (server_subconnect()) {
        goto error;
    }

    return connect_volume(url.volumename);
}
```

**New code:**
```c
int com_connect(char * arg)
{
    char mesg[MAX_ERROR_LEN];
    int error = 0;
    unsigned int uam_mask;
    serverid_t server_id;  // Not saved, only used during connection

    // ... existing URL parsing code ...

    // Determine UAM mask
    if (strlen(url.uamname) > 0) {
        if ((uam_mask = find_uam_by_name(url.uamname)) == 0) {
            printf("I don't know about UAM %s\n", url.uamname);
            goto error;
        }
    } else {
        uam_mask = default_uams_mask();
    }

    // Connect to server via stateless library
    if (afp_sl_connect(&url, uam_mask, &server_id, mesg, &error)) {
        printf("Could not connect to server: %s\n", mesg);
        goto error;
    }

    printf("Connected to server %s\n", url.servername);

    // Attach to volume
    if (strlen(url.volumename) > 0) {
        unsigned int volume_options = VOLUME_EXTRA_FLAGS_NO_LOCKING;

        if (afp_sl_attach(&url, volume_options, &vol_id)) {
            printf("Could not attach to volume %s\n", url.volumename);
            goto error;
        }

        printf("Attached to volume %s\n", url.volumename);
        connected = 1;
    }

    return 0;
error:
    return -1;
}
```

#### com_disconnect() - Refactor to use stateless library

**Current code (line 354):**
```c
int com_disconnect(__attribute__((unused)) char * arg)
{
    if (server == NULL) {
        printf("You're not connected yet to a server\n");
        goto error;
    }

    afp_unmount_volume(vol);
    vol = NULL;
    server = NULL;
    snprintf(curdir, AFP_MAX_PATH, "/");
    return 0;
error:
    return -1;
}
```

**New code:**
```c
int com_disconnect(__attribute__((unused)) char * arg)
{
    if (!connected) {
        printf("You're not connected yet to a server\n");
        goto error;
    }

    if (afp_sl_detach(&vol_id, NULL)) {
        printf("Error detaching from volume\n");
    }

    vol_id = NULL;
    connected = 0;
    snprintf(curdir, AFP_MAX_PATH, "/");
    printf("Disconnected\n");
    return 0;
error:
    return -1;
}
```

### 4. File Operations

#### com_ls() / ls_files() - Uses ml_readdir()

**Current code (line 473):**
```c
if (ml_readdir(vol, dir_path, &filebase)) {
    printf("could not get listing\n");
    return -1;
}
```

**New code:**
```c
struct afp_file_info_basic *filebase_basic = NULL;
unsigned int numfiles = 0;
int eod = 0;

if (!connected) {
    printf("Not connected to a volume\n");
    return -1;
}

if (afp_sl_readdir(&vol_id, dir_path, NULL, 0, 100, &numfiles, &filebase_basic, &eod)) {
    printf("could not get listing\n");
    return -1;
}

// Process filebase_basic (different structure than filebase)
for (unsigned int i = 0; i < numfiles; i++) {
    printf("%s\n", filebase_basic[i].name);
}

free(filebase_basic);
```

**Note**: `afp_file_info_basic` is a simpler structure than `afp_file_info`, so print_file_details() needs adjustment or we need to call afp_sl_stat() for each file to get full details.

#### com_get() - Uses ml_getattr(), ml_open(), ml_read(), ml_close()

**Current code (line 688-725):**
```c
if ((ret = ml_getattr(vol, path, stat)) != 0) {
    printf("Could not stat: %s\n", afp_strerror(ret));
    goto error;
}

ret = ml_open(vol, path, flags, &fp);
// ... read loop ...
ret = ml_read(vol, path, buf, size, offset, fp, &eof);
// ...
ml_close(vol, path, fp);
```

**New code:**
```c
struct stat stat;
unsigned int fileid;
unsigned int received, eof = 0;

if (!connected) {
    printf("Not connected\n");
    goto error;
}

// Get file info
if (afp_sl_stat(&vol_id, path, NULL, &stat)) {
    printf("Could not stat file\n");
    goto error;
}

// Open file (O_RDONLY)
if (afp_sl_open(&vol_id, path, NULL, &fileid, O_RDONLY)) {
    printf("Could not open file\n");
    goto error;
}

// Read loop
unsigned long long offset = 0;
while (!eof) {
    ret = afp_sl_read(&vol_id, fileid, 0, offset, COPY_BUFSIZE,
                      &received, &eof, buf);
    if (ret) {
        printf("Read error\n");
        break;
    }

    write(localfd, buf, received);
    offset += received;
}

// Close file
afp_sl_close(&vol_id, fileid);
```

#### com_stat() - Uses ml_getattr()

**Replace ml_getattr() with afp_sl_stat()** at line 688, 763, etc.

### 5. Operations to Disable (Temporarily)

For commands that require operations not yet in the stateless library, add stubs:

```c
int com_put(char * arg)
{
    printf("put command not yet implemented via stateless library\n");
    printf("(requires afp_sl_write and afp_sl_creat)\n");
    return -1;
}

int com_mkdir(char * arg)
{
    printf("mkdir command not yet implemented via stateless library\n");
    printf("(requires afp_sl_mkdir)\n");
    return -1;
}

int com_rm(char * arg)
{
    printf("rm command not yet implemented via stateless library\n");
    printf("(requires afp_sl_unlink)\n");
    return -1;
}

int com_rmdir(char * arg)
{
    printf("rmdir command not yet implemented via stateless library\n");
    printf("(requires afp_sl_rmdir)\n");
    return -1;
}

int com_mv(char * arg)
{
    printf("mv command not yet implemented via stateless library\n");
    printf("(requires afp_sl_rename)\n");
    return -1;
}

int com_chmod(char * arg)
{
    printf("chmod command not yet implemented via stateless library\n");
    printf("(requires afp_sl_chmod)\n");
    return -1;
}
```

### 6. Helper Function Changes

#### Need to remove dependency on vol->* and server->* fields

**Functions that access vol or server directly:**
- `connect_volume()` - Remove, functionality moved to com_connect()
- `server_subconnect()` - Remove, functionality moved to com_connect()
- Any function using `vol->mapping`, `server->server_name_printable`, etc.

## Testing Plan

### Build Steps
```bash
# Build afpsld and libafpsl
meson setup build -Denable-fuse=false
meson compile -C build

# Start afpsld manually (for debugging)
./build/daemon/afpsld

# Run afpcmd
./build/cmdline/afpcmd
```

### Test Sequence
```bash
# Test 1: Connect to server
afp> connect afp://user:pass@server/volume

# Test 2: List directory
afp> ls

# Test 3: Change directory
afp> cd SomeDirectory
afp> ls

# Test 4: Get file info
afp> stat somefile.txt

# Test 5: Download file
afp> get somefile.txt

# Test 6: Disconnect
afp> disconnect

# Test 7: Verify disabled commands
afp> put localfile.txt
# Should print: "put command not yet implemented via stateless library"
```

## Success Criteria

✅ afpcmd connects to AFP server via stateless library
✅ afpcmd can list directories (ls)
✅ afpcmd can get file info (stat)
✅ afpcmd can download files (get)
✅ afpcmd can change directories (cd)
✅ afpcmd properly disconnects
✅ Disabled commands print informative messages
✅ afpsld daemon handles all requests correctly
✅ No crashes or memory leaks

## Next Steps (Stage 2)

After Stage 1 is complete and tested:
1. Implement afp_sl_write() + command handler
2. Implement afp_sl_creat() + command handler
3. Implement afp_sl_chmod() + command handler
4. Implement afp_sl_rename() + command handler
5. Implement afp_sl_unlink() + command handler
6. Implement afp_sl_mkdir() + command handler
7. Implement afp_sl_rmdir() + command handler
8. Implement afp_sl_statfs() + command handler
9. Enable corresponding afpcmd commands
10. Full testing
