# Phase 4: cmdline Migration Analysis

## Overview

Migrate `cmdline/afpcmd` from using the midlevel API (`ml_*`) directly to using the stateless library API (`afp_sl_*`).

**Strategy**: Incremental migration in two stages:
1. **Stage 1 (PRIORITY)**: Refactor afpcmd to use existing stateless library operations - proves the stateless library actually works
2. **Stage 2**: Add missing operations to stateless library, complete the migration

## Current State

**cmdline/cmdline_afp.c** currently:
- Uses `#include "midlevel.h"` directly
- Maintains global `struct afp_server *server` and `struct afp_volume *vol`
- Calls `ml_*()` functions directly

## Required Stateless Library Extensions

### Operations Used by cmdline/cmdline_afp.c

| ml_* function | afp_sl_* equivalent | Status | Lines in cmdline_afp.c |
|---------------|---------------------|--------|------------------------|
| ml_readdir() | afp_sl_readdir() | ✅ EXISTS | 473, 1515 |
| ml_getattr() | afp_sl_stat() | ✅ EXISTS | 688, 694, 763, 879, 886, 921, 986, 1000, 1035, 1427, 1641 |
| ml_open() | afp_sl_open() | ✅ EXISTS | 608, 694, 1053, 1071 |
| ml_read() | afp_sl_read() | ✅ EXISTS | 705, 1087 |
| ml_close() | afp_sl_close() | ✅ EXISTS | 658, 725, 1116, 1117, 1123, 1125 |
| ml_write() | afp_sl_write() | ❌ MISSING | 641, 1099 |
| ml_creat() | afp_sl_creat() | ❌ MISSING | 513, 1062 |
| ml_chmod() | afp_sl_chmod() | ❌ MISSING | 551, 618 |
| ml_rename() | afp_sl_rename() | ❌ MISSING | 938 |
| ml_unlink() | afp_sl_unlink() | ❌ MISSING | 1148 |
| ml_mkdir() | afp_sl_mkdir() | ❌ MISSING | 1178 |
| ml_rmdir() | afp_sl_rmdir() | ❌ MISSING | 1208 |
| ml_statfs() | afp_sl_statfs() | ❌ MISSING | 1268 |

## Implementation Plan

### Step 1: Add Command Constants

Add to `include/afpfsd.h`:
```c
#define AFP_SERVER_COMMAND_WRITE 27
#define AFP_SERVER_COMMAND_CREAT 28
#define AFP_SERVER_COMMAND_CHMOD 29
#define AFP_SERVER_COMMAND_RENAME 30
#define AFP_SERVER_COMMAND_UNLINK 31
#define AFP_SERVER_COMMAND_MKDIR 32
#define AFP_SERVER_COMMAND_RMDIR 33
#define AFP_SERVER_COMMAND_STATFS 34
```

### Step 2: Define Request/Response Structures

Add to `include/afpfsd.h` for each operation:

#### WRITE
```c
struct afp_server_write_request {
    struct afp_server_request_header header;
    volumeid_t volumeid;
    unsigned int fileid;
    unsigned long long offset;
    unsigned int length;
    unsigned int uid;
    unsigned int gid;
    char data[0];  // Variable length
};

struct afp_server_write_response {
    struct afp_server_response_header header;
    unsigned int written;
};
```

#### CREAT
```c
struct afp_server_creat_request {
    struct afp_server_request_header header;
    volumeid_t volumeid;
    char path[AFP_MAX_PATH];
    mode_t mode;
};

struct afp_server_creat_response {
    struct afp_server_response_header header;
};
```

#### CHMOD
```c
struct afp_server_chmod_request {
    struct afp_server_request_header header;
    volumeid_t volumeid;
    char path[AFP_MAX_PATH];
    mode_t mode;
};

struct afp_server_chmod_response {
    struct afp_server_response_header header;
};
```

#### RENAME
```c
struct afp_server_rename_request {
    struct afp_server_request_header header;
    volumeid_t volumeid;
    char path_from[AFP_MAX_PATH];
    char path_to[AFP_MAX_PATH];
};

struct afp_server_rename_response {
    struct afp_server_response_header header;
};
```

#### UNLINK
```c
struct afp_server_unlink_request {
    struct afp_server_request_header header;
    volumeid_t volumeid;
    char path[AFP_MAX_PATH];
};

struct afp_server_unlink_response {
    struct afp_server_response_header header;
};
```

#### MKDIR
```c
struct afp_server_mkdir_request {
    struct afp_server_request_header header;
    volumeid_t volumeid;
    char path[AFP_MAX_PATH];
    mode_t mode;
};

struct afp_server_mkdir_response {
    struct afp_server_response_header header;
};
```

#### RMDIR
```c
struct afp_server_rmdir_request {
    struct afp_server_request_header header;
    volumeid_t volumeid;
    char path[AFP_MAX_PATH];
};

struct afp_server_rmdir_response {
    struct afp_server_response_header header;
};
```

#### STATFS
```c
struct afp_server_statfs_request {
    struct afp_server_request_header header;
    volumeid_t volumeid;
    char path[AFP_MAX_PATH];
};

struct afp_server_statfs_response {
    struct afp_server_response_header header;
    struct afp_volstats stats;
};
```

### Step 3: Implement Command Handlers in daemon/commands.c

For each operation, add a handler function following the existing pattern:
- Extract request data
- Find volume by volumeid
- Call appropriate ml_* function
- Build response
- Send response

Example pattern (for WRITE):
```c
static int handle_write(struct afpfsd_client *c)
{
    struct afp_server_write_request *req = (void *)c->incoming_buffer;
    struct afp_server_write_response response;
    struct afp_volume *vol;
    int ret;
    unsigned int written;

    // Find volume
    vol = find_volume_by_volumeid(&req->volumeid);
    if (!vol) {
        response.header.result = AFP_SERVER_RESULT_ERROR;
        response.written = 0;
        afpfsd_send_response(c, (void *)&response, sizeof(response));
        return -1;
    }

    // Call midlevel function
    ret = ml_write(vol, req->path, req->data, req->length,
                   req->offset, req->fileid, req->uid, req->gid);

    // Build response
    response.header.result = (ret >= 0) ? AFP_SERVER_RESULT_OKAY : AFP_SERVER_RESULT_ERROR;
    response.written = (ret >= 0) ? ret : 0;

    afpfsd_send_response(c, (void *)&response, sizeof(response));
    return ret;
}
```

### Step 4: Implement Stateless Library Functions in daemon/stateless.c

For each operation, implement the client-side function following the existing pattern:
- Check connection with `afp_sl_setup()`
- Build request structure
- Send command with `send_command()`
- Read answer with `read_answer()`
- Parse response
- Return result

### Step 5: Add Function Declarations to include/afpsl.h

```c
int afp_sl_write(volumeid_t *volid, unsigned int fileid,
                 const char *data, unsigned int length,
                 unsigned long long offset,
                 unsigned int uid, unsigned int gid,
                 unsigned int *written);

int afp_sl_creat(volumeid_t *volid, const char *path, mode_t mode);

int afp_sl_chmod(volumeid_t *volid, const char *path, mode_t mode);

int afp_sl_rename(volumeid_t *volid, const char *path_from,
                  const char *path_to);

int afp_sl_unlink(volumeid_t *volid, const char *path);

int afp_sl_mkdir(volumeid_t *volid, const char *path, mode_t mode);

int afp_sl_rmdir(volumeid_t *volid, const char *path);

int afp_sl_statfs(volumeid_t *volid, const char *path,
                  struct afp_volstats *stats);
```

### Step 6: Refactor cmdline/cmdline_afp.c

Changes required:
1. Remove `#include "midlevel.h"`
2. Add `#include "afpsl.h"`
3. Replace `struct afp_server *server` with `serverid_t server_id`
4. Replace `struct afp_volume *vol` with `volumeid_t vol_id`
5. Add connection management:
   - Call `afp_sl_connect()` on server connection
   - Call `afp_sl_attach()` on volume mount
   - Call `afp_sl_detach()` on volume unmount
6. Replace all `ml_*` calls with `afp_sl_*` equivalents

## Testing Plan

1. Build afpsld and libafpsl.so with new functions
2. Build afpcmd with stateless library
3. Test each command operation:
   - connect/disconnect to server
   - attach/detach volume
   - list directory (ls)
   - get file (get)
   - put file (put)
   - create directory (mkdir)
   - remove directory (rmdir)
   - delete file (rm)
   - rename file/directory (mv)
   - change permissions (chmod)
   - show disk usage (df)

## REVISED Implementation Order

### Stage 1: Prove Stateless Library Works (PRIORITY)

**Goal**: Demonstrate end-to-end functionality of the stateless library with existing operations.

**Operations available in stateless library:**
- ✅ afp_sl_connect() - Server connection
- ✅ afp_sl_attach() - Volume attach
- ✅ afp_sl_detach() - Volume detach
- ✅ afp_sl_getvolid() - Get volume ID
- ✅ afp_sl_readdir() - Directory listing
- ✅ afp_sl_stat() - File/dir attributes (replaces ml_getattr)
- ✅ afp_sl_open() - Open file
- ✅ afp_sl_read() - Read file data
- ✅ afp_sl_close() - Close file
- ✅ afp_sl_getvols() - List volumes on server
- ✅ afp_sl_serverinfo() - Get server info

**afpcmd commands we can fully implement with existing operations:**
1. **connect** - Uses afp_sl_connect()
2. **disconnect** - Uses afp_sl_detach()
3. **ls** (list directory) - Uses afp_sl_readdir() + afp_sl_stat()
4. **get** (download file) - Uses afp_sl_stat() + afp_sl_open() + afp_sl_read() + afp_sl_close()
5. **stat** (show file info) - Uses afp_sl_stat()
6. **df** (disk free) - Uses afp_sl_statfs() if it exists, or disable for now
7. **testafp** commands - Most can work with existing operations

**afpcmd commands that require new operations (defer to Stage 2):**
- **put** (upload file) - Needs afp_sl_write() + afp_sl_creat()
- **mkdir** - Needs afp_sl_mkdir()
- **rm** (delete file) - Needs afp_sl_unlink()
- **rmdir** - Needs afp_sl_rmdir()
- **mv** (rename) - Needs afp_sl_rename()
- **chmod** - Needs afp_sl_chmod()

**Implementation steps for Stage 1:**
1. Refactor cmdline/cmdline_afp.c:
   - Remove direct `struct afp_server *server` and `struct afp_volume *vol` globals
   - Add `volumeid_t vol_id` instead
   - Change initialization to use afp_sl_connect() and afp_sl_attach()
   - Refactor ls command to use afp_sl_readdir()
   - Refactor get command to use afp_sl_stat/open/read/close
   - For commands requiring missing operations, print "Not yet implemented via stateless library"
2. Build and test with afpsld
3. Verify: connect → attach → ls → get → detach works end-to-end

### Stage 2: Complete the Migration

**Goal**: Add missing operations and complete full afpcmd migration.

**New operations to implement (in order of simplicity):**
1. **CREAT** - Simple file creation
2. **CHMOD** - Simple permission change
3. **MKDIR** - Simple directory creation
4. **RMDIR** - Simple directory removal
5. **UNLINK** - Simple file deletion
6. **RENAME** - Two paths
7. **STATFS** - Filesystem stats (may already be handled by existing code)
8. **WRITE** - Most complex (variable-length data)

For each operation:
- Add command constant to include/afpfsd.h
- Add request/response structures
- Implement handler in daemon/commands.c
- Implement client function in daemon/stateless.c
- Add declaration to include/afpsl.h
- Refactor corresponding afpcmd command

## Notes

- Stage 1 will prove the stateless architecture works without needing to implement all operations
- The WRITE command is the most complex because it needs to handle variable-length data like READ
- Need to ensure proper buffer sizing for WRITE requests (similar to READ response)
- All operations need proper volumeid lookup and validation
- Error codes from ml_* functions need to be properly propagated through the stateless API
