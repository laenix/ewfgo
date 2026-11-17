# Mounting an E01 through NBD

`nbdserve` exports a whole image or one partition as a **read-only** Network
Block Device (NBD newstyle protocol). A local NBD client can then attach it as a
block device and the operating system can mount its filesystem read-only.

The server is pure Go and runs on Windows, Linux and macOS. It advertises
`NBD_FLAG_READ_ONLY`; write, trim and flush requests are rejected, so the
evidence image cannot be modified through this path.

## 1. Start the server

```bash
go build -o nbdserve ./cmd/nbdserve

# Whole disk (partition table visible to the client)
./nbdserve -addr 127.0.0.1:10809 -export evidence evidence.E01

# A single partition (raw volume, no partition table)
./nbdserve -addr 127.0.0.1:10809 -export part2 -partition 2 evidence.E01
```

The default address is `127.0.0.1:10809`, the IANA NBD port. The default export
name is the image's base name. Keep the default loopback binding unless you
have a trusted, isolated network: the server has no authentication or TLS.

`-unix /path/to/socket` binds a Unix domain socket instead of TCP on platforms
that support them.

## 2. Attach and mount on Linux

The Linux kernel has a built-in NBD client. Install the userspace `nbd-client`
package and load the module once:

```bash
sudo modprobe nbd max_part=16
```

Attach the export to `/dev/nbd0`, using the export name from `-export`:

```bash
sudo nbd-client -N evidence 127.0.0.1 10809 /dev/nbd0
lsblk /dev/nbd0
```

For a **whole-disk** export, mount the partition you need:

```bash
sudo mount -o ro /dev/nbd0p1 /mnt/evidence
```

For a **partition** export (`-partition 2`), the whole device is the volume:

```bash
sudo mount -o ro /dev/nbd0 /mnt/evidence
```

When finished:

```bash
sudo umount /mnt/evidence
sudo nbd-client -d /dev/nbd0
```

If the filesystem is not supported by the host kernel (APFS, ZFS, BitLocker,
LUKS, …), mount the block device with the matching userspace driver, or use
this library's filesystem readers directly instead of mounting.

## 3. Verify the export without mounting

QEMU's NBD client works on Windows, Linux and macOS and is enough to prove that
the export is readable:

```bash
qemu-img info "nbd://127.0.0.1:10809/evidence"
```

Export it to a raw file when a tool needs a file path:

```bash
qemu-img convert -f raw -O raw "nbd://127.0.0.1:10809/evidence" evidence.raw
```

`qemu-img convert` reads through NBD and writes a separate raw file; the
original E01 and the NBD export stay read-only.

On Windows, QEMU can also attach the export as a virtual disk to a VM
(`-drive file=nbd://127.0.0.1:10809/evidence,format=raw,if=virtio`). Native
Windows has no kernel NBD client, so WSL2 plus `nbd-client` or a QEMU VM is the
mount path there. macOS has no built-in NBD client either; use QEMU or a
FUSE-based NBD client.

## 4. Library API

The CLI is a thin wrapper over the public `nbd` package:

```go
img, err := forensic.Open(ctx, "evidence.E01", forensic.Options{})
if err != nil {
    return err
}
defer img.Close()

exp := nbd.NewExporter(img.Source()) // whole image
// exp = nbd.NewExporter(parts[0].Source()) // one partition

listener, err := nbd.Listen("127.0.0.1:10809", exp, "evidence")
if err != nil {
    return err
}
defer listener.Close()
return listener.Serve()
```

A runnable version is in [`examples/nbd`](../examples/nbd). The CLI is
[`cmd/nbdserve`](../cmd/nbdserve).

## Limits

- One export per server process; start another process for another image or
  partition.
- The protocol is unauthenticated. Bind to loopback, or put it behind an
  authenticated tunnel.
- Reads are served on demand from the original image; no raw copy is created.
  Filesystem support for mounting is the host's responsibility, not this
  library's.
