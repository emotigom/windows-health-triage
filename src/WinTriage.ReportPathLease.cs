// Copyright (c) contributors to Windows Health Triage. MIT licensed.
// Windows-only directory path identity lease: pin each ancestor with
// a metadata-only handle and compare on-disk file IDs at write checkpoints.
// Delete sharing is omitted as defense-in-depth, but Windows may still allow
// directory rename through parent rights. NOT a race-free filesystem sandbox.
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace WinTriage
{
    public sealed class ReportPathLease : IDisposable
    {
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_READ_ATTRIBUTES = 0x80;
        private const uint FILE_ADD_FILE = 0x2;
        private const uint FILE_SHARE_READ = 1;
        private const uint FILE_SHARE_WRITE = 2;
        private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
        private const uint FILE_ATTRIBUTE_DIRECTORY = 0x10;
        private const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x400;

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        private struct ByHandleInfo
        {
            public uint Attributes;
            public long CreationTime;
            public long LastAccessTime;
            public long LastWriteTime;
            public uint VolumeSerial;
            public uint FileSizeHigh;
            public uint FileSizeLow;
            public uint NumberOfLinks;
            public uint FileIndexHigh;
            public uint FileIndexLow;
        }

        [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle OpenDirectory(
            string fileName, uint desiredAccess, uint shareMode, IntPtr securityAttributes,
            uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileInformationByHandle(SafeFileHandle file, out ByHandleInfo information);

        private readonly List<SafeFileHandle> handles = new List<SafeFileHandle>();
        private readonly List<string> components = new List<string>();
        private readonly List<ByHandleInfo> identities = new List<ByHandleInfo>();
        private bool disposed;

        private ReportPathLease() { }

        private static SafeFileHandle OpenChecked(string path, bool requireFileCreation, out ByHandleInfo info)
        {
            // Request FILE_READ_ATTRIBUTES rather than zero desired access so the
            // handle participates in ordinary filesystem sharing checks.
            // Share read and write, but
            // intentionally NOT share delete/rename.
            SafeFileHandle handle = OpenDirectory(path,
                FILE_READ_ATTRIBUTES | (requireFileCreation ? FILE_ADD_FILE : 0),
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
            if (handle == null || handle.IsInvalid)
            {
                if (handle != null) handle.Dispose();
                throw new IOException("Report path cannot be pinned (open).");
            }
            if (!GetFileInformationByHandle(handle, out info) ||
                (info.Attributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
                (info.Attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
            {
                handle.Dispose();
                throw new IOException("Report path is not a direct readable local directory.");
            }
            return handle;
        }

        private static bool IsSame(ByHandleInfo x, ByHandleInfo y)
        {
            return x.VolumeSerial == y.VolumeSerial &&
                   x.FileIndexHigh == y.FileIndexHigh &&
                   x.FileIndexLow == y.FileIndexLow;
        }

        public static ReportPathLease Acquire(string directory)
        {
            if (String.IsNullOrEmpty(directory))
                throw new ArgumentException("Missing report path.");
            string full = Path.GetFullPath(directory);
            string root = Path.GetPathRoot(full);
            if (String.IsNullOrEmpty(root) || root.StartsWith(@"\\") || root.StartsWith("//"))
                throw new IOException("Only a direct local drive is supported.");

            ReportPathLease lease = new ReportPathLease();
            try
            {
                string current = root;
                lease.Pin(current, false);
                string tail = full.Substring(root.Length);
                if (tail.Length == 0) throw new IOException("Cannot write reports at a drive root.");
                string[] parts = tail.Split(new char[] { '\\', '/' }, StringSplitOptions.RemoveEmptyEntries);
                for (int i = 0; i < parts.Length; i++)
                {
                    current = Path.Combine(current, parts[i]);
                    lease.Pin(current, i == parts.Length - 1);
                }
                lease.AssertStable();
                return lease;
            }
            catch
            {
                lease.Dispose();
                throw;
            }
        }

        private void Pin(string path, bool requireFileCreation)
        {
            ByHandleInfo info;
            SafeFileHandle h = OpenChecked(path, requireFileCreation, out info);
            handles.Add(h);
            components.Add(path);
            identities.Add(info);
        }

        public void AssertStable()
        {
            if (disposed) throw new ObjectDisposedException("ReportPathLease");
            for (int i = 0; i < components.Count; i++)
            {
                ByHandleInfo now;
                using (SafeFileHandle current = OpenChecked(components[i], false, out now))
                {
                    if (!IsSame(identities[i], now))
                        throw new IOException("Report path identity changed.");
                }
            }
        }

        // The final pinned directory handle is the RootDirectory for the native
        // FILE_CREATE operation: no second path lookup to open a report file.
        public void WriteNewUtf8(string leafName, string content, bool emitBom)
        {
            AssertStable();
            if (handles.Count < 2) throw new IOException("Missing private report directory handle.");
            HandleBoundReportWriter.WriteNewUtf8(handles[handles.Count - 1], leafName, content, emitBom);
        }

        public void Dispose()
        {
            if (disposed) return;
            disposed = true;
            for (int i = handles.Count - 1; i >= 0; i--)
                handles[i].Dispose();
            handles.Clear();
            identities.Clear();
            components.Clear();
        }
    }
}
