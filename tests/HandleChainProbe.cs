// ADR-026 TEST ONLY: constrain a multi-hop child walk to an already held anchor.
// No production import. Type-neutral FILE_OPEN + FILE_OPEN_REPARSE_POINT is
// intentionally different from the unconfirmed directory-specific combination.
// It rejects a returned reparse object; never follows paths as a fallback.
using System;
using System.IO;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace WinTriageTests
{
    public static class HandleChainProbe
    {
        private const uint FILE_READ_ATTRIBUTES = 0x80;
        private const uint FILE_TRAVERSE = 0x20;
        private const uint FILE_ADD_SUBDIRECTORY = 0x4;
        private const uint READ_CONTROL = 0x00020000;
        private const uint SYNCHRONIZE = 0x00100000;
        private const uint FILE_SHARE_READ = 1;
        private const uint FILE_SHARE_WRITE = 2;
        private const uint FILE_SHARE_DELETE = 4; // Test-only swap fixture.
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_OPEN = 1;
        private const uint FILE_ATTRIBUTE_NORMAL = 0x80;
        private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
        private const uint FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020;
        private const uint FILE_OPEN_REPARSE_POINT = 0x00200000;
        private const uint FILE_ATTRIBUTE_DIRECTORY = 0x10;
        private const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x400;
        private const uint OBJ_CASE_INSENSITIVE = 0x40;

        [StructLayout(LayoutKind.Sequential)]
        private struct UnicodeString
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ObjectAttributes
        {
            public int Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IoStatusBlock
        {
            public IntPtr Status;
            public IntPtr Information;
        }

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
        private static extern SafeFileHandle OpenWin32Directory(
            string path, uint access, uint shares, IntPtr security,
            uint disposition, uint flags, IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out ByHandleInfo info);

        [DllImport("ntdll.dll", ExactSpelling = true)]
        private static extern int NtCreateFile(
            out SafeFileHandle handle, uint access, ref ObjectAttributes attributes,
            out IoStatusBlock ioStatus, IntPtr allocationSize, uint fileAttributes,
            uint shares, uint disposition, uint createOptions, IntPtr eaBuffer,
            uint eaLength);

        private static ByHandleInfo CheckedInfo(SafeFileHandle handle)
        {
            ByHandleInfo info;
            if (handle == null || handle.IsInvalid || handle.IsClosed ||
                !GetFileInformationByHandle(handle, out info) ||
                (info.Attributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
                (info.Attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
                throw new IOException("Synthetic hop is not a direct directory handle.");
            return info;
        }

        public static string Identity(SafeFileHandle handle)
        {
            ByHandleInfo info = CheckedInfo(handle);
            return info.VolumeSerial.ToString("X8") + ":" +
                info.FileIndexHigh.ToString("X8") + ":" + info.FileIndexLow.ToString("X8");
        }

        // The only absolute open is this synthetic, test-owned known anchor.
        // The ancestor-to-anchor trust problem is NOT solved by this probe.
        public static SafeFileHandle PinSyntheticAnchor(string path)
        {
            if (String.IsNullOrEmpty(path)) throw new ArgumentException("Missing test anchor.");
            SafeFileHandle handle = OpenWin32Directory(path,
                FILE_READ_ATTRIBUTES | FILE_TRAVERSE | FILE_ADD_SUBDIRECTORY | READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                IntPtr.Zero, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
            try { CheckedInfo(handle); return handle; }
            catch { if (handle != null) handle.Dispose(); throw; }
        }

        // Synthetic-only: caller supplies an independently established trusted
        // volume/file identity. This does NOT establish where that trust originates.
        // Compare on the acquired handle, not through a second pathname open.
        public static SafeFileHandle PinSyntheticAnchorExpectIdentity(string path, string trustedId)
        {
            if (String.IsNullOrEmpty(trustedId))
                throw new ArgumentException("Missing independently trusted synthetic identity.");
            SafeFileHandle handle = PinSyntheticAnchor(path);
            try
            {
                if (!String.Equals(Identity(handle), trustedId, StringComparison.Ordinal))
                    throw new IOException("Synthetic anchor identity mismatched.");
                return handle;
            }
            catch
            {
                handle.Dispose();
                throw;
            }
        }

        private static SafeFileHandle OpenExistingChild(SafeFileHandle parent, string name)
        {
            bool borrowed = false;
            IntPtr nameBuffer = IntPtr.Zero;
            IntPtr namePointer = IntPtr.Zero;
            SafeFileHandle result = null;
            try
            {
                parent.DangerousAddRef(ref borrowed);
                CheckedInfo(parent);
                nameBuffer = Marshal.StringToHGlobalUni(name);
                UnicodeString str = new UnicodeString();
                str.Buffer = nameBuffer;
                str.Length = checked((ushort)(name.Length * 2));
                str.MaximumLength = checked((ushort)((name.Length + 1) * 2));
                namePointer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UnicodeString)));
                Marshal.StructureToPtr(str, namePointer, false);
                ObjectAttributes attributes = new ObjectAttributes();
                attributes.Length = Marshal.SizeOf(typeof(ObjectAttributes));
                attributes.RootDirectory = parent.DangerousGetHandle();
                attributes.ObjectName = namePointer;
                attributes.Attributes = OBJ_CASE_INSENSITIVE;
                IoStatusBlock io;
                int status = NtCreateFile(out result,
                    FILE_READ_ATTRIBUTES | FILE_TRAVERSE | FILE_ADD_SUBDIRECTORY |
                    READ_CONTROL | SYNCHRONIZE,
                    ref attributes, out io, IntPtr.Zero, FILE_ATTRIBUTE_NORMAL,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    FILE_OPEN,
                    FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
                    IntPtr.Zero, 0);
                if (status != 0)
                    throw new IOException("Synthetic handle-relative hop refused. NTSTATUS=0x" +
                        unchecked((uint)status).ToString("X8"));
                CheckedInfo(result);
                SafeFileHandle returned = result;
                result = null;
                return returned;
            }
            finally
            {
                if (result != null) result.Dispose();
                if (namePointer != IntPtr.Zero) Marshal.FreeHGlobal(namePointer);
                if (nameBuffer != IntPtr.Zero) Marshal.FreeHGlobal(nameBuffer);
                if (borrowed) parent.DangerousRelease();
            }
        }

        public static SafeFileHandle Walk(SafeFileHandle anchor, string[] leaves)
        {
            return WalkCore(anchor, leaves, null);
        }

        // Deterministic interleaving BEFORE opening a hop. Not exposed to CLI.
        // A test can replace only its own GUID fixture at the native boundary.
        public static SafeFileHandle WalkWithSyntheticBeforeHop(
            SafeFileHandle anchor, string[] leaves, Action<int> beforeHop)
        {
            if (beforeHop == null) throw new ArgumentNullException("beforeHop");
            return WalkCore(anchor, leaves, beforeHop);
        }

        private static SafeFileHandle WalkCore(
            SafeFileHandle anchor, string[] leaves, Action<int> beforeHop)
        {
            if (anchor == null || anchor.IsInvalid || anchor.IsClosed)
                throw new ArgumentException("Missing synthetic anchor handle.");
            if (leaves == null || leaves.Length == 0 || leaves.Length > 8)
                throw new ArgumentException("Invalid synthetic hop count.");
            // Validate all leaves BEFORE any native call.
            foreach (string leaf in leaves)
            {
                if (String.IsNullOrEmpty(leaf) || leaf.Length > 80 ||
                    !Regex.IsMatch(leaf, @"^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$"))
                    throw new ArgumentException("Invalid synthetic leaf component.");
            }

            List<SafeFileHandle> held = new List<SafeFileHandle>();
            try
            {
                CheckedInfo(anchor);
                SafeFileHandle cursor = anchor;
                for (int index = 0; index < leaves.Length; index++)
                {
                    // Caller remains responsible for anchor provenance. Any
                    // mutated directory must be checked by the native open.
                    CheckedInfo(cursor);
                    if (beforeHop != null) beforeHop(index);
                    SafeFileHandle opened = OpenExistingChild(cursor, leaves[index]);
                    held.Add(opened);
                    cursor = opened;
                }
                SafeFileHandle last = held[held.Count - 1];
                held.RemoveAt(held.Count - 1);
                return last;
            }
            finally
            {
                // Keep all intermediate parents open until the final child is
                // acquired; dispose them even if an inner hop fails.
                for (int i = held.Count - 1; i >= 0; i--) held[i].Dispose();
            }
        }
    }
}
