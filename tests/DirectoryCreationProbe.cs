// ADR-025 synthetic research ONLY. NEVER imported by WinTriage.ps1 or src/.
// Parent-relative NtCreateFile FILE_CREATE, returning the new directory handle.
// Only test-owned GUID directories; no real reports, deletion or scanning.
using System;
using System.IO;
using System.Text.RegularExpressions;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace WinTriageTests
{
    public static class DirectoryCreationProbe
    {
        private const uint FILE_READ_ATTRIBUTES = 0x80;
        private const uint FILE_TRAVERSE = 0x20;
        private const uint FILE_ADD_SUBDIRECTORY = 0x4;
        private const uint READ_CONTROL = 0x00020000;
        private const uint SYNCHRONIZE = 0x00100000;
        private const uint FILE_SHARE_READ = 0x1;
        private const uint FILE_SHARE_WRITE = 0x2;
        private const uint FILE_SHARE_DELETE = 0x4; // Explicitly test-only rename sharing.
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_CREATE = 2;
        private const uint FILE_ATTRIBUTE_NORMAL = 0x80;
        private const uint FILE_ATTRIBUTE_DIRECTORY = 0x10;
        private const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x400;
        private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
        private const uint FILE_DIRECTORY_FILE = 0x00000001;
        private const uint FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020;
        private const uint OBJ_CASE_INSENSITIVE = 0x40;
        private const int FILE_CREATED = 2;

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
        private static extern SafeFileHandle OpenDirectory(
            string fileName, uint desiredAccess, uint shareMode,
            IntPtr attributes, uint disposition, uint flags, IntPtr templateFile);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out ByHandleInfo info);
        [DllImport("ntdll.dll", ExactSpelling = true)]
        private static extern int NtCreateFile(
            out SafeFileHandle handle, uint access,
            ref ObjectAttributes attributes, out IoStatusBlock ioStatus,
            IntPtr allocationSize, uint fileAttributes, uint shareAccess,
            uint disposition, uint createOptions, IntPtr eaBuffer, uint eaLength);

        private static void ValidateHandle(SafeFileHandle handle)
        {
            ByHandleInfo info;
            if (handle == null || handle.IsClosed || handle.IsInvalid ||
                !GetFileInformationByHandle(handle, out info) ||
                (info.Attributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
                (info.Attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
                throw new IOException("Synthetic directory handle was not a direct directory.");
        }

        public static SafeFileHandle PinParentForSyntheticTest(string path)
        {
            if (String.IsNullOrEmpty(path)) throw new ArgumentException("Missing synthetic parent.");
            SafeFileHandle h = OpenDirectory(path,
                FILE_READ_ATTRIBUTES | FILE_TRAVERSE | FILE_ADD_SUBDIRECTORY | READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                IntPtr.Zero, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
            try { ValidateHandle(h); return h; }
            catch { if (h != null) h.Dispose(); throw; }
        }

        // Return the SAME handle that NtCreateFile returned at creation time:
        // no second path lookup of the child or fallback to CreateDirectoryW.
        // The caller must own and dispose this handle.
        public static SafeFileHandle CreateChildRelative(
            SafeFileHandle parent, string leaf, byte[] securityDescriptor)
        {
            if (parent == null || parent.IsInvalid || parent.IsClosed)
                throw new ArgumentException("Missing synthetic parent handle.");
            if (String.IsNullOrEmpty(leaf) || leaf.Length > 80 ||
                !Regex.IsMatch(leaf, @"^[A-Za-z][A-Za-z0-9_-]{5,79}$"))
                throw new ArgumentException("Invalid synthetic directory leaf.");
            if (securityDescriptor == null || securityDescriptor.Length == 0 ||
                securityDescriptor.Length > 65536)
                throw new ArgumentException("Missing synthetic private descriptor.");

            bool borrowed = false;
            IntPtr name = IntPtr.Zero;
            IntPtr namePointer = IntPtr.Zero;
            IntPtr securityPointer = IntPtr.Zero;
            SafeFileHandle child = null;
            try
            {
                parent.DangerousAddRef(ref borrowed);
                ValidateHandle(parent);
                name = Marshal.StringToHGlobalUni(leaf);
                UnicodeString str = new UnicodeString();
                str.Buffer = name;
                str.Length = checked((ushort)(leaf.Length * 2));
                str.MaximumLength = checked((ushort)((leaf.Length + 1) * 2));
                namePointer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UnicodeString)));
                Marshal.StructureToPtr(str, namePointer, false);
                securityPointer = Marshal.AllocHGlobal(securityDescriptor.Length);
                Marshal.Copy(securityDescriptor, 0, securityPointer, securityDescriptor.Length);

                ObjectAttributes attributes = new ObjectAttributes();
                attributes.Length = Marshal.SizeOf(typeof(ObjectAttributes));
                attributes.RootDirectory = parent.DangerousGetHandle();
                attributes.ObjectName = namePointer;
                attributes.Attributes = OBJ_CASE_INSENSITIVE;
                attributes.SecurityDescriptor = securityPointer;

                IoStatusBlock io;
                int status = NtCreateFile(out child,
                    FILE_READ_ATTRIBUTES | READ_CONTROL | FILE_TRAVERSE | SYNCHRONIZE,
                    ref attributes, out io, IntPtr.Zero, FILE_ATTRIBUTE_NORMAL,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    FILE_CREATE, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                    IntPtr.Zero, 0);
                if (status != 0)
                    throw new IOException("Synthetic directory FILE_CREATE refused. NTSTATUS=0x" +
                        unchecked((uint)status).ToString("X8"));
                if (io.Information != new IntPtr(FILE_CREATED))
                    throw new IOException("Synthetic directory creation was not exclusive.");
                ValidateHandle(child);
                SafeFileHandle result = child;
                child = null; // transfer sole ownership to the test caller
                return result;
            }
            finally
            {
                if (child != null) child.Dispose();
                if (securityPointer != IntPtr.Zero) Marshal.FreeHGlobal(securityPointer);
                if (namePointer != IntPtr.Zero) Marshal.FreeHGlobal(namePointer);
                if (name != IntPtr.Zero) Marshal.FreeHGlobal(name);
                if (borrowed) parent.DangerousRelease();
            }
        }
    }
}
