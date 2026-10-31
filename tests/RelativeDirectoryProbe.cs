// Test-only Windows interop for ADR-023. NEVER imported by the production CLI.
// Opens existing directories only: FILE_OPEN, no create/write/delete disposition.
// A successful hosted-Windows observation is not a supported race-free contract.
using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace WinTriageTests
{
    public static class RelativeDirectoryProbe
    {
        private const uint FILE_READ_ATTRIBUTES = 0x0080;
        private const uint FILE_TRAVERSE = 0x0020;
        private const uint SYNCHRONIZE = 0x00100000;
        private const uint FILE_SHARE_READ = 1;
        private const uint FILE_SHARE_WRITE = 2;
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_OPEN = 1;
        private const uint FILE_ATTRIBUTE_NORMAL = 0x80;
        private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
        private const uint FILE_DIRECTORY_FILE = 0x00000001;
        private const uint FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020;
        private const uint FILE_OPEN_REPARSE_POINT = 0x00200000;
        private const uint OBJ_CASE_INSENSITIVE = 0x40;
        private const uint FILE_ATTRIBUTE_DIRECTORY = 0x10;
        private const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x400;

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
            string path, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out ByHandleInfo info);

        [DllImport("ntdll.dll", ExactSpelling = true)]
        private static extern int NtCreateFile(
            out SafeFileHandle handle,
            uint access,
            ref ObjectAttributes attributes,
            out IoStatusBlock ioStatus,
            IntPtr allocationSize,
            uint fileAttributes,
            uint shareAccess,
            uint disposition,
            uint createOptions,
            IntPtr eaBuffer,
            uint eaLength);

        private static string Identify(SafeFileHandle handle)
        {
            ByHandleInfo info;
            if (handle == null || handle.IsClosed || handle.IsInvalid ||
                !GetFileInformationByHandle(handle, out info) ||
                (info.Attributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
                (info.Attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
                throw new IOException("Synthetic directory handle cannot be identified without a reparse.");
            return info.VolumeSerial.ToString("X8") + ":" +
                info.FileIndexHigh.ToString("X8") + ":" + info.FileIndexLow.ToString("X8");
        }

        public static SafeFileHandle PinTestParent(string directory)
        {
            if (String.IsNullOrEmpty(directory)) throw new ArgumentException("Missing synthetic parent.");
            SafeFileHandle handle = OpenWin32Directory(directory,
                FILE_READ_ATTRIBUTES | FILE_TRAVERSE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                IntPtr.Zero, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
            try
            {
                Identify(handle);
                return handle;
            }
            catch
            {
                if (handle != null) handle.Dispose();
                throw;
            }
        }

        public static string IdentifyTestDirectory(string path)
        {
            using (SafeFileHandle h = PinTestParent(path))
                return Identify(h);
        }

        // Single leaf only. This method cannot create, replace, or write a file.
        // The FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT combination is a
        // research question, not a claimed universally supported configuration.
        public static string IdentifyChildRelative(SafeFileHandle parent, string leaf)
        {
            if (parent == null || parent.IsInvalid || parent.IsClosed ||
                String.IsNullOrEmpty(leaf) || leaf == "." || leaf == ".." ||
                leaf.IndexOfAny(new char[] {'/', '\\', ':'}) >= 0 ||
                leaf.EndsWith(".", StringComparison.Ordinal) ||
                leaf.EndsWith(" ", StringComparison.Ordinal))
                throw new ArgumentException("Invalid synthetic parent handle or child name.");

            bool borrowed = false;
            IntPtr nameBuffer = IntPtr.Zero;
            IntPtr unicodePointer = IntPtr.Zero;
            SafeFileHandle child = null;
            try
            {
                parent.DangerousAddRef(ref borrowed);
                nameBuffer = Marshal.StringToHGlobalUni(leaf);
                UnicodeString u = new UnicodeString();
                u.Buffer = nameBuffer;
                u.Length = checked((ushort)(leaf.Length * 2));
                u.MaximumLength = checked((ushort)((leaf.Length + 1) * 2));
                unicodePointer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UnicodeString)));
                Marshal.StructureToPtr(u, unicodePointer, false);

                ObjectAttributes attrs = new ObjectAttributes();
                attrs.Length = Marshal.SizeOf(typeof(ObjectAttributes));
                attrs.RootDirectory = parent.DangerousGetHandle();
                attrs.ObjectName = unicodePointer;
                attrs.Attributes = OBJ_CASE_INSENSITIVE;

                IoStatusBlock io;
                int status = NtCreateFile(out child,
                    FILE_READ_ATTRIBUTES | FILE_TRAVERSE | SYNCHRONIZE,
                    ref attrs, out io, IntPtr.Zero,
                    FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    FILE_OPEN,
                    FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
                    IntPtr.Zero, 0);
                if (status != 0)
                    throw new IOException("Synthetic relative directory open refused. NTSTATUS=0x" +
                        unchecked((uint)status).ToString("X8"));
                return Identify(child);
            }
            finally
            {
                if (child != null) child.Dispose();
                if (unicodePointer != IntPtr.Zero) Marshal.FreeHGlobal(unicodePointer);
                if (nameBuffer != IntPtr.Zero) Marshal.FreeHGlobal(nameBuffer);
                if (borrowed) parent.DangerousRelease();
            }
        }
    }
}
