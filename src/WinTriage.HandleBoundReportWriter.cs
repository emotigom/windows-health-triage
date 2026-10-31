// Copyright (c) contributors to Windows Health Triage. MIT licensed.
// Create a NEW report file relative to an already-open directory HANDLE.
// No ordinary absolute path, overwrite, open-if, redirect or delete fallback.
// NtCreateFile user-mode interop: Windows-only; fail closed on unsupported policy.
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace WinTriage
{
    public static class HandleBoundReportWriter
    {
        private const uint FILE_WRITE_DATA = 0x0002;
        private const uint SYNCHRONIZE = 0x00100000;
        private const uint FILE_SHARE_READ = 0x0001;
        private const uint FILE_CREATE = 0x0002;
        private const uint FILE_NON_DIRECTORY_FILE = 0x0040;
        private const uint FILE_SYNCHRONOUS_IO_NONALERT = 0x0020;
        private const uint FILE_OPEN_REPARSE_POINT = 0x00200000;
        private const uint FILE_ATTRIBUTE_NORMAL = 0x0080;
        private const uint OBJ_CASE_INSENSITIVE = 0x0040;

        // Deliberately allow only names emitted by the core report writer.
        // Extension work must pass the privacy and security review first.
        private static readonly HashSet<string> AllowedNames = new HashSet<string>(
            new string[] {
                "system.json", "processes.json", "memory-samples.csv",
                "memory-growth.csv", "events.json", "event-summary.json",
                "triage-advice.json", "security.json", "hardware.json",
                "integrity.json", "SUMMARY.md", "manifest.json"
            }, StringComparer.OrdinalIgnoreCase);

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

        [DllImport("ntdll.dll", ExactSpelling = true)]
        private static extern int NtCreateFile(
            out SafeFileHandle file,
            uint desiredAccess,
            ref ObjectAttributes attributes,
            out IoStatusBlock ioStatus,
            IntPtr allocationSize,
            uint fileAttributes,
            uint shareAccess,
            uint disposition,
            uint createOptions,
            IntPtr eaBuffer,
            uint eaLength);

        public static void WriteNewUtf8(SafeFileHandle directory, string leafName, string content, bool emitBom)
        {
            if (directory == null || directory.IsInvalid || directory.IsClosed ||
                String.IsNullOrEmpty(leafName) || !AllowedNames.Contains(leafName) ||
                content == null)
                throw new ArgumentException("Invalid handle-bound report writer input.");

            IntPtr nameBuffer = IntPtr.Zero;
            IntPtr unicodePointer = IntPtr.Zero;
            bool borrowed = false;
            SafeFileHandle output = null;
            try
            {
                // Fixed, no-slash leaf only; ROOT directory is a pinned handle,
                // so the file is not resolved from a mutable parent path.
                directory.DangerousAddRef(ref borrowed);
                nameBuffer = Marshal.StringToHGlobalUni(leafName);
                UnicodeString name = new UnicodeString();
                name.Buffer = nameBuffer;
                name.Length = checked((ushort)(leafName.Length * 2));
                name.MaximumLength = checked((ushort)((leafName.Length + 1) * 2));
                unicodePointer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UnicodeString)));
                Marshal.StructureToPtr(name, unicodePointer, false);

                ObjectAttributes attrs = new ObjectAttributes();
                attrs.Length = Marshal.SizeOf(typeof(ObjectAttributes));
                attrs.RootDirectory = directory.DangerousGetHandle();
                attrs.ObjectName = unicodePointer;
                attrs.Attributes = OBJ_CASE_INSENSITIVE;
                attrs.SecurityDescriptor = IntPtr.Zero;
                attrs.SecurityQualityOfService = IntPtr.Zero;

                IoStatusBlock io;
                int status = NtCreateFile(
                    out output,
                    FILE_WRITE_DATA | SYNCHRONIZE,
                    ref attrs,
                    out io,
                    IntPtr.Zero,
                    FILE_ATTRIBUTE_NORMAL,
                    FILE_SHARE_READ,
                    FILE_CREATE,
                    FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
                    IntPtr.Zero,
                    0);
                // No overwrite, no open-if, no retry-by-path. Even if a malicious
                // name already exists, refuse rather than writing through it.
                if (status != 0 || output == null || output.IsInvalid)
                    throw new IOException("Handle-relative report creation failed. NTSTATUS=" + status);

                // FileStream owns the child handle, not the borrowed directory.
                using (output)
                {
                    output = null;
                    using (FileStream stream = new FileStream(output, FileAccess.Write))
                    using (StreamWriter writer = new StreamWriter(stream, new UTF8Encoding(emitBom)))
                    {
                        writer.Write(content);
                        writer.Flush();
                    }
                }
            }
            finally
            {
                if (output != null) output.Dispose();
                if (unicodePointer != IntPtr.Zero) Marshal.FreeHGlobal(unicodePointer);
                if (nameBuffer != IntPtr.Zero) Marshal.FreeHGlobal(nameBuffer);
                if (borrowed) directory.DangerousRelease();
            }
        }
    }
}
