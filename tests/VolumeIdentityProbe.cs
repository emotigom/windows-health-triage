// ADR-029 test-only volume/file identity research. No src/ import.
// Read existing handles only. Volume GUID path and serial numbers are NOT
// authentication credentials or durable identities.
using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace WinTriageTests
{
    public static class VolumeIdentityProbe
    {
        private const int FileIdInfo = 18;
        private const uint FILE_ID_INFO_BYTES = 24; // UINT64 + FILE_ID_128
        private const uint VOLUME_NAME_GUID = 0x1;
        private const int MAX_GUID_PATH_CHARS = 4096;

        [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileInfo(
            SafeFileHandle file, int infoClass, IntPtr buffer, uint bufferSize);

        [DllImport("kernel32.dll", EntryPoint = "GetFinalPathNameByHandleW",
            CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetFinalPath(
            SafeFileHandle file, StringBuilder buffer, uint bufferLength, uint flags);

        private static void RequireHandle(SafeFileHandle handle)
        {
            if (handle == null || handle.IsClosed || handle.IsInvalid)
                throw new ArgumentException("Synthetic handle not open.");
        }

        private static byte[] ReadIdentityBytes(SafeFileHandle handle)
        {
            RequireHandle(handle);
            IntPtr buffer = Marshal.AllocHGlobal((int)FILE_ID_INFO_BYTES);
            try
            {
                // No fallback to a truncated 64-bit file index on ReFS.
                if (!GetFileInfo(handle, FileIdInfo, buffer, FILE_ID_INFO_BYTES))
                    throw new IOException("Native 128-bit file identity query refused.");
                byte[] result = new byte[(int)FILE_ID_INFO_BYTES];
                Marshal.Copy(buffer, result, 0, result.Length);
                return result;
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }

        private static string Hex(byte[] bytes)
        {
            return BitConverter.ToString(bytes).Replace("-", "");
        }

        public static string VolumeSerial(SafeFileHandle handle)
        {
            byte[] bytes = ReadIdentityBytes(handle);
            byte[] volume = new byte[8];
            Buffer.BlockCopy(bytes, 0, volume, 0, volume.Length);
            return Hex(volume);
        }

        public static string FileIdentity(SafeFileHandle handle)
        {
            return Hex(ReadIdentityBytes(handle));
        }

        public static void RequireFileIdentity(SafeFileHandle handle, string expected)
        {
            if (String.IsNullOrEmpty(expected) || expected.Length != 48 ||
                !Regex.IsMatch(expected, @"\A[0-9A-F]{48}\z"))
                throw new ArgumentException("Missing trusted synthetic file identity.");
            if (!String.Equals(FileIdentity(handle), expected, StringComparison.Ordinal))
                throw new IOException("Synthetic full file identity mismatch.");
        }

        public static void RequireVolumeSerial(SafeFileHandle handle, string expected)
        {
            if (String.IsNullOrEmpty(expected) || expected.Length != 16 ||
                !Regex.IsMatch(expected, @"\A[0-9A-F]{16}\z"))
                throw new ArgumentException("Missing trusted synthetic volume serial.");
            if (!String.Equals(VolumeSerial(handle), expected, StringComparison.Ordinal))
                throw new IOException("Synthetic volume serial mismatch.");
        }

        // Observational volume-GUID prefix from this SAME OPEN HANDLE; no
        // pathname resolution, drive remapping, mounting or system mutations.
        // Null means GUID mapping unavailable: the fixture must report SKIP,
        // not claim that a GUID check succeeded.
        public static string TryVolumeGuidPrefix(SafeFileHandle handle)
        {
            RequireHandle(handle);
            StringBuilder buffer = new StringBuilder(MAX_GUID_PATH_CHARS);
            uint result = GetFinalPath(handle, buffer, (uint)buffer.Capacity, VOLUME_NAME_GUID);
            if (result == 0 || result >= (uint)buffer.Capacity) return null;
            Match prefix = Regex.Match(buffer.ToString(),
                @"\A\\\\\?\\Volume\{[0-9a-fA-F-]{36}\}\\",
                RegexOptions.CultureInvariant);
            return prefix.Success ? prefix.Value.ToUpperInvariant() : null;
        }
    }
}
