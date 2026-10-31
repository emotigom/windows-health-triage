// ADR-028: test-only fail-closed LOCAL FIXED DRIVE PATH SPELLING policy.
// No filesystem operations or normalization. A drive letter is not a trusted
// identity, and this restricted ASCII policy is not shipping path policy.
using System;
using System.IO;
using System.Text.RegularExpressions;

namespace WinTriageTests
{
    public static class RootPathPolicyProbe
    {
        public static string[] SplitStrictDrivePath(string candidate)
        {
            if (String.IsNullOrEmpty(candidate) || candidate.Length > 240 ||
                !Regex.IsMatch(candidate, @"^[A-Za-z]:\\"))
                throw new ArgumentException("Unsupported synthetic path namespace.");
            string rest = candidate.Substring(3);
            if (rest.Length == 0) throw new ArgumentException("Synthetic path cannot be root only.");
            string[] pieces = rest.Split(new char[] { '\\' }, StringSplitOptions.None);
            if (pieces.Length > 32) throw new ArgumentException("Too many synthetic path components.");
            string[] result = new string[pieces.Length + 1];
            result[0] = char.ToUpperInvariant(candidate[0]) + @":\";
            for (int i = 0; i < pieces.Length; i++)
            {
                string leaf = pieces[i];
                // Validate spelling BEFORE Path.GetFullPath or any API that
                // might silently normalize dot, relative or device components.
                if (leaf.Length == 0 || leaf.Length > 80 ||
                    !Regex.IsMatch(leaf, @"^[A-Za-z0-9][A-Za-z0-9 _().~-]{0,79}$") ||
                    leaf.EndsWith(".") || leaf.EndsWith(" "))
                    throw new ArgumentException("Invalid synthetic path component.");
                string deviceStem = leaf.Split('.')[0];
                if (Regex.IsMatch(deviceStem, @"^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$",
                    RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
                    throw new ArgumentException("Reserved DOS device in synthetic path.");
                result[i + 1] = leaf;
            }
            return result;
        }

        public static bool IsFixedNtfsVolumeForResearch(string root)
        {
            if (String.IsNullOrEmpty(root) || !Regex.IsMatch(root, @"^[A-Za-z]:\\$"))
                throw new ArgumentException("Expected synthetic drive root.");
            DriveInfo drive = new DriveInfo(root);
            return drive.IsReady && drive.DriveType == DriveType.Fixed &&
                String.Equals(drive.DriveFormat, "NTFS", StringComparison.OrdinalIgnoreCase);
        }
    }
}
