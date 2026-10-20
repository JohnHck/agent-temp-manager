// AgentTempManager native helpers.
// Written in C# 5 so it compiles under Windows PowerShell 5.1 (CodeDom/csc v4)
// and PowerShell 7 (Roslyn). No external dependencies.
//
// Safety invariants enforced here:
//  * Reparse points (junctions, symlinks, mount points, cloud placeholders) are
//    NEVER traversed. They are counted and reported.
//  * The scanner and the lock probe never write to the filesystem.
//  * The deleter never forces: no attribute changes, no ACL changes, no
//    ownership changes, no privileges. It pins ancestors and the tree by handle
//    (no FILE_SHARE_DELETE) so names cannot be redirected, deletes by handle, aborts
//    before deleting anything on reparse points or protected files, and stops at the
//    first failure.
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace AgentTempManager
{
    public static class AtmNative
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetLongPathNameW(string shortPath, StringBuilder longPath, uint bufferLength);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetShortPathNameW(string longPath, StringBuilder shortPath, uint bufferLength);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetCompressedFileSizeW(string fileName, out uint fileSizeHigh);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool GetDiskFreeSpaceW(string rootPath, out uint sectorsPerCluster, out uint bytesPerSector, out uint freeClusters, out uint totalClusters);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern SafeFileHandle CreateFileW(string fileName, uint desiredAccess, uint shareMode, IntPtr securityAttributes, uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

        public static string GetLongPath(string path)
        {
            StringBuilder sb = new StringBuilder(1024);
            uint n = GetLongPathNameW(path, sb, (uint)sb.Capacity);
            if (n == 0) return null;
            if (n > sb.Capacity) { sb = new StringBuilder((int)n + 1); n = GetLongPathNameW(path, sb, (uint)sb.Capacity); if (n == 0) return null; }
            return sb.ToString();
        }

        public static string GetShortPath(string path)
        {
            StringBuilder sb = new StringBuilder(1024);
            uint n = GetShortPathNameW(path, sb, (uint)sb.Capacity);
            if (n == 0) return null;
            if (n > sb.Capacity) { sb = new StringBuilder((int)n + 1); n = GetShortPathNameW(path, sb, (uint)sb.Capacity); if (n == 0) return null; }
            return sb.ToString();
        }

        public static long GetClusterSize(string volumeRoot)
        {
            uint spc, bps, fc, tc;
            if (GetDiskFreeSpaceW(volumeRoot, out spc, out bps, out fc, out tc)) return (long)spc * (long)bps;
            return 4096;
        }

        // Estimated on-disk allocation: compressed/sparse aware size rounded up to cluster.
        // MFT-resident tiny files are overestimated. This is an ESTIMATE.
        public static long EstimateAllocated(string file, long logicalLength, long clusterSize)
        {
            uint high;
            uint low = GetCompressedFileSizeW(file, out high);
            long size = logicalLength;
            if (!(low == 0xFFFFFFFF && Marshal.GetLastWin32Error() != 0))
                size = ((long)high << 32) | low;
            if (clusterSize <= 0) return size;
            return ((size + clusterSize - 1) / clusterSize) * clusterSize;
        }
    }

    public sealed class AtmTreeStats
    {
        public string Path;
        public bool Exists;
        public bool IsDirectory;
        public bool RootIsReparsePoint;
        public long Bytes;
        public long AllocatedBytesEstimate;
        public long Files;
        public long Dirs;            // descendant directories (root excluded)
        public long DirectChildren;
        public long ReparsePoints;
        public long ReadOnlyOrSystemFiles;
        public long ErrorCount;
        public bool MeasurementComplete;
        public DateTime CreationTimeUtc;
        public DateTime LastWriteTimeUtc;
        public DateTime NewestWriteTimeUtc;  // max LastWriteTime over root + all observed descendants
        public List<string> ErrorSamples = new List<string>();
        public List<string> ReparseSamples = new List<string>();

        internal int MaxSamples;

        internal void AddError(string path, Exception ex)
        {
            ErrorCount++;
            MeasurementComplete = false;
            if (ErrorSamples.Count < MaxSamples)
                ErrorSamples.Add(ex.GetType().Name + ": " + path);
        }

        internal void Touch(DateTime t)
        {
            if (t > NewestWriteTimeUtc) NewestWriteTimeUtc = t;
        }
    }

    public static class AtmScanner
    {
        // Single pass over one partition root. Never follows reparse points.
        public static AtmTreeStats ScanTree(string path, int maxSamples, long clusterSize)
        {
            AtmTreeStats s = new AtmTreeStats();
            s.Path = path;
            s.MaxSamples = maxSamples;
            s.MeasurementComplete = true;
            s.NewestWriteTimeUtc = DateTime.MinValue;

            FileAttributes rootAttr;
            try
            {
                rootAttr = File.GetAttributes(path);
            }
            catch (FileNotFoundException) { s.Exists = false; s.MeasurementComplete = false; return s; }
            catch (DirectoryNotFoundException) { s.Exists = false; s.MeasurementComplete = false; return s; }
            catch (Exception ex) { s.Exists = false; s.AddError(path, ex); return s; }

            s.Exists = true;
            s.IsDirectory = (rootAttr & FileAttributes.Directory) != 0;
            if ((rootAttr & FileAttributes.ReparsePoint) != 0)
            {
                s.RootIsReparsePoint = true;
                s.ReparsePoints = 1;
                s.ReparseSamples.Add(path);
                return s;
            }

            try
            {
                FileSystemInfo ri = s.IsDirectory ? (FileSystemInfo)new DirectoryInfo(path) : (FileSystemInfo)new FileInfo(path);
                s.CreationTimeUtc = ri.CreationTimeUtc;
                s.LastWriteTimeUtc = ri.LastWriteTimeUtc;
                s.Touch(s.LastWriteTimeUtc);
                if (!s.IsDirectory)
                {
                    FileInfo f = (FileInfo)ri;
                    s.Files = 1;
                    s.Bytes = f.Length;
                    s.AllocatedBytesEstimate = AtmNative.EstimateAllocated(path, f.Length, clusterSize);
                    if ((rootAttr & (FileAttributes.ReadOnly | FileAttributes.System)) != 0) s.ReadOnlyOrSystemFiles = 1;
                    return s;
                }
            }
            catch (Exception ex) { s.AddError(path, ex); return s; }

            Stack<string> stack = new Stack<string>();
            stack.Push(path);
            bool isRoot = true;
            while (stack.Count > 0)
            {
                string dir = stack.Pop();
                IEnumerator<FileSystemInfo> en;
                try
                {
                    en = new DirectoryInfo(dir).EnumerateFileSystemInfos().GetEnumerator();
                }
                catch (Exception ex) { s.AddError(dir, ex); isRoot = false; continue; }

                using (en)
                {
                    while (true)
                    {
                        FileSystemInfo fi;
                        try
                        {
                            if (!en.MoveNext()) break;
                            fi = en.Current;
                        }
                        catch (Exception ex) { s.AddError(dir, ex); break; }

                        if (isRoot) s.DirectChildren++;
                        try
                        {
                            FileAttributes a = fi.Attributes;
                            if ((a & FileAttributes.ReparsePoint) != 0)
                            {
                                s.ReparsePoints++;
                                if (s.ReparseSamples.Count < maxSamples) s.ReparseSamples.Add(fi.FullName);
                                continue; // never traverse
                            }
                            s.Touch(fi.LastWriteTimeUtc);
                            if ((a & FileAttributes.Directory) != 0)
                            {
                                s.Dirs++;
                                stack.Push(fi.FullName);
                            }
                            else
                            {
                                long len = ((FileInfo)fi).Length;
                                s.Files++;
                                s.Bytes += len;
                                s.AllocatedBytesEstimate += AtmNative.EstimateAllocated(fi.FullName, len, clusterSize);
                                if ((a & (FileAttributes.ReadOnly | FileAttributes.System)) != 0) s.ReadOnlyOrSystemFiles++;
                            }
                        }
                        catch (Exception ex) { s.AddError(fi.FullName, ex); }
                    }
                }
                isRoot = false;
            }
            return s;
        }
    }

    public sealed class AtmProbeResult
    {
        public string Path;
        public long Probed;
        public long InUse;
        public long Denied;
        public long Errors;
        public long ReparsePoints;
        public bool Complete;
        public List<string> Samples = new List<string>();
        public bool Ok { get { return Complete && InUse == 0 && Denied == 0 && Errors == 0 && ReparsePoints == 0; } }
    }

    public static class AtmLockProbe
    {
        const uint DELETE = 0x00010000;
        const uint FILE_READ_ATTRIBUTES = 0x0080;
        const uint OPEN_EXISTING = 3;
        const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;

        // Opens every file and directory of the tree with DELETE access and share mode 0,
        // then closes the handle immediately. Nothing is read, written, or deleted.
        // A sharing violation means some process holds a handle that would conflict
        // (open data handle, or a directory used as current directory).
        // LIMITATION: handles opened with full sharing (incl. FILE_SHARE_DELETE) that
        // only read attributes are not detectable; the result is a point-in-time check.
        public static AtmProbeResult ProbeTree(string root, int maxSamples)
        {
            AtmProbeResult r = new AtmProbeResult();
            r.Path = root;
            r.Complete = true;
            List<string> dirs = new List<string>();
            Stack<string> stack = new Stack<string>();
            FileAttributes ra;
            try { ra = File.GetAttributes(root); }
            catch (Exception ex) { r.Errors++; r.Complete = false; r.Samples.Add(ex.GetType().Name + ": " + root); return r; }
            if ((ra & FileAttributes.ReparsePoint) != 0) { r.ReparsePoints++; r.Complete = false; r.Samples.Add("REPARSE: " + root); return r; }
            if ((ra & FileAttributes.Directory) == 0) { ProbeOne(root, false, r, maxSamples); return r; }

            stack.Push(root);
            while (stack.Count > 0)
            {
                string dir = stack.Pop();
                dirs.Add(dir);
                IEnumerator<FileSystemInfo> en;
                try { en = new DirectoryInfo(dir).EnumerateFileSystemInfos().GetEnumerator(); }
                catch (Exception ex) { r.Errors++; r.Complete = false; Sample(r, maxSamples, ex.GetType().Name + ": " + dir); continue; }
                using (en)
                {
                    while (true)
                    {
                        FileSystemInfo fi;
                        try { if (!en.MoveNext()) break; fi = en.Current; }
                        catch (Exception ex) { r.Errors++; r.Complete = false; Sample(r, maxSamples, ex.GetType().Name + ": " + dir); break; }
                        FileAttributes a = fi.Attributes;
                        if ((a & FileAttributes.ReparsePoint) != 0) { r.ReparsePoints++; r.Complete = false; Sample(r, maxSamples, "REPARSE: " + fi.FullName); continue; }
                        if ((a & FileAttributes.Directory) != 0) stack.Push(fi.FullName);
                        else ProbeOne(fi.FullName, false, r, maxSamples);
                    }
                }
            }
            foreach (string d in dirs) ProbeOne(d, true, r, maxSamples);
            return r;
        }

        static void Sample(AtmProbeResult r, int max, string s) { if (r.Samples.Count < max) r.Samples.Add(s); }

        static void ProbeOne(string path, bool isDir, AtmProbeResult r, int maxSamples)
        {
            r.Probed++;
            uint flags = FILE_FLAG_OPEN_REPARSE_POINT | (isDir ? FILE_FLAG_BACKUP_SEMANTICS : 0u);
            using (SafeFileHandle h = AtmNative.CreateFileW(path, DELETE | FILE_READ_ATTRIBUTES, 0, IntPtr.Zero, OPEN_EXISTING, flags, IntPtr.Zero))
            {
                if (!h.IsInvalid) return;
                int err = Marshal.GetLastWin32Error();
                if (err == 32 || err == 33) { r.InUse++; Sample(r, maxSamples, "IN_USE: " + path); }
                else if (err == 5) { r.Denied++; Sample(r, maxSamples, "ACCESS_DENIED: " + path); }
                else { r.Errors++; r.Complete = false; Sample(r, maxSamples, "WIN32_" + err + ": " + path); }
            }
        }
    }

    public sealed class AtmDeleteResult
    {
        public string Path;
        public bool Attempted;
        public bool Completed;
        public long FilesDeleted;
        public long DirsDeleted;
        public long FilesPlanned;
        public long DirsPlanned;
        public string AbortReason;
        public string FailedAt;
    }

    // Deletes one directory tree WITHOUT force and WITHOUT trusting names between checks:
    //  1. Every ancestor (volume root excluded) and every directory of the tree is opened top-down and kept
    //     open WITHOUT FILE_SHARE_DELETE (tree directories also WITHOUT FILE_SHARE_WRITE, so an emptied
    //     directory cannot be opened for writing and converted into a reparse point in place). While pinned, no other process can rename, delete or replace any of
    //     them (e.g. swap a directory for a junction), so path resolution below cannot be redirected.
    //  2. Each pinned handle is checked: directory, not a reparse point, final path == expected path.
    //  3. Files are opened with share mode 0 (fails if anyone has them open), checked the same way, and
    //     deleted through their handle (FileDispositionInfo). Directories are deleted bottom-up through
    //     their pinned handles; a directory that is no longer empty makes the operation stop.
    //  4. Anything unexpected (reparse point, read-only/system file, enumeration error, mismatch) aborts
    //     BEFORE the first deletion when found during planning, or stops at the first failure afterwards.
    public static class AtmDeleter
    {
        const uint DELETE = 0x00010000;
        const uint FILE_LIST_DIRECTORY = 0x0001;
        const uint FILE_READ_ATTRIBUTES = 0x0080;
        const uint SYNCHRONIZE = 0x00100000;
        const uint FILE_SHARE_READ = 1, FILE_SHARE_WRITE = 2;
        const uint OPEN_EXISTING = 3;
        const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
        const uint ATTR_DIRECTORY = 0x10, ATTR_REPARSE = 0x400, ATTR_READONLY = 0x1, ATTR_SYSTEM = 0x4;

        [StructLayout(LayoutKind.Sequential)]
        struct BY_HANDLE_FILE_INFORMATION
        {
            public uint FileAttributes;
            public uint CreationLow, CreationHigh, AccessLow, AccessHigh, WriteLow, WriteHigh;
            public uint VolumeSerialNumber, FileSizeHigh, FileSizeLow, NumberOfLinks, FileIndexHigh, FileIndexLow;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct FILE_DISPOSITION_INFO { [MarshalAs(UnmanagedType.U1)] public bool DeleteFile; }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetFileInformationByHandle(SafeFileHandle h, out BY_HANDLE_FILE_INFORMATION info);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern uint GetFinalPathNameByHandleW(SafeFileHandle h, StringBuilder buf, uint len, uint flags);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool SetFileInformationByHandle(SafeFileHandle h, int infoClass, ref FILE_DISPOSITION_INFO info, uint size);

        sealed class Pinned { public string Path; public int Depth; public SafeFileHandle Handle; }

        static string FinalPath(SafeFileHandle h)
        {
            StringBuilder sb = new StringBuilder(1024);
            uint n = GetFinalPathNameByHandleW(h, sb, (uint)sb.Capacity, 0);
            if (n == 0) return null;
            if (n >= sb.Capacity) { sb = new StringBuilder((int)n + 2); n = GetFinalPathNameByHandleW(h, sb, (uint)sb.Capacity, 0); if (n == 0) return null; }
            string s = sb.ToString();
            if (s.StartsWith(@"\\?\UNC\", StringComparison.Ordinal)) return null;   // never remote
            if (s.StartsWith(@"\\?\", StringComparison.Ordinal)) s = s.Substring(4);
            return s;
        }

        // Opens and validates; returns null and sets 'why' on any problem.
        static SafeFileHandle OpenChecked(string path, bool isDir, uint access, uint share, out string why)
        {
            BY_HANDLE_FILE_INFORMATION ignored;
            return OpenChecked(path, isDir, access, share, out why, out ignored);
        }

        static SafeFileHandle OpenChecked(string path, bool isDir, uint access, uint share, out string why, out BY_HANDLE_FILE_INFORMATION info)
        {
            why = null;
            info = new BY_HANDLE_FILE_INFORMATION();
            uint flags = FILE_FLAG_OPEN_REPARSE_POINT | (isDir ? FILE_FLAG_BACKUP_SEMANTICS : 0u);
            SafeFileHandle h = CtmCreate(path, access, share, flags);
            if (h.IsInvalid) { int e = Marshal.GetLastWin32Error(); h.Dispose(); why = (e == 32 || e == 33 ? "IN_USE" : (e == 5 ? "ACCESS_DENIED" : "WIN32_" + e)) + ": " + path; return null; }
            if (!GetFileInformationByHandle(h, out info)) { h.Dispose(); why = "NO_INFO: " + path; return null; }
            if ((info.FileAttributes & ATTR_REPARSE) != 0) { h.Dispose(); why = "REPARSE_POINT: " + path; return null; }
            bool dir = (info.FileAttributes & ATTR_DIRECTORY) != 0;
            if (dir != isDir) { h.Dispose(); why = "TYPE_CHANGED: " + path; return null; }
            if (!isDir && (info.FileAttributes & (ATTR_READONLY | ATTR_SYSTEM)) != 0) { h.Dispose(); why = "PROTECTED_FILE: " + path; return null; }
            string fp = FinalPath(h);
            if (fp == null || !string.Equals(fp.TrimEnd('\\'), path.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase)) { h.Dispose(); why = "PATH_REDIRECTED: " + path + " -> " + fp; return null; }
            return h;
        }

        static SafeFileHandle CtmCreate(string path, uint access, uint share, uint flags)
        {
            return AtmNative.CreateFileW(path, access, share, IntPtr.Zero, OPEN_EXISTING, flags, IntPtr.Zero);
        }

        // Re-reads attributes through the pinned handle: still a directory, still not a reparse point.
        static bool StillPlainDirectory(SafeFileHandle h)
        {
            BY_HANDLE_FILE_INFORMATION info;
            if (!GetFileInformationByHandle(h, out info)) return false;
            return (info.FileAttributes & ATTR_DIRECTORY) != 0 && (info.FileAttributes & ATTR_REPARSE) == 0;
        }

        static bool Dispose(SafeFileHandle h)
        {
            FILE_DISPOSITION_INFO d = new FILE_DISPOSITION_INFO();
            d.DeleteFile = true;
            return SetFileInformationByHandle(h, 4 /* FileDispositionInfo */, ref d, (uint)Marshal.SizeOf(typeof(FILE_DISPOSITION_INFO)));
        }

        // Overloads without an expected measurement exist for the test suite only. The clean engine always calls
        // the checked overload with the measurement it has just validated.
        public static AtmDeleteResult DeleteTree(string root) { return DeleteTree(root, -1, -1, -1, -1, null); }
        public static AtmDeleteResult DeleteTree(string root, Action<string> afterPinning) { return DeleteTree(root, -1, -1, -1, -1, afterPinning); }

        // expected*: validated measurement (files, descendant dirs, logical bytes, newest write ticks UTC). Once
        // everything is pinned, the plan must match it exactly, otherwise nothing is deleted.
        // afterPinning: test hook invoked once everything is pinned and planned, before the first deletion.
        public static AtmDeleteResult DeleteTree(string root, long expectedFiles, long expectedDirs, long expectedBytes, long expectedNewestTicksUtc, Action<string> afterPinning)
        {
            AtmDeleteResult r = new AtmDeleteResult();
            r.Path = root;
            List<SafeFileHandle> ancestors = new List<SafeFileHandle>();
            List<Pinned> dirs = new List<Pinned>();
            List<string> files = new List<string>();
            List<long> fileWrites = new List<long>();
            long planBytes = 0;
            long planNewest = 0;
            string why;
            try
            {
                if (root == null || root.Length < 4 || root[1] != ':' || root[2] != '\\') { r.AbortReason = "ROOT_INVALID"; return r; }
                string full = System.IO.Path.GetFullPath(root).TrimEnd('\\');
                if (!string.Equals(full, root.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase)) { r.AbortReason = "ROOT_NOT_CANONICAL"; return r; }

                // 1. Pin ancestors top-down (volume root excluded).
                string[] parts = full.Substring(3).Split('\\');
                string cur = full.Substring(0, 3);
                for (int i = 0; i < parts.Length - 1; i++)
                {
                    cur = System.IO.Path.Combine(cur, parts[i]);
                    SafeFileHandle h = OpenChecked(cur, true, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE, out why);
                    if (h == null) { r.AbortReason = "ANCESTOR_" + why; return r; }
                    ancestors.Add(h);
                }

                // 2. Pin the tree top-down and plan.
                SafeFileHandle rh = OpenChecked(full, true, DELETE | FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE, FILE_SHARE_READ, out why);
                if (rh == null) { r.AbortReason = "ROOT_" + why; return r; }
                Pinned rp = new Pinned(); rp.Path = full; rp.Depth = 0; rp.Handle = rh;
                dirs.Add(rp);
                try { planNewest = new DirectoryInfo(full).LastWriteTimeUtc.Ticks; } catch (Exception ex) { r.AbortReason = "ROOT_TIME_UNREADABLE: " + ex.GetType().Name; return r; }
                for (int k = 0; k < dirs.Count; k++)
                {
                    Pinned d = dirs[k];
                    try
                    {
                        if (!StillPlainDirectory(d.Handle)) { r.AbortReason = "PINNED_DIR_CHANGED: " + d.Path; return r; }
                        foreach (FileSystemInfo fi in new DirectoryInfo(d.Path).EnumerateFileSystemInfos())
                        {
                            FileAttributes a = fi.Attributes;
                            if ((a & FileAttributes.ReparsePoint) != 0) { r.AbortReason = "REPARSE_POINT_FOUND: " + fi.FullName; return r; }
                            long wt = fi.LastWriteTimeUtc.Ticks;
                            if (wt > planNewest) planNewest = wt;
                            if ((a & FileAttributes.Directory) != 0)
                            {
                                SafeFileHandle ch = OpenChecked(fi.FullName, true, DELETE | FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE, FILE_SHARE_READ, out why);
                                if (ch == null) { r.AbortReason = "PIN_" + why; return r; }
                                Pinned cp = new Pinned(); cp.Path = fi.FullName; cp.Depth = d.Depth + 1; cp.Handle = ch;
                                dirs.Add(cp);
                            }
                            else
                            {
                                if ((a & (FileAttributes.ReadOnly | FileAttributes.System)) != 0) { r.AbortReason = "PROTECTED_FILE_FOUND: " + fi.FullName; return r; }
                                files.Add(fi.FullName);
                                fileWrites.Add(fi.LastWriteTimeUtc.ToFileTimeUtc());
                                planBytes += ((FileInfo)fi).Length;
                            }
                        }
                    }
                    catch (Exception ex) { r.AbortReason = "ENUMERATION_FAILED: " + ex.GetType().Name + ": " + d.Path; return r; }
                }
                r.FilesPlanned = files.Count;
                r.DirsPlanned = dirs.Count;
                if (expectedFiles >= 0 && (files.Count != expectedFiles || dirs.Count - 1 != expectedDirs || planBytes != expectedBytes || planNewest != expectedNewestTicksUtc))
                {
                    r.AbortReason = "PLAN_DIFFERS_FROM_VALIDATED_MEASUREMENT (files " + files.Count + "/" + expectedFiles + ", dirs " + (dirs.Count - 1) + "/" + expectedDirs + ", bytes " + planBytes + "/" + expectedBytes + ", newest " + planNewest + "/" + expectedNewestTicksUtc + ")";
                    return r;
                }
                if (afterPinning != null) afterPinning(full);
                r.Attempted = true;

                // 3. Files: exclusive open, validate (incl. unchanged write time), delete by handle.
                for (int n = 0; n < files.Count; n++)
                {
                    string f = files[n];
                    BY_HANDLE_FILE_INFORMATION finfo;
                    SafeFileHandle fh = OpenChecked(f, false, DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE, 0, out why, out finfo);
                    if (fh == null) { r.AbortReason = "DELETE_FILE_REFUSED: " + why; r.FailedAt = f; return r; }
                    using (fh)
                    {
                        long w = ((long)finfo.WriteHigh << 32) | finfo.WriteLow;
                        if (w != fileWrites[n]) { r.AbortReason = "FILE_CHANGED_AFTER_PLANNING"; r.FailedAt = f; return r; }
                        if (!Dispose(fh)) { r.AbortReason = "DELETE_FILE_FAILED: WIN32_" + Marshal.GetLastWin32Error(); r.FailedAt = f; return r; }
                    }
                    r.FilesDeleted++;
                }

                // 4. Directories bottom-up through their pinned handles.
                dirs.Sort(delegate (Pinned x, Pinned y) { return y.Depth.CompareTo(x.Depth); });
                foreach (Pinned d in dirs)
                {
                    if (!StillPlainDirectory(d.Handle)) { r.AbortReason = "PINNED_DIR_CHANGED: " + d.Path; r.FailedAt = d.Path; return r; }
                    if (!Dispose(d.Handle)) { r.AbortReason = "DELETE_DIR_FAILED: WIN32_" + Marshal.GetLastWin32Error(); r.FailedAt = d.Path; return r; }
                    d.Handle.Dispose();
                    d.Handle = null;
                    r.DirsDeleted++;
                }
                r.Completed = true;
                return r;
            }
            finally
            {
                foreach (Pinned d in dirs) { if (d.Handle != null) d.Handle.Dispose(); }
                foreach (SafeFileHandle h in ancestors) h.Dispose();
            }
        }
    }
}
