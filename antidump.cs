using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace ConsoleApplication1
{
    public class Program
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr VirtualQuery(IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, IntPtr dwLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

        [StructLayout(LayoutKind.Sequential)]
        private struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        public static void Main(string[] args)
        {
            IntPtr moduleBase = Process.GetCurrentProcess().MainModule.BaseAddress;
            IntPtr peHeader = moduleBase;
            MEMORY_BASIC_INFORMATION mbi;

            // Find the PE header
            if (VirtualQuery(peHeader, out mbi, (IntPtr)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))) == IntPtr.Zero)
            {
                Console.WriteLine("Failed to find PE header.");
                return;
            }

            // Change the protection of the PE header to read-write
            uint oldProtect;
            if (!VirtualProtect(mbi.BaseAddress, (uint)mbi.RegionSize.ToInt32(), 0x40, out oldProtect))
            {
                Console.WriteLine("Failed to change protection of PE header.");
                return;
            }

            // Clear the PE header
            byte[] emptyHeader = new byte[0x200];
            Marshal.Copy(emptyHeader, 0, mbi.BaseAddress, emptyHeader.Length);

            // Restore the protection of the PE header
            if (!VirtualProtect(mbi.BaseAddress, (uint)mbi.RegionSize.ToInt32(), oldProtect, out oldProtect))
            {
                Console.WriteLine("Failed to restore protection of PE header.");
                return;
            }

            Console.WriteLine("PE header cleared successfully.");
            Console.ReadKey();
        }
    }
}