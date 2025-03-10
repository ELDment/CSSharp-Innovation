# VMTHook 原理与实现指南
> **本文理论 & 实践皆基于Windows x64平台！**

## 前言
相较于CounterStrikeSharp提供的Hook方法（调用游戏函数HookFunc），底层为InlineHook。VMTHook具有以下优势与局限性。
1. **VMTHook是精准的✅**  
  直接替换虚函数表指针，仅针对特定类/对象的虚函数调用进行拦截，无需修改指令流。相比InlineHook的指令级修补，避免了指令长度计算和跳转劫持的兼容性问题。

2. **VMTHook是稳定的♾️**  
  通过指针替换实现Hook，无指令热修补（hotpatch）带来的性能损耗。

3. **VMTHook是受限的⚠️**  
  仅适用于虚函数调用场景，无法Hook非虚函数。而InlineHook可劫持任意函数。

### 预备知识
- **[虚函数表（vtable）工作原理](https://blog.csdn.net/weixin_43844521/article/details/132136220)**
- **[虚函数表内存布局解析](https://www.cnblogs.com/pluser/p/virtual_fun_table.html)**
- **[实战：虚函数表偏移分析](https://www.bilibili.com/video/BV1kA6eYgEaG/?p=4)**

## 原理剖析
主流编译器实现虚函数调用机制时，会在类实例中隐式包含虚函数表指针（vptr）。虚函数表本质是函数指针数组，其内存结构如下：
```
类实例内存布局：
+------------------+
| 虚表指针   | --> 指向数组起始地址
| 成员变量   |
+------------------+

虚函数表结构：
+------------------+
| 虚表索引0  | --> 虚函数0的指针
| 虚表索引1  | --> 虚函数1的指针
| 虚表索引n  |
+------------------+
```

当通过基类指针调用虚函数时，实际调用流程为：
1. 通过对象vptr定位虚函数表。
2. 根据函数在虚表中的索引获取**实际**函数地址。
3. 执行目标函数。

> **VMTHook的核心：修改虚表中指定内存位置存储的数据，使调用者调用我们定义的Hook函数。**

## 实现
**文中以CCSPlayer_MovementServices类中的__int64 __fastcall sub_18074E090(__int64 a1, __int64 a2)为例**
![image](https://github.com/user-attachments/assets/2abe2bf6-514e-475d-b21e-54f13d5e66fc)

### 主要步骤
1. **虚表定位**  
   通过IDA或其他工具获取目标虚表的偏移（RVA）<br>
   ![image](https://github.com/user-attachments/assets/d7a06668-eeac-4a98-a7e4-431bc1f4058d)<br>
2. **索引计算**  
   确定目标虚函数在虚表中的位置偏移（索引）<br>
   **sizeof( IntPtr ) * index**<br>
3. **解除内存保护**
   由于虚表位于.rdata段，该段在加载完成后只读。<br>
   因此我们需要修改想要更改的字段为可读写。<br>
4. **替换虚表内容**  
   将目标虚表中存储的函数指针替换为Hook函数的绝对地址（VA）<br>
5. **调用原始函数**  
   保存原始函数指针实现链式调用。<br>

### C# 实现代码
> **注意**：这段代码不具有通用性！！！❌

![image](https://github.com/user-attachments/assets/b135c526-df60-4033-a432-61ba727f3140)
```csharp
using CounterStrikeSharp.API.Core;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace FunctionHook {
	[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
	public delegate IntPtr FastCallDelegate(IntPtr a1, IntPtr a2);

	public class VmtHook : IDisposable {
		private readonly IntPtr _vtable;
		private readonly int _index;
		private IntPtr _originalFunctionPtr;
		private FastCallDelegate _originalDelegate;
		private static VmtHook? _activeInstance;

		public VmtHook(IntPtr vtable, int index, FastCallDelegate hookDelegate) {
			_activeInstance = this;
			_vtable = vtable;
			_index = index;

			// 计算目标地址：vtable + index * 指针大小
			IntPtr targetSlot = _vtable + (_index * IntPtr.Size);

			// 获取并保存原始函数指针
			_originalFunctionPtr = Marshal.ReadIntPtr(targetSlot);
			_originalDelegate = Marshal.GetDelegateForFunctionPointer<FastCallDelegate>(_originalFunctionPtr);

			// 获取Hook函数的函数指针
			var hookPtr = Marshal.GetFunctionPointerForDelegate(hookDelegate);

			uint oldProtect;
			VirtualProtect(targetSlot, (UIntPtr)IntPtr.Size, 0x04, out oldProtect);
			// 修改虚表中指针
			Marshal.WriteIntPtr(targetSlot, hookPtr);
			VirtualProtect(targetSlot, (UIntPtr)IntPtr.Size, oldProtect, out oldProtect);
		}

		public static IntPtr GlobalCallOriginal(IntPtr a1, IntPtr a2) {
			// 调用原函数并返回结果
			return _activeInstance?._originalDelegate(a1, a2) ?? 0;
		}

		public void Dispose() {
			// 在这里恢复虚表中指针
		}


		[DllImport("kernel32.dll", SetLastError = true)]
		private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
	}

	public class FunctionHook : BasePlugin {
		public override string ModuleName => "Function Hook";
		public override string ModuleVersion => "1.0.0";
		public override string ModuleAuthor => "Ambr0se";

		public static IntPtr HookFunction(IntPtr a1, IntPtr a2) {
			Console.WriteLine($"[VMTHook] 钩子函数 -> 参数1: {a1}，参数2: {a2}");
			var originalResult = VmtHook.GlobalCallOriginal(a1, a2);
			Console.WriteLine($"[VMTHook] 原始函数 -> 返回: {originalResult}");

			return originalResult;
		}

		private static VmtHook? _hook;

		public override void Load(bool hotReload) {
			Process currentProcess = Process.GetCurrentProcess();
			IntPtr serverDllBaseAddress = currentProcess.Modules.Cast<ProcessModule>().LastOrDefault(m => string.Equals(m.ModuleName, "server.dll", StringComparison.OrdinalIgnoreCase))?.BaseAddress ?? throw new InvalidOperationException("找不到server.dll");

			_hook = new VmtHook(serverDllBaseAddress + 0x0F8D2E8, 31, HookFunction);
			Console.WriteLine($"[VMTHook] 虚表已修改");

			return;
		}
	}
}
```

#### 关键步骤说明
使用 ``_vtable + (_index * IntPtr.Size)`` 计算目标虚函数指针在内存中的地址。<br>
通过 ``Marshal.ReadIntPtr`` 读取原始函数指针并转换为委托后储存至变量。<br>
调用 ``VirtualProtect`` 将目标内存页属性改为**可读写**``（0x04 = PAGE_READWRITE）``<br>
使用 ``Marshal.WriteIntPtr`` 将虚表储存的**原虚函数地址**替换为**自定义Hook函数地址**。<br>
通过静态方法 ``GlobalCallOriginal`` 实现链式调用。<br>
> BTW. Windows x64平台统一了函数调用约定。**一般情况下**，函数的前四个参数都通过寄存器传递，其余参数压栈传递。<br>
> 因此，即使本文的目标函数使用**fastcall**调用约定，我们在C#中将目标函数的调用约定定义为**Cdecl**，依旧不会存在错误。<br>
> ![image](https://github.com/user-attachments/assets/61501e21-8876-47dd-8b19-67f485aec0db)<br>
> 引用一下，**[@MoxXiE1337](https://github.com/MOxXiE1337)** 提供的截图🎖️
