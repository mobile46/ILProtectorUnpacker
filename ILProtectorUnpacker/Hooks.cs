using HarmonyLib;
using System;
using System.Linq;
using System.Reflection;

namespace ILProtectorUnpacker {
	public class Hooks {
		static readonly Harmony Harmony = new("ILProtectorUnpacker-Mobile46");
		public static MethodBase MethodBase;

		public static void ApplyHook() {
			var runtimeType = typeof(Delegate).Assembly.GetType("System.RuntimeType");
			var getMethod = runtimeType.GetMethods((BindingFlags)(-1)).First(m =>
				m.Name == "GetMethodBase" && m.GetParameters().Length == 2 &&
				m.GetParameters()[0].ParameterType == runtimeType &&
				m.GetParameters()[1].ParameterType.Name == "IRuntimeMethodInfo");
			Harmony.Patch(getMethod, null, new HarmonyMethod(typeof(Hooks).GetMethod("Postfix")));
		}

		public static void Postfix(ref MethodBase __result) {
			if (__result.Name == "InvokeMethod") {
				__result = MethodBase;
			}
		}
	}
}
