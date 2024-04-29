using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace ILProtectorUnpacker {
	public class Program {
		static ModuleDefMD Module { get; set; }
		static Assembly Assembly { get; set; }
		static TypeDef GlobalType { get; set; }

		static readonly List<object> JunkTypes = new();

		public static void Main(string[] args) {
			if (args.Length < 1) {
				return;
			}

			try {
				var filePath = Path.GetFullPath(args[0]);

				if (!File.Exists(filePath)) {
					return;
				}

				var dirPath = Path.GetDirectoryName(filePath)!;

				Directory.SetCurrentDirectory(dirPath);

				Module = ModuleDefMD.Load(filePath, new ModuleCreationOptions { TryToLoadPdbFromDisk = false });
				Assembly = Assembly.LoadFrom(filePath);

				var modCtx = ModuleDef.CreateModuleContext();
				var asmResolver = (AssemblyResolver)modCtx.AssemblyResolver;
				asmResolver.DefaultModuleContext = modCtx;
				asmResolver.EnableTypeDefCache = true;

				Module.Context = modCtx;
				asmResolver.AddToCache(Module);

				var asmRefs = Module.GetAssemblyRefs().ToList();

				var notFound = new List<string>();

				foreach (var asmRef in asmRefs) {
					if (asmRef == null) {
						continue;
					}

					var asmDef = asmResolver.Resolve(asmRef.FullName, Module);
					if (asmDef == null) {
						notFound.Add(asmRef.FullName);
					}
					else {
						asmResolver.AddToCache(asmDef);
					}
				}

				if (notFound.Count > 0) {
					Console.WriteLine("Could not load file or assembly or one of its dependencies:");

					foreach (var item in notFound) {
						Console.WriteLine(item);
					}

					Console.WriteLine();
				}

				LoadNativeLibrary(dirPath);

				RuntimeHelpers.RunModuleConstructor(Assembly.ManifestModule.ModuleHandle);

				GlobalType = Module.GlobalType;

				var invokeField = GlobalType.Fields.FirstOrDefault(x => x.Name == "Invoke");
				var stringField = GlobalType.Fields.FirstOrDefault(x => x.Name == "String");

				var invokeMethodToken = invokeField?.FieldType.TryGetTypeDef().Methods
					.FirstOrDefault(x => x.Name == "Invoke")?.MDToken.ToInt32();
				var strInvokeMethodToken = stringField?.FieldType.TryGetTypeDef().Methods
					.FirstOrDefault(x => x.Name == "Invoke")?.MDToken.ToInt32();

				if (invokeMethodToken == null) {
					throw new Exception("Cannot find Invoke field!");
				}

				var invokeMethod = Assembly.ManifestModule.ResolveMethod(invokeMethodToken.Value);
				var invokeInstance = Assembly.ManifestModule.ResolveField(invokeField.MDToken.ToInt32());

				FieldInfo strInstance = null;
				MethodBase strInvokeMethod = null;

				if (strInvokeMethodToken != null) {
					strInstance = Assembly.ManifestModule.ResolveField(stringField.MDToken.ToInt32());
					strInvokeMethod = Assembly.ManifestModule.ResolveMethod(strInvokeMethodToken.Value);
				}

				Hooks.ApplyHook();

				foreach (var type in Module.GetTypes()) {
					foreach (var method in type.Methods) {
						DecryptMethods(method, invokeMethod, invokeInstance.GetValue(invokeInstance));

						if (strInstance != null) {
							DecryptStrings(method, strInvokeMethod, strInstance.GetValue(strInstance));
						}
					}
				}

				JunkTypes.Add(invokeField);
				JunkTypes.Add(stringField);

				var methods = GlobalType.Methods.Where(x => x.IsPrivate && x.IsStatic && x.Name.Length == 1).ToList();

				JunkTypes.AddRange(methods);

				CleanCctor();

				RemoveJunkTypes();

				RemoveEmbeddedAssemblies();

				Save(filePath);
			}
			catch (Exception ex) {
				Console.WriteLine($"Error: {ex.Message}");
			}

			Console.WriteLine("Press any key to exit...");
			Console.ReadKey();
		}

		[DllImport("kernel32.dll", CharSet = CharSet.Auto)]
		static extern IntPtr LoadLibrary(string lpFileName);

		static void LoadNativeLibrary(string path) {
			var files = Directory.GetFiles(path, "Protect*.dll");
			foreach (var file in files) {
				var handle = LoadLibrary(file);
				if (handle != IntPtr.Zero) {
					break;
				}
			}
		}

		static void DecryptMethods(MethodDef methodDef, MethodBase invokeMethod, object fieldInstance) {
			if (!methodDef.HasBody) {
				return;
			}

			var instructions = methodDef.Body.Instructions;

			if (instructions.Count > 2 && instructions[0].OpCode.Code == Code.Ldsfld &&
			    instructions[0].Operand.ToString().Contains("Invoke") && instructions[1].IsLdcI4()) {
				try {
					var mdToken = ((IType)methodDef.Body.Instructions[3].Operand).MDToken.ToInt32();
					JunkTypes.Add(
						methodDef.DeclaringType.NestedTypes.FirstOrDefault(net => net.MDToken.ToInt32() == mdToken));

					Hooks.MethodBase = Assembly.ManifestModule.ResolveMethod(methodDef.MDToken.ToInt32());

					var index = instructions[1].GetLdcI4Value();
					var method = invokeMethod.Invoke(fieldInstance, new object[] { index });

					var reader = new DynamicMethodBodyReader(Module, method);
					reader.Read();

					methodDef.FreeMethodBody();
					methodDef.Body = reader.GetMethod().Body;
				}
				catch (Exception ex) {
					Console.WriteLine(
						$"Error: {ex.Message}{Environment.NewLine}Method: {methodDef.FullName}{Environment.NewLine}MDToken: 0x{methodDef.MDToken}{Environment.NewLine}");
				}
			}
		}

		static void DecryptStrings(MethodDef methodDef, MethodBase invokeMethod, object fieldInstance) {
			if (!methodDef.HasBody) {
				return;
			}

			var instsr = methodDef.Body.Instructions;

			for (var i = 0; i < instsr.Count; i++) {
				var instr = instsr[i];

				if (instr.OpCode == OpCodes.Ldsfld && instr.Operand.ToString().Contains("<Module>::String") &&
				    instsr[i + 1].IsLdcI4() && instsr[i + 2].OpCode == OpCodes.Callvirt &&
				    instsr[i + 2].Operand.ToString().Contains("Invoke")) {
					var index = (int)instsr[i + 1].Operand;
					instsr[i].OpCode = OpCodes.Ldstr;
					instsr[i].Operand = invokeMethod.Invoke(fieldInstance, new object[] { index });
					instsr[i + 1].OpCode = OpCodes.Nop;
					instsr[i + 2].OpCode = OpCodes.Nop;
				}
			}
		}

		static void CleanCctor() {
			var methodDef = GlobalType.FindStaticConstructor();

			if (methodDef.HasBody) {
				var startIndex = methodDef.Body.Instructions.IndexOf(methodDef.Body.Instructions.FirstOrDefault(inst =>
					inst.OpCode == OpCodes.Call && ((IMethod)inst.Operand).Name == "GetIUnknownForObject")) - 2;

				var endIndex = methodDef.Body.Instructions.IndexOf(methodDef.Body.Instructions.FirstOrDefault(inst =>
					inst.OpCode == OpCodes.Call && ((IMethod)inst.Operand).Name == "Release")) + 2;

				methodDef.Body.ExceptionHandlers.Remove(methodDef.Body.ExceptionHandlers.FirstOrDefault(exh =>
					exh.HandlerEnd == methodDef.Body.Instructions[endIndex + 1]));

				for (var i = startIndex; i <= endIndex; i++) {
					methodDef.Body.Instructions.Remove(methodDef.Body.Instructions[startIndex]);
				}

				if (methodDef.Body.Instructions.Count == 1) {
					JunkTypes.Add(methodDef);
				}
			}

			foreach (var def in GlobalType.Methods.Where(met => met.HasImplMap).Where(met =>
					         new[] { "Protect32.dll", "Protect64.dll" }.Any(x =>
						         x == met.ImplMap?.Module.Name.ToString()))
				         .ToList()) {
				GlobalType.Remove(def);
			}
		}

		static void RemoveJunkTypes() {
			foreach (var typeDef in JunkTypes) {
				switch (typeDef) {
					case FieldDef field:
						Module.Types.Remove(field.FieldType.ToTypeDefOrRef().ResolveTypeDef());
						GlobalType.Fields.Remove(field);
						break;

					case MethodDef method:
						if (method.HasBody && method.Body.Instructions[0].OpCode == OpCodes.Ldstr &&
						    method.Body.Instructions[0].Operand.ToString().Contains("P0")) {
							Module.Types.Remove((TypeDef)method.Body.Instructions[1].Operand);
						}

						GlobalType.Methods.Remove(method);
						break;

					case TypeDef type:
						type.DeclaringType.NestedTypes.Remove(type);
						break;
				}
			}
		}

		static void RemoveEmbeddedAssemblies() {
			var resources = Module.Resources.Where(x => x.Name.StartsWith("Protect") && x.Name.EndsWith(".dll"))
				.ToList();

			foreach (var resource in resources) {
				Module.Resources.Remove(resource);
			}
		}

		static void Save(string filePath) {
			var path = GenerateFileName(filePath, "-unpacked");
			if (Module.IsILOnly) {
				var moduleWriterOptions = new ModuleWriterOptions(Module);
				moduleWriterOptions.MetadataOptions.Flags |= MetadataFlags.PreserveAll | MetadataFlags.KeepOldMaxStack;
				moduleWriterOptions.Logger = DummyLogger.NoThrowInstance;
				Module.Write(path, moduleWriterOptions);
			}
			else {
				var nativeModuleWriterOptions = new NativeModuleWriterOptions(Module, false);
				nativeModuleWriterOptions.MetadataOptions.Flags |=
					MetadataFlags.PreserveAll | MetadataFlags.KeepOldMaxStack;
				nativeModuleWriterOptions.Logger = DummyLogger.NoThrowInstance;
				nativeModuleWriterOptions.KeepExtraPEData = true;
				nativeModuleWriterOptions.KeepWin32Resources = true;
				Module.NativeWrite(path, nativeModuleWriterOptions);
			}
		}

		static string GenerateFileName(string filePath, string append) => Path.Combine(Path.GetDirectoryName(filePath)!,
			Path.GetFileNameWithoutExtension(filePath) + append + Path.GetExtension(filePath));
	}
}
