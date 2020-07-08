using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;

namespace ILProtectorUnpacker
{
    public class Program
    {
        private static ModuleDefMD Module { get; set; }
        private static Assembly Assembly { get; set; }
        private static TypeDef GlobalType { get; set; }

        private static readonly List<object> JunkType = new List<object>();

        public static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                return;
            }

            var filePath = Path.GetFullPath(args[0]);

            if (!File.Exists(filePath))
            {
                return;
            }

            filePath = args[0];

            try
            {
                Module = ModuleDefMD.Load(filePath);
                Assembly = Assembly.LoadFrom(filePath);

                var asmResolver = new AssemblyResolver { EnableTypeDefCache = true };

                Module.Context = asmResolver.DefaultModuleContext = new ModuleContext(asmResolver);
                Module.Location = filePath;

                var asmRefs = Module.GetAssemblyRefs().ToList();

                var notFound = new List<string>();

                foreach (var asmRef in asmRefs)
                {
                    if (asmRef == null) continue;

                    var asmDef = asmResolver.Resolve(asmRef.FullName, Module);

                    if (asmDef == null)
                    {
                        notFound.Add(asmRef.FullName);
                    }
                    else
                    {
                        ((AssemblyResolver)Module.Context.AssemblyResolver).AddToCache(asmDef);
                    }
                }

                if (notFound.Count > 0)
                {
                    Console.WriteLine("Could not load file or assembly or one of its dependencies:");

                    foreach (var item in notFound)
                    {
                        Console.WriteLine(item);
                    }

                    Console.WriteLine();
                }

                RuntimeHelpers.RunModuleConstructor(Assembly.ManifestModule.ModuleHandle);

                GlobalType = Module.GlobalType;

                var invokeField = GlobalType.Fields.FirstOrDefault(x => x.Name == "Invoke");
                var stringField = GlobalType.Fields.FirstOrDefault(x => x.Name == "String");

                var invokeMethodToken = invokeField?.FieldType.TryGetTypeDef().Methods.FirstOrDefault(x => x.Name == "Invoke")?.MDToken.ToInt32();
                var strInvokeMethodToken = stringField?.FieldType.TryGetTypeDef().Methods.FirstOrDefault(x => x.Name == "Invoke")?.MDToken.ToInt32();

                if (invokeMethodToken == null) throw new Exception("Cannot find Invoke field!");

                var invokeMethod = Assembly.ManifestModule.ResolveMethod(invokeMethodToken.Value);
                var invokeInstance = Assembly.ManifestModule.ResolveField(invokeField.MDToken.ToInt32());

                FieldInfo strInstance = null;
                MethodBase strInvokeMethod = null;

                if (strInvokeMethodToken != null)
                {
                    strInstance = Assembly.ManifestModule.ResolveField(stringField.MDToken.ToInt32());
                    strInvokeMethod = Assembly.ManifestModule.ResolveMethod(strInvokeMethodToken.Value);
                }

                Hooks.ApplyHook();

                foreach (var type in Module.GetTypes())
                {
                    foreach (var method in type.Methods)
                    {
                        DecryptMethods(method, invokeMethod, invokeInstance.GetValue(invokeInstance));

                        if (strInstance != null)
                            DecryptStrings(method, strInvokeMethod, strInstance.GetValue(strInstance));
                    }
                }

                JunkType.Add(invokeField);
                JunkType.Add(stringField);

                var methods = GlobalType.Methods.Where(x => x.IsPrivate && x.IsStatic && x.Name.Length == 1).ToList();

                JunkType.AddRange(methods);

                CleanCctor();

                RemoveJunkTypes();

                RemoveEmbeddedAssemblies();

                Save(filePath);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }

            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
        }

        private static void DecryptMethods(MethodDef methodDef, MethodBase invokeMethod, object fieldInstance)
        {
            if (!methodDef.HasBody)
                return;

            var instructions = methodDef.Body.Instructions;

            if (instructions.Count > 2 &&
                instructions[0].OpCode.Code == Code.Ldsfld &&
                instructions[0].Operand.ToString().Contains("Invoke") &&
                instructions[1].IsLdcI4())
            {
                var mdToken = ((IType)methodDef.Body.Instructions[3].Operand).MDToken.ToInt32();
                JunkType.Add(methodDef.DeclaringType.NestedTypes.FirstOrDefault(net => net.MDToken.ToInt32() == mdToken));

                Hooks.MethodBase = Assembly.ManifestModule.ResolveMethod(methodDef.MDToken.ToInt32());

                var index = instructions[1].GetLdcI4Value();
                var method = invokeMethod.Invoke(fieldInstance, new object[] { index });

                try
                {
                    var reader = new DynamicMethodBodyReader(Module, method);
                    reader.Read();

                    methodDef.FreeMethodBody();
                    methodDef.Body = reader.GetMethod().Body;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error: {ex.Message}{Environment.NewLine}Method: {methodDef.FullName}{Environment.NewLine}MDToken:{methodDef.MDToken}{Environment.NewLine}");
                }
            }
        }

        private static void DecryptStrings(MethodDef methodDef, MethodBase invokeMethod, object fieldInstance)
        {
            if (methodDef.HasBody)
            {
                var instructions = methodDef.Body.Instructions;

                for (var i = 0; i < instructions.Count; i++)
                {
                    var instruction = instructions[i];

                    if (instruction.OpCode == OpCodes.Ldsfld &&
                        instruction.Operand.ToString().Contains("<Module>::String") &&
                        instructions[i + 1].IsLdcI4() && instructions[i + 2].OpCode == OpCodes.Callvirt &&
                        instructions[i + 2].Operand.ToString().Contains("Invoke"))
                    {
                        var index = (int)instructions[i + 1].Operand;
                        instructions[i].OpCode = OpCodes.Ldstr;
                        instructions[i].Operand = invokeMethod.Invoke(fieldInstance, new object[] { index });
                        instructions[i + 1].OpCode = OpCodes.Nop;
                        instructions[i + 2].OpCode = OpCodes.Nop;
                    }
                }
            }
        }

        private static void CleanCctor()
        {
            var methodDef = GlobalType.FindStaticConstructor();

            if (methodDef.HasBody)
            {
                var startIndex = methodDef.Body.Instructions.IndexOf(methodDef.Body.Instructions.FirstOrDefault(
                    inst => inst.OpCode == OpCodes.Call &&
                            ((IMethod)inst.Operand).Name == "GetIUnknownForObject")) - 2;

                var endIndex = methodDef.Body.Instructions.IndexOf(methodDef.Body.Instructions.FirstOrDefault(
                    inst => inst.OpCode == OpCodes.Call && ((IMethod)inst.Operand).Name == "Release")) + 2;

                methodDef.Body.ExceptionHandlers.Remove(methodDef.Body.ExceptionHandlers.FirstOrDefault(
                    exh => exh.HandlerEnd == methodDef.Body.Instructions[endIndex + 1]));

                for (var i = startIndex; i <= endIndex; i++)
                    methodDef.Body.Instructions.Remove(methodDef.Body.Instructions[startIndex]);

                if (methodDef.Body.Instructions.Count == 1)
                {
                    JunkType.Add(methodDef);
                }
            }

            foreach (var def in GlobalType.Methods.Where(met => met.HasImplMap)
                .Where(met => new[] { "Protect32.dll", "Protect64.dll" }
                    .Any(x => x == met.ImplMap?.Module.Name.ToString())).ToList())
                GlobalType.Remove(def);
        }

        private static void RemoveJunkTypes()
        {
            foreach (var typeDef in JunkType)
            {
                switch (typeDef)
                {
                    case FieldDef field:
                        Module.Types.Remove(field.FieldType.ToTypeDefOrRef().ResolveTypeDef());
                        GlobalType.Fields.Remove(field);
                        break;

                    case MethodDef method:
                        if (method.HasBody && method.Body.Instructions[0].OpCode == OpCodes.Ldstr && method.Body.Instructions[0].Operand.ToString().Contains("P0"))
                            Module.Types.Remove((TypeDef)method.Body.Instructions[1].Operand);

                        GlobalType.Methods.Remove(method);
                        break;

                    case TypeDef type:
                        type.DeclaringType.NestedTypes.Remove(type);
                        break;
                }
            }
        }

        private static void RemoveEmbeddedAssemblies()
        {
            var resources = Module.Resources.Where(x => x.Name.StartsWith("Protect") && x.Name.EndsWith(".dll")).ToList();

            foreach (var resource in resources)
            {
                Module.Resources.Remove(resource);
            }
        }

        private static void Save(string filePath)
        {
            var path = GenerateFileName(filePath, "-unpacked");

            if (Module.IsILOnly)
            {
                Module.Write(path, new ModuleWriterOptions(Module)
                {
                    MetadataOptions = { Flags = MetadataFlags.PreserveAll | MetadataFlags.KeepOldMaxStack },
                    Logger = DummyLogger.NoThrowInstance
                });
            }
            else
            {
                Module.NativeWrite(path, new NativeModuleWriterOptions(Module, false)
                {
                    MetadataOptions = { Flags = MetadataFlags.PreserveAll | MetadataFlags.KeepOldMaxStack },
                    Logger = DummyLogger.NoThrowInstance
                });
            }
        }

        private static string GenerateFileName(string filePath, string append)
        {
            return Path.Combine(Path.GetDirectoryName(filePath), Path.GetFileNameWithoutExtension(filePath) + append + Path.GetExtension(filePath));
        }
    }
}