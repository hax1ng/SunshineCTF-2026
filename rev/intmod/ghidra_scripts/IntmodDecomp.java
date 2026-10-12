import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import java.io.*;
public class IntmodDecomp extends GhidraScript {
  public void run() throws Exception {
    DecompInterface d = new DecompInterface(); d.openProgram(currentProgram);
    PrintWriter pw = new PrintWriter(new FileWriter(getScriptArgs()[0]));
    for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
      DecompileResults r = d.decompileFunction(f, 120, monitor);
      pw.println("// ==== " + f.getName() + " @ " + f.getEntryPoint());
      if (r.decompileCompleted()) pw.println(r.getDecompiledFunction().getC());
    }
    pw.close();
  }
}
