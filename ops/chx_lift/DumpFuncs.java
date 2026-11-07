// DumpFuncs.java — chx-lift0 headless pseudo-C exporter
// Runs under Ghidra 12.2 analyzeHeadless via -postScript.
// Emits /out/funcs.json : [{name, addr, sig, bytes, body(pseudo-C)}...]
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class DumpFuncs extends GhidraScript {

    private String esc(String s) {
        if (s == null) return "";
        StringBuilder b = new StringBuilder();
        for (char c : s.toCharArray()) {
            switch (c) {
                case '\\': b.append("\\\\"); break;
                case '"':  b.append("\\\""); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append(""); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 32) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        return b.toString();
    }

    @Override
    public void run() throws Exception {
        java.io.File outDir = new java.io.File("/out");
        if (!outDir.exists()) outDir.mkdirs();
        java.io.PrintWriter out = new java.io.PrintWriter(new java.io.FileWriter("/out/funcs.json"));
        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(currentProgram);
        out.println("[");
        boolean first = true;
        FunctionIterator funcs = currentProgram.getFunctionManager().getFunctions(true);
        for (Function f : funcs) {
            if (f.isThunk()) continue;
            String name = f.getName();
            String sig = f.getSignature().toString();
            long addr = f.getEntryPoint().getOffset();
            long bytes = f.getBody().getNumAddresses();
            String body = "";
            try {
                DecompileResults res = ifc.decompileFunction(f, 30, monitor);
                if (res != null && res.decompileCompleted()) {
                    body = res.getDecompiledFunction().getC();
                }
            } catch (Exception e) {
                body = "";
            }
            if (!first) out.println(",");
            first = false;
            out.print("{\"name\":\"" + esc(name) + "\",\"addr\":" + addr +
                      ",\"bytes\":" + bytes +
                      ",\"sig\":\"" + esc(sig) +
                      "\",\"body\":\"" + esc(body) + "\"}");
            out.flush();
        }
        out.println();
        out.println("]");
        out.close();
        ifc.dispose();
        println("DUMPFUNCS_DONE");
    }
}
